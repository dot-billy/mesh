(() => {
  "use strict";

  const state = {
    contract: null,
    operations: [],
    selectedTag: "All operations",
    search: "",
  };

  const elements = {
    description: document.querySelector("#api-description"),
    version: document.querySelector("#contract-version"),
    operationCount: document.querySelector("#operation-count"),
    tagCount: document.querySelector("#tag-count"),
    tags: document.querySelector("#tag-navigation"),
    search: document.querySelector("#operation-search"),
    resultCount: document.querySelector("#result-count"),
    list: document.querySelector("#operation-list"),
    error: document.querySelector("#contract-error"),
    errorMessage: document.querySelector("#contract-error-message"),
  };

  const methods = new Set(["get", "put", "post", "delete", "patch", "head", "options", "trace"]);
  const safeMethods = new Set(["GET", "HEAD"]);

  function node(tag, options = {}, children = []) {
    const element = document.createElement(tag);
    for (const [key, value] of Object.entries(options)) {
      if (key === "className") {
        element.className = value;
      } else if (key === "text") {
        element.textContent = value;
      } else if (key === "dataset") {
        for (const [dataKey, dataValue] of Object.entries(value)) {
          element.dataset[dataKey] = dataValue;
        }
      } else if (key === "attrs") {
        for (const [attribute, attributeValue] of Object.entries(value)) {
          if (attributeValue !== null && attributeValue !== undefined) {
            element.setAttribute(attribute, attributeValue);
          }
        }
      }
    }
    for (const child of children) {
      if (child !== null && child !== undefined) {
        element.append(child);
      }
    }
    return element;
  }

  function textOr(value, fallback) {
    return typeof value === "string" && value.trim() ? value : fallback;
  }

  function methodClass(method) {
    return `method-badge method-${method.toLowerCase()}`;
  }

  function extractOperations(contract) {
    const result = [];
    for (const [path, pathItem] of Object.entries(contract.paths || {})) {
      for (const [method, operation] of Object.entries(pathItem || {})) {
        if (!methods.has(method)) {
          continue;
        }
        result.push({
          path,
          method: method.toUpperCase(),
          ...operation,
          tag: Array.isArray(operation.tags) && operation.tags.length ? operation.tags[0] : "Other",
        });
      }
    }
    return result.sort((left, right) =>
      left.tag.localeCompare(right.tag)
      || left.path.localeCompare(right.path)
      || left.method.localeCompare(right.method)
    );
  }

  function tagCounts() {
    const counts = new Map([["All operations", state.operations.length]]);
    for (const operation of state.operations) {
      counts.set(operation.tag, (counts.get(operation.tag) || 0) + 1);
    }
    return counts;
  }

  function renderTags() {
    elements.tags.replaceChildren();
    for (const [tag, count] of tagCounts()) {
      const button = node("button", {
        className: `tag-button${tag === state.selectedTag ? " active" : ""}`,
        attrs: {
          type: "button",
          "aria-pressed": tag === state.selectedTag ? "true" : "false",
        },
      }, [
        node("span", { text: tag }),
        node("span", { text: String(count) }),
      ]);
      button.addEventListener("click", () => {
        state.selectedTag = tag;
        renderTags();
        renderOperations();
      });
      elements.tags.append(button);
    }
  }

  function filteredOperations() {
    const query = state.search.trim().toLowerCase();
    return state.operations.filter((operation) => {
      if (state.selectedTag !== "All operations" && operation.tag !== state.selectedTag) {
        return false;
      }
      if (!query) {
        return true;
      }
      const searchable = [
        operation.method,
        operation.path,
        operation.operationId,
        operation.summary,
        operation.description,
        operation.tag,
        operation["x-required-permission"],
      ].filter(Boolean).join(" ").toLowerCase();
      return searchable.includes(query);
    });
  }

  function metaChip(value, className = "") {
    return node("span", { className: `meta-chip ${className}`.trim(), text: value });
  }

  function renderFieldList(parameters) {
    const list = node("dl", { className: "field-list" });
    for (const parameter of parameters) {
      const type = parameter.schema?.type || "value";
      const required = parameter.required ? "required" : "optional";
      const description = `${parameter.in} · ${type} · ${required}. ${textOr(parameter.description, "")}`.trim();
      list.append(node("div", {}, [
        node("dt", { text: parameter.name }),
        node("dd", { text: description }),
      ]));
    }
    return list;
  }

  function jsonText(value) {
    return JSON.stringify(value, null, 2);
  }

  function codeBlock(value, label = "Copy") {
    const text = typeof value === "string" ? value : jsonText(value);
    const pre = node("pre", {}, [node("code", { text })]);
    const button = node("button", {
      className: "copy-button",
      text: label,
      attrs: { type: "button" },
    });
    button.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(text);
        button.textContent = "Copied";
      } catch {
        button.textContent = "Select to copy";
      }
      window.setTimeout(() => {
        button.textContent = label;
      }, 1600);
    });
    return node("div", { className: "code-block" }, [pre, button]);
  }

  function requestMedia(operation) {
    return operation.requestBody?.content?.["application/json"] || null;
  }

  function successfulResponseMedia(operation) {
    const responses = operation.responses || {};
    const success = Object.keys(responses).sort().find((status) => /^[23]\d\d$/.test(status));
    return success ? responses[success]?.content?.["application/json"] || null : null;
  }

  function schemaLabel(schema) {
    if (!schema) {
      return "No JSON body";
    }
    if (typeof schema.$ref === "string") {
      return schema.$ref.split("/").pop();
    }
    if (schema.type === "array") {
      return `array of ${schemaLabel(schema.items)}`;
    }
    return schema.type || "JSON value";
  }

  function renderResponses(operation) {
    const list = node("div", { className: "response-list" });
    for (const [status, response] of Object.entries(operation.responses || {}).sort()) {
      const description = response.description || (
        typeof response.$ref === "string"
          ? response.$ref.split("/").pop().replace(/([a-z])([A-Z])/g, "$1 $2")
          : "Documented response"
      );
      list.append(node("div", { className: "response-row" }, [
        node("span", { className: "response-status", text: status }),
        node("p", { text: description }),
      ]));
    }
    return list;
  }

  function securityNames(operation) {
    const names = new Set();
    for (const choice of operation.security || []) {
      for (const name of Object.keys(choice || {})) {
        names.add(name);
      }
    }
    return names;
  }

  function cookieValue(names) {
    for (const part of document.cookie.split(";")) {
      const separator = part.indexOf("=");
      if (separator < 0) {
        continue;
      }
      const name = part.slice(0, separator).trim();
      if (names.includes(name)) {
        return decodeURIComponent(part.slice(separator + 1));
      }
    }
    return "";
  }

  function tryPanel(operation) {
    const interactive = operation["x-interactive"] === true;
    const panel = node("section", {
      className: `try-panel${interactive ? "" : " disabled"}`,
      attrs: { "aria-label": `Try ${operation.operationId}` },
    });
    const title = interactive ? "Try from this browser" : "Interactive request disabled";
    const explanation = interactive
      ? "Uses your current same-origin browser session. Inputs and responses remain in this tab and are never persisted."
      : "Use the generated curl example from the intended client. This operation accepts or returns sensitive credential material, uses an agent credential, or is not safe for a browser console.";
    panel.append(node("div", { className: "try-heading" }, [
      node("div", {}, [
        node("h3", { text: title }),
        node("p", { text: explanation }),
      ]),
      node("span", { className: "try-label", text: interactive ? "Same origin" : "Protected" }),
    ]));
    if (!interactive) {
      return panel;
    }

    const form = node("form", { className: "try-form" });
    const fields = node("div", { className: "try-fields" });
    for (const parameter of operation.parameters || []) {
      const input = node("input", {
        attrs: {
          type: parameter.schema?.type === "integer" ? "number" : "text",
          name: parameter.name,
          placeholder: parameter.example !== undefined ? String(parameter.example) : "",
          required: parameter.required ? "required" : null,
          autocomplete: "off",
          spellcheck: "false",
        },
        dataset: { location: parameter.in },
      });
      if (parameter.example !== undefined) {
        input.value = String(parameter.example);
      }
      fields.append(node("label", {}, [
        node("span", { text: `${parameter.name}${parameter.required ? " · required" : " · optional"}` }),
        input,
      ]));
    }
    if (fields.childElementCount) {
      form.append(fields);
    }

    const media = requestMedia(operation);
    let bodyInput = null;
    if (media) {
      bodyInput = node("textarea", {
        attrs: {
          name: "request-body",
          spellcheck: "false",
          "aria-label": "JSON request body",
        },
      });
      bodyInput.value = jsonText(media.example ?? {});
      form.append(node("label", {}, [
        node("span", { text: `JSON body · ${schemaLabel(media.schema)}` }),
        bodyInput,
      ]));
    }

    let confirmation = null;
    if (!safeMethods.has(operation.method)) {
      confirmation = node("input", { attrs: { type: "checkbox", required: "required" } });
      form.append(node("label", { className: "mutation-confirm" }, [
        confirmation,
        node("span", { text: "I understand this sends a real state-changing request to the currently open Mesh control plane." }),
      ]));
    }
    const send = node("button", {
      className: "send-button",
      text: `Send ${operation.method}`,
      attrs: { type: "submit" },
    });
    form.append(send);
    const error = node("p", { className: "try-error hidden", attrs: { role: "alert" } });
    const result = node("div", { className: "try-result hidden", attrs: { "aria-live": "polite" } });
    panel.append(form, error, result);

    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      error.classList.add("hidden");
      result.classList.add("hidden");
      send.disabled = true;
      send.textContent = "Sending…";
      try {
        let path = operation.path;
        const query = new URLSearchParams();
        for (const input of fields.querySelectorAll("input")) {
          const value = input.value.trim();
          if (input.required && !value) {
            throw new Error(`${input.name} is required.`);
          }
          if (!value) {
            continue;
          }
          if (input.dataset.location === "path") {
            path = path.replace(`{${input.name}}`, encodeURIComponent(value));
          } else if (input.dataset.location === "query") {
            query.set(input.name, value);
          }
        }
        if (path.includes("{")) {
          throw new Error("All path parameters are required.");
        }
        const headers = new Headers({ Accept: "application/json" });
        const request = {
          method: operation.method,
          credentials: "same-origin",
          headers,
        };
        if (bodyInput) {
          let parsed;
          try {
            parsed = JSON.parse(bodyInput.value);
          } catch {
            throw new Error("The request body is not valid JSON.");
          }
          headers.set("Content-Type", "application/json");
          request.body = JSON.stringify(parsed);
        }
        if (!safeMethods.has(operation.method) && securityNames(operation).has("cookieSession")) {
          const csrf = cookieValue(["__Host-mesh_csrf", "mesh_csrf"]);
          if (!csrf) {
            throw new Error("No Mesh CSRF cookie is available. Sign in to the control plane in this browser first.");
          }
          headers.set("X-Mesh-CSRF", csrf);
        }
        const controller = new AbortController();
        request.signal = controller.signal;
        const timeout = window.setTimeout(() => controller.abort(), 20000);
        let response;
        try {
          response = await fetch(`${path}${query.size ? `?${query}` : ""}`, request);
        } finally {
          window.clearTimeout(timeout);
        }
        const contentType = response.headers.get("content-type") || "";
        const raw = operation.method === "HEAD" ? "" : await response.text();
        let displayBody = raw;
        if (raw && contentType.includes("json")) {
          try {
            displayBody = jsonText(JSON.parse(raw));
          } catch {
            displayBody = raw;
          }
        }
        const headerSummary = ["content-type", "etag", "location", "retry-after"]
          .map((name) => [name, response.headers.get(name)])
          .filter(([, value]) => value)
          .map(([name, value]) => `${name}: ${value}`)
          .join("\n");
        result.replaceChildren(
          node("div", { className: "try-result-heading" }, [
            node("strong", { text: `${response.status} ${response.statusText}` }),
            node("span", { text: response.ok ? "Request completed" : "Request returned an error" }),
          ]),
          codeBlock([headerSummary, displayBody || "(empty response body)"].filter(Boolean).join("\n\n")),
        );
        result.classList.remove("hidden");
      } catch (requestError) {
        error.textContent = requestError.name === "AbortError"
          ? "The request timed out after 20 seconds."
          : requestError.message || "The request could not be sent.";
        error.classList.remove("hidden");
      } finally {
        send.disabled = false;
        send.textContent = `Send ${operation.method}`;
      }
    });
    return panel;
  }

  function operationElement(operation) {
    const details = node("details", {
      className: "operation",
      attrs: { id: `operation-${operation.operationId}` },
    });
    const summary = node("summary", { className: "operation-summary" }, [
      node("span", { className: methodClass(operation.method), text: operation.method }),
      node("code", { className: "operation-path", text: operation.path }),
      node("span", { className: "operation-name" }, [
        node("strong", { text: textOr(operation.summary, operation.operationId) }),
        node("span", { text: operation.tag }),
      ]),
      node("i", { className: "fa fa-chevron-down operation-chevron", attrs: { "aria-hidden": "true" } }),
    ]);
    const metadata = node("div", { className: "metadata" });
    metadata.append(metaChip(textOr(operation["x-availability"], "always")));
    if (operation["x-required-permission"]) {
      metadata.append(metaChip(operation["x-required-permission"], "permission"));
    }
    if (operation.deprecated) {
      metadata.append(metaChip("deprecated", "deprecated-chip"));
    }

    const content = node("div", { className: "operation-content" });
    content.append(node("div", { className: "operation-intro" }, [
      node("p", { text: textOr(operation.description, "No description supplied.") }),
      metadata,
    ]));

    const detailGrid = node("div", { className: "detail-grid" });
    const parameters = operation.parameters || [];
    detailGrid.append(node("section", { className: "detail-panel" }, [
      node("h3", { text: "Parameters" }),
      parameters.length
        ? renderFieldList(parameters)
        : node("p", { className: "muted", text: "No path or query parameters." }),
    ]));
    detailGrid.append(node("section", { className: "detail-panel" }, [
      node("h3", { text: "Responses" }),
      renderResponses(operation),
    ]));

    const request = requestMedia(operation);
    if (request) {
      detailGrid.append(node("section", { className: "detail-panel" }, [
        node("h3", { text: `Request · ${schemaLabel(request.schema)}` }),
        codeBlock(request.example ?? {}),
      ]));
    }
    const response = successfulResponseMedia(operation);
    if (response) {
      detailGrid.append(node("section", { className: "detail-panel" }, [
        node("h3", { text: `Success · ${schemaLabel(response.schema)}` }),
        codeBlock(response.example ?? {}),
      ]));
    }
    const sample = Array.isArray(operation["x-codeSamples"]) ? operation["x-codeSamples"][0]?.source : null;
    if (sample) {
      detailGrid.append(node("section", { className: "detail-panel full" }, [
        node("h3", { text: "Command-line example" }),
        codeBlock(sample),
      ]));
    }
    content.append(detailGrid, tryPanel(operation));
    details.append(summary, content);
    return details;
  }

  function renderOperations() {
    const operations = filteredOperations();
    elements.list.replaceChildren();
    elements.list.setAttribute("aria-busy", "false");
    elements.resultCount.textContent = `${operations.length} of ${state.operations.length} operations`;
    if (!operations.length) {
      elements.list.append(node("div", {
        className: "empty-results",
        text: "No operations match this filter.",
      }));
      return;
    }
    const fragment = document.createDocumentFragment();
    for (const operation of operations) {
      fragment.append(operationElement(operation));
    }
    elements.list.append(fragment);
  }

  async function loadContract() {
    try {
      const response = await fetch("/openapi.json", {
        headers: { Accept: "application/vnd.oai.openapi+json, application/json" },
        credentials: "same-origin",
      });
      if (!response.ok) {
        throw new Error(`The contract endpoint returned ${response.status}.`);
      }
      const contract = await response.json();
      if (contract.openapi !== "3.1.0" || !contract.paths || !contract.info) {
        throw new Error("The contract is not a complete OpenAPI 3.1 document.");
      }
      state.contract = contract;
      state.operations = extractOperations(contract);
      elements.description.textContent = `Search all ${state.operations.length} operations, inspect typed requests and responses, copy placeholder-only commands, and safely try eligible calls against this Mesh control plane.`;
      elements.version.textContent = textOr(contract.info.version, "—");
      elements.operationCount.textContent = String(state.operations.length);
      elements.tagCount.textContent = String(tagCounts().size - 1);
      renderTags();
      renderOperations();
      const hash = window.location.hash;
      if (hash.startsWith("#operation-")) {
        const target = document.querySelector(hash);
        if (target instanceof HTMLDetailsElement) {
          target.open = true;
          target.scrollIntoView();
        }
      }
    } catch (error) {
      elements.list.setAttribute("aria-busy", "false");
      elements.resultCount.textContent = "Contract unavailable";
      elements.errorMessage.textContent = error.message || "The contract could not be loaded.";
      elements.error.classList.remove("hidden");
    }
  }

  elements.search.addEventListener("input", () => {
    state.search = elements.search.value;
    renderOperations();
  });

  loadContract();
})();
