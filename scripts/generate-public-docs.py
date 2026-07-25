#!/usr/bin/env python3
"""Generate the public, embedded Mesh documentation page."""

from __future__ import annotations

import argparse
import html
import json
import os
import pathlib
import re
import tempfile
from typing import Any


ROOT = pathlib.Path(__file__).resolve().parents[1]
DEFAULT_SOURCE = ROOT / "docs" / "public-guide.json"
DEFAULT_OUTPUT = ROOT / "internal" / "httpapi" / "web" / "docs.html"
ID_PATTERN = re.compile(r"^[a-z][a-z0-9-]{1,47}$")
NOTE_KINDS = {"important", "warning", "info"}


class ManifestError(ValueError):
    pass


def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ManifestError(f"duplicate JSON field {key!r}")
        result[key] = value
    return result


def require_text(value: Any, label: str, *, maximum: int = 2000) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise ManifestError(f"{label} must be nonempty trimmed text")
    if len(value) > maximum:
        raise ManifestError(f"{label} exceeds {maximum} characters")
    return value


def require_text_list(value: Any, label: str, *, maximum_items: int = 12) -> list[str]:
    if not isinstance(value, list) or not value or len(value) > maximum_items:
        raise ManifestError(f"{label} must contain 1-{maximum_items} items")
    return [require_text(item, f"{label}[{index}]") for index, item in enumerate(value)]


def validate_topic(topic: Any, label: str) -> dict[str, Any]:
    if not isinstance(topic, dict):
        raise ManifestError(f"{label} must be an object")
    allowed = {"title", "wide", "body", "bullets", "steps", "note"}
    unknown = set(topic) - allowed
    if unknown:
        raise ManifestError(f"{label} has unknown fields: {sorted(unknown)}")
    title = require_text(topic.get("title"), f"{label}.title", maximum=120)
    wide = topic.get("wide", False)
    if not isinstance(wide, bool):
        raise ManifestError(f"{label}.wide must be a boolean")
    body = topic.get("body")
    if body is not None:
        body = require_text(body, f"{label}.body")
    bullets = topic.get("bullets")
    if bullets is not None:
        bullets = require_text_list(bullets, f"{label}.bullets")
    steps = topic.get("steps")
    if steps is not None:
        steps = require_text_list(steps, f"{label}.steps")
    if body is None and bullets is None and steps is None:
        raise ManifestError(f"{label} must include body, bullets, or steps")
    note = topic.get("note")
    if note is not None:
        if not isinstance(note, dict) or set(note) != {"kind", "title", "body"}:
            raise ManifestError(f"{label}.note must contain exactly kind, title, and body")
        if note["kind"] not in NOTE_KINDS:
            raise ManifestError(f"{label}.note.kind is unsupported")
        note = {
            "kind": note["kind"],
            "title": require_text(note["title"], f"{label}.note.title", maximum=120),
            "body": require_text(note["body"], f"{label}.note.body"),
        }
    return {
        "title": title,
        "wide": wide,
        "body": body,
        "bullets": bullets,
        "steps": steps,
        "note": note,
    }


def load_manifest(path: pathlib.Path) -> dict[str, Any]:
    try:
        raw = path.read_text(encoding="utf-8")
        decoder = json.JSONDecoder(object_pairs_hook=reject_duplicates)
        document, offset = decoder.raw_decode(raw)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ManifestError(f"cannot read public documentation manifest: {error}") from error
    if raw[offset:].strip():
        raise ManifestError("public documentation manifest has trailing data")
    if not isinstance(document, dict):
        raise ManifestError("public documentation manifest must be an object")
    expected = {
        "schema", "title", "subtitle", "description", "reviewed_at",
        "quick_start", "sections",
    }
    if set(document) != expected:
        raise ManifestError(
            f"public documentation manifest fields differ: missing={sorted(expected - set(document))} "
            f"unknown={sorted(set(document) - expected)}"
        )
    if document["schema"] != "mesh-public-guide-v1":
        raise ManifestError("unsupported public documentation schema")
    reviewed_at = require_text(document["reviewed_at"], "reviewed_at", maximum=10)
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", reviewed_at):
        raise ManifestError("reviewed_at must be YYYY-MM-DD")
    quick_start = document["quick_start"]
    if not isinstance(quick_start, list) or not 3 <= len(quick_start) <= 6:
        raise ManifestError("quick_start must contain 3-6 steps")
    normalized_steps = []
    for index, step in enumerate(quick_start):
        if not isinstance(step, dict) or set(step) != {"title", "body"}:
            raise ManifestError(f"quick_start[{index}] must contain exactly title and body")
        normalized_steps.append({
            "title": require_text(step["title"], f"quick_start[{index}].title", maximum=100),
            "body": require_text(step["body"], f"quick_start[{index}].body"),
        })
    sections = document["sections"]
    if not isinstance(sections, list) or not 4 <= len(sections) <= 12:
        raise ManifestError("sections must contain 4-12 sections")
    seen_ids: set[str] = set()
    normalized_sections = []
    for section_index, section in enumerate(sections):
        label = f"sections[{section_index}]"
        if not isinstance(section, dict) or set(section) != {"id", "title", "intro", "topics"}:
            raise ManifestError(f"{label} must contain exactly id, title, intro, and topics")
        section_id = require_text(section["id"], f"{label}.id", maximum=48)
        if not ID_PATTERN.fullmatch(section_id) or section_id in seen_ids:
            raise ManifestError(f"{label}.id is invalid or duplicated")
        seen_ids.add(section_id)
        topics = section["topics"]
        if not isinstance(topics, list) or not 1 <= len(topics) <= 8:
            raise ManifestError(f"{label}.topics must contain 1-8 topics")
        normalized_sections.append({
            "id": section_id,
            "title": require_text(section["title"], f"{label}.title", maximum=120),
            "intro": require_text(section["intro"], f"{label}.intro"),
            "topics": [
                validate_topic(topic, f"{label}.topics[{topic_index}]")
                for topic_index, topic in enumerate(topics)
            ],
        })
    return {
        "schema": document["schema"],
        "title": require_text(document["title"], "title", maximum=120),
        "subtitle": require_text(document["subtitle"], "subtitle", maximum=180),
        "description": require_text(document["description"], "description", maximum=300),
        "reviewed_at": reviewed_at,
        "quick_start": normalized_steps,
        "sections": normalized_sections,
    }


def esc(value: str) -> str:
    return html.escape(value, quote=True)


def render_topic(topic: dict[str, Any]) -> str:
    classes = "docs-topic docs-topic-wide" if topic["wide"] else "docs-topic"
    parts = [
        f'          <article class="{classes}">',
        f"            <h3>{esc(topic['title'])}</h3>",
    ]
    if topic["body"]:
        parts.append(f"            <p>{esc(topic['body'])}</p>")
    if topic["bullets"]:
        parts.append('            <ul class="docs-list">')
        parts.extend(f"              <li>{esc(item)}</li>" for item in topic["bullets"])
        parts.append("            </ul>")
    if topic["steps"]:
        parts.append('            <ol class="docs-steps">')
        parts.extend(f"              <li>{esc(item)}</li>" for item in topic["steps"])
        parts.append("            </ol>")
    if topic["note"]:
        note = topic["note"]
        parts.extend([
            f'            <aside class="docs-note {esc(note["kind"])}">',
            f"              <strong>{esc(note['title'])}</strong>",
            f"              <p>{esc(note['body'])}</p>",
            "            </aside>",
        ])
    parts.append("          </article>")
    return "\n".join(parts)


def render(manifest: dict[str, Any]) -> str:
    navigation = "\n".join(
        f'          <a href="#{esc(section["id"])}">{esc(section["title"])}</a>'
        for section in manifest["sections"]
    )
    quick_start = "\n".join(
        "\n".join([
            '          <article class="quick-step">',
            f'            <span class="quick-step-number">{index}</span>',
            f"            <h3>{esc(step['title'])}</h3>",
            f"            <p>{esc(step['body'])}</p>",
            "          </article>",
        ])
        for index, step in enumerate(manifest["quick_start"], start=1)
    )
    sections = "\n".join(
        "\n".join([
            f'      <section id="{esc(section["id"])}" class="docs-section" aria-labelledby="{esc(section["id"])}-title">',
            '        <div class="docs-section-heading">',
            '          <p class="eyebrow">Operator guide</p>',
            f'          <h2 id="{esc(section["id"])}-title">{esc(section["title"])}</h2>',
            f"          <p>{esc(section['intro'])}</p>",
            "        </div>",
            '        <div class="docs-topic-grid">',
            "\n".join(render_topic(topic) for topic in section["topics"]),
            "        </div>",
            "      </section>",
        ])
        for section in manifest["sections"]
    )
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="color-scheme" content="dark">
  <meta name="description" content="{esc(manifest['description'])}">
  <title>{esc(manifest['title'])} · Mesh</title>
  <link rel="stylesheet" href="/font-awesome/css/font-awesome.min.css">
  <link rel="stylesheet" href="/docs.css">
</head>
<body>
  <a class="skip-link" href="#documentation">Skip to documentation</a>
  <header class="docs-header">
    <a class="docs-brand" href="/" aria-label="Return to Mesh">
      <span class="docs-mark" aria-hidden="true">M</span>
      <span>Mesh</span>
    </a>
    <nav aria-label="Documentation sections">
{navigation}
    </nav>
    <div class="docs-header-actions">
      <a class="docs-api-link" href="/api-docs.html">API reference</a>
      <a class="docs-app-link" href="/">Open control plane</a>
    </div>
  </header>

  <main id="documentation">
    <section class="docs-hero">
      <p class="eyebrow">Public documentation</p>
      <h1>{esc(manifest['subtitle'])}</h1>
      <p>{esc(manifest['description'])}</p>
      <div class="docs-hero-actions">
        <a class="primary-action" href="#quick-start">Start with the rollout checklist</a>
        <a class="secondary-action" href="#troubleshooting">Troubleshoot a node</a>
      </div>
    </section>

    <section id="quick-start" class="docs-quick-start" aria-labelledby="quick-start-title">
      <div class="docs-section-heading">
        <p class="eyebrow">Recommended path</p>
        <h2 id="quick-start-title">Build a healthy network</h2>
        <p>Follow this order for a new environment. Each stage creates evidence needed by the next.</p>
      </div>
      <div class="quick-step-grid">
{quick_start}
      </div>
    </section>

{sections}
  </main>

  <footer class="docs-footer">
    <div><span class="docs-mark small" aria-hidden="true">M</span><strong>Mesh documentation</strong></div>
    <p>Last reviewed {esc(manifest['reviewed_at'])}. Validate current health and policy in your own control plane before making production changes.</p>
  </footer>
</body>
</html>
"""


def atomic_write(path: pathlib.Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(handle, "w", encoding="utf-8", newline="\n") as output:
            output.write(body)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=pathlib.Path, default=DEFAULT_SOURCE)
    parser.add_argument("--output", type=pathlib.Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    try:
        rendered = render(load_manifest(args.source))
    except ManifestError as error:
        parser.error(str(error))
    if args.check:
        try:
            existing = args.output.read_text(encoding="utf-8")
        except OSError as error:
            parser.error(f"cannot read generated documentation: {error}")
        if existing != rendered:
            parser.error(
                f"{args.output} is stale; run scripts/generate-public-docs.py"
            )
        print(f"public documentation is current: {args.output}")
        return 0
    atomic_write(args.output, rendered)
    print(f"generated {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
