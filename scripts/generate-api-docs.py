#!/usr/bin/env python3
"""Generate and validate the canonical Mesh OpenAPI 3.1 contract."""

from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import sys
import tempfile
from typing import Any


ROOT = pathlib.Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "docs" / "openapi.json"
HTTP_METHODS = {"get", "put", "post", "delete", "patch", "head", "options", "trace"}


class ContractError(ValueError):
    pass


def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ContractError(f"duplicate JSON field {key!r}")
        result[key] = value
    return result


def generate() -> bytes:
    result = subprocess.run(
        ["go", "run", "-buildvcs=false", "./cmd/mesh-openapi"],
        cwd=ROOT,
        check=False,
        capture_output=True,
    )
    if result.returncode != 0:
        raise ContractError(
            "OpenAPI generator failed: "
            + result.stderr.decode("utf-8", errors="replace").strip()
        )
    validate(result.stdout)
    return result.stdout


def require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ContractError(f"{label} must be an object")
    return value


def validate(raw: bytes) -> dict[str, Any]:
    try:
        text = raw.decode("utf-8")
        decoder = json.JSONDecoder(object_pairs_hook=reject_duplicates)
        document, offset = decoder.raw_decode(text)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ContractError(f"OpenAPI output is not strict UTF-8 JSON: {error}") from error
    if text[offset:].strip():
        raise ContractError("OpenAPI output contains trailing data")
    root = require_object(document, "contract")
    if root.get("openapi") != "3.1.0":
        raise ContractError("contract must declare OpenAPI 3.1.0")
    if root.get("jsonSchemaDialect") != "https://json-schema.org/draft/2020-12/schema":
        raise ContractError("contract must declare the JSON Schema 2020-12 dialect")
    info = require_object(root.get("info"), "info")
    for field in ("title", "version", "description"):
        if not isinstance(info.get(field), str) or not info[field].strip():
            raise ContractError(f"info.{field} must be nonempty text")
    paths = require_object(root.get("paths"), "paths")
    if not paths:
        raise ContractError("contract must contain API paths")
    operation_ids: set[str] = set()
    operation_count = 0
    for path, path_item_value in paths.items():
        if not isinstance(path, str) or not path.startswith("/"):
            raise ContractError(f"invalid path {path!r}")
        path_item = require_object(path_item_value, f"paths[{path!r}]")
        for method, operation_value in path_item.items():
            if method not in HTTP_METHODS:
                continue
            operation_count += 1
            operation = require_object(operation_value, f"{method.upper()} {path}")
            operation_id = operation.get("operationId")
            if not isinstance(operation_id, str) or not operation_id:
                raise ContractError(f"{method.upper()} {path} lacks operationId")
            if operation_id in operation_ids:
                raise ContractError(f"duplicate operationId {operation_id!r}")
            operation_ids.add(operation_id)
            for field in ("summary", "description"):
                if not isinstance(operation.get(field), str) or not operation[field].strip():
                    raise ContractError(f"{operation_id} lacks {field}")
            if not isinstance(operation.get("tags"), list) or not operation["tags"]:
                raise ContractError(f"{operation_id} lacks tags")
            if not isinstance(operation.get("security"), list):
                raise ContractError(f"{operation_id} lacks explicit security")
            responses = require_object(operation.get("responses"), f"{operation_id}.responses")
            if not responses:
                raise ContractError(f"{operation_id} lacks responses")
            samples = operation.get("x-codeSamples")
            if not isinstance(samples, list) or not samples:
                raise ContractError(f"{operation_id} lacks a code sample")
            request_body = operation.get("requestBody")
            if request_body is not None:
                content = require_object(
                    require_object(request_body, f"{operation_id}.requestBody").get("content"),
                    f"{operation_id}.requestBody.content",
                )
                media = require_object(content.get("application/json"), f"{operation_id} JSON request")
                if "schema" not in media or "example" not in media:
                    raise ContractError(f"{operation_id} request lacks schema or example")
            for status, response_value in responses.items():
                response = require_object(response_value, f"{operation_id} response {status}")
                if "$ref" in response:
                    continue
                content = response.get("content")
                if content is None:
                    continue
                media = require_object(
                    require_object(content, f"{operation_id} response {status} content").get(
                        "application/json"
                    ),
                    f"{operation_id} response {status} JSON",
                )
                if "schema" not in media or "example" not in media:
                    raise ContractError(
                        f"{operation_id} response {status} lacks schema or example"
                    )
    if operation_count < 1:
        raise ContractError("contract must contain operations")
    components = require_object(root.get("components"), "components")
    schemes = require_object(components.get("securitySchemes"), "security schemes")
    if set(schemes) != {"cookieSession", "legacyAdminBearer", "agentBearer"}:
        raise ContractError("contract security schemes are incomplete")
    schemas = require_object(components.get("schemas"), "schemas")
    error = require_object(schemas.get("Error"), "Error schema")
    if error.get("required") != ["error"]:
        raise ContractError("Error schema must require exactly error")
    return root


def atomic_write(path: pathlib.Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as temporary:
        temporary.write(content)
        temporary.flush()
        temporary_path = pathlib.Path(temporary.name)
    temporary_path.replace(path)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--output", type=pathlib.Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    try:
        generated = generate()
    except ContractError as error:
        print(f"API documentation generation failed: {error}", file=sys.stderr)
        return 1
    output = args.output.resolve()
    if args.check:
        try:
            current = output.read_bytes()
        except OSError as error:
            print(f"API contract is missing: {error}", file=sys.stderr)
            return 1
        if current != generated:
            print(
                f"{output.relative_to(ROOT)} is stale; run make api-docs",
                file=sys.stderr,
            )
            return 1
        print(f"verified {output.relative_to(ROOT)}")
        return 0
    atomic_write(output, generated)
    print(f"generated {output.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
