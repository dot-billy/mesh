#!/usr/bin/env python3
"""Require an OpenAPI contract review for application API changes."""

from __future__ import annotations

import argparse
import pathlib
import subprocess
import sys


API_SOURCE = "internal/httpapi/openapi.go"
API_OUTPUT = "docs/openapi.json"
API_PREFIXES = (
    "internal/control/",
    "internal/httpapi/",
    "internal/identity/",
    "internal/runtimetelemetry/",
)
IGNORED_SUFFIXES = ("_test.go", "_test.py")
API_AUTOMATION_FILES = {
    "cmd/mesh-openapi/main.go",
    "internal/httpapi/web/api-docs.html",
    "internal/httpapi/web/api-docs.css",
    "internal/httpapi/web/api-docs.js",
    "internal/httpapi/web/docs.html",
    "internal/httpapi/web/docs.css",
    "internal/httpapi/web/index.html",
    "scripts/generate-api-docs.py",
    "scripts/api-docs-change-gate.py",
    "scripts/api_docs_test.py",
}


def normalize_paths(paths: list[str]) -> list[str]:
    return sorted({
        pathlib.PurePosixPath(path.strip()).as_posix()
        for path in paths
        if path.strip()
    })


def is_api_facing(path: str) -> bool:
    if path in API_AUTOMATION_FILES or path.endswith(IGNORED_SUFFIXES):
        return False
    return path.startswith(API_PREFIXES)


def evaluate(paths: list[str]) -> tuple[bool, list[str], list[str]]:
    normalized = normalize_paths(paths)
    affected = [path for path in normalized if is_api_facing(path)]
    if not affected:
        return True, [], []
    missing = [
        required
        for required in (API_SOURCE, API_OUTPUT)
        if required not in normalized
    ]
    return not missing, affected, missing


def git_changed_files(base: str, head: str) -> list[str]:
    if not base or not head:
        raise RuntimeError("--base and --head are required when --changed-file is not used")
    if set(base) == {"0"}:
        command = ["git", "diff-tree", "--no-commit-id", "--name-only", "-r", head]
    else:
        command = ["git", "diff", "--name-only", base, head]
    result = subprocess.run(command, check=False, text=True, capture_output=True)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "git diff failed")
    return result.stdout.splitlines()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", default="")
    parser.add_argument("--head", default="")
    parser.add_argument("--changed-file", action="append", default=[])
    args = parser.parse_args()
    try:
        changed = args.changed_file or git_changed_files(args.base, args.head)
    except RuntimeError as error:
        parser.error(str(error))
    passed, affected, missing = evaluate(changed)
    if not affected:
        print("API documentation review not required: no API-facing product files changed")
        return 0
    if not passed:
        print(
            "API documentation review required: update the typed route catalog and "
            "regenerate the canonical OpenAPI contract",
            file=sys.stderr,
        )
        for path in affected:
            print(f"  API change: {path}", file=sys.stderr)
        for path in missing:
            print(f"  required documentation change: {path}", file=sys.stderr)
        return 1
    print(f"API documentation review recorded for {len(affected)} API-facing file(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
