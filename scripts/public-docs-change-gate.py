#!/usr/bin/env python3
"""Require a public documentation review for user-facing product changes."""

from __future__ import annotations

import argparse
import pathlib
import subprocess
import sys


PUBLIC_SOURCE = "docs/public-guide.json"
PUBLIC_OUTPUT = "internal/httpapi/web/docs.html"
USER_FACING_PREFIXES = (
    "cmd/mesh-server/",
    "cmd/meshctl/",
    "config/",
    "deploy/",
    "internal/control/",
    "internal/httpapi/",
    "internal/identity/",
    "internal/nodeagent/",
    "internal/runtimetelemetry/",
    "packaging/",
)
USER_FACING_FILES = {"README.md"}
IGNORED_SUFFIXES = ("_test.go", "_test.py")
DOC_AUTOMATION_FILES = {
    PUBLIC_OUTPUT,
    "internal/httpapi/web/docs.css",
    "scripts/generate-public-docs.py",
    "scripts/public-docs-change-gate.py",
    "scripts/public_docs_test.py",
}


def normalize_paths(paths: list[str]) -> list[str]:
    return sorted({
        pathlib.PurePosixPath(path.strip()).as_posix()
        for path in paths
        if path.strip()
    })


def is_user_facing(path: str) -> bool:
    if path in DOC_AUTOMATION_FILES or path.endswith(IGNORED_SUFFIXES):
        return False
    return path in USER_FACING_FILES or path.startswith(USER_FACING_PREFIXES)


def evaluate(paths: list[str]) -> tuple[bool, list[str]]:
    normalized = normalize_paths(paths)
    affected = [path for path in normalized if is_user_facing(path)]
    if not affected:
        return True, []
    return PUBLIC_SOURCE in normalized, affected


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
    passed, affected = evaluate(changed)
    if not affected:
        print("public documentation review not required: no user-facing product files changed")
        return 0
    if not passed:
        print(
            "public documentation review required: update docs/public-guide.json and regenerate "
            "internal/httpapi/web/docs.html",
            file=sys.stderr,
        )
        for path in affected:
            print(f"  - {path}", file=sys.stderr)
        return 1
    print(
        f"public documentation review recorded for {len(affected)} user-facing product file(s)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
