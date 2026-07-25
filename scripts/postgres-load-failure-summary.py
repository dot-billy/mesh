#!/usr/bin/env python3

"""Emit one bounded, terminal-safe PostgreSQL load-gate failure summary."""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import stat
import sys
import unicodedata
from collections.abc import Iterable
from typing import TextIO


REPORT_SCHEMA = "mesh-postgres-load-soak-v1"
MAX_REPORT_BYTES = 8 * 1024 * 1024
MAX_SECRET_FILE_BYTES = 8 * 1024 * 1024
MAX_STDERR_TAIL_BYTES = 64 * 1024
MAX_SUMMARY_BYTES = 512

_SECRET_TOKEN = re.compile(r"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])")
_CREDENTIAL_URL = re.compile(r"(?i)\b(?:postgres(?:ql)?|https?)://[^\s/:]+:[^\s@]+@")
_CREDENTIAL_FIELD = re.compile(r"(?i)\b(?:authorization|password|passwd|cookie)\s*[:=]\s*\S+")
_BEARER = re.compile(r"(?i)\bbearer\s+\S+")
_LONG_SECRET_FRAGMENT = re.compile(r"[A-Za-z0-9_-]{16,}")


class InvalidInput(Exception):
    """An input cannot safely contribute to a failure summary."""


def _open_private_regular(path: pathlib.Path) -> tuple[int, os.stat_result]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as error:
        raise InvalidInput from error
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) & 0o077
        ):
            raise InvalidInput
        return fd, info
    except BaseException:
        os.close(fd)
        raise


def _read_private_file(path: pathlib.Path, maximum_bytes: int) -> bytes:
    fd, info = _open_private_regular(path)
    try:
        if info.st_size < 0 or info.st_size > maximum_bytes:
            raise InvalidInput
        raw = os.read(fd, maximum_bytes + 1)
        if len(raw) != info.st_size:
            raise InvalidInput
        return raw
    finally:
        os.close(fd)


def _reject_duplicate_names(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise InvalidInput
        value[key] = item
    return value


def _safe_summary(value: object, secret_markers: set[str]) -> str | None:
    if type(value) is not str or not value or value != value.strip():
        return None
    try:
        encoded = value.encode("utf-8", "strict")
    except UnicodeError:
        return None
    if len(encoded) > MAX_SUMMARY_BYTES:
        return None
    if any(unicodedata.category(character).startswith("C") for character in value):
        return None
    if any(marker and marker in value for marker in secret_markers):
        return None
    if any(pattern.search(value) for pattern in (_SECRET_TOKEN, _CREDENTIAL_URL, _CREDENTIAL_FIELD, _BEARER)):
        return None
    return value


def _report_summary(path: pathlib.Path, secret_markers: set[str]) -> str | None:
    try:
        raw = _read_private_file(path, MAX_REPORT_BYTES)
        value = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_reject_duplicate_names)
    except (InvalidInput, UnicodeError, json.JSONDecodeError):
        return None
    if type(value) is not dict or value.get("schema") != REPORT_SCHEMA:
        return None
    return _safe_summary(value.get("error"), secret_markers)


def _stderr_summary(path: pathlib.Path, secret_markers: set[str]) -> str | None:
    try:
        fd, info = _open_private_regular(path)
    except InvalidInput:
        return None
    try:
        start = max(0, info.st_size - MAX_STDERR_TAIL_BYTES)
        raw = os.pread(fd, info.st_size - start, start)
    except OSError:
        return None
    finally:
        os.close(fd)
    lines = raw.split(b"\n")
    if start:
        lines = lines[1:]
    for raw_line in reversed(lines):
        if not raw_line:
            continue
        try:
            line = raw_line.decode("utf-8", "strict")
        except UnicodeError:
            continue
        summary = _safe_summary(line, secret_markers)
        if summary is not None:
            return summary
    return None


def _secret_markers(paths: Iterable[pathlib.Path]) -> set[str]:
    markers: set[str] = set()
    for path in paths:
        raw = _read_private_file(path, MAX_SECRET_FILE_BYTES)
        try:
            text = raw.decode("utf-8", "strict")
        except UnicodeError as error:
            raise InvalidInput from error
        for line in text.splitlines():
            if line:
                markers.add(line)
            for field in line.split("\t"):
                if field:
                    markers.add(field)
                if "=" in field:
                    _, value = field.split("=", 1)
                    if value:
                        markers.add(value)
                markers.update(_LONG_SECRET_FRAGMENT.findall(field))
    return markers


def emit_failure_summary(
    report_path: pathlib.Path,
    stderr_path: pathlib.Path,
    required_secret_paths: Iterable[pathlib.Path],
    optional_secret_paths: Iterable[pathlib.Path],
    output: TextIO = sys.stderr,
) -> bool:
    try:
        optional = [path for path in optional_secret_paths if path.exists() and not path.is_symlink()]
        markers = _secret_markers([*required_secret_paths, *optional])
    except (InvalidInput, OSError):
        return False
    summary = _report_summary(report_path, markers)
    if summary is None:
        summary = _stderr_summary(stderr_path, markers)
    if summary is None:
        return False
    print(f"LOAD_GATE_ERROR: {summary}", file=output)
    return True


def main() -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--report", required=True, type=pathlib.Path)
    parser.add_argument("--stderr", required=True, type=pathlib.Path)
    parser.add_argument("--secret-file", action="append", default=[], type=pathlib.Path)
    parser.add_argument("--optional-secret-file", action="append", default=[], type=pathlib.Path)
    try:
        arguments = parser.parse_args()
        emit_failure_summary(
            arguments.report,
            arguments.stderr,
            arguments.secret_file,
            arguments.optional_secret_file,
        )
    except (InvalidInput, OSError):
        # Diagnostics must never turn a workload failure into a second failure
        # or disclose raw parser/file-system details.
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
