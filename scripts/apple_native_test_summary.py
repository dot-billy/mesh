#!/usr/bin/env python3
"""Reduce an Xcode test summary to bounded, non-identifying Apple CI evidence."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import math
import os
import pathlib
import re
import stat


INPUT_SCHEMA_VERSION = "0.1.0"
OUTPUT_SCHEMA = "mesh-apple-native-test-summary-v1"
SOURCE_RECEIPT_SCHEMA = "mesh-apple-source-build-receipt-v1"
MAXIMUM_INPUT_BYTES = 1024 * 1024
MAXIMUM_SOURCE_RECEIPT_BYTES = 64 * 1024
MAXIMUM_OUTPUT_BYTES = 4096
EXPECTED_DEVICE_PLATFORMS = {
    "macos": "macOS",
    "ios-simulator": "iOS Simulator",
}
EXPECTED_TOP_LEVEL_KEYS = {
    "devicesAndConfigurations",
    "environmentDescription",
    "expectedFailures",
    "failedTests",
    "finishTime",
    "passedTests",
    "result",
    "skippedTests",
    "startTime",
    "statistics",
    "testFailures",
    "title",
    "topInsights",
    "totalTestCount",
}


class SummaryError(RuntimeError):
    pass


def canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode()


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def read_physical(path: pathlib.Path, maximum_bytes: int, description: str) -> bytes:
    if not path.is_absolute() or not path.exists() or path.is_symlink():
        raise SummaryError(f"{description} must be one absolute physical file")
    before = path.stat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise SummaryError(f"{description} must be one singly linked regular file")
    raw = path.read_bytes()
    after = path.stat()
    identity = lambda value: (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
    )
    if (
        not raw
        or len(raw) > maximum_bytes
        or len(raw) != before.st_size
        or identity(before) != identity(after)
    ):
        raise SummaryError(f"{description} is empty, oversized, or changed during read")
    return raw


def load_json(raw: bytes, description: str) -> dict[str, object]:
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SummaryError(f"{description} is not valid JSON") from exc
    if not isinstance(value, dict):
        raise SummaryError(f"{description} must be one JSON object")
    return value


def load_source_receipt(path: pathlib.Path) -> tuple[dict[str, object], str]:
    raw = read_physical(path, MAXIMUM_SOURCE_RECEIPT_BYTES, "source receipt")
    value = load_json(raw, "source receipt")
    source = value.get("source")
    host = value.get("host")
    preflight = value.get("preflight")
    if (
        raw != canonical_json(value)
        or value.get("schema") != SOURCE_RECEIPT_SCHEMA
        or not isinstance(source, dict)
        or re.fullmatch(r"[0-9a-f]{40}", str(source.get("commit", ""))) is None
        or source.get("clean") is not True
        or not isinstance(host, dict)
        or host.get("xcode_version") != "26.5"
        or host.get("xcode_build") != "17F42"
        or host.get("architecture") not in {"arm64", "x86_64"}
        or not isinstance(preflight, dict)
        or preflight.get("release_credentials_present") is not False
        or preflight.get("source_keychain_code_signing_identities") != 0
    ):
        raise SummaryError("source receipt is not the reviewed clean Apple source gate")
    return value, sha256(raw)


def require_count(value: dict[str, object], name: str) -> int:
    count = value.get(name)
    if isinstance(count, bool) or not isinstance(count, int) or count < 0:
        raise SummaryError(f"Xcode summary field {name} is not a nonnegative integer")
    return count


def sanitize(
    raw_summary: dict[str, object],
    source_receipt: dict[str, object],
    source_receipt_sha256: str,
    platform_name: str,
) -> dict[str, object]:
    if set(raw_summary) != EXPECTED_TOP_LEVEL_KEYS:
        raise SummaryError("Xcode summary top-level schema differs from the pinned schema")
    total = require_count(raw_summary, "totalTestCount")
    passed = require_count(raw_summary, "passedTests")
    failed = require_count(raw_summary, "failedTests")
    skipped = require_count(raw_summary, "skippedTests")
    expected_failures = require_count(raw_summary, "expectedFailures")
    if (
        raw_summary.get("result") != "Passed"
        or total < 1
        or passed != total
        or failed != 0
        or skipped != 0
        or expected_failures != 0
        or raw_summary.get("testFailures") != []
    ):
        raise SummaryError("native Apple tests did not all pass without skips or failures")

    devices = raw_summary.get("devicesAndConfigurations")
    if not isinstance(devices, list) or len(devices) != 1:
        raise SummaryError("Xcode summary must contain exactly one test destination")
    destination = devices[0]
    if not isinstance(destination, dict):
        raise SummaryError("Xcode summary destination is invalid")
    device = destination.get("device")
    if not isinstance(device, dict):
        raise SummaryError("Xcode summary device is invalid")
    architecture = device.get("architecture")
    os_version = device.get("osVersion")
    os_build = device.get("osBuildNumber")
    if (
        device.get("platform") != EXPECTED_DEVICE_PLATFORMS[platform_name]
        or architecture not in {"arm64", "x86_64"}
        or re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,2}", str(os_version)) is None
        or re.fullmatch(r"[0-9A-Za-z]{3,20}", str(os_build)) is None
    ):
        raise SummaryError("Xcode summary destination differs from the Apple test platform")

    source = source_receipt["source"]
    host = source_receipt["host"]
    assert isinstance(source, dict) and isinstance(host, dict)
    if architecture != host["architecture"]:
        raise SummaryError("native test architecture differs from the source-build host")

    start = raw_summary.get("startTime")
    finish = raw_summary.get("finishTime")
    if (
        isinstance(start, bool)
        or isinstance(finish, bool)
        or not isinstance(start, (int, float))
        or not isinstance(finish, (int, float))
        or not math.isfinite(start)
        or not math.isfinite(finish)
        or finish < start
        or finish - start > 3600
    ):
        raise SummaryError("Xcode summary test interval is invalid or unbounded")
    completed_at = (
        dt.datetime.fromtimestamp(finish, tz=dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )

    return {
        "schema": OUTPUT_SCHEMA,
        "platform": platform_name,
        "source": {
            "commit": source["commit"],
            "receipt_sha256": source_receipt_sha256,
        },
        "toolchain": {
            "xcode_version": host["xcode_version"],
            "xcode_build": host["xcode_build"],
            "xcresult_summary_schema": INPUT_SCHEMA_VERSION,
        },
        "environment": {
            "architecture": architecture,
            "os_version": os_version,
            "os_build": os_build,
        },
        "tests": {
            "result": "passed",
            "total": total,
            "passed": passed,
            "failed": failed,
            "skipped": skipped,
            "expected_failures": expected_failures,
        },
        "completed_at": completed_at,
    }


def write_create_only(path: pathlib.Path, value: dict[str, object]) -> None:
    if not path.is_absolute() or path.exists() or path.parent.is_symlink():
        raise SummaryError("sanitized summary output must be one new absolute path")
    if not path.parent.is_dir():
        raise SummaryError("sanitized summary output parent must already exist")
    raw = canonical_json(value)
    if len(raw) > MAXIMUM_OUTPUT_BYTES:
        raise SummaryError("sanitized native-test summary exceeds its output bound")
    with path.open("xb") as target:
        target.write(raw)
        target.flush()
        os.fsync(target.fileno())


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--platform", choices=sorted(EXPECTED_DEVICE_PLATFORMS), required=True)
    parser.add_argument("--input", required=True)
    parser.add_argument("--source-receipt", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    input_path = pathlib.Path(args.input)
    source_path = pathlib.Path(args.source_receipt)
    output_path = pathlib.Path(args.output)
    raw = read_physical(input_path, MAXIMUM_INPUT_BYTES, "raw Xcode summary")
    raw_summary = load_json(raw, "raw Xcode summary")
    source_receipt, source_receipt_sha256 = load_source_receipt(source_path)
    sanitized = sanitize(
        raw_summary,
        source_receipt,
        source_receipt_sha256,
        args.platform,
    )
    write_create_only(output_path, sanitized)
    print(f"sanitized native Apple test summary: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
