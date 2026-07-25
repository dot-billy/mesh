#!/usr/bin/env python3
"""Bind every unsigned Apple source artifact receipt to one clean preflight."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import stat


OUTPUT_SCHEMA = "mesh-apple-source-matrix-receipt-v1"
PREFLIGHT_SCHEMA = "mesh-apple-source-build-receipt-v1"
MAXIMUM_INPUT_BYTES = 128 * 1024
MAXIMUM_OUTPUT_BYTES = 16 * 1024
ARTIFACT_SPECS = (
    (
        "macos-debug",
        "macos_debug",
        "mesh-apple-macos-source-artifact-receipt-v2",
        "debug",
        None,
    ),
    (
        "macos-release",
        "macos_release",
        "mesh-apple-macos-source-artifact-receipt-v2",
        "release",
        None,
    ),
    (
        "ios-admin-simulator",
        "ios_admin_simulator",
        "mesh-apple-ios-simulator-source-artifact-receipt-v1",
        "debug",
        "ios-simulator",
    ),
    (
        "ios-tunnel-simulator",
        "ios_tunnel_simulator",
        "mesh-apple-ios-tunnel-simulator-source-artifact-receipt-v1",
        "debug",
        "ios-tunnel-simulator",
    ),
    (
        "ios-mobile-framework",
        "ios_mobile_framework",
        "mesh-apple-ios-mobile-framework-source-receipt-v1",
        None,
        None,
    ),
)
TIMESTAMP = re.compile(r"20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")


class MatrixError(RuntimeError):
    pass


def canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode()


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def read_receipt(path: pathlib.Path, description: str) -> tuple[bytes, dict[str, object]]:
    if not path.is_absolute() or not path.exists() or path.is_symlink():
        raise MatrixError(f"{description} must be one absolute physical file")
    before = path.stat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise MatrixError(f"{description} must be one singly linked regular file")
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
        or len(raw) > MAXIMUM_INPUT_BYTES
        or len(raw) != before.st_size
        or identity(before) != identity(after)
    ):
        raise MatrixError(f"{description} is empty, oversized, or changed during read")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MatrixError(f"{description} is not valid JSON") from exc
    if not isinstance(value, dict) or raw != canonical_json(value):
        raise MatrixError(f"{description} is not one canonical JSON object")
    return raw, value


def validate_preflight(value: dict[str, object]) -> tuple[str, str]:
    source = value.get("source")
    host = value.get("host")
    preflight = value.get("preflight")
    completed_at = value.get("completed_at")
    if (
        value.get("schema") != PREFLIGHT_SCHEMA
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
        or TIMESTAMP.fullmatch(str(completed_at)) is None
    ):
        raise MatrixError("Apple source preflight is not one reviewed clean build")
    return str(source["commit"]), str(completed_at)


def validate_artifact(
    *,
    name: str,
    raw: bytes,
    value: dict[str, object],
    expected_schema: str,
    expected_configuration: str | None,
    expected_platform: str | None,
    source_commit: str,
    preflight_sha256: str,
) -> tuple[dict[str, object], str]:
    source = value.get("source")
    completed_at = value.get("completed_at")
    if (
        value.get("schema") != expected_schema
        or not isinstance(source, dict)
        or source.get("commit") != source_commit
        or source.get("clean") is not True
        or value.get("input_receipt_sha256") != preflight_sha256
        or (
            expected_configuration is not None
            and value.get("configuration") != expected_configuration
        )
        or (expected_platform is not None and value.get("platform") != expected_platform)
        or TIMESTAMP.fullmatch(str(completed_at)) is None
    ):
        raise MatrixError(f"{name} is not the expected clean source artifact receipt")
    return (
        {
            "name": name,
            "schema": expected_schema,
            "sha256": digest(raw),
            "bytes": len(raw),
        },
        str(completed_at),
    )


def build_matrix(
    preflight_path: pathlib.Path,
    artifact_paths: dict[str, pathlib.Path],
) -> dict[str, object]:
    preflight_raw, preflight = read_receipt(preflight_path, "Apple source preflight")
    source_commit, preflight_completed_at = validate_preflight(preflight)
    preflight_sha256 = digest(preflight_raw)
    artifacts: list[dict[str, object]] = []
    completed = [preflight_completed_at]
    for name, argument_name, schema, configuration, platform_name in ARTIFACT_SPECS:
        raw, value = read_receipt(
            artifact_paths[argument_name],
            f"{name} receipt",
        )
        artifact, completed_at = validate_artifact(
            name=name,
            raw=raw,
            value=value,
            expected_schema=schema,
            expected_configuration=configuration,
            expected_platform=platform_name,
            source_commit=source_commit,
            preflight_sha256=preflight_sha256,
        )
        artifacts.append(artifact)
        completed.append(completed_at)
    return {
        "schema": OUTPUT_SCHEMA,
        "source": {"commit": source_commit, "clean": True},
        "preflight": {
            "schema": PREFLIGHT_SCHEMA,
            "sha256": preflight_sha256,
            "bytes": len(preflight_raw),
        },
        "artifacts": artifacts,
        "limitations": [
            "unsigned-source-artifacts-only",
            "ios-products-simulator-only",
            "mobile-framework-statically-linked-simulator-only",
            "no-release-authority-device-or-support-claim",
        ],
        "completed_at": max(completed),
    }


def write_create_only(path: pathlib.Path, value: dict[str, object]) -> None:
    if not path.is_absolute() or path.exists() or path.parent.is_symlink():
        raise MatrixError("Apple source matrix output must be one new absolute path")
    if not path.parent.is_dir():
        raise MatrixError("Apple source matrix output parent must already exist")
    raw = canonical_json(value)
    if len(raw) > MAXIMUM_OUTPUT_BYTES:
        raise MatrixError("Apple source matrix receipt exceeds its output bound")
    with path.open("xb") as target:
        target.write(raw)
        target.flush()
        os.fsync(target.fileno())


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--preflight", required=True)
    for _, argument_name, _, _, _ in ARTIFACT_SPECS:
        parser.add_argument(f"--{argument_name.replace('_', '-')}", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    artifact_paths = {
        argument_name: pathlib.Path(getattr(args, argument_name))
        for _, argument_name, _, _, _ in ARTIFACT_SPECS
    }
    value = build_matrix(pathlib.Path(args.preflight), artifact_paths)
    output = pathlib.Path(args.output)
    write_create_only(output, value)
    print(f"Apple source matrix receipt passed: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
