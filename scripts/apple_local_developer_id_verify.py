#!/usr/bin/env python3
"""Bind a non-release local Developer ID feasibility signature."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import pathlib
import plistlib
import re
import subprocess
from typing import Any

from apple_source_artifact_receipt import tree_identity


ROOT = pathlib.Path(__file__).resolve().parents[1]
TEAM = "Y3P5UNNG23"
BUNDLE_IDENTIFIER = "io.rw0.mesh.admin"
EXPECTED_FRAMEWORKS = {"App.framework", "FlutterMacOS.framework", "objective_c.framework"}
IDENTITY = re.compile(
    r"^Authority=Developer ID Application: .+ \(Y3P5UNNG23\)$", re.MULTILINE
)


class VerificationError(RuntimeError):
    pass


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: pathlib.Path, schema: str) -> dict[str, Any]:
    if (
        not path.is_file()
        or path.is_symlink()
        or path.stat().st_size > 8 * 1024 * 1024
    ):
        raise VerificationError(f"{path}: invalid receipt file")
    try:
        value = json.loads(path.read_bytes())
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VerificationError(f"{path}: invalid JSON") from exc
    if not isinstance(value, dict) or value.get("schema") != schema:
        raise VerificationError(f"{path}: receipt schema does not match")
    return value


def run(
    *arguments: str, check: bool = True
) -> subprocess.CompletedProcess[bytes]:
    environment = {
        name: os.environ[name]
        for name in ("HOME", "LOGNAME", "PATH", "TMPDIR", "USER")
        if os.environ.get(name)
    }
    environment["LANG"] = "C"
    try:
        return subprocess.run(
            arguments,
            cwd=ROOT,
            env=environment,
            capture_output=True,
            check=check,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise VerificationError(
            f"command failed: {' '.join(arguments)}: {exc}"
        ) from exc


def parse_signature_details(raw: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in raw.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key in {"Identifier", "TeamIdentifier", "CDHash", "Timestamp"}:
            fields[key] = value
    if fields.get("Identifier") != BUNDLE_IDENTIFIER:
        raise VerificationError("signed application identifier does not match")
    if fields.get("TeamIdentifier") != TEAM:
        raise VerificationError("signed application Team ID does not match")
    if not re.fullmatch(r"[0-9a-f]{40}", fields.get("CDHash", "")):
        raise VerificationError("signed application CDHash is invalid")
    if not fields.get("Timestamp") or IDENTITY.search(raw) is None:
        raise VerificationError(
            "Developer ID Application identity or timestamp is missing"
        )
    return fields


def signed_entitlements(app: pathlib.Path) -> dict[str, Any]:
    result = run("codesign", "-d", "--entitlements", ":-", str(app))
    raw = result.stdout or result.stderr
    start = raw.find(b"<?xml")
    if start < 0:
        raise VerificationError("codesign returned no entitlement plist")
    try:
        value = plistlib.loads(raw[start:])
    except plistlib.InvalidFileException as exc:
        raise VerificationError("signed entitlements are invalid") from exc
    if not isinstance(value, dict):
        raise VerificationError("signed entitlements are not a dictionary")
    return value


def verify(
    app: pathlib.Path,
    source_receipt_path: pathlib.Path,
    security_receipt_path: pathlib.Path,
    entitlements_path: pathlib.Path,
) -> dict[str, Any]:
    if not app.is_dir() or app.is_symlink() or app.name != "Mesh Admin.app":
        raise VerificationError("app must be an unlinked Mesh Admin.app")
    source = load_json(
        source_receipt_path, "mesh-apple-macos-source-artifact-receipt-v2"
    )
    security = load_json(
        security_receipt_path, "mesh-apple-admin-security-receipt-v1"
    )
    if security.get("artifact", {}).get("source_receipt", {}).get(
        "sha256"
    ) != sha256_file(source_receipt_path):
        raise VerificationError("security receipt does not bind source receipt")
    if not entitlements_path.is_file() or entitlements_path.is_symlink():
        raise VerificationError("release entitlements are missing")
    expected_entitlements = plistlib.loads(entitlements_path.read_bytes())
    if signed_entitlements(app) != expected_entitlements:
        raise VerificationError("signed entitlements do not match source")
    frameworks = app / "Contents" / "Frameworks"
    observed = {
        path.name
        for path in frameworks.iterdir()
        if path.is_dir() and path.name.endswith(".framework")
    }
    if observed != EXPECTED_FRAMEWORKS:
        raise VerificationError("signed framework inventory does not match")
    run("codesign", "--verify", "--deep", "--strict", "--verbose=4", str(app))
    details_result = run("codesign", "-dvvv", str(app))
    details = parse_signature_details(
        (details_result.stdout + details_result.stderr).decode("utf-8", "strict")
    )
    assessment = run(
        "spctl",
        "--assess",
        "--type",
        "execute",
        "--verbose=4",
        str(app),
        check=False,
    )
    assessment_text = (assessment.stdout + assessment.stderr).decode(
        "utf-8", "strict"
    )
    if (
        assessment.returncode == 0
        or "source=Unnotarized Developer ID" not in assessment_text
    ):
        raise VerificationError(
            "local proof must be rejected specifically as unnotarized"
        )
    tree_sha, files, total = tree_identity(app)
    return {
        "schema": "mesh-apple-local-developer-id-verification-receipt-v1",
        "verified_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "application": {
            "bundle_identifier": BUNDLE_IDENTIFIER,
            "team_id": TEAM,
            "signed_tree_sha256": tree_sha,
            "regular_files": files,
            "regular_file_bytes": total,
            "cdhash": details["CDHash"],
            "secure_timestamp_present": True,
            "hardened_runtime_present": True,
            "strict_signature_verified": True,
            "entitlements_sha256": sha256_file(entitlements_path),
            "frameworks": sorted(EXPECTED_FRAMEWORKS),
        },
        "inputs": {
            "source_receipt_sha256": sha256_file(source_receipt_path),
            "security_receipt_sha256": sha256_file(security_receipt_path),
        },
        "gatekeeper": {
            "accepted": False,
            "classification": "Unnotarized Developer ID",
        },
        "limitations": {
            "clean_source": False,
            "protected_release_context": False,
            "notarized": False,
            "stapled": False,
            "published": False,
            "release_authority": False,
        },
    }


def write_receipt(path: pathlib.Path, value: dict[str, Any]) -> None:
    if not path.is_absolute() or path.exists():
        raise VerificationError("output must be one new absolute path")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    payload = (
        json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n"
    ).encode()
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(payload)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--app", type=pathlib.Path, required=True)
    parser.add_argument("--source-receipt", type=pathlib.Path, required=True)
    parser.add_argument("--security-receipt", type=pathlib.Path, required=True)
    parser.add_argument("--entitlements", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    write_receipt(
        args.output,
        verify(
            args.app,
            args.source_receipt,
            args.security_receipt,
            args.entitlements,
        ),
    )
    print(f"local Developer ID proof verified: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
