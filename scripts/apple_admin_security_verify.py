#!/usr/bin/env python3
"""Validate and bind one exact unsigned macOS Mesh Admin security scan."""

from __future__ import annotations

import argparse
import datetime as dt
import gzip
import hashlib
import json
import pathlib
import re
import sys
from typing import Any

from apple_source_artifact_receipt import tree_identity
from image_security_verify import (
    VerificationError,
    canonical_json,
    exclusive_write,
    hash_file,
    read_json,
    require,
    validate_empty_gitleaks,
    validate_grype,
    validate_grype_db,
    validate_regular_file,
    validate_spdx,
)


DIGEST = re.compile(r"^[0-9a-f]{64}$")
EXPECTED_PRIVACY = {
    "NSPrivacyAccessedAPITypes": [
        {
            "NSPrivacyAccessedAPIType": (
                "NSPrivacyAccessedAPICategoryUserDefaults"
            ),
            "NSPrivacyAccessedAPITypeReasons": ["AC6B.1"],
        }
    ],
    "NSPrivacyCollectedDataTypes": [],
    "NSPrivacyTracking": False,
    "NSPrivacyTrackingDomains": [],
}


def canonical_source_receipt(path: pathlib.Path) -> dict[str, Any]:
    validate_regular_file(path, max_bytes=4 * 1024 * 1024)
    raw = path.read_bytes()
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VerificationError("macOS source receipt is invalid JSON") from exc
    require(isinstance(document, dict), "macOS source receipt is not an object")
    require(raw == canonical_json(document), "macOS source receipt is not canonical JSON")
    require(
        document.get("schema") == "mesh-apple-macos-source-artifact-receipt-v2",
        "macOS source receipt schema is invalid",
    )
    require(document.get("configuration") == "release", "security evidence requires a Release app")
    bundle = document.get("bundle")
    require(isinstance(bundle, dict), "macOS source receipt bundle is missing")
    require(bundle.get("identifier") == "io.rw0.mesh.admin", "macOS bundle identifier is invalid")
    require(
        bundle.get("architectures") in (["arm64", "x86_64"], ["x86_64", "arm64"]),
        "macOS source receipt is not universal",
    )
    require(bundle.get("release_signature") == "absent", "source app must remain unsigned")
    require(bundle.get("entitlements_applied") is False, "source app must have no applied entitlements")
    require(
        isinstance(bundle.get("tree_sha256"), str)
        and DIGEST.fullmatch(bundle["tree_sha256"]),
        "macOS source receipt tree digest is invalid",
    )
    privacy = document.get("privacy_manifest")
    require(
        isinstance(privacy, dict)
        and privacy.get("status")
        == "source-reviewed-final-dependency-reconciliation-pending",
        "macOS source privacy evidence is missing",
    )
    return document


def runtime_packages(document: dict[str, Any]) -> dict[str, str]:
    packages = document.get("packages")
    root_name = document.get("root")
    require(
        isinstance(packages, list) and isinstance(root_name, str),
        "Dart dependency graph is invalid",
    )
    by_name: dict[str, dict[str, Any]] = {}
    for package in packages:
        require(isinstance(package, dict), "Dart dependency record is invalid")
        name = package.get("name")
        require(
            isinstance(name, str) and name and name not in by_name,
            "Dart dependency names are invalid or repeated",
        )
        require(
            isinstance(package.get("version"), str)
            and isinstance(package.get("kind"), str)
            and isinstance(package.get("source"), str)
            and isinstance(package.get("dependencies"), list)
            and all(isinstance(item, str) for item in package["dependencies"]),
            f"Dart dependency metadata is invalid: {name}",
        )
        by_name[name] = package
    root = by_name.get(root_name)
    require(root is not None and root.get("kind") == "root", "Dart dependency root is invalid")
    pending = [
        name
        for name in root["dependencies"]
        if name in by_name and by_name[name].get("kind") != "dev"
    ]
    observed: set[str] = set()
    while pending:
        name = pending.pop()
        require(name in by_name, f"Dart dependency graph references unknown package: {name}")
        if name in observed:
            continue
        observed.add(name)
        pending.extend(by_name[name]["dependencies"])
    require("flutter" in observed, "Dart runtime dependency graph omits Flutter")
    hosted = {
        name: by_name[name]["version"]
        for name in observed
        if by_name[name]["source"] == "hosted"
    }
    require(hosted, "Dart runtime hosted dependency inventory is empty")
    return dict(sorted(hosted.items()))


def validate_syft(
    document: dict[str, Any],
    expected_runtime: dict[str, str],
) -> tuple[set[str], int]:
    descriptor = document.get("descriptor")
    require(
        isinstance(descriptor, dict)
        and descriptor.get("name") == "syft"
        and descriptor.get("version") == "1.44.0",
        "Apple Admin SBOM descriptor is invalid",
    )
    schema = document.get("schema")
    require(
        isinstance(schema, dict) and schema.get("version") == "16.1.3",
        "Apple Admin Syft schema is unexpected",
    )
    source = document.get("source")
    require(
        isinstance(source, dict) and source.get("type") == "directory",
        "Apple Admin SBOM source is not the stable scan directory",
    )
    artifacts = document.get("artifacts")
    require(isinstance(artifacts, list) and artifacts, "Apple Admin SBOM is empty")
    runtime_found: set[tuple[str, str]] = set()
    purls: set[str] = set()
    for artifact in artifacts:
        require(isinstance(artifact, dict), "Apple Admin SBOM artifact is invalid")
        name, version, package_type = (
            artifact.get("name"),
            artifact.get("version"),
            artifact.get("type"),
        )
        require(
            isinstance(name, str)
            and isinstance(version, str)
            and isinstance(package_type, str),
            "Apple Admin SBOM package identity is invalid",
        )
        purl = artifact.get("purl")
        if isinstance(purl, str) and purl:
            purls.add(purl)
        if package_type == "dart-pub" and name in expected_runtime:
            require(
                version == expected_runtime[name],
                f"Apple Admin SBOM has an unexpected Dart version: {name}",
            )
            require(
                isinstance(purl, str) and purl.startswith("pkg:pub/"),
                f"Apple Admin SBOM lacks a Dart purl: {name}",
            )
            runtime_found.add((name, version))
    require(
        runtime_found == set(expected_runtime.items()),
        "Apple Admin SBOM runtime Dart inventory is incomplete",
    )
    require(purls, "Apple Admin SBOM has no package URLs")
    return purls, len(artifacts)


def validate_notices(
    path: pathlib.Path,
    expected_runtime: dict[str, str],
) -> dict[str, Any]:
    validate_regular_file(path, max_bytes=16 * 1024 * 1024)
    try:
        payload = gzip.decompress(path.read_bytes())
    except (OSError, EOFError) as exc:
        raise VerificationError("embedded Flutter notices are not valid gzip") from exc
    require(
        64 * 1024 <= len(payload) <= 32 * 1024 * 1024,
        "embedded Flutter notices size is outside the reviewed bound",
    )
    try:
        text = "\n" + payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise VerificationError("embedded Flutter notices are not UTF-8") from exc
    missing = [
        name for name in expected_runtime if f"\n{name}\n" not in text
    ]
    require(not missing, f"embedded Flutter notices omit runtime packages: {', '.join(missing)}")
    return {
        "compressed": hash_file(path),
        "decompressed_sha256": hashlib.sha256(payload).hexdigest(),
        "decompressed_size": len(payload),
        "runtime_package_headings": len(expected_runtime),
        "status": "inventory-present-legal-review-pending",
    }


def finalize(args: argparse.Namespace) -> None:
    work = pathlib.Path(args.work_dir)
    script_dir = pathlib.Path(__file__).resolve().parent
    repo_root = script_dir.parent
    require(work.is_dir() and not work.is_symlink(), "Apple Admin verification workspace is unsafe")
    app = work / "scan-root" / "Mesh Admin.app"
    require(app.is_dir() and not app.is_symlink(), "stable Apple Admin app snapshot is missing")
    source_path = work / "source-receipt.json"
    source = canonical_source_receipt(source_path)
    tree_sha, file_count, total_bytes = tree_identity(app)
    bundle = source["bundle"]
    require(tree_sha == bundle["tree_sha256"], "app snapshot differs from its source receipt")
    require(file_count == bundle["regular_files"], "app snapshot file count differs from its source receipt")
    require(total_bytes == bundle["regular_file_bytes"], "app snapshot byte count differs from its source receipt")

    pub_deps_path = work / "pub-deps.json"
    pub_deps = read_json(pub_deps_path, max_bytes=4 * 1024 * 1024)
    require(isinstance(pub_deps, dict), "Dart dependency graph is not an object")
    expected_runtime = runtime_packages(pub_deps)

    syft_path, spdx_path = work / "sbom.syft.json", work / "sbom.spdx.json"
    grype_path, database_path = work / "vulnerabilities.json", work / "grype-db-status.json"
    metadata_secrets = work / "metadata-secrets.json"
    app_secrets = work / "app-strings-secrets.json"
    syft, spdx, grype, database = (
        read_json(path) for path in (syft_path, spdx_path, grype_path, database_path)
    )
    require(
        all(isinstance(item, dict) for item in (syft, spdx, grype, database)),
        "Apple Admin scanner output is not an object",
    )
    purls, syft_count = validate_syft(syft, expected_runtime)
    spdx_count = validate_spdx(spdx, purls)
    database_schema, database_built = validate_grype_db(database)
    vulnerability_summary = validate_grype(grype, purls)
    validate_empty_gitleaks(metadata_secrets)
    validate_empty_gitleaks(app_secrets)

    privacy_path = app / "Contents" / "Resources" / "PrivacyInfo.xcprivacy"
    validate_regular_file(privacy_path, max_bytes=64 * 1024)
    import plistlib

    try:
        privacy = plistlib.loads(privacy_path.read_bytes())
    except plistlib.InvalidFileException as exc:
        raise VerificationError("built macOS privacy manifest is invalid") from exc
    require(privacy == EXPECTED_PRIVACY, "built macOS privacy manifest differs from the reviewed minimum")
    require(
        hash_file(privacy_path)["sha256"] == source["privacy_manifest"]["sha256"],
        "built macOS privacy manifest differs from source evidence",
    )
    notices = validate_notices(
        app
        / "Contents"
        / "Frameworks"
        / "App.framework"
        / "Versions"
        / "A"
        / "Resources"
        / "flutter_assets"
        / "NOTICES.Z",
        expected_runtime,
    )

    receipt = {
        "schema": "mesh-apple-admin-security-receipt-v1",
        "gate": {
            "baseline": hash_file(
                script_dir / "apple-admin-security-baseline.sh"
            ),
            "gitleaks_policy": hash_file(repo_root / ".gitleaks-image.toml"),
            "verifier": hash_file(pathlib.Path(__file__).resolve()),
        },
        "artifact": {
            "bundle_identifier": bundle["identifier"],
            "tree_sha256": tree_sha,
            "regular_files": file_count,
            "regular_file_bytes": total_bytes,
            "source_receipt": hash_file(source_path),
        },
        "dependencies": {
            "pub_deps": hash_file(pub_deps_path),
            "runtime_hosted_packages": expected_runtime,
            "runtime_hosted_package_count": len(expected_runtime),
        },
        "licenses": notices,
        "privacy": {
            "manifest": hash_file(privacy_path),
            "accessed_api_types": EXPECTED_PRIVACY["NSPrivacyAccessedAPITypes"],
            "collected_data_types": [],
            "tracking": False,
            "tracking_domains": [],
            "status": "source-reviewed-final-distribution-reconciliation-pending",
        },
        "sbom": {
            "syft_json": hash_file(syft_path),
            "syft_package_count": syft_count,
            "syft_schema": "16.1.3",
            "syft_version": "1.44.0",
            "spdx_json": hash_file(spdx_path),
            "spdx_package_count": spdx_count,
            "spdx_version": "SPDX-2.3",
        },
        "secret_scan": {
            "gitleaks_version": "v8.30.1",
            "metadata_report": hash_file(metadata_secrets),
            "app_strings_report": hash_file(app_secrets),
            "policy": "redacted default-rule scan of bound metadata and secret-scan text from every regular app-bundle file; generated CodeResources byte digests are normalized and only exact reviewed public integrity digests are allowlisted",
        },
        "scanner_boundary": {
            "artifact_and_scan": "stable unsigned app snapshot; networkless read-only non-root scanners; no Docker socket",
            "database_update": "networked scanner with only an empty private database cache mounted",
            "registry_authentication": "anonymous public pulls through an empty private Docker configuration",
            "code_signature_byte_digests": "normalized-only-inside-generated-_CodeSignature/CodeResources-plists",
        },
        "vulnerability_scan": {
            "database_built": database_built,
            "database_schema": database_schema,
            "database_status": hash_file(database_path),
            "grype_version": "0.112.0",
            "policy": "reject High or Critical matches and every match with a published fix",
            "report": hash_file(grype_path),
            **vulnerability_summary,
        },
        "verified_at": dt.datetime.now(dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
    }
    receipt_path = pathlib.Path(args.receipt)
    require(receipt_path.parent == work, "Apple Admin receipt must be written inside the workspace")
    exclusive_write(receipt_path, canonical_json(receipt), mode=0o400)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--work-dir", required=True)
    result.add_argument("--receipt", required=True)
    return result


def main() -> int:
    try:
        finalize(parser().parse_args())
    except (VerificationError, OSError) as exc:
        print(f"Apple Admin security verification: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
