#!/usr/bin/env python3
"""Validate and bind one exact unsigned iOS Admin simulator security scan."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import pathlib
import plistlib
import re
import sys
from typing import Any

from apple_admin_security_verify import (
    EXPECTED_PRIVACY,
    runtime_packages,
    validate_notices,
    validate_syft,
)
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
EMPTY_PRIVACY = {
    "NSPrivacyAccessedAPITypes": [],
    "NSPrivacyCollectedDataTypes": [],
    "NSPrivacyTracking": False,
    "NSPrivacyTrackingDomains": [],
}
FLUTTER_PRIVACY = {
    "NSPrivacyAccessedAPITypes": [
        {
            "NSPrivacyAccessedAPIType": (
                "NSPrivacyAccessedAPICategoryFileTimestamp"
            ),
            "NSPrivacyAccessedAPITypeReasons": ["0A2A.1", "C617.1"],
        },
        {
            "NSPrivacyAccessedAPIType": (
                "NSPrivacyAccessedAPICategorySystemBootTime"
            ),
            "NSPrivacyAccessedAPITypeReasons": ["35F9.1"],
        },
    ],
    "NSPrivacyCollectedDataTypes": [],
    "NSPrivacyTracking": False,
    "NSPrivacyTrackingDomains": [],
}
EXPECTED_PRIVACY_MANIFESTS = {
    "Frameworks/Flutter.framework/PrivacyInfo.xcprivacy": FLUTTER_PRIVACY,
    "PrivacyInfo.xcprivacy": EXPECTED_PRIVACY,
    (
        "flutter_secure_storage_darwin_flutter_secure_storage_darwin.bundle/"
        "PrivacyInfo.xcprivacy"
    ): EMPTY_PRIVACY,
    "url_launcher_ios_url_launcher_ios.bundle/PrivacyInfo.xcprivacy": (
        EMPTY_PRIVACY
    ),
}


def canonical_source_receipt(path: pathlib.Path) -> dict[str, Any]:
    validate_regular_file(path, max_bytes=4 * 1024 * 1024)
    raw = path.read_bytes()
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VerificationError("iOS Admin source receipt is invalid JSON") from exc
    require(
        isinstance(document, dict),
        "iOS Admin source receipt is not an object",
    )
    require(
        raw == canonical_json(document),
        "iOS Admin source receipt is not canonical JSON",
    )
    require(
        document.get("schema")
        == "mesh-apple-ios-simulator-source-artifact-receipt-v1"
        and document.get("platform") == "ios-simulator"
        and document.get("configuration") == "debug",
        "iOS Admin source receipt target is invalid",
    )
    bundle = document.get("bundle")
    require(isinstance(bundle, dict), "iOS Admin source receipt bundle is missing")
    require(
        bundle.get("identifier") == "io.rw0.mesh.admin.mobile"
        and bundle.get("architectures")
        in (["arm64", "x86_64"], ["x86_64", "arm64"])
        and bundle.get("release_signature") == "absent"
        and bundle.get("entitlements_applied") is False
        and isinstance(bundle.get("tree_sha256"), str)
        and DIGEST.fullmatch(bundle["tree_sha256"]),
        "iOS Admin source receipt bundle boundary is invalid",
    )
    source_boundary = document.get("source_boundary")
    require(
        isinstance(source_boundary, dict)
        and source_boundary.get("physical_device_validated") is False,
        "iOS Admin source receipt physical-device boundary is invalid",
    )
    privacy = document.get("privacy_manifest")
    require(
        isinstance(privacy, dict)
        and privacy.get("status")
        == "source-reviewed-final-dependency-reconciliation-pending"
        and isinstance(privacy.get("sha256"), str)
        and DIGEST.fullmatch(privacy["sha256"]),
        "iOS Admin source privacy evidence is missing",
    )
    return document


def validate_privacy_manifests(
    app: pathlib.Path,
    source: dict[str, Any],
) -> dict[str, Any]:
    observed_paths = sorted(
        path.relative_to(app).as_posix()
        for path in app.rglob("PrivacyInfo.xcprivacy")
        if path.is_file() and not path.is_symlink()
    )
    require(
        observed_paths == sorted(EXPECTED_PRIVACY_MANIFESTS),
        "packaged iOS privacy manifest inventory differs from the reviewed set",
    )
    records: dict[str, Any] = {}
    for relative in observed_paths:
        path = app / relative
        validate_regular_file(path, max_bytes=64 * 1024)
        try:
            document = plistlib.loads(path.read_bytes())
        except plistlib.InvalidFileException as exc:
            raise VerificationError(
                f"packaged iOS privacy manifest is invalid: {relative}"
            ) from exc
        require(
            document == EXPECTED_PRIVACY_MANIFESTS[relative],
            f"packaged iOS privacy manifest differs from review: {relative}",
        )
        records[relative] = {
            **hash_file(path),
            "accessed_api_types": document["NSPrivacyAccessedAPITypes"],
            "collected_data_types": [],
            "tracking": False,
            "tracking_domains": [],
        }
    require(
        records["PrivacyInfo.xcprivacy"]["sha256"]
        == source["privacy_manifest"]["sha256"],
        "packaged Mesh iOS privacy manifest differs from source evidence",
    )
    return {
        "manifest_count": len(records),
        "manifests": records,
        "status": (
            "packaged-inventory-reviewed-final-store-declarations-pending"
        ),
    }


def finalize(args: argparse.Namespace) -> None:
    work = pathlib.Path(args.work_dir)
    require(
        work.is_dir() and not work.is_symlink(),
        "iOS Admin verification workspace is unsafe",
    )
    app = work / "scan-root" / "Runner.app"
    require(
        app.is_dir() and not app.is_symlink(),
        "stable iOS Admin app snapshot is missing",
    )
    source_path = work / "source-receipt.json"
    source = canonical_source_receipt(source_path)
    tree_sha, file_count, total_bytes = tree_identity(app)
    bundle = source["bundle"]
    require(
        tree_sha == bundle["tree_sha256"],
        "iOS Admin snapshot differs from its source receipt",
    )
    require(
        file_count == bundle["regular_files"],
        "iOS Admin snapshot file count differs from its source receipt",
    )
    require(
        total_bytes == bundle["regular_file_bytes"],
        "iOS Admin snapshot byte count differs from its source receipt",
    )

    pub_deps_path = work / "pub-deps.json"
    pub_deps = read_json(pub_deps_path, max_bytes=4 * 1024 * 1024)
    require(isinstance(pub_deps, dict), "Dart dependency graph is not an object")
    expected_runtime = runtime_packages(pub_deps)

    syft_path, spdx_path = work / "sbom.syft.json", work / "sbom.spdx.json"
    grype_path = work / "vulnerabilities.json"
    database_path = work / "grype-db-status.json"
    metadata_secrets = work / "metadata-secrets.json"
    app_secrets = work / "app-strings-secrets.json"
    syft, spdx, grype, database = (
        read_json(path)
        for path in (syft_path, spdx_path, grype_path, database_path)
    )
    require(
        all(
            isinstance(item, dict)
            for item in (syft, spdx, grype, database)
        ),
        "iOS Admin scanner output is not an object",
    )
    purls, syft_count = validate_syft(syft, expected_runtime)
    spdx_count = validate_spdx(spdx, purls)
    database_schema, database_built = validate_grype_db(database)
    vulnerability_summary = validate_grype(grype, purls)
    validate_empty_gitleaks(metadata_secrets)
    validate_empty_gitleaks(app_secrets)

    privacy = validate_privacy_manifests(app, source)
    notices = validate_notices(
        app
        / "Frameworks"
        / "App.framework"
        / "flutter_assets"
        / "NOTICES.Z",
        expected_runtime,
    )

    script_dir = pathlib.Path(__file__).resolve().parent
    repo_root = script_dir.parent
    receipt = {
        "schema": "mesh-apple-ios-admin-simulator-security-receipt-v1",
        "verified_at": dt.datetime.now(dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        "gate": {
            "baseline": hash_file(
                script_dir / "apple-ios-admin-security-baseline.sh"
            ),
            "gitleaks_policy": hash_file(
                repo_root / ".gitleaks-apple-ios-admin.toml"
            ),
            "verifier": hash_file(pathlib.Path(__file__).resolve()),
        },
        "artifact": {
            "bundle_identifier": bundle["identifier"],
            "configuration": "debug",
            "platform": "ios-simulator",
            "architectures": sorted(bundle["architectures"]),
            "tree_sha256": tree_sha,
            "regular_files": file_count,
            "regular_file_bytes": total_bytes,
            "source_receipt": hash_file(source_path),
            "signed": False,
            "entitlements_applied": False,
            "physical_device_validated": False,
            "distribution_validated": False,
        },
        "dependencies": {
            "pub_deps": hash_file(pub_deps_path),
            "runtime_hosted_packages": expected_runtime,
            "runtime_hosted_package_count": len(expected_runtime),
        },
        "licenses": notices,
        "privacy": privacy,
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
            "policy": (
                "redacted default-rule scan of bound source/dependency/"
                "notice metadata and strings from every app file; generated "
                "CodeResources byte digests are normalized only in scan text"
            ),
        },
        "scanner_boundary": {
            "artifact_and_scan": (
                "stable unsigned simulator-app snapshot; networkless "
                "read-only non-root scanners; no Docker socket"
            ),
            "database_update": (
                "networked scanner with only an empty private database cache "
                "mounted"
            ),
            "registry_authentication": (
                "anonymous public pulls through an empty private Docker "
                "configuration"
            ),
        },
        "vulnerability_scan": {
            "database_built": database_built,
            "database_schema": database_schema,
            "database_status": hash_file(database_path),
            "grype_version": "0.112.0",
            "policy": (
                "reject High or Critical matches and every match with a "
                "published fix"
            ),
            "report": hash_file(grype_path),
            **vulnerability_summary,
        },
    }
    output = pathlib.Path(args.receipt)
    require(
        output.parent == work,
        "iOS Admin security receipt must be written inside the workspace",
    )
    exclusive_write(output, canonical_json(receipt), mode=0o400)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--work-dir", required=True)
    result.add_argument("--receipt", required=True)
    return result


def main() -> int:
    try:
        finalize(parser().parse_args())
    except (VerificationError, OSError) as exc:
        print(f"Apple iOS Admin security verification: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
