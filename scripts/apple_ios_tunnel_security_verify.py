#!/usr/bin/env python3
"""Validate and bind one exact fail-closed iOS Tunnel simulator security scan."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import pathlib
import plistlib
import re
import sys
from typing import Any

from apple_ios_admin_security_verify import EMPTY_PRIVACY
from apple_mobile_framework_security_verify import (
    EXPECTED_MODULES,
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
EXPECTED_PRIVACY_PATHS = [
    "PlugIns/MeshPacketTunnel.appex/PrivacyInfo.xcprivacy",
    "PrivacyInfo.xcprivacy",
]


def canonical_source_receipt(path: pathlib.Path) -> dict[str, Any]:
    validate_regular_file(path, max_bytes=4 * 1024 * 1024)
    raw = path.read_bytes()
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VerificationError(
            "iOS Tunnel source receipt is invalid JSON"
        ) from exc
    require(
        isinstance(document, dict),
        "iOS Tunnel source receipt is not an object",
    )
    require(
        raw == canonical_json(document),
        "iOS Tunnel source receipt is not canonical JSON",
    )
    require(
        document.get("schema")
        == "mesh-apple-ios-tunnel-simulator-source-artifact-receipt-v1"
        and document.get("platform") == "ios-tunnel-simulator"
        and document.get("configuration") == "debug",
        "iOS Tunnel source receipt target is invalid",
    )
    bundle = document.get("bundle")
    extension = document.get("extension")
    boundary = document.get("source_boundary")
    require(
        isinstance(bundle, dict)
        and bundle.get("identifier") == "io.rw0.mesh.tunnel.mobile"
        and bundle.get("architectures")
        in (["arm64", "x86_64"], ["x86_64", "arm64"])
        and bundle.get("release_signature") == "absent"
        and bundle.get("entitlements_applied") is False
        and isinstance(bundle.get("tree_sha256"), str)
        and DIGEST.fullmatch(bundle["tree_sha256"]),
        "iOS Tunnel containing-app boundary is invalid",
    )
    require(
        isinstance(extension, dict)
        and extension.get("identifier")
        == "io.rw0.mesh.tunnel.mobile.packet-tunnel"
        and extension.get("extension_point")
        == "com.apple.networkextension.packet-tunnel"
        and extension.get("architectures")
        in (["arm64", "x86_64"], ["x86_64", "arm64"])
        and extension.get("engine_frameworks") == []
        and extension.get("engine_linkage") == "static"
        and extension.get("engine_dynamic_dependency") is False
        and extension.get("engine_framework_reproducible") is True
        and extension.get("physical_device_validated") is False
        and isinstance(
            extension.get("engine_framework_source_receipt_sha256"),
            str,
        )
        and DIGEST.fullmatch(
            extension["engine_framework_source_receipt_sha256"]
        )
        and isinstance(extension.get("engine_framework_tree_sha256"), str)
        and DIGEST.fullmatch(extension["engine_framework_tree_sha256"])
        and extension.get("release_signature") == "absent"
        and extension.get("entitlements_applied") is False
        and isinstance(extension.get("tree_sha256"), str)
        and DIGEST.fullmatch(extension["tree_sha256"]),
        "iOS Tunnel extension boundary is invalid",
    )
    require(
        isinstance(boundary, dict)
        and boundary.get("physical_device_validated") is False
        and boundary.get("provider")
        == (
            "coordinator-apple-flow-current-config-only-lifecycle-mobile-"
            "evidence-identity-removal-static-engine-network-path-source-wired"
        )
        and boundary.get("packet_pump")
        == "bounded-apple-flow-source-wired-static-engine"
        and boundary.get("apple_settings_mapping")
        == "coordinator-gated-provider-adapter-source-wired"
        and boundary.get("engine_adapter")
        == (
            "gomobile-extension-lifecycle-renewal-credential-"
            "rotation-mobile-evidence-identity-removal-signed-config-packet-"
            "session-source-wired"
        )
        and boundary.get("host_enrollment_adapter")
        == (
            "gomobile-host-self-enrollment-shared-identity-"
            "config-activation-source-wired"
        )
        and boundary.get("identity_keychain_custody")
        == "shared-host-extension-device-only-source-proven"
        and boundary.get("host_runtime_controls")
        == (
            "provision-first-connect-second-real-evidence-"
            "start-stop-inspect-source-proven"
        )
        and boundary.get("host_manager_recovery")
        == (
            "preauth-confirmed-disabled-no-identity-exact-replacement-"
            "postauth-bounded-fresh-manager-retry-terminal-status-source-"
            "proven"
        )
        and boundary.get("remote_endpoint")
        == "authenticated-canonical-required"
        and boundary.get("runtime_coordinator")
        == "ordered-rebind-cleanup-source-proven"
        and boundary.get("extension_logging")
        == "fixed-reviewed-16-event-codes-only",
        "iOS Tunnel unsupported source boundary is invalid",
    )
    privacy = document.get("privacy_manifest")
    require(
        isinstance(privacy, dict)
        and privacy.get("status")
        == "source-reviewed-final-dependency-reconciliation-pending"
        and isinstance(privacy.get("sha256"), str)
        and DIGEST.fullmatch(privacy["sha256"]),
        "iOS Tunnel source privacy evidence is missing",
    )
    return document


def validate_swift_dependencies(
    document: dict[str, Any],
) -> dict[str, Any]:
    require(
        document
        == {
            "schema": "mesh-apple-ios-tunnel-swift-dependencies-v1",
            "package_identity": "ios-tunnel",
            "package_name": "MeshTunnelContract",
            "third_party_dependencies": [],
        },
        "iOS Tunnel Swift dependency inventory is not the reviewed empty graph",
    )
    return {
        "swiftpm_third_party_dependency_count": 0,
        "swiftpm_third_party_dependencies": [],
    }


def validate_static_engine_sboms(
    syft: dict[str, Any],
    spdx: dict[str, Any],
) -> tuple[set[str], int, int]:
    purls, syft_count = validate_syft(syft, EXPECTED_MODULES)
    spdx_count = validate_spdx(spdx, purls)
    return purls, syft_count, spdx_count


def validate_privacy_manifests(
    app: pathlib.Path,
    source: dict[str, Any],
) -> dict[str, Any]:
    paths = sorted(
        path.relative_to(app).as_posix()
        for path in app.rglob("PrivacyInfo.xcprivacy")
        if path.is_file() and not path.is_symlink()
    )
    require(
        paths == EXPECTED_PRIVACY_PATHS,
        "iOS Tunnel privacy manifest inventory differs from the reviewed set",
    )
    records: dict[str, Any] = {}
    for relative in paths:
        path = app / relative
        validate_regular_file(path, max_bytes=64 * 1024)
        try:
            document = plistlib.loads(path.read_bytes())
        except plistlib.InvalidFileException as exc:
            raise VerificationError(
                f"iOS Tunnel privacy manifest is invalid: {relative}"
            ) from exc
        require(
            document == EMPTY_PRIVACY,
            f"iOS Tunnel privacy manifest differs from review: {relative}",
        )
        records[relative] = {
            **hash_file(path),
            "accessed_api_types": [],
            "collected_data_types": [],
            "tracking": False,
            "tracking_domains": [],
        }
    require(
        all(
            record["sha256"] == source["privacy_manifest"]["sha256"]
            for record in records.values()
        ),
        "iOS Tunnel privacy manifests differ from source evidence",
    )
    return {
        "manifest_count": len(records),
        "manifests": records,
        "status": (
            "packaged-empty-manifests-reviewed-final-store-declarations-pending"
        ),
    }


def finalize(args: argparse.Namespace) -> None:
    work = pathlib.Path(args.work_dir)
    require(
        work.is_dir() and not work.is_symlink(),
        "iOS Tunnel verification workspace is unsafe",
    )
    app = work / "scan-root" / "Mesh Tunnel.app"
    require(
        app.is_dir() and not app.is_symlink(),
        "stable iOS Tunnel app snapshot is missing",
    )
    source_path = work / "source-receipt.json"
    source = canonical_source_receipt(source_path)
    observed_tree = tree_identity(app)
    bundle = source["bundle"]
    require(
        observed_tree
        == (
            bundle["tree_sha256"],
            bundle["regular_files"],
            bundle["regular_file_bytes"],
        ),
        "iOS Tunnel app snapshot differs from its source receipt",
    )
    extension_path = app / "PlugIns" / "MeshPacketTunnel.appex"
    observed_extension = tree_identity(extension_path)
    extension = source["extension"]
    require(
        observed_extension
        == (
            extension["tree_sha256"],
            extension["regular_files"],
            extension["regular_file_bytes"],
        ),
        "iOS Tunnel extension snapshot differs from its source receipt",
    )

    dependencies_path = work / "swift-dependencies.json"
    dependencies = read_json(dependencies_path, max_bytes=64 * 1024)
    require(
        isinstance(dependencies, dict),
        "iOS Tunnel Swift dependency inventory is not an object",
    )
    dependency_summary = validate_swift_dependencies(dependencies)

    syft_path = work / "sbom.syft.json"
    spdx_path = work / "sbom.spdx.json"
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
        "iOS Tunnel scanner output is not an object",
    )
    purls, syft_count, spdx_count = validate_static_engine_sboms(
        syft,
        spdx,
    )
    database_schema, database_built = validate_grype_db(database)
    vulnerability_summary = validate_grype(grype, purls)
    validate_empty_gitleaks(metadata_secrets)
    validate_empty_gitleaks(app_secrets)
    privacy = validate_privacy_manifests(app, source)

    script_dir = pathlib.Path(__file__).resolve().parent
    repo_root = script_dir.parent
    receipt = {
        "schema": "mesh-apple-ios-tunnel-simulator-security-receipt-v1",
        "verified_at": dt.datetime.now(dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        "gate": {
            "baseline": hash_file(
                script_dir / "apple-ios-tunnel-security-baseline.sh"
            ),
            "gitleaks_policy": hash_file(
                repo_root / ".gitleaks-apple-ios-tunnel.toml"
            ),
            "verifier": hash_file(pathlib.Path(__file__).resolve()),
        },
        "artifact": {
            "bundle_identifier": bundle["identifier"],
            "extension_identifier": extension["identifier"],
            "configuration": "debug",
            "platform": "ios-tunnel-simulator",
            "architectures": sorted(bundle["architectures"]),
            "tree_sha256": observed_tree[0],
            "regular_files": observed_tree[1],
            "regular_file_bytes": observed_tree[2],
            "extension_tree_sha256": observed_extension[0],
            "source_receipt": hash_file(source_path),
            "signed": False,
            "entitlements_applied": False,
            "engine_embedded": True,
            "engine_linkage": "static",
            "engine_framework_source_receipt_sha256": (
                extension["engine_framework_source_receipt_sha256"]
            ),
            "engine_framework_tree_sha256": (
                extension["engine_framework_tree_sha256"]
            ),
            "packet_flow_source_wired": True,
            "packet_flow_connected": False,
            "network_settings_applied": False,
            "physical_device_validated": False,
            "distribution_validated": False,
        },
        "dependencies": {
            "manifest": hash_file(dependencies_path),
            "package_swift": hash_file(repo_root / "ios-tunnel" / "Package.swift"),
            "static_engine_runtime_modules": dict(
                sorted(EXPECTED_MODULES.items())
            ),
            "static_engine_runtime_module_count": len(EXPECTED_MODULES),
            **dependency_summary,
        },
        "licenses": {
            "third_party_dependency_count": len(EXPECTED_MODULES),
            "status": (
                "static-engine-license-inventory-bound-by-mobile-framework-"
                "source-receipt-legal-review-pending"
            ),
        },
        "privacy": privacy,
        "sbom": {
            "syft_json": hash_file(syft_path),
            "syft_package_count": syft_count,
            "syft_schema": "16.1.3",
            "syft_version": "1.44.0",
            "spdx_json": hash_file(spdx_path),
            "spdx_package_count": spdx_count,
            "spdx_version": "SPDX-2.3",
            "status": "reviewed-static-engine-runtime-module-inventory",
        },
        "secret_scan": {
            "gitleaks_version": "v8.30.1",
            "metadata_report": hash_file(metadata_secrets),
            "app_strings_report": hash_file(app_secrets),
            "policy": (
                "redacted default-rule scan of bound source/dependency "
                "metadata and strings from all ten app and extension files"
            ),
        },
        "scanner_boundary": {
            "artifact_and_scan": (
                "stable unsigned static-engine simulator product; networkless "
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
        "iOS Tunnel security receipt must be written inside the workspace",
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
        print(f"Apple iOS Tunnel security verification: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
