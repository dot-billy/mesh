#!/usr/bin/env python3
"""Tests for the fail-closed iOS Tunnel simulator security verifier."""

from __future__ import annotations

import datetime as dt
import json
import pathlib
import plistlib
import tempfile
import types
import unittest

import apple_ios_tunnel_security_verify as verifier
from image_security_verify import VerificationError, canonical_json


def write_json(path: pathlib.Path, value: object) -> None:
    path.write_bytes(canonical_json(value))


def fixture(root: pathlib.Path) -> pathlib.Path:
    work = root / "work"
    app = work / "scan-root" / "Mesh Tunnel.app"
    extension = app / "PlugIns" / "MeshPacketTunnel.appex"
    extension.mkdir(parents=True)
    files = {
        app / "Info.plist": b"app-info",
        app / "Mesh Tunnel": b"app-executable",
        app / "PkgInfo": b"APPL????",
        extension / "Info.plist": b"extension-info",
        extension / "MeshPacketTunnel": b"extension-executable",
    }
    for path, payload in files.items():
        path.write_bytes(payload)
    privacy_payload = plistlib.dumps(verifier.EMPTY_PRIVACY)
    (app / "PrivacyInfo.xcprivacy").write_bytes(privacy_payload)
    (extension / "PrivacyInfo.xcprivacy").write_bytes(privacy_payload)

    extension_tree = verifier.tree_identity(extension)
    app_tree = verifier.tree_identity(app)
    privacy_hash = verifier.hash_file(app / "PrivacyInfo.xcprivacy")["sha256"]
    source = {
        "schema": (
            "mesh-apple-ios-tunnel-simulator-source-artifact-receipt-v1"
        ),
        "platform": "ios-tunnel-simulator",
        "configuration": "debug",
        "bundle": {
            "identifier": "io.rw0.mesh.tunnel.mobile",
            "architectures": ["x86_64", "arm64"],
            "release_signature": "absent",
            "entitlements_applied": False,
            "tree_sha256": app_tree[0],
            "regular_files": app_tree[1],
            "regular_file_bytes": app_tree[2],
        },
        "extension": {
            "identifier": "io.rw0.mesh.tunnel.mobile.packet-tunnel",
            "extension_point": "com.apple.networkextension.packet-tunnel",
            "architectures": ["x86_64", "arm64"],
            "engine_frameworks": [],
            "engine_linkage": "static",
            "engine_dynamic_dependency": False,
            "engine_framework_reproducible": True,
            "engine_framework_source_receipt_sha256": "1" * 64,
            "engine_framework_tree_sha256": "2" * 64,
            "physical_device_validated": False,
            "release_signature": "absent",
            "entitlements_applied": False,
            "tree_sha256": extension_tree[0],
            "regular_files": extension_tree[1],
            "regular_file_bytes": extension_tree[2],
        },
        "source_boundary": {
            "physical_device_validated": False,
            "provider": (
                "coordinator-apple-flow-current-config-only-lifecycle-mobile-"
                "evidence-identity-removal-static-engine-network-path-source-wired"
            ),
            "packet_pump": "bounded-apple-flow-source-wired-static-engine",
            "apple_settings_mapping": (
                "coordinator-gated-provider-adapter-source-wired"
            ),
            "engine_adapter": (
                "gomobile-extension-lifecycle-renewal-credential-"
                "rotation-mobile-evidence-identity-removal-signed-config-packet-"
                "session-source-wired"
            ),
            "host_enrollment_adapter": (
                "gomobile-host-self-enrollment-shared-identity-"
                "config-activation-source-wired"
            ),
            "identity_keychain_custody": (
                "shared-host-extension-device-only-source-proven"
            ),
            "host_runtime_controls": (
                "provision-first-connect-second-real-evidence-"
                "start-stop-inspect-source-proven"
            ),
            "host_manager_recovery": (
                "preauth-confirmed-disabled-no-identity-exact-replacement-"
                "postauth-bounded-fresh-manager-retry-terminal-status-source-"
                "proven"
            ),
            "remote_endpoint": "authenticated-canonical-required",
            "runtime_coordinator": "ordered-rebind-cleanup-source-proven",
            "extension_logging": "fixed-reviewed-16-event-codes-only",
        },
        "privacy_manifest": {
            "sha256": privacy_hash,
            "status": (
                "source-reviewed-final-dependency-reconciliation-pending"
            ),
        },
    }
    write_json(work / "source-receipt.json", source)
    write_json(
        work / "swift-dependencies.json",
        {
            "schema": "mesh-apple-ios-tunnel-swift-dependencies-v1",
            "package_identity": "ios-tunnel",
            "package_name": "MeshTunnelContract",
            "third_party_dependencies": [],
        },
    )
    purls = [
        f"pkg:golang/{name}@{version}"
        for name, version in sorted(verifier.EXPECTED_MODULES.items())
    ]
    write_json(
        work / "sbom.syft.json",
        {
            "descriptor": {"name": "syft", "version": "1.44.0"},
            "schema": {"version": "16.1.3"},
            "source": {"type": "directory"},
            "artifacts": [
                {
                    "name": name,
                    "version": version,
                    "type": "go-module",
                    "purl": f"pkg:golang/{name}@{version}",
                }
                for name, version in sorted(
                    verifier.EXPECTED_MODULES.items()
                )
            ],
            "artifactRelationships": [],
        },
    )
    write_json(
        work / "sbom.spdx.json",
        {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "creationInfo": {"creators": ["Tool: syft-1.44.0"]},
            "packages": [
                {
                    "name": name,
                    "externalRefs": [
                        {
                            "referenceType": "purl",
                            "referenceLocator": purl,
                        }
                    ],
                }
                for name, purl in zip(
                    sorted(verifier.EXPECTED_MODULES),
                    purls,
                    strict=True,
                )
            ],
        },
    )
    built = (
        dt.datetime.now(dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
    write_json(
        work / "grype-db-status.json",
        {"status": "valid", "schema": "v6.1.9", "built": built},
    )
    write_json(
        work / "vulnerabilities.json",
        {
            "descriptor": {"name": "grype", "version": "0.112.0"},
            "ignoredMatches": [],
            "matches": [],
        },
    )
    write_json(work / "metadata-secrets.json", [])
    write_json(work / "app-strings-secrets.json", [])
    return work


class AppleIOSTunnelSecurityVerifyTest(unittest.TestCase):
    def test_exact_fixture_produces_fail_closed_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            work = fixture(pathlib.Path(temporary))
            output = work / "receipt.json"
            verifier.finalize(
                types.SimpleNamespace(work_dir=str(work), receipt=str(output))
            )
            receipt = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(
                receipt["schema"],
                "mesh-apple-ios-tunnel-simulator-security-receipt-v1",
            )
            self.assertEqual(
                receipt["dependencies"][
                    "swiftpm_third_party_dependency_count"
                ],
                0,
            )
            self.assertEqual(
                receipt["sbom"]["syft_package_count"],
                len(verifier.EXPECTED_MODULES),
            )
            self.assertTrue(receipt["artifact"]["engine_embedded"])
            self.assertEqual(receipt["artifact"]["engine_linkage"], "static")
            self.assertTrue(
                receipt["artifact"]["packet_flow_source_wired"]
            )
            self.assertFalse(receipt["artifact"]["packet_flow_connected"])
            self.assertFalse(receipt["artifact"]["physical_device_validated"])

    def test_dynamic_engine_claim_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            work = fixture(pathlib.Path(temporary))
            source_path = work / "source-receipt.json"
            source = json.loads(source_path.read_text(encoding="utf-8"))
            source["extension"]["engine_linkage"] = "dynamic"
            write_json(source_path, source)
            with self.assertRaisesRegex(
                VerificationError, "extension boundary"
            ):
                verifier.canonical_source_receipt(source_path)

    def test_incomplete_static_engine_sbom_is_rejected(self) -> None:
        syft = {
            "descriptor": {"name": "syft", "version": "1.44.0"},
            "schema": {"version": "16.1.3"},
            "source": {"type": "directory"},
            "artifacts": [],
            "artifactRelationships": [],
        }
        spdx = {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "creationInfo": {"creators": ["Tool: syft-1.44.0"]},
            "packages": [{"name": "/scan", "externalRefs": []}],
        }
        with self.assertRaisesRegex(VerificationError, "SBOM is empty"):
            verifier.validate_static_engine_sboms(syft, spdx)

    def test_privacy_drift_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            work = fixture(pathlib.Path(temporary))
            app = work / "scan-root" / "Mesh Tunnel.app"
            path = app / "PrivacyInfo.xcprivacy"
            changed = dict(verifier.EMPTY_PRIVACY)
            changed["NSPrivacyTracking"] = True
            path.write_bytes(plistlib.dumps(changed))
            source = json.loads(
                (work / "source-receipt.json").read_text(encoding="utf-8")
            )
            with self.assertRaisesRegex(
                VerificationError, "differs from review"
            ):
                verifier.validate_privacy_manifests(app, source)


if __name__ == "__main__":
    unittest.main()
