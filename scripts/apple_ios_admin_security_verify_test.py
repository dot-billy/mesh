#!/usr/bin/env python3
"""Tests for the iOS Admin simulator security evidence verifier."""

from __future__ import annotations

import datetime as dt
import gzip
import json
import pathlib
import plistlib
import tempfile
import types
import unittest

import apple_ios_admin_security_verify as verifier
from image_security_verify import VerificationError, canonical_json


def write_json(path: pathlib.Path, value: object) -> None:
    path.write_bytes(canonical_json(value))


def fixture(root: pathlib.Path) -> pathlib.Path:
    work = root / "work"
    app = work / "scan-root" / "Runner.app"
    notices = (
        app
        / "Frameworks"
        / "App.framework"
        / "flutter_assets"
        / "NOTICES.Z"
    )
    notices.parent.mkdir(parents=True)
    notices.write_bytes(
        gzip.compress(b"\nalpha\n\n" + b"permissive license text\n" * 4096)
    )
    for relative, document in verifier.EXPECTED_PRIVACY_MANIFESTS.items():
        path = app / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(plistlib.dumps(document))

    tree_sha, file_count, total_bytes = verifier.tree_identity(app)
    source = {
        "schema": "mesh-apple-ios-simulator-source-artifact-receipt-v1",
        "platform": "ios-simulator",
        "configuration": "debug",
        "bundle": {
            "identifier": "io.rw0.mesh.admin.mobile",
            "architectures": ["x86_64", "arm64"],
            "release_signature": "absent",
            "entitlements_applied": False,
            "tree_sha256": tree_sha,
            "regular_files": file_count,
            "regular_file_bytes": total_bytes,
        },
        "source_boundary": {"physical_device_validated": False},
        "privacy_manifest": {
            "sha256": verifier.hash_file(
                app / "PrivacyInfo.xcprivacy"
            )["sha256"],
            "status": (
                "source-reviewed-final-dependency-reconciliation-pending"
            ),
        },
    }
    write_json(work / "source-receipt.json", source)
    write_json(
        work / "pub-deps.json",
        {
            "root": "mesh_desktop",
            "packages": [
                {
                    "name": "mesh_desktop",
                    "version": "0.1.0+1",
                    "kind": "root",
                    "source": "root",
                    "dependencies": ["flutter", "alpha", "dev_only"],
                },
                {
                    "name": "flutter",
                    "version": "0.0.0",
                    "kind": "direct",
                    "source": "sdk",
                    "dependencies": [],
                },
                {
                    "name": "alpha",
                    "version": "1.2.3",
                    "kind": "direct",
                    "source": "hosted",
                    "dependencies": [],
                },
                {
                    "name": "dev_only",
                    "version": "9.9.9",
                    "kind": "dev",
                    "source": "hosted",
                    "dependencies": [],
                },
            ],
        },
    )
    purl = "pkg:pub/alpha@1.2.3"
    write_json(
        work / "sbom.syft.json",
        {
            "descriptor": {"name": "syft", "version": "1.44.0"},
            "schema": {"version": "16.1.3"},
            "source": {"type": "directory"},
            "artifacts": [
                {
                    "name": "alpha",
                    "version": "1.2.3",
                    "type": "dart-pub",
                    "purl": purl,
                }
            ],
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
                    "externalRefs": [
                        {
                            "referenceType": "purl",
                            "referenceLocator": purl,
                        }
                    ]
                }
            ],
        },
    )
    now = dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")
    write_json(
        work / "grype-db-status.json",
        {"status": "valid", "schema": "v6.1.9", "built": now},
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


class AppleIOSAdminSecurityVerifyTest(unittest.TestCase):
    def test_exact_fixture_produces_simulator_only_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            work = fixture(pathlib.Path(temporary))
            output = work / "receipt.json"
            verifier.finalize(
                types.SimpleNamespace(work_dir=str(work), receipt=str(output))
            )
            receipt = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(
                receipt["schema"],
                "mesh-apple-ios-admin-simulator-security-receipt-v1",
            )
            self.assertEqual(receipt["privacy"]["manifest_count"], 4)
            self.assertFalse(receipt["artifact"]["signed"])
            self.assertFalse(
                receipt["artifact"]["physical_device_validated"]
            )
            self.assertFalse(receipt["artifact"]["distribution_validated"])

    def test_physical_device_claim_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            work = fixture(pathlib.Path(temporary))
            source_path = work / "source-receipt.json"
            source = json.loads(source_path.read_text(encoding="utf-8"))
            source["source_boundary"]["physical_device_validated"] = True
            write_json(source_path, source)
            with self.assertRaisesRegex(
                VerificationError, "physical-device boundary"
            ):
                verifier.canonical_source_receipt(source_path)

    def test_privacy_manifest_drift_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            work = fixture(pathlib.Path(temporary))
            app = work / "scan-root" / "Runner.app"
            unexpected = app / "Unexpected.bundle" / "PrivacyInfo.xcprivacy"
            unexpected.parent.mkdir()
            unexpected.write_bytes(plistlib.dumps(verifier.EMPTY_PRIVACY))
            with self.assertRaisesRegex(
                VerificationError, "privacy manifest inventory"
            ):
                verifier.validate_privacy_manifests(
                    app,
                    json.loads(
                        (work / "source-receipt.json").read_text(
                            encoding="utf-8"
                        )
                    ),
                )

    def test_missing_runtime_package_and_secret_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            work = fixture(pathlib.Path(temporary))
            syft_path = work / "sbom.syft.json"
            syft = json.loads(syft_path.read_text(encoding="utf-8"))
            syft["artifacts"] = []
            write_json(syft_path, syft)
            with self.assertRaisesRegex(
                VerificationError, "SBOM is empty"
            ):
                verifier.finalize(
                    types.SimpleNamespace(
                        work_dir=str(work), receipt=str(work / "receipt.json")
                    )
                )

            work = fixture(pathlib.Path(temporary) / "secret")
            write_json(
                work / "metadata-secrets.json",
                [{"RuleID": "generic-api-key", "Secret": "REDACTED"}],
            )
            with self.assertRaisesRegex(VerificationError, "not empty"):
                verifier.finalize(
                    types.SimpleNamespace(
                        work_dir=str(work), receipt=str(work / "receipt.json")
                    )
                )


if __name__ == "__main__":
    unittest.main()
