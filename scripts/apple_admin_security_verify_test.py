#!/usr/bin/env python3
"""Tests for the macOS Mesh Admin security evidence verifier."""

from __future__ import annotations

import datetime as dt
import gzip
import importlib.util
import json
import pathlib
import plistlib
import sys
import tempfile
import types
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location(
    "apple_admin_security_verify",
    ROOT / "scripts" / "apple_admin_security_verify.py",
)
assert SPEC is not None and SPEC.loader is not None
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)


def write_json(path: pathlib.Path, value: object, *, canonical: bool = False) -> None:
    if canonical:
        path.write_bytes(VERIFY.canonical_json(value))
    else:
        path.write_text(json.dumps(value), encoding="utf-8")


def fixture(root: pathlib.Path) -> pathlib.Path:
    work = root / "work"
    app = work / "scan-root" / "Mesh Admin.app"
    resources = app / "Contents" / "Resources"
    notices = (
        app
        / "Contents"
        / "Frameworks"
        / "App.framework"
        / "Versions"
        / "A"
        / "Resources"
        / "flutter_assets"
    )
    resources.mkdir(parents=True)
    notices.mkdir(parents=True)
    privacy_path = resources / "PrivacyInfo.xcprivacy"
    privacy_path.write_bytes(plistlib.dumps(VERIFY.EXPECTED_PRIVACY))
    notice_payload = b"\nalpha\n\n" + b"permissive license text\n" * 4096
    (notices / "NOTICES.Z").write_bytes(gzip.compress(notice_payload))

    tree_sha, file_count, total_bytes = VERIFY.tree_identity(app)
    source = {
        "schema": "mesh-apple-macos-source-artifact-receipt-v2",
        "configuration": "release",
        "bundle": {
            "identifier": "io.rw0.mesh.admin",
            "architectures": ["arm64", "x86_64"],
            "release_signature": "absent",
            "entitlements_applied": False,
            "tree_sha256": tree_sha,
            "regular_files": file_count,
            "regular_file_bytes": total_bytes,
        },
        "privacy_manifest": {
            "sha256": VERIFY.hash_file(privacy_path)["sha256"],
            "status": "source-reviewed-final-dependency-reconciliation-pending",
        },
    }
    write_json(work / "source-receipt.json", source, canonical=True)
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
        {"status": "valid", "schema": "v6.1.2", "built": now},
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


class AppleAdminSecurityVerifyTest(unittest.TestCase):
    def test_exact_fixture_produces_bound_receipt(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mesh-apple-security-") as root:
            work = fixture(pathlib.Path(root))
            output = work / "receipt.json"
            VERIFY.finalize(
                types.SimpleNamespace(work_dir=str(work), receipt=str(output))
            )
            receipt = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(
                receipt["schema"], "mesh-apple-admin-security-receipt-v1"
            )
            self.assertEqual(
                receipt["dependencies"]["runtime_hosted_packages"],
                {"alpha": "1.2.3"},
            )
            self.assertEqual(
                receipt["licenses"]["status"],
                "inventory-present-legal-review-pending",
            )
            self.assertEqual(receipt["privacy"]["tracking"], False)

    def test_missing_runtime_package_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mesh-apple-security-") as root:
            work = fixture(pathlib.Path(root))
            syft = json.loads((work / "sbom.syft.json").read_text())
            syft["artifacts"] = [
                {
                    "name": "other",
                    "version": "1.0.0",
                    "type": "dart-pub",
                    "purl": "pkg:pub/other@1.0.0",
                }
            ]
            write_json(work / "sbom.syft.json", syft)
            with self.assertRaisesRegex(
                VERIFY.VerificationError, "runtime Dart inventory is incomplete"
            ):
                VERIFY.finalize(
                    types.SimpleNamespace(
                        work_dir=str(work), receipt=str(work / "receipt.json")
                    )
                )

    def test_notice_and_source_tampering_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mesh-apple-security-") as root:
            work = fixture(pathlib.Path(root))
            notice = (
                work
                / "scan-root"
                / "Mesh Admin.app"
                / "Contents"
                / "Frameworks"
                / "App.framework"
                / "Versions"
                / "A"
                / "Resources"
                / "flutter_assets"
                / "NOTICES.Z"
            )
            notice.write_bytes(gzip.compress(b"\nmissing\n" + b"x" * 65536))
            with self.assertRaisesRegex(
                VERIFY.VerificationError, "snapshot differs from its source receipt"
            ):
                VERIFY.finalize(
                    types.SimpleNamespace(
                        work_dir=str(work), receipt=str(work / "receipt.json")
                    )
                )
            source_path = work / "source-receipt.json"
            source = json.loads(source_path.read_text(encoding="utf-8"))
            app = work / "scan-root" / "Mesh Admin.app"
            tree_sha, file_count, total_bytes = VERIFY.tree_identity(app)
            source["bundle"]["tree_sha256"] = tree_sha
            source["bundle"]["regular_files"] = file_count
            source["bundle"]["regular_file_bytes"] = total_bytes
            write_json(source_path, source, canonical=True)
            with self.assertRaisesRegex(
                VERIFY.VerificationError, "notices omit runtime packages"
            ):
                VERIFY.finalize(
                    types.SimpleNamespace(
                        work_dir=str(work), receipt=str(work / "receipt.json")
                    )
                )

    def test_fixable_vulnerability_and_secret_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mesh-apple-security-") as root:
            work = fixture(pathlib.Path(root))
            grype = json.loads((work / "vulnerabilities.json").read_text())
            grype["matches"] = [
                {
                    "vulnerability": {
                        "id": "CVE-TEST",
                        "severity": "Low",
                        "fix": {"versions": ["1.2.4"]},
                    },
                    "artifact": {"purl": "pkg:pub/alpha@1.2.3"},
                }
            ]
            write_json(work / "vulnerabilities.json", grype)
            with self.assertRaisesRegex(
                VERIFY.VerificationError, "published fixes"
            ):
                VERIFY.finalize(
                    types.SimpleNamespace(
                        work_dir=str(work), receipt=str(work / "receipt.json")
                    )
                )

            work = fixture(pathlib.Path(root) / "second")
            write_json(
                work / "metadata-secrets.json",
                [{"RuleID": "generic-api-key", "Secret": "REDACTED"}],
            )
            with self.assertRaisesRegex(VERIFY.VerificationError, "not empty"):
                VERIFY.finalize(
                    types.SimpleNamespace(
                        work_dir=str(work), receipt=str(work / "receipt.json")
                    )
                )


if __name__ == "__main__":
    unittest.main()
