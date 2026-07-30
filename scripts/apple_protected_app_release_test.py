#!/usr/bin/env python3
"""Portable tests for protected Mesh Admin release evidence boundaries."""

from __future__ import annotations

import datetime as dt
import hashlib
import importlib.util
import json
import os
import pathlib
import plistlib
import stat
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "apple_protected_app_release",
    ROOT / "scripts" / "apple-protected-app-release.py",
)
assert SPEC and SPEC.loader
RELEASE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RELEASE)

class AppleProtectedAppReleaseTest(unittest.TestCase):
    def test_developer_id_provisioning_profile_is_exact(self) -> None:
        certificate = b"test-only-developer-id-certificate"
        identity_sha1 = hashlib.sha1(certificate).hexdigest().upper()
        expiration = dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=30)
        document = {
            "ApplicationIdentifierPrefix": ["AB12CD34EF"],
            "DeveloperCertificates": [certificate],
            "Entitlements": {
                "com.apple.application-identifier": (
                    "AB12CD34EF.io.rw0.mesh.admin"
                ),
                "com.apple.developer.team-identifier": "AB12CD34EF",
                "keychain-access-groups": ["AB12CD34EF.*"],
            },
            "ExpirationDate": expiration,
            "Platform": ["OSX"],
            "ProvisionsAllDevices": True,
            "TeamIdentifier": ["AB12CD34EF"],
            "UUID": "1851d214-90a0-46e9-9490-617e3e6f5b20",
        }

        validated = RELEASE.validate_provisioning_document(
            document,
            "AB12CD34EF",
            identity_sha1,
        )

        self.assertEqual(
            validated["uuid"],
            "1851d214-90a0-46e9-9490-617e3e6f5b20",
        )
        document["Entitlements"] = {}
        with self.assertRaisesRegex(RELEASE.ReleaseError, "contract"):
            RELEASE.validate_provisioning_document(
                document,
                "AB12CD34EF",
                identity_sha1,
            )

    def test_admin_team_and_identity_are_exact(self) -> None:
        self.assertEqual(
            RELEASE.validate_team_id(RELEASE.APP_TEAM_ID),
            "Y3P5UNNG23",
        )
        for candidate in ("", "AB12CD34EF", "Y3P5UNNG2"):
            with self.assertRaisesRegex(RELEASE.ReleaseError, "approved"):
                RELEASE.validate_team_id(candidate)

        output = (
            '  1) 0123456789ABCDEF0123456789ABCDEF01234567 '
            '"Developer ID Application: Mesh Corp (AB12CD34EF)"\n'
            "     1 valid identities found\n"
        )
        self.assertEqual(
            RELEASE.parse_identity_output(output, "AB12CD34EF"),
            "0123456789ABCDEF0123456789ABCDEF01234567",
        )
        with self.assertRaisesRegex(RELEASE.ReleaseError, "exactly one"):
            RELEASE.parse_identity_output(output + output, "AB12CD34EF")

    def test_notary_result_requires_accepted_canonical_uuid(self) -> None:
        accepted = json.dumps(
            {
                "id": "12345678-1234-1234-1234-123456789abc",
                "status": "Accepted",
            }
        ).encode()
        self.assertEqual(
            RELEASE.parse_notary_result(accepted),
            "12345678-1234-1234-1234-123456789abc",
        )
        with self.assertRaisesRegex(RELEASE.ReleaseError, "not accepted"):
            RELEASE.parse_notary_result(
                accepted.replace(b"Accepted", b"Invalid")
            )

    def test_tree_and_bundle_executable_are_bounded(self) -> None:
        self.assertEqual(
            RELEASE.canonical_tree_mode(stat.S_IFLNK | 0o700),
            0o777,
        )
        self.assertEqual(
            RELEASE.canonical_tree_mode(stat.S_IFDIR | 0o750),
            0o750,
        )
        with tempfile.TemporaryDirectory(prefix="mesh-protected-app-") as temporary:
            app = pathlib.Path(temporary) / "Nested.framework"
            executable = app / "Versions" / "A" / "Nested"
            resources = app / "Versions" / "A" / "Resources"
            resources.mkdir(parents=True)
            executable.write_bytes(b"\xcf\xfa\xed\xfe" + b"\0" * 32)
            (resources / "Info.plist").write_bytes(
                plistlib.dumps({"CFBundleExecutable": "Nested"})
            )
            current = app / "Versions" / "Current"
            current.symlink_to("A")
            (app / "Nested").symlink_to("Versions/Current/Nested")
            (app / "Resources").symlink_to("Versions/Current/Resources")
            self.assertEqual(
                RELEASE.code_executable(app).resolve(), executable.resolve()
            )
            identity = RELEASE.tree_identity(app)
            self.assertEqual(identity[1], 2)
            self.assertGreater(identity[2], 32)
            if hasattr(os, "lchmod"):
                os.lchmod(current, 0o700)
                restricted = RELEASE.tree_identity(app)
                os.lchmod(current, 0o777)
                permissive = RELEASE.tree_identity(app)
                self.assertEqual(restricted, permissive)

    def test_nested_code_inventory_is_exact(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mesh-protected-inventory-") as temporary:
            app = pathlib.Path(temporary) / "Mesh Admin.app"
            for relative in RELEASE.EXPECTED_NESTED_CODE:
                (app / relative).mkdir(parents=True)
            bundles, standalone = RELEASE.nested_code(app)
            self.assertEqual(
                {path.relative_to(app).as_posix() for path in bundles},
                set(RELEASE.EXPECTED_NESTED_CODE),
            )
            self.assertEqual(standalone, [])

            (app / "Contents" / "Frameworks" / "Unexpected.framework").mkdir()
            with self.assertRaisesRegex(RELEASE.ReleaseError, "inventory"):
                RELEASE.nested_code(app)

    def test_security_receipt_is_current_and_bound_to_source(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mesh-protected-security-") as temporary:
            path = pathlib.Path(temporary) / "security.json"
            source_sha = "a" * 64
            tree_sha = "b" * 64
            record = {"sha256": "c" * 64, "size": 128}
            receipt = {
                "schema": "mesh-apple-admin-security-receipt-v1",
                "gate": {
                    name: {
                        "sha256": RELEASE.digest_file(gate_path),
                        "size": gate_path.stat().st_size,
                    }
                    for name, gate_path in {
                        "baseline": (
                            ROOT / "scripts" / "apple-admin-security-baseline.sh"
                        ),
                        "gitleaks_policy": ROOT / ".gitleaks-image.toml",
                        "verifier": (
                            ROOT
                            / "scripts"
                            / "apple_admin_security_verify.py"
                        ),
                    }.items()
                },
                "artifact": {
                    "tree_sha256": tree_sha,
                    "source_receipt": {"sha256": source_sha, "size": 1024},
                },
                "dependencies": {"runtime_hosted_package_count": 1},
                "licenses": {
                    "status": "inventory-present-legal-review-pending"
                },
                "privacy": {
                    "status": (
                        "source-reviewed-final-distribution-reconciliation-pending"
                    )
                },
                "sbom": {
                    "syft_version": "1.44.0",
                    "spdx_version": "SPDX-2.3",
                    "syft_json": record,
                    "spdx_json": record,
                },
                "secret_scan": {
                    "gitleaks_version": "v8.30.1",
                    "metadata_report": record,
                    "app_strings_report": record,
                },
                "vulnerability_scan": {
                    "grype_version": "0.112.0",
                    "database_status": record,
                    "report": record,
                },
                "verified_at": (
                    dt.datetime.now(dt.timezone.utc)
                    .replace(microsecond=0)
                    .isoformat()
                    .replace("+00:00", "Z")
                ),
            }
            path.write_bytes(
                (
                    json.dumps(receipt, sort_keys=True, separators=(",", ":"))
                    + "\n"
                ).encode()
            )
            parsed, identity = RELEASE.validate_security_receipt(
                path, source_sha, tree_sha
            )
            self.assertEqual(parsed, receipt)
            self.assertEqual(identity["sha256"], RELEASE.digest_file(path))

            with self.assertRaisesRegex(RELEASE.ReleaseError, "complete reviewed"):
                RELEASE.validate_security_receipt(path, "d" * 64, tree_sha)


if __name__ == "__main__":
    unittest.main()
