#!/usr/bin/env python3

from __future__ import annotations

import base64
import datetime as dt
import importlib.util
import json
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "apple-node-package-verify.py"
SPEC = importlib.util.spec_from_file_location("apple_node_package_verify", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
verify = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verify)


def frame(prefix: str, suffix: str, document: dict[str, object]) -> str:
    raw = json.dumps(document, separators=(",", ":")).encode()
    return prefix + base64.urlsafe_b64encode(raw).decode().rstrip("=") + suffix


def package_policy() -> dict[str, object]:
    return {
        "schema": "mesh-darwin-node-package-policy-v2",
        "package_identifier": "io.mesh.node",
        "package_install_location": "/Library/Application Support/Mesh",
        "package_root_path": "/Library/Application Support/Mesh/NodePackage",
        "installed_bootstrap_path": "/Library/Application Support/Mesh/NodePackage/mesh-install",
        "package_snapshot_path": "/Library/Application Support/Mesh/NodePackage/snapshot",
        "require_compiled_postinstall": True,
        "require_root_wheel": True,
        "require_notarization": True,
    }


def codesign_policy() -> dict[str, object]:
    return {
        "schema": "mesh-darwin-codesign-policy-v2",
        "team_id": "AB12CD34EF",
        "mesh_install_identifier": "io.mesh.node.mesh-install",
        "meshctl_identifier": "io.mesh.node.meshctl",
        "nebula_identifier": "io.mesh.node.nebula",
        "nebula_cert_identifier": "io.mesh.node.nebula-cert",
        "require_apple_anchor": True,
        "require_developer_id": True,
        "require_strict_verification": True,
    }


def receipt(
    package_sha: str,
    codesign_sha: str,
    package_identity: dict[str, object],
) -> dict[str, object]:
    digest = {"sha256": "1" * 64, "size": 1024}
    return {
        "bootstrap": {
            "code_identifier": "io.mesh.node.mesh-install",
            "sha256": "2" * 64,
            "size": 8192,
        },
        "contents": {
            "bom": digest,
            "directory_count": 2,
            "file_count": 4,
            "package_info": digest,
            "payload_tree_sha256": "3" * 64,
            "postinstall_sha256": "2" * 64,
            "scripts_archive": digest,
            "unexpected_xattrs": 0,
        },
        "notarization": {
            "gatekeeper_assessment": "accepted",
            "staple": "validated",
            "status": "Accepted",
            "submission_id": "12345678-1234-1234-1234-123456789abc",
        },
        "package": {
            "architecture": "arm64",
            "identifier": "io.mesh.node",
            "install_location": "/Library/Application Support/Mesh",
            "package_root": "/Library/Application Support/Mesh/NodePackage",
            **package_identity,
            "version": "1.2.3",
        },
        "schema": "mesh-darwin-node-package-release-receipt-v1",
        "signing": {
            "installer_certificate_sha256": "b" * 64,
            "installer_identity_sha1": "A" * 40,
            "team_id": "AB12CD34EF",
        },
        "snapshot": {
            "artifact": digest,
            "bundle_json": digest,
            "install_json": digest,
        },
        "source": {
            "bundle_security_receipt": {"sha256": "5" * 64, "size": 1024},
            "codesign_policy_sha256": codesign_sha,
            "codesign_receipt": {"sha256": "4" * 64, "size": 1024},
            "package_policy_sha256": package_sha,
        },
        "tools": {"/usr/bin/codesign": digest},
        "verified_at": dt.datetime.now(dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
    }


class NativeNodePackageVerifierTests(unittest.TestCase):
    def test_policies_round_trip_and_bind_direct_root(self) -> None:
        package, package_sha = verify.parse_package_policy(
            frame(verify.PACKAGE_POLICY_PREFIX, verify.PACKAGE_POLICY_SUFFIX, package_policy())
        )
        codesign, codesign_sha = verify.parse_codesign_policy(
            frame(verify.CODESIGN_POLICY_PREFIX, verify.CODESIGN_POLICY_SUFFIX, codesign_policy())
        )
        self.assertEqual(package["package_root_path"], "/Library/Application Support/Mesh/NodePackage")
        self.assertEqual(codesign["team_id"], "AB12CD34EF")
        self.assertRegex(package_sha, r"^[0-9a-f]{64}$")
        self.assertRegex(codesign_sha, r"^[0-9a-f]{64}$")

    def test_receipt_binds_package_and_upstream_authority(self) -> None:
        package_frame = frame(
            verify.PACKAGE_POLICY_PREFIX, verify.PACKAGE_POLICY_SUFFIX, package_policy()
        )
        codesign_frame = frame(
            verify.CODESIGN_POLICY_PREFIX, verify.CODESIGN_POLICY_SUFFIX, codesign_policy()
        )
        package, package_sha = verify.parse_package_policy(package_frame)
        codesign, codesign_sha = verify.parse_codesign_policy(codesign_frame)
        package_identity = {"sha256": "0" * 64, "size": 4096}
        document = receipt(package_sha, codesign_sha, package_identity)
        raw = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()
        verify.parse_receipt(
            raw,
            package,
            codesign,
            package_sha,
            codesign_sha,
            "arm64",
            "1.2.3",
            package_identity,
            "4" * 64,
            "5" * 64,
        )
        with self.assertRaises(verify.VerificationError):
            verify.parse_receipt(
                raw,
                package,
                codesign,
                package_sha,
                codesign_sha,
                "arm64",
                "1.2.3",
                {"sha256": "9" * 64, "size": 4096},
                "4" * 64,
                "5" * 64,
            )

    def test_receipt_rejects_noncanonical_json(self) -> None:
        with self.assertRaises(verify.VerificationError):
            verify.canonical_document(b'{ "schema": "x" }\\n', 1024, "receipt")


if __name__ == "__main__":
    unittest.main()
