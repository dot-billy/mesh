#!/usr/bin/env python3

from __future__ import annotations

import base64
import datetime as dt
import importlib.util
import json
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "apple-protected-node-package-release.py"
SPEC = importlib.util.spec_from_file_location("apple_protected_node_package_release", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)


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


class ProtectedNodePackageReleaseTests(unittest.TestCase):
    def test_policies_round_trip_and_bind_safe_single_root(self) -> None:
        package, package_sha = release.parse_package_policy(
            frame(release.PACKAGE_POLICY_PREFIX, release.PACKAGE_POLICY_SUFFIX, package_policy())
        )
        codesign, codesign_sha = release.parse_codesign_policy(
            frame(release.CODESIGN_POLICY_PREFIX, release.CODESIGN_POLICY_SUFFIX, codesign_policy())
        )
        self.assertEqual(package["package_root_path"], "/Library/Application Support/Mesh/NodePackage")
        self.assertEqual(codesign["mesh_install_identifier"], "io.mesh.node.mesh-install")
        self.assertRegex(package_sha, r"^[0-9a-f]{64}$")
        self.assertRegex(codesign_sha, r"^[0-9a-f]{64}$")

    def test_package_policy_rejects_system_ancestor_or_nested_root(self) -> None:
        for root in ("/Library", "/Library/Application Support/Mesh/Nested/NodePackage"):
            document = package_policy()
            document["package_root_path"] = root
            with self.assertRaises(release.ReleaseError):
                release.parse_package_policy(
                    frame(release.PACKAGE_POLICY_PREFIX, release.PACKAGE_POLICY_SUFFIX, document)
                )

    def test_codesign_receipt_requires_all_four_exact_files(self) -> None:
        policy = codesign_policy()
        _, policy_sha = release.parse_codesign_policy(
            frame(release.CODESIGN_POLICY_PREFIX, release.CODESIGN_POLICY_SUFFIX, policy)
        )
        bootstrap = {"sha256": "0" * 64, "size": 8192}
        now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        receipt = {
            "architecture": "arm64",
            "files": [
                {
                    "identifier": "io.mesh.node.mesh-install",
                    "path": "mesh-install",
                    "role": "mesh-install",
                    **bootstrap,
                },
                {
                    "identifier": "io.mesh.node.meshctl",
                    "path": "bin/meshctl",
                    "role": "meshctl",
                    "sha256": "1" * 64,
                    "size": 8192,
                },
                {
                    "identifier": "io.mesh.node.nebula",
                    "path": "bin/nebula",
                    "role": "nebula",
                    "sha256": "2" * 64,
                    "size": 8192,
                },
                {
                    "identifier": "io.mesh.node.nebula-cert",
                    "path": "bin/nebula-cert",
                    "role": "nebula-cert",
                    "sha256": "3" * 64,
                    "size": 8192,
                },
            ],
            "policy_sha256": policy_sha,
            "schema": "mesh-darwin-codesign-receipt-v2",
            "team_id": "AB12CD34EF",
            "verified_at": now,
        }
        raw = (json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n").encode()
        release.parse_codesign_receipt(raw, policy, policy_sha, "arm64", bootstrap)
        receipt["files"] = receipt["files"][1:]
        raw = (json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n").encode()
        with self.assertRaises(release.ReleaseError):
            release.parse_codesign_receipt(raw, policy, policy_sha, "arm64", bootstrap)

    def test_notary_result_requires_accepted_canonical_uuid(self) -> None:
        accepted = json.dumps(
            {"id": "12345678-1234-1234-1234-123456789abc", "status": "Accepted"}
        ).encode()
        self.assertEqual(
            release.parse_notary_result(accepted),
            "12345678-1234-1234-1234-123456789abc",
        )
        with self.assertRaises(release.ReleaseError):
            release.parse_notary_result(
                json.dumps(
                    {"id": "12345678-1234-1234-1234-123456789abc", "status": "Invalid"}
                ).encode()
            )


if __name__ == "__main__":
    unittest.main()
