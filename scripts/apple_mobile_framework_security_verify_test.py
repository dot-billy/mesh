#!/usr/bin/env python3
"""Tests for the Apple mobile framework security evidence verifier."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import pathlib
import tempfile
import unittest
from unittest import mock

import apple_mobile_framework_security_verify as verifier
from apple_mobile_framework_receipt import tree_identity
from image_security_verify import VerificationError, canonical_json


class AppleMobileFrameworkSecurityVerifyTest(unittest.TestCase):
    def source_receipt(self, framework: pathlib.Path) -> dict[str, object]:
        identity = tree_identity(framework)
        return {
            "schema": "mesh-apple-ios-mobile-framework-source-receipt-v1",
            "source": {"clean": False, "commit": "3" * 40},
            "framework": {
                "name": "MeshMobile.xcframework",
                "tree_sha256": identity[0],
                "regular_files": identity[1],
                "regular_file_bytes": identity[2],
                "reproducible": True,
                "signed": False,
            },
            "scope": {
                "embedded_in_tunnel": False,
                "packet_transport_implemented": True,
                "static_tunnel_link_validated": False,
                "physical_device_validated": False,
                "production_signing_used": False,
            },
        }

    def runtime_manifest(
        self, runtime: pathlib.Path
    ) -> tuple[dict[str, object], dict[pathlib.Path, dict[str, object]]]:
        modules = []
        mocked_hashes: dict[pathlib.Path, dict[str, object]] = {}
        for index, (name, version) in enumerate(
            sorted(verifier.EXPECTED_MODULES.items())
        ):
            filename = "LICENSE"
            relative = f"licenses/{index:02d}/{filename}"
            path = runtime / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("fixture\n", encoding="utf-8")
            digest = "a" * 64
            size = len(b"fixture\n")
            mocked_hashes[path] = {"sha256": digest, "size": size}
            licenses = [
                {
                    "name": filename,
                    "path": relative,
                    "sha256": digest,
                    "size": size,
                }
            ]
            modules.append(
                {
                    "name": name,
                    "version": version,
                    "sum": "h1:module",
                    "go_mod_sum": "h1:gomod",
                    "licenses": licenses,
                }
            )
        return (
            {
                "schema": "mesh-apple-mobile-runtime-modules-v1",
                "goos": "ios",
                "goarch": "arm64",
                "modules": modules,
            },
            mocked_hashes,
        )

    def make_workspace(
        self, root: pathlib.Path
    ) -> tuple[pathlib.Path, dict[pathlib.Path, dict[str, object]]]:
        framework = (
            root / "scan-root" / "MeshMobile.xcframework"
        )
        framework.mkdir(parents=True)
        (framework / "fixture").write_bytes(b"framework")
        source = self.source_receipt(framework)
        (root / "source-receipt.json").write_bytes(canonical_json(source))

        runtime = root / "scan-root" / "metadata" / "runtime"
        runtime.mkdir(parents=True)
        manifest, mocked_hashes = self.runtime_manifest(runtime)
        (runtime / "runtime-modules.json").write_bytes(canonical_json(manifest))

        purls = []
        artifacts = []
        for name, version in sorted(verifier.EXPECTED_MODULES.items()):
            purl = f"pkg:golang/{name}@{version}"
            purls.append(purl)
            artifacts.append(
                {
                    "name": name,
                    "version": version,
                    "type": "go-module",
                    "purl": purl,
                }
            )
        (root / "sbom.syft.json").write_bytes(
            canonical_json(
                {
                    "descriptor": {"name": "syft", "version": "1.44.0"},
                    "schema": {"version": "16.1.3"},
                    "source": {"type": "directory"},
                    "artifacts": artifacts,
                }
            )
        )
        (root / "sbom.spdx.json").write_bytes(
            canonical_json(
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
                        for purl in purls
                    ],
                }
            )
        )
        (root / "vulnerabilities.json").write_bytes(
            canonical_json(
                {
                    "descriptor": {"name": "grype", "version": "0.112.0"},
                    "ignoredMatches": [],
                    "matches": [],
                }
            )
        )
        built = (
            dt.datetime.now(dt.timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z")
        )
        (root / "grype-db-status.json").write_bytes(
            canonical_json({"status": "valid", "schema": "v6.1.9", "built": built})
        )
        for name in ("metadata-secrets.json", "framework-strings-secrets.json"):
            (root / name).write_bytes(canonical_json([]))
        return framework, mocked_hashes

    def test_finalize_emits_bound_unsupported_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            _, mocked_hashes = self.make_workspace(root)
            real_hash = verifier.hash_file

            def controlled_hash(path: pathlib.Path) -> dict[str, object]:
                return mocked_hashes.get(path, real_hash(path))

            with mock.patch.object(
                verifier, "hash_file", side_effect=controlled_hash
            ):
                verifier.finalize(
                    argparse.Namespace(
                        work_dir=str(root), receipt=str(root / "receipt.json")
                    )
                )
            receipt = json.loads((root / "receipt.json").read_text())
            self.assertEqual(
                receipt["schema"],
                "mesh-apple-ios-mobile-framework-security-receipt-v1",
            )
            self.assertEqual(receipt["dependencies"]["runtime_module_count"], 29)
            self.assertEqual(receipt["licenses"]["file_count"], 29)
            self.assertFalse(receipt["artifact"]["embedded_in_tunnel"])
            self.assertFalse(receipt["artifact"]["physical_device_validated"])
            self.assertEqual(receipt["vulnerability_scan"]["match_count"], 0)

    def test_source_receipt_rejects_supported_claim(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            framework = root / "MeshMobile.xcframework"
            framework.mkdir()
            (framework / "fixture").write_bytes(b"framework")
            receipt = self.source_receipt(framework)
            receipt["scope"]["embedded_in_tunnel"] = True
            path = root / "source.json"
            path.write_bytes(canonical_json(receipt))
            with self.assertRaisesRegex(
                VerificationError, "source receipt boundary"
            ):
                verifier.canonical_source_receipt(path)

    def test_runtime_manifest_rejects_missing_module(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runtime = pathlib.Path(temporary)
            manifest, mocked_hashes = self.runtime_manifest(runtime)
            manifest["modules"].pop()
            with mock.patch.object(
                verifier,
                "hash_file",
                side_effect=lambda path: mocked_hashes[path],
            ):
                with self.assertRaisesRegex(
                    VerificationError, "inventory count"
                ):
                    verifier.validate_runtime_manifest(manifest, runtime)

    def test_syft_rejects_incomplete_runtime_inventory(self) -> None:
        modules = dict(verifier.EXPECTED_MODULES)
        name, version = modules.popitem()
        document = {
            "descriptor": {"name": "syft", "version": "1.44.0"},
            "schema": {"version": "16.1.3"},
            "source": {"type": "directory"},
            "artifacts": [
                {
                    "name": module,
                    "version": module_version,
                    "type": "go-module",
                    "purl": f"pkg:golang/{module}@{module_version}",
                }
                for module, module_version in modules.items()
            ],
        }
        with self.assertRaisesRegex(VerificationError, "inventory is incomplete"):
            verifier.validate_syft(
                document, {**modules, name: version}
            )


if __name__ == "__main__":
    unittest.main()
