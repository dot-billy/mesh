#!/usr/bin/env python3
"""Tests for the canonical Apple source-matrix receipt."""

from __future__ import annotations

import importlib.util
import json
import pathlib
import tempfile
import unittest


MODULE_PATH = pathlib.Path(__file__).with_name("apple_source_matrix_receipt.py")
SPEC = importlib.util.spec_from_file_location("apple_source_matrix_receipt", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MATRIX = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MATRIX)


COMMIT = "2" * 40
COMPLETED = "2026-07-24T22:30:00Z"


def canonical(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode()


def preflight() -> dict[str, object]:
    return {
        "schema": "mesh-apple-source-build-receipt-v1",
        "source": {"commit": COMMIT, "clean": True},
        "host": {
            "architecture": "arm64",
            "xcode_version": "26.5",
            "xcode_build": "17F42",
        },
        "preflight": {
            "release_credentials_present": False,
            "source_keychain_code_signing_identities": 0,
        },
        "completed_at": COMPLETED,
    }


def artifact(
    schema: str,
    preflight_sha256: str,
    configuration: str | None,
    platform_name: str | None,
) -> dict[str, object]:
    value: dict[str, object] = {
        "schema": schema,
        "source": {"commit": COMMIT, "clean": True},
        "input_receipt_sha256": preflight_sha256,
        "completed_at": COMPLETED,
    }
    if configuration is not None:
        value["configuration"] = configuration
    if platform_name is not None:
        value["platform"] = platform_name
    return value


class SourceMatrixReceiptTests(unittest.TestCase):
    def fixture(
        self, root: pathlib.Path
    ) -> tuple[pathlib.Path, dict[str, pathlib.Path]]:
        preflight_path = root / "preflight.json"
        preflight_raw = canonical(preflight())
        preflight_path.write_bytes(preflight_raw)
        preflight_sha256 = MATRIX.digest(preflight_raw)
        artifacts: dict[str, pathlib.Path] = {}
        for name, argument_name, schema, configuration, platform_name in MATRIX.ARTIFACT_SPECS:
            path = root / f"{name}.json"
            path.write_bytes(
                canonical(
                    artifact(
                        schema,
                        preflight_sha256,
                        configuration,
                        platform_name,
                    )
                )
            )
            artifacts[argument_name] = path
        return preflight_path, artifacts

    def test_binds_all_five_receipts_to_one_clean_preflight(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mesh-apple-matrix-") as root:
            directory = pathlib.Path(root)
            preflight_path, artifacts = self.fixture(directory)
            value = MATRIX.build_matrix(preflight_path, artifacts)
            self.assertEqual(value["schema"], "mesh-apple-source-matrix-receipt-v1")
            self.assertEqual(value["source"], {"commit": COMMIT, "clean": True})
            self.assertEqual(len(value["artifacts"]), 5)
            output = directory / "matrix.json"
            MATRIX.write_create_only(output, value)
            self.assertEqual(output.read_bytes(), canonical(value))

    def test_rejects_mixed_commit_and_preflight_digest(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mesh-apple-matrix-") as root:
            directory = pathlib.Path(root)
            preflight_path, artifacts = self.fixture(directory)
            target = artifacts["macos_release"]
            value = json.loads(target.read_text())
            value["source"]["commit"] = "3" * 40
            target.write_bytes(canonical(value))
            with self.assertRaisesRegex(MATRIX.MatrixError, "macos-release"):
                MATRIX.build_matrix(preflight_path, artifacts)

            preflight_path, artifacts = self.fixture(directory)
            target = artifacts["ios_admin_simulator"]
            value = json.loads(target.read_text())
            value["input_receipt_sha256"] = "4" * 64
            target.write_bytes(canonical(value))
            with self.assertRaisesRegex(MATRIX.MatrixError, "ios-admin-simulator"):
                MATRIX.build_matrix(preflight_path, artifacts)

    def test_rejects_wrong_configuration_platform_and_dirty_source(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mesh-apple-matrix-") as root:
            directory = pathlib.Path(root)
            preflight_path, artifacts = self.fixture(directory)
            target = artifacts["ios_tunnel_simulator"]
            value = json.loads(target.read_text())
            value["platform"] = "ios-simulator"
            target.write_bytes(canonical(value))
            with self.assertRaisesRegex(MATRIX.MatrixError, "ios-tunnel-simulator"):
                MATRIX.build_matrix(preflight_path, artifacts)

            preflight_path, artifacts = self.fixture(directory)
            value = json.loads(preflight_path.read_text())
            value["source"]["clean"] = False
            preflight_path.write_bytes(canonical(value))
            with self.assertRaisesRegex(MATRIX.MatrixError, "reviewed clean build"):
                MATRIX.build_matrix(preflight_path, artifacts)

    def test_rejects_symlink_and_existing_output(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mesh-apple-matrix-") as root:
            directory = pathlib.Path(root)
            preflight_path, artifacts = self.fixture(directory)
            linked = directory / "linked.json"
            linked.symlink_to(preflight_path)
            with self.assertRaisesRegex(MATRIX.MatrixError, "physical file"):
                MATRIX.build_matrix(linked, artifacts)
            value = MATRIX.build_matrix(preflight_path, artifacts)
            output = directory / "matrix.json"
            MATRIX.write_create_only(output, value)
            with self.assertRaisesRegex(MATRIX.MatrixError, "new absolute path"):
                MATRIX.write_create_only(output, value)


if __name__ == "__main__":
    unittest.main()
