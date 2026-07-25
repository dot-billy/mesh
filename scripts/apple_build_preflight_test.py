#!/usr/bin/env python3
"""Focused tests for the Apple build-input and receipt boundary."""

from __future__ import annotations

import importlib.util
import json
import pathlib
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "apple_build_preflight", ROOT / "scripts" / "apple-build-preflight.py"
)
assert SPEC and SPEC.loader
PREFLIGHT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PREFLIGHT)


class AppleBuildPreflightTest(unittest.TestCase):
    def setUp(self) -> None:
        self.inputs, _ = PREFLIGHT.load_json(
            ROOT / "desktop" / "tool" / "apple-build.json"
        )
        self.flutter, _ = PREFLIGHT.load_json(
            ROOT / "desktop" / "tool" / "flutter-sdk.json"
        )

    def test_repository_inputs_are_strict_and_cross_architecture(self) -> None:
        PREFLIGHT.require_configuration(self.inputs, self.flutter)
        arm_key, arm = PREFLIGHT.select_archive(self.inputs, self.flutter, "arm64")
        intel_key, intel = PREFLIGHT.select_archive(
            self.inputs, self.flutter, "x86_64"
        )
        self.assertEqual(arm_key, "macos_arm64")
        self.assertEqual(intel_key, "macos_x64")
        self.assertNotEqual(arm["sha256"], intel["sha256"])
        self.assertEqual(
            self.inputs["nebula"],
            {
                "module": "github.com/slackhq/nebula",
                "version": "1.10.3",
                "certificate_tool": "nebula-cert",
            },
        )

    def test_unknown_architecture_is_rejected(self) -> None:
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "unsupported"):
            PREFLIGHT.select_archive(self.inputs, self.flutter, "powerpc")

    def test_json_input_is_bounded_and_object_only(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mesh-apple-preflight-") as root:
            path = pathlib.Path(root) / "input.json"
            path.write_text("[]")
            with self.assertRaisesRegex(PREFLIGHT.PreflightError, "object"):
                PREFLIGHT.load_json(path)
            path.write_bytes(b"x" * (PREFLIGHT.MAXIMUM_INPUT_BYTES + 1))
            with self.assertRaisesRegex(PREFLIGHT.PreflightError, "size bound"):
                PREFLIGHT.load_json(path)

    def test_canonical_receipt_encoding_is_stable(self) -> None:
        value = {"z": 1, "a": ["safe"]}
        self.assertEqual(
            PREFLIGHT.canonical_json(value),
            b'{"a":["safe"],"z":1}\n',
        )
        self.assertEqual(json.loads(PREFLIGHT.canonical_json(value)), value)

    def test_source_keychain_must_be_private_physical_and_empty(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mesh-apple-keychain-") as root:
            keychain = pathlib.Path(root) / "source.keychain-db"
            keychain.touch(mode=0o600)
            calls: list[tuple[str, ...]] = []

            def empty_identity_lookup(*arguments: str) -> str:
                calls.append(arguments)
                return "     0 valid identities found"

            PREFLIGHT.validate_source_keychain(keychain, empty_identity_lookup)
            self.assertEqual(calls[0][-1], str(keychain))

            keychain.chmod(0o644)
            with self.assertRaisesRegex(PREFLIGHT.PreflightError, "private"):
                PREFLIGHT.validate_source_keychain(keychain, empty_identity_lookup)

            keychain.chmod(0o600)
            link = pathlib.Path(root) / "linked.keychain-db"
            link.symlink_to(keychain)
            with self.assertRaisesRegex(PREFLIGHT.PreflightError, "physical"):
                PREFLIGHT.validate_source_keychain(link, empty_identity_lookup)

            with self.assertRaisesRegex(PREFLIGHT.PreflightError, "contains"):
                PREFLIGHT.validate_source_keychain(
                    keychain, lambda *_: "1 valid identities found"
                )


if __name__ == "__main__":
    unittest.main()
