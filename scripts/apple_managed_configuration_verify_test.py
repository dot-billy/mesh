#!/usr/bin/env python3

from __future__ import annotations

import copy
import plistlib
import tempfile
import unittest
from pathlib import Path

import apple_managed_configuration_verify as verifier


class ManagedConfigurationVerifierTests(unittest.TestCase):
    def test_repository_examples_are_canonical(self) -> None:
        verifier.verify()

    def test_secret_like_unknown_key_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary)
            for name in (
                "ios-admin-managed-configuration.plist",
                "macos-admin.mobileconfig",
            ):
                value = plistlib.loads(
                    (verifier.SOURCE_DIR / name).read_bytes()
                )
                if name.startswith("ios"):
                    value["EnrollmentToken"] = "must-never-cross"
                (destination / name).write_bytes(
                    plistlib.dumps(value, sort_keys=False)
                )
            with self.assertRaisesRegex(ValueError, "exact reviewed set"):
                verifier.verify(destination)

    def test_non_https_origin_is_rejected_in_each_surface(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary)
            ios = plistlib.loads(
                (
                    verifier.SOURCE_DIR
                    / "ios-admin-managed-configuration.plist"
                ).read_bytes()
            )
            ios["ControlPlaneOrigin"] = "http://mesh.example.com"
            profile = plistlib.loads(
                (
                    verifier.SOURCE_DIR / "macos-admin.mobileconfig"
                ).read_bytes()
            )
            (destination / "ios-admin-managed-configuration.plist").write_bytes(
                plistlib.dumps(ios, sort_keys=False)
            )
            (destination / "macos-admin.mobileconfig").write_bytes(
                plistlib.dumps(copy.deepcopy(profile), sort_keys=False)
            )
            with self.assertRaisesRegex(ValueError, "HTTPS origin"):
                verifier.verify(destination)


if __name__ == "__main__":
    unittest.main()
