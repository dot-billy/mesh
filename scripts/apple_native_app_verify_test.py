#!/usr/bin/env python3
"""Portable tests for the downloaded Mesh Admin native verifier."""

from __future__ import annotations

import importlib.util
import pathlib
import stat
import tempfile
import unittest
import zipfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "apple_native_app_verify",
    ROOT / "scripts" / "apple-native-app-verify.py",
)
assert SPEC and SPEC.loader
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)


class AppleNativeAppVerifyTest(unittest.TestCase):
    def test_network_inventory_rejects_nonloopback_unicast(self) -> None:
        isolated = b"""lo0: flags=8049<UP,LOOPBACK>\n\tinet 127.0.0.1\n\tinet6 ::1\n"""
        self.assertFalse(VERIFY.network_has_nonloopback_unicast(isolated))
        self.assertTrue(
            VERIFY.network_has_nonloopback_unicast(
                isolated + b"en0: flags=8863<UP>\n\tinet 192.0.2.4 netmask 0xffffff00\n"
            )
        )
        self.assertTrue(
            VERIFY.network_has_nonloopback_unicast(
                isolated + b"utun4: flags=8051<UP>\n\tinet6 2001:db8::2 prefixlen 64\n"
            )
        )
        self.assertFalse(
            VERIFY.network_has_nonloopback_unicast(
                isolated + b"en0: flags=8863<UP>\n\tinet6 fe80::1%en0 prefixlen 64\n"
            )
        )

    def test_requirements_bind_exact_identifiers_and_team(self) -> None:
        outer = VERIFY.application_requirement("AB12CD34EF")
        nested = VERIFY.nested_requirement("io.flutter.flutter.app", "AB12CD34EF")
        self.assertIn('identifier "io.rw0.mesh.admin"', outer)
        self.assertIn('identifier "io.flutter.flutter.app"', nested)
        self.assertIn('subject.OU] = "AB12CD34EF"', outer)
        self.assertIn('subject.OU] = "AB12CD34EF"', nested)

    def test_archive_inventory_rejects_escape_and_accepts_bounded_app(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mesh-native-zip-") as temporary:
            valid = pathlib.Path(temporary) / "valid.zip"
            with zipfile.ZipFile(valid, "w") as archive:
                directory = zipfile.ZipInfo("Mesh Admin.app/")
                directory.external_attr = (stat.S_IFDIR | 0o700) << 16
                archive.writestr(directory, b"")
                executable = zipfile.ZipInfo(
                    "Mesh Admin.app/Contents/MacOS/Mesh Admin"
                )
                executable.external_attr = (stat.S_IFREG | 0o700) << 16
                archive.writestr(executable, b"mesh")
            VERIFY.inspect_archive(valid)

            escaping = pathlib.Path(temporary) / "escaping.zip"
            with zipfile.ZipFile(escaping, "w") as archive:
                entry = zipfile.ZipInfo("../escape")
                entry.external_attr = (stat.S_IFREG | 0o600) << 16
                archive.writestr(entry, b"escape")
            with self.assertRaisesRegex(VERIFY.VerificationError, "roots"):
                VERIFY.inspect_archive(escaping)


if __name__ == "__main__":
    unittest.main()
