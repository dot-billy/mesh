#!/usr/bin/env python3

from __future__ import annotations

import copy
import datetime as dt
import pathlib
import plistlib
import subprocess
import tempfile
import unittest
from unittest import mock

import apple_distribution_verify as verifier


NOW = dt.datetime(2026, 7, 24, tzinfo=dt.timezone.utc)


def profile(kind: str) -> dict[str, object]:
    spec = verifier.PROFILE_SPECS[kind]
    entitlements: dict[str, object] = {
        "application-identifier": spec["application_identifier"],
        "beta-reports-active": True,
        "com.apple.developer.team-identifier": verifier.TEAM,
        "get-task-allow": False,
        "keychain-access-groups": [f"{verifier.TEAM}.*", "com.apple.token"],
    }
    if spec["groups"]:
        entitlements["com.apple.security.application-groups"] = spec["groups"]
    if spec["network_extension"]:
        entitlements[
            "com.apple.developer.networking.networkextension"
        ] = ["packet-tunnel-provider", "dns-proxy"]
    return {
        "Name": spec["name"],
        "UUID": spec["uuid"],
        "TeamIdentifier": [verifier.TEAM],
        "TeamName": "Bounded Test Team",
        "ExpirationDate": NOW + dt.timedelta(days=300),
        "Entitlements": entitlements,
    }


class DistributionVerifierTests(unittest.TestCase):
    def test_static_tunnel_engine_is_required_and_bound(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            app = pathlib.Path(raw) / "Mesh Tunnel.app"
            extension = app / "PlugIns" / "MeshPacketTunnel.appex"
            extension.mkdir(parents=True)
            (app / "Mesh Tunnel").write_bytes(b"static host sessions")
            (extension / "Info.plist").write_bytes(
                plistlib.dumps(
                    {"CFBundleExecutable": "MeshPacketTunnel"}
                )
            )
            executable = extension / "MeshPacketTunnel"
            executable.write_bytes(b"static engine")

            def inspected(
                *arguments: str,
                **_kwargs: object,
            ) -> subprocess.CompletedProcess[bytes]:
                if arguments[0] == "nm":
                    symbols = (
                        verifier.TUNNEL_ENGINE_SYMBOLS
                        if pathlib.Path(arguments[-1]).name
                        == "MeshPacketTunnel"
                        else verifier.TUNNEL_HOST_SESSION_SYMBOLS
                    )
                    output = "\n".join(sorted(symbols)).encode()
                elif arguments[0] == "otool":
                    output = (
                        b"/System/Library/Frameworks/Foundation.framework\n"
                    )
                elif arguments[0] == "strings":
                    markers = (
                        verifier.TUNNEL_HOST_SESSION_SYMBOLS
                        if pathlib.Path(arguments[-1]).name == "Mesh Tunnel"
                        else verifier.TUNNEL_ENGINE_MARKERS
                    )
                    output = "\n".join(sorted(markers)).encode()
                else:
                    raise AssertionError(arguments)
                return subprocess.CompletedProcess(
                    arguments,
                    0,
                    stdout=output,
                    stderr=b"",
                )

            with mock.patch.object(
                verifier,
                "run",
                side_effect=inspected,
            ):
                result = verifier.verify_static_tunnel_engine(
                    extension,
                    app,
                )
            self.assertEqual(result["linkage"], "static")
            self.assertFalse(result["dynamic_framework_embedded"])
            self.assertFalse(
                result["physical_device_packet_path_validated"]
            )

            (extension / "Unexpected.framework").mkdir()
            with self.assertRaisesRegex(
                verifier.VerificationError,
                "static Packet Tunnel engine layout",
            ):
                verifier.verify_static_tunnel_engine(extension, app)

    def test_products_can_be_verified_independently(self) -> None:
        self.assertEqual(
            verifier.selected_products("all"),
            ("ios-admin", "ios-tunnel"),
        )
        self.assertEqual(
            verifier.selected_products("ios-admin"),
            ("ios-admin",),
        )
        self.assertEqual(
            verifier.selected_products("ios-tunnel"),
            ("ios-tunnel",),
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "selection",
        ):
            verifier.selected_products("unknown")
        self.assertEqual(
            verifier.receipt_limitations("ios-admin"),
            {
                "app_store_or_testflight_uploaded": False,
                "managed_distribution_tested": False,
                "physical_device_tested": False,
                "real_browser_authentication_tested": False,
                "release_authority": False,
            },
        )
        self.assertEqual(
            verifier.receipt_limitations("ios-tunnel"),
            {
                "app_store_or_testflight_uploaded": False,
                "lifecycle_validated": False,
                "network_settings_applied": False,
                "packet_path_verified": False,
                "physical_device_tested": False,
                "release_authority": False,
            },
        )

    def test_exact_profiles_are_accepted(self) -> None:
        for kind, spec in verifier.PROFILE_SPECS.items():
            result = verifier.validate_profile(profile(kind), spec, NOW)
            self.assertEqual(result["uuid"], spec["uuid"])

    def test_missing_app_group_is_rejected(self) -> None:
        value = profile("host")
        del value["Entitlements"]["com.apple.security.application-groups"]
        with self.assertRaisesRegex(verifier.VerificationError, "App Groups"):
            verifier.validate_profile(
                value, verifier.PROFILE_SPECS["host"], NOW
            )

    def test_expired_or_development_profile_is_rejected(self) -> None:
        expired = profile("admin")
        expired["ExpirationDate"] = NOW - dt.timedelta(seconds=1)
        with self.assertRaisesRegex(verifier.VerificationError, "expired"):
            verifier.validate_profile(
                expired, verifier.PROFILE_SPECS["admin"], NOW
            )
        development = profile("admin")
        development["ProvisionedDevices"] = ["device"]
        with self.assertRaisesRegex(
            verifier.VerificationError, "ProvisionedDevices"
        ):
            verifier.validate_profile(
                development, verifier.PROFILE_SPECS["admin"], NOW
            )

    def test_packet_tunnel_capability_is_required(self) -> None:
        value = profile("extension")
        value["Entitlements"][
            "com.apple.developer.networking.networkextension"
        ] = ["dns-proxy"]
        with self.assertRaisesRegex(verifier.VerificationError, "Packet Tunnel"):
            verifier.validate_profile(
                value, verifier.PROFILE_SPECS["extension"], NOW
            )

    def test_signed_entitlements_are_an_exact_allowlist(self) -> None:
        expected = {
            "application-identifier": (
                f"{verifier.TEAM}.io.rw0.mesh.admin.mobile"
            ),
            "beta-reports-active": True,
            "com.apple.developer.team-identifier": verifier.TEAM,
            "get-task-allow": False,
            "keychain-access-groups": [
                f"{verifier.TEAM}.io.rw0.mesh.admin.mobile"
            ],
        }
        verifier.validate_signed_entitlements(
            expected,
            "io.rw0.mesh.admin.mobile",
            [f"{verifier.TEAM}.io.rw0.mesh.admin.mobile"],
            [],
            [],
        )
        broadened = copy.deepcopy(expected)
        broadened["aps-environment"] = "production"
        with self.assertRaisesRegex(
            verifier.VerificationError, "exact allowlist"
        ):
            verifier.validate_signed_entitlements(
                broadened,
                "io.rw0.mesh.admin.mobile",
                [f"{verifier.TEAM}.io.rw0.mesh.admin.mobile"],
                [],
                [],
            )

    def test_tunnel_targets_share_the_exact_identity_keychain_groups(
        self,
    ) -> None:
        groups = list(verifier.TUNNEL_SHARED_KEYCHAIN_GROUPS)
        self.assertEqual(
            groups,
            [
                f"{verifier.TEAM}.io.rw0.mesh.tunnel.mobile.handoff",
                f"{verifier.TEAM}.io.rw0.mesh.tunnel.mobile.identity",
            ],
        )
        for identifier in (
            "io.rw0.mesh.tunnel.mobile",
            "io.rw0.mesh.tunnel.mobile.packet-tunnel",
        ):
            entitlements = {
                "application-identifier": f"{verifier.TEAM}.{identifier}",
                "beta-reports-active": True,
                "com.apple.developer.team-identifier": verifier.TEAM,
                "com.apple.developer.networking.networkextension": [
                    "packet-tunnel-provider"
                ],
                "com.apple.security.application-groups": [verifier.GROUP],
                "get-task-allow": False,
                "keychain-access-groups": groups,
            }
            verifier.validate_signed_entitlements(
                entitlements,
                identifier,
                groups,
                [verifier.GROUP],
                ["packet-tunnel-provider"],
            )
            missing_identity = copy.deepcopy(entitlements)
            missing_identity["keychain-access-groups"] = groups[:1]
            with self.assertRaisesRegex(
                verifier.VerificationError,
                "exact allowlist",
            ):
                verifier.validate_signed_entitlements(
                    missing_identity,
                    identifier,
                    groups,
                    [verifier.GROUP],
                    ["packet-tunnel-provider"],
                )


if __name__ == "__main__":
    unittest.main()
