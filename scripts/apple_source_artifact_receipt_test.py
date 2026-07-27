#!/usr/bin/env python3
"""Focused tests for unsigned macOS artifact receipt boundaries."""

from __future__ import annotations

import importlib.util
import hashlib
import json
import os
import pathlib
import plistlib
import stat
import subprocess
import tempfile
import types
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
FLUTTER_COMMIT = "058e0af2c2b57e369d905a03ac9748b0ebf543c6"
FLUTTER_ARCHIVE_SHA256 = (
    "c3d6fe95078f7001d947a31d42527de91d5bfe62e4cf444a1493a2e8f1fb199d"
)
SPEC = importlib.util.spec_from_file_location(
    "apple_source_artifact_receipt",
    ROOT / "scripts" / "apple_source_artifact_receipt.py",
)
assert SPEC and SPEC.loader
RECEIPT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RECEIPT)


def valid_input_receipt() -> dict[str, object]:
    return {
        "schema": "mesh-apple-source-build-receipt-v1",
        "source": {"commit": "a" * 40, "clean": True},
        "host": {
            "developer_directory": "/Applications/Xcode.app/Contents/Developer",
            "xcode_version": "26.5",
            "xcode_build": "17F42",
            "flutter_version": "3.44.8",
            "flutter_commit": FLUTTER_COMMIT,
        },
        "inputs": {
            "apple_build_sha256": "b" * 64,
            "flutter_sdk_sha256": "c" * 64,
            "flutter_archive_sha256": FLUTTER_ARCHIVE_SHA256,
            "nebula_certificate_tool_sha256": "e" * 64,
        },
        "preflight": {
            "release_credentials_present": False,
            "source_keychain_code_signing_identities": 0,
        },
    }


def write_receipt(path: pathlib.Path, value: dict[str, object]) -> None:
    path.write_text(
        json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
    )


def write_ios_admin_native_assets(app: pathlib.Path) -> pathlib.Path:
    frameworks = app / "Frameworks"
    app_framework = frameworks / "App.framework" / "flutter_assets"
    flutter_framework = frameworks / "Flutter.framework"
    objective_framework = frameworks / "objective_c.framework"
    app_framework.mkdir(parents=True)
    flutter_framework.mkdir()
    objective_framework.mkdir()
    binary = objective_framework / "objective_c"
    binary.write_bytes(b"universal objective-c native asset")
    (objective_framework / "Info.plist").write_bytes(
        plistlib.dumps(
            {
                "CFBundleExecutable": "objective_c",
                "CFBundleIdentifier": (
                    "io.flutter.flutter.native-assets.objective-c"
                ),
                "CFBundleName": "objective_c",
                "CFBundlePackageType": "FMWK",
            }
        )
    )
    (app_framework / "NativeAssetsManifest.json").write_text(
        json.dumps(
            {
                "format-version": [1, 0, 0],
                "native-assets": {
                    "ios_arm64": {
                        "package:objective_c/objective_c.dylib": [
                            "absolute",
                            "objective_c.framework/objective_c",
                        ]
                    },
                    "ios_x64": {
                        "package:objective_c/objective_c.dylib": [
                            "absolute",
                            "objective_c.framework/objective_c",
                        ]
                    },
                },
            },
            separators=(",", ":"),
        )
    )
    return binary


class AppleSourceArtifactReceiptTest(unittest.TestCase):
    def test_admin_source_boundary_binds_diagnostics_and_copy_custody(self) -> None:
        boundary = RECEIPT.inspect_admin_source_boundary()
        self.assertEqual(
            boundary["diagnostic_schema"],
            "mesh-apple-admin-diagnostic-v2",
        )
        self.assertEqual(boundary["diagnostic_maximum_bytes"], 16 * 1024)
        self.assertEqual(
            boundary["diagnostic_copy"],
            "operator-initiated-platform-retention-disclosed-not-uploaded-not-persisted",
        )
        self.assertEqual(
            boundary["notifications"],
            "fixed-warning-critical-foreground-poll-transitions",
        )
        self.assertEqual(
            boundary["macos_lock_sleep_custody"],
            "fixed-data-free-native-events-source-proven",
        )
        self.assertEqual(
            boundary["macos_hide_close_custody"],
            "fixed-data-free-native-events-source-proven",
        )
        self.assertEqual(
            boundary["macos_menu"],
            "fixed-refresh-preferences-data-free-source-proven",
        )
        self.assertEqual(
            boundary["network_context_custody"],
            "operator-selection-erases-one-time-material",
        )
        self.assertEqual(
            boundary["session_authority"],
            "foreground-poll-exact-permissions-revocation-fail-closed",
        )
        self.assertEqual(
            boundary["browser_authorization"],
            "same-origin-expiring-transient-retry-one-time-completion",
        )
        self.assertEqual(
            boundary["ios_clipboard"],
            "local-only-expiring-fail-closed",
        )
        self.assertEqual(
            boundary["unified_logging"],
            "fixed-reviewed-event-codes-only",
        )
        self.assertEqual(
            boundary["mobile_accessibility"],
            "widget-matrix-source-proven-physical-review-pending",
        )
        self.assertEqual(
            boundary["managed_configuration"],
            "strict-non-secret-source-proven-unsigned-profile",
        )
        self.assertEqual(
            boundary["local_data_erasure"],
            "exact-session-profile-keychain-deletion-confirmed-retention-"
            "disclosed-source-proven",
        )
        self.assertEqual(
            boundary["local_state_upgrade"],
            "frozen-v1-session-profile-compatibility-unknown-schema-"
            "fail-closed-source-proven",
        )
        self.assertTrue(
            {
                "app_shell",
                "theme",
                "fleet",
                "evidence_badge",
                "mobile_accessibility_test",
                "managed_configuration",
                "managed_configuration_test",
                "ios_managed_configuration",
                "macos_managed_configuration",
                "ios_managed_application_configuration",
                "macos_managed_profile",
                "managed_configuration_verifier",
                "pubspec_lock",
                "flutter_sdk_declaration",
                "source_artifact_receipt",
                "notifications",
                "notifications_test",
                "ios_notifications",
                "macos_notifications",
                "macos_custody_events",
                "macos_admin_menu",
                "dart_admin_menu",
                "main_entry",
                "macos_runner_tests",
                "presentation_models",
                "secure_session_store",
                "secure_session_store_test",
                "controller_test",
                "permission_gate",
                "networks_directory",
                "network_screen",
                "nodes_screen",
                "controller_authority_test",
                "browser_api_test",
                "json_transport",
                "json_transport_test",
                "real_control_plane_test",
                "external_control_plane_test",
                "permission_presentation_test",
            }.issubset(boundary["source_sha256"])
        )
        self.assertTrue(boundary["release_identity_embedded"])
        self.assertFalse(boundary["physical_device_validated"])

    def test_tunnel_source_boundary_remains_fail_closed(self) -> None:
        boundary = RECEIPT.inspect_tunnel_source_boundary()
        self.assertEqual(
            boundary["network_settings_plan"],
            "authenticated-validated-source-proven",
        )
        self.assertEqual(
            boundary["apple_settings_mapping"],
            "coordinator-gated-provider-adapter-source-wired",
        )
        self.assertEqual(
            boundary["remote_endpoint"],
            "authenticated-canonical-required",
        )
        self.assertEqual(
            boundary["packet_pump"],
            "bounded-apple-flow-source-wired-static-engine",
        )
        self.assertEqual(
            boundary["provider"],
            "coordinator-apple-flow-extension-enrollment-lifecycle-mobile-"
            "evidence-identity-removal-static-engine-network-path-source-wired",
        )
        self.assertEqual(
            boundary["engine_adapter"],
            "gomobile-extension-enrollment-lifecycle-renewal-credential-"
            "rotation-mobile-evidence-identity-removal-signed-config-packet-"
            "session-source-wired",
        )
        self.assertEqual(
            boundary["runtime_coordinator"],
            "ordered-rebind-cleanup-source-proven",
        )
        self.assertEqual(
            boundary["extension_logging"],
            "fixed-reviewed-18-event-codes-only",
        )
        self.assertEqual(
            boundary["host_manager_recovery"],
            "preauth-confirmed-disabled-no-identity-exact-replacement-"
            "postauth-bounded-fresh-manager-retry-terminal-status-source-"
            "proven",
        )
        self.assertFalse(boundary["physical_device_validated"])
        source_names = set(boundary["source_sha256"])
        self.assertTrue(
            {
                "contract",
                "configuration_store",
                "apple_settings",
                "packet_pump",
                "runtime_coordinator",
                "provider",
                "runtime_adapters",
                "go_adapter",
                "host_controller",
                "tunnel_log",
                "project",
                "app_icon_manifest",
            }.issubset(source_names)
        )
        self.assertEqual(
            len([
                name for name in source_names
                if name.startswith("app_icon_")
                and name != "app_icon_manifest"
            ]),
            15,
        )

    def test_input_receipt_requires_empty_keychain_and_no_credentials(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mesh-apple-receipt-") as root:
            path = pathlib.Path(root) / "receipt.json"
            value = valid_input_receipt()
            write_receipt(path, value)
            loaded, digest = RECEIPT.load_receipt(path)
            self.assertEqual(loaded, value)
            self.assertEqual(len(digest), 64)

            value["preflight"]["source_keychain_code_signing_identities"] = 1
            write_receipt(path, value)
            with self.assertRaisesRegex(RECEIPT.ReceiptError, "credential state"):
                RECEIPT.load_receipt(path)

            value["preflight"]["source_keychain_code_signing_identities"] = 0
            value["preflight"]["release_credentials_present"] = True
            write_receipt(path, value)
            with self.assertRaisesRegex(RECEIPT.ReceiptError, "credential state"):
                RECEIPT.load_receipt(path)

            value["preflight"]["release_credentials_present"] = False
            value["inputs"]["flutter_sdk_sha256"] = "missing"
            write_receipt(path, value)
            with self.assertRaisesRegex(RECEIPT.ReceiptError, "credential state"):
                RECEIPT.load_receipt(path)

            value["inputs"]["flutter_sdk_sha256"] = "c" * 64
            value["inputs"]["flutter_archive_sha256"] = "d" * 64
            write_receipt(path, value)
            with self.assertRaisesRegex(RECEIPT.ReceiptError, "credential state"):
                RECEIPT.load_receipt(path)

            value["inputs"]["flutter_archive_sha256"] = FLUTTER_ARCHIVE_SHA256
            path.write_text(json.dumps(value, indent=2))
            with self.assertRaisesRegex(RECEIPT.ReceiptError, "canonical"):
                RECEIPT.load_receipt(path)

    def test_tree_identity_is_stable_and_rejects_escaping_symlinks(self) -> None:
        self.assertEqual(
            RECEIPT.canonical_tree_mode(stat.S_IFLNK | 0o700),
            0o777,
        )
        self.assertEqual(
            RECEIPT.canonical_tree_mode(stat.S_IFREG | 0o640),
            0o640,
        )
        with tempfile.TemporaryDirectory(prefix="mesh-apple-tree-") as root:
            bundle = pathlib.Path(root) / "Mesh Admin.app"
            contents = bundle / "Contents"
            contents.mkdir(parents=True)
            payload = contents / "payload"
            payload.write_bytes(b"mesh")
            current = contents / "current"
            current.symlink_to("payload")
            first = RECEIPT.tree_identity(bundle)
            if hasattr(os, "lchmod"):
                os.lchmod(current, 0o700)
                restricted = RECEIPT.tree_identity(bundle)
                os.lchmod(current, 0o777)
                permissive = RECEIPT.tree_identity(bundle)
                self.assertEqual(restricted, permissive)
            second = RECEIPT.tree_identity(bundle)
            self.assertEqual(first, second)
            self.assertEqual(first[1:], (1, 4))

            escaping = contents / "escape"
            escaping.symlink_to("../../..")
            with self.assertRaisesRegex(RECEIPT.ReceiptError, "escapes"):
                RECEIPT.tree_identity(bundle)

            escaping.unlink()
            absolute = contents / "absolute"
            absolute.symlink_to(pathlib.Path(root))
            self.assertTrue(os.path.isabs(os.readlink(absolute)))
            with self.assertRaisesRegex(RECEIPT.ReceiptError, "absolute"):
                RECEIPT.tree_identity(bundle)

    def test_ios_simulator_receipt_is_unsigned_universal_and_privacy_bounded(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(prefix="mesh-ios-receipt-") as root:
            root_path = pathlib.Path(root)
            app = root_path / "Runner.app"
            app.mkdir()
            (app / "Runner").write_bytes(
                b"simulator executable mesh-apple-admin-diagnostic-v2 "
                + b"a" * 40
            )
            (app / "Info.plist").write_bytes(
                plistlib.dumps(
                    {
                        "CFBundleDisplayName": "Mesh Admin",
                        "CFBundleIdentifier": "io.rw0.mesh.admin.mobile",
                        "CFBundleExecutable": "Runner",
                        "CFBundleShortVersionString": "0.1.0",
                        "CFBundleVersion": "1",
                        "CFBundleSupportedPlatforms": ["iPhoneSimulator"],
                        "UIDeviceFamily": [1, 2],
                        "MinimumOSVersion": "17.0",
                        "DTPlatformName": "iphonesimulator",
                        "DTXcode": "2650",
                        "DTXcodeBuild": "17F42",
                        "DTSDKName": "iphonesimulator26.5",
                    }
                )
            )
            (app / "PrivacyInfo.xcprivacy").write_bytes(
                plistlib.dumps(
                    {
                        "NSPrivacyAccessedAPITypes": [
                            {
                                "NSPrivacyAccessedAPIType": (
                                    "NSPrivacyAccessedAPICategoryUserDefaults"
                                ),
                                "NSPrivacyAccessedAPITypeReasons": ["AC6B.1"],
                            }
                        ],
                        "NSPrivacyCollectedDataTypes": [],
                        "NSPrivacyTracking": False,
                        "NSPrivacyTrackingDomains": [],
                    }
                )
            )
            write_ios_admin_native_assets(app)
            receipt = valid_input_receipt()
            input_path = root_path / "input.json"
            write_receipt(input_path, receipt)

            def fake_command(*arguments: str) -> subprocess.CompletedProcess[str]:
                if arguments[0] == "lipo":
                    return subprocess.CompletedProcess(
                        arguments,
                        0,
                        stdout="x86_64 arm64\n",
                        stderr="",
                    )
                if arguments[0] == "otool":
                    return subprocess.CompletedProcess(
                        arguments,
                        0,
                        stdout=(
                            f"{arguments[-1]} (architecture x86_64):\n"
                            "@rpath/objective_c.framework/objective_c\n"
                            f"{arguments[-1]} (architecture arm64):\n"
                            "@rpath/objective_c.framework/objective_c\n"
                        ),
                        stderr="",
                    )
                return subprocess.CompletedProcess(
                    arguments,
                    1,
                    stdout="",
                    stderr="code object is not signed at all",
                )

            args = types.SimpleNamespace(
                app=str(app),
                input_receipt=str(input_path),
                configuration="debug",
                platform="ios-simulator",
            )
            with mock.patch.object(RECEIPT, "command", fake_command):
                result = RECEIPT.inspect(args)

            self.assertEqual(
                result["schema"],
                "mesh-apple-ios-simulator-source-artifact-receipt-v1",
            )
            self.assertEqual(result["platform"], "ios-simulator")
            self.assertEqual(result["bundle"]["minimum_ios"], "17.0")
            self.assertEqual(
                set(result["bundle"]["architectures"]),
                {"arm64", "x86_64"},
            )
            self.assertEqual(result["bundle"]["release_signature"], "absent")
            self.assertEqual(
                result["native_assets"]["status"],
                "verified-known-flutter-fat-asset-grouping-warning",
            )
            self.assertEqual(
                result["native_assets"]["package"],
                {
                    "name": "objective_c",
                    "version": "9.4.1",
                    "sha256": RECEIPT.OBJECTIVE_C_SHA256,
                },
            )
            self.assertFalse(
                result["native_assets"]["unexpected_transient_framework_present"]
            )

    def test_native_asset_disposition_rejects_transient_framework_name(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(prefix="mesh-native-assets-") as root:
            app = pathlib.Path(root) / "Runner.app"
            app.mkdir()
            write_ios_admin_native_assets(app)
            (app / "Frameworks" / "objective_c1.framework").mkdir()

            def fake_command(*arguments: str) -> subprocess.CompletedProcess[str]:
                if arguments[0] == "lipo":
                    return subprocess.CompletedProcess(
                        arguments, 0, stdout="arm64 x86_64\n", stderr=""
                    )
                return subprocess.CompletedProcess(
                    arguments,
                    0,
                    stdout=(
                        f"{arguments[-1]} (architecture arm64):\n"
                        "@rpath/objective_c.framework/objective_c\n"
                        f"{arguments[-1]} (architecture x86_64):\n"
                        "@rpath/objective_c.framework/objective_c\n"
                    ),
                    stderr="",
                )

            with mock.patch.object(RECEIPT, "command", fake_command):
                with self.assertRaisesRegex(
                    RECEIPT.ReceiptError,
                    "framework inventory",
                ):
                    RECEIPT.inspect_admin_native_assets(
                        app,
                        ios_admin=True,
                        architectures=["arm64", "x86_64"],
                        input_receipt=valid_input_receipt(),
                    )

    def test_ios_tunnel_receipt_binds_exact_fail_closed_extension(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mesh-ios-tunnel-receipt-") as root:
            root_path = pathlib.Path(root)
            app = root_path / "Mesh Tunnel.app"
            extension = app / "PlugIns" / "MeshPacketTunnel.appex"
            extension.mkdir(parents=True)
            (app / "Mesh Tunnel").write_bytes(b"host executable")
            (extension / "MeshPacketTunnel").write_bytes(b"extension executable")

            common = {
                "CFBundleShortVersionString": "0.1.0",
                "CFBundleVersion": "1",
                "CFBundleSupportedPlatforms": ["iPhoneSimulator"],
                "UIDeviceFamily": [1, 2],
                "MinimumOSVersion": "17.0",
                "DTPlatformName": "iphonesimulator",
                "DTXcode": "2650",
                "DTXcodeBuild": "17F42",
                "DTSDKName": "iphonesimulator26.5",
            }
            (app / "Info.plist").write_bytes(
                plistlib.dumps(
                    {
                        **common,
                        "CFBundleDisplayName": "Mesh Tunnel",
                        "CFBundleIdentifier": "io.rw0.mesh.tunnel.mobile",
                        "CFBundleExecutable": "Mesh Tunnel",
                    }
                )
            )
            (extension / "Info.plist").write_bytes(
                plistlib.dumps(
                    {
                        **common,
                        "CFBundleDisplayName": "Mesh Packet Tunnel",
                        "CFBundleIdentifier": (
                            "io.rw0.mesh.tunnel.mobile.packet-tunnel"
                        ),
                        "CFBundleExecutable": "MeshPacketTunnel",
                        "NSExtension": {
                            "NSExtensionPointIdentifier": (
                                "com.apple.networkextension.packet-tunnel"
                            ),
                            "NSExtensionPrincipalClass": (
                                "MeshPacketTunnel.PacketTunnelProvider"
                            ),
                        },
                    }
                )
            )
            privacy = plistlib.dumps(
                {
                    "NSPrivacyAccessedAPITypes": [],
                    "NSPrivacyCollectedDataTypes": [],
                    "NSPrivacyTracking": False,
                    "NSPrivacyTrackingDomains": [],
                }
            )
            (app / "PrivacyInfo.xcprivacy").write_bytes(privacy)
            (extension / "PrivacyInfo.xcprivacy").write_bytes(privacy)

            receipt = valid_input_receipt()
            input_path = root_path / "input.json"
            write_receipt(input_path, receipt)
            framework = root_path / "MeshMobile.xcframework"
            framework.mkdir()
            (framework / "fixture").write_bytes(b"reviewed static framework")
            framework_identity = RECEIPT.tree_identity(framework)
            framework_receipt = {
                "schema": (
                    "mesh-apple-ios-mobile-framework-source-receipt-v1"
                ),
                "source": receipt["source"],
                "build_host": receipt["host"],
                "build_inputs": receipt["inputs"],
                "input_receipt_sha256": hashlib.sha256(
                    input_path.read_bytes()
                ).hexdigest(),
                "engine": {
                    "framework_schema": "mesh-ios-mobile-framework-v5",
                    "capability": (
                        "extension-enrollment-lifecycle-renewal-credential-"
                        "rotation-mobile-evidence-identity-removal-signed-"
                        "config-packet-session"
                    ),
                    "private_key_exported": False,
                },
                "framework": {
                    "name": "MeshMobile.xcframework",
                    "tree_sha256": framework_identity[0],
                    "regular_files": framework_identity[1],
                    "regular_file_bytes": framework_identity[2],
                    "exports": [
                        "IosmobileEnsureIdentity",
                        "IosmobileFrameworkIdentity",
                        "IosmobileFrameworkIdentitySHA256",
                        "IosmobileNewEngineSession",
                        "IosmobileNewEnrollmentSession",
                        "IosmobileNewIdentityRemovalSession",
                        "IosmobileNewLifecycleSession",
                    ],
                    "signed": False,
                    "reproducible": True,
                },
                "scope": {
                    "embedded_in_tunnel": False,
                    "packet_transport_implemented": True,
                    "static_tunnel_link_validated": False,
                    "physical_device_validated": False,
                    "production_signing_used": False,
                },
            }
            framework_receipt_path = root_path / "framework-receipt.json"
            write_receipt(framework_receipt_path, framework_receipt)

            def fake_command(*arguments: str) -> subprocess.CompletedProcess[str]:
                if arguments[0] == "lipo":
                    return subprocess.CompletedProcess(
                        arguments,
                        0,
                        stdout="x86_64 arm64\n",
                        stderr="",
                    )
                if arguments[0] == "nm":
                    return subprocess.CompletedProcess(
                        arguments,
                        0,
                        stdout="\n".join(
                            [
                                "_IosmobileNewEngineSession",
                                "_IosmobileNewEnrollmentSession",
                                "_IosmobileNewIdentityRemovalSession",
                                "_IosmobileNewLifecycleSession",
                                "_proxyiosmobile_EnrollmentSession_Enroll",
                                (
                                    "_proxyiosmobile_IdentityRemovalSession_"
                                    "Remove"
                                ),
                                (
                                    "_proxyiosmobile_LifecycleSession_"
                                    "ReportRuntime"
                                ),
                                "_proxyiosmobile_LifecycleSession_Refresh",
                                (
                                    "_proxyiosmobile_EngineSession_"
                                    "FrameworkIdentity"
                                ),
                                "_proxyiosmobile_EngineSession_Prepare",
                                "_proxyiosmobile_EngineSession_Rebind",
                                "_proxyiosmobile_EngineSession_Receive",
                                "_proxyiosmobile_EngineSession_Send",
                                "_proxyiosmobile_EngineSession_Start",
                                "_proxyiosmobile_EngineSession_Stop",
                            ]
                        ),
                        stderr="",
                    )
                if arguments[0] == "otool":
                    return subprocess.CompletedProcess(
                        arguments,
                        0,
                        stdout="/System/Library/Frameworks/Foundation.framework\n",
                        stderr="",
                    )
                if arguments[0] == "strings":
                    return subprocess.CompletedProcess(
                        arguments,
                        0,
                        stdout="\n".join(
                            [
                                "mesh-ios-mobile-framework-v5",
                                (
                                    "extension-enrollment-lifecycle-renewal-"
                                    "credential-rotation-mobile-evidence-"
                                    "identity-removal-signed-config-packet-"
                                    "session"
                                ),
                                "mesh-ios-tunnel-configuration-v4",
                                "mesh-ios-lifecycle-refresh-v1",
                                "mesh-ios-nebula-engine-configuration-v1",
                            ]
                        ),
                        stderr="",
                    )
                return subprocess.CompletedProcess(
                    arguments,
                    1,
                    stdout="",
                    stderr="code object is not signed at all",
                )

            args = types.SimpleNamespace(
                app=str(app),
                input_receipt=str(input_path),
                configuration="debug",
                platform="ios-tunnel-simulator",
                mobile_framework=str(framework),
                mobile_framework_receipt=str(framework_receipt_path),
            )
            with mock.patch.object(RECEIPT, "command", fake_command):
                result = RECEIPT.inspect(args)

            self.assertEqual(
                result["schema"],
                "mesh-apple-ios-tunnel-simulator-source-artifact-receipt-v1",
            )
            self.assertEqual(
                result["extension"]["extension_point"],
                "com.apple.networkextension.packet-tunnel",
            )
            self.assertEqual(result["extension"]["engine_frameworks"], [])
            self.assertEqual(
                result["extension"]["engine_linkage"],
                "static",
            )
            self.assertFalse(
                result["extension"]["engine_dynamic_dependency"]
            )

            framework = extension / "Unreviewed.framework"
            framework.mkdir()
            with mock.patch.object(RECEIPT, "command", fake_command):
                with self.assertRaisesRegex(RECEIPT.ReceiptError, "engine framework"):
                    RECEIPT.inspect(args)


if __name__ == "__main__":
    unittest.main()
