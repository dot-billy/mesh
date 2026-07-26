#!/usr/bin/env python3
"""Static contract checks for Apple Flutter project files."""

from __future__ import annotations

import hashlib
import json
import pathlib
import plistlib
import re
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
DESKTOP = ROOT / "desktop"
MACOS = DESKTOP / "macos"
IOS = DESKTOP / "ios"
IOS_TUNNEL = ROOT / "ios-tunnel"


def plist(path: pathlib.Path) -> dict[str, object]:
    value = plistlib.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise AssertionError(f"{path} is not one plist dictionary")
    return value


class AppleProjectTest(unittest.TestCase):
    def test_ios_app_store_export_options_are_exact_and_manual(self) -> None:
        shared = {
            "destination": "export",
            "manageAppVersionAndBuildNumber": False,
            "method": "app-store-connect",
            "signingCertificate": "Apple Distribution",
            "signingStyle": "manual",
            "stripSwiftSymbols": True,
            "teamID": "Y3P5UNNG23",
            "uploadSymbols": False,
        }
        admin = plist(
            ROOT
            / "packaging"
            / "apple"
            / "ios-admin-app-store-export-options.plist"
        )
        self.assertEqual(
            admin,
            {
                **shared,
                "provisioningProfiles": {
                    "io.rw0.mesh.admin.mobile": "Mesh Admin App Store"
                },
            },
        )
        tunnel = plist(
            ROOT
            / "packaging"
            / "apple"
            / "ios-tunnel-app-store-export-options.plist"
        )
        self.assertEqual(
            tunnel,
            {
                **shared,
                "provisioningProfiles": {
                    "io.rw0.mesh.tunnel.mobile": (
                        "Mesh Tunnel Host App Store"
                    ),
                    "io.rw0.mesh.tunnel.mobile.packet-tunnel": (
                        "Mesh Packet Tunnel App Store"
                    ),
                },
            },
        )

    def test_macos_product_identity_and_minimum_are_explicit(self) -> None:
        app_info = (MACOS / "Runner" / "Configs" / "AppInfo.xcconfig").read_text()
        self.assertIn("PRODUCT_NAME = Mesh Admin", app_info)
        self.assertIn("PRODUCT_BUNDLE_IDENTIFIER = io.rw0.mesh.admin", app_info)
        project = (MACOS / "Runner.xcodeproj" / "project.pbxproj").read_text()
        self.assertNotIn("io.rw0.meshDesktop", project)
        self.assertNotIn("MACOSX_DEPLOYMENT_TARGET = 10.15", project)
        self.assertEqual(project.count("MACOSX_DEPLOYMENT_TARGET = 14.0"), 3)
        self.assertEqual(
            project.count("PRODUCT_BUNDLE_IDENTIFIER = io.rw0.mesh.admin.RunnerTests"),
            3,
        )
        scheme = (
            MACOS
            / "Runner.xcodeproj"
            / "xcshareddata"
            / "xcschemes"
            / "Runner.xcscheme"
        ).read_text()
        self.assertNotIn("mesh_desktop.app", scheme)
        self.assertEqual(scheme.count('BuildableName = "Mesh Admin.app"'), 5)

    def test_release_entitlements_are_the_exact_minimum(self) -> None:
        release = plist(MACOS / "Runner" / "Release.entitlements")
        self.assertEqual(
            release,
            {
                "com.apple.security.app-sandbox": True,
                "com.apple.security.network.client": True,
                "keychain-access-groups": ["Y3P5UNNG23.io.rw0.mesh.admin"],
            },
        )
        debug = plist(MACOS / "Runner" / "DebugProfile.entitlements")
        self.assertEqual(
            debug,
            {
                "com.apple.security.app-sandbox": True,
                "com.apple.security.cs.allow-jit": True,
                "com.apple.security.network.client": True,
                "com.apple.security.network.server": True,
                "keychain-access-groups": ["Y3P5UNNG23.io.rw0.mesh.admin"],
            },
        )

    def test_info_plist_has_no_privileged_or_local_node_usage(self) -> None:
        info = plist(MACOS / "Runner" / "Info.plist")
        self.assertEqual(info["CFBundleDisplayName"], "Mesh Admin")
        serialized = json.dumps(info, sort_keys=True)
        for forbidden in (
            "NSAppleEventsUsageDescription",
            "NSSystemAdministrationUsageDescription",
            "NSSupportsAutomaticTermination",
            "io.mesh.node-agent",
            "/opt/mesh",
            "/private/var/db/mesh",
        ):
            self.assertNotIn(forbidden, serialized)

    def test_macos_privacy_manifest_is_the_reviewed_minimum(self) -> None:
        privacy = plist(MACOS / "Runner" / "PrivacyInfo.xcprivacy")
        self.assertEqual(
            privacy,
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
            },
        )
        project = (MACOS / "Runner.xcodeproj" / "project.pbxproj").read_text()
        self.assertEqual(project.count("PrivacyInfo.xcprivacy in Resources"), 2)
        self.assertEqual(
            project.count("PrivacyInfo.xcprivacy */ = {isa = PBXFileReference"),
            1,
        )

    def test_native_window_contract_is_bounded_and_restorable(self) -> None:
        window = (MACOS / "Runner" / "MainFlutterWindow.swift").read_text()
        self.assertIn('self.title = "Mesh Admin"', window)
        self.assertIn("NSSize(width: 900, height: 600)", window)
        self.assertIn('setFrameAutosaveName("MeshAdminMainWindow")', window)
        interface = (MACOS / "Runner" / "Base.lproj" / "MainMenu.xib").read_text()
        self.assertIn('width="1200" height="760"', interface)
        self.assertIn('keyEquivalent="q"', interface)
        self.assertIn('keyEquivalent=","', interface)

    def test_ordered_macos_and_ios_operator_runners_exist(self) -> None:
        self.assertTrue(MACOS.is_dir())
        self.assertTrue(IOS.is_dir())
        metadata = (DESKTOP / ".metadata").read_text()
        for platform_name in ("root", "linux", "windows", "macos", "ios"):
            self.assertIn(f"platform: {platform_name}", metadata)
        self.assertEqual(metadata.count("platform: ios"), 1)

    def test_ios_identity_minimum_and_distribution_entitlements_are_explicit(
        self,
    ) -> None:
        project = (IOS / "Runner.xcodeproj" / "project.pbxproj").read_text()
        for forbidden in (
            "iPhone Developer",
            "io.rw0.meshDesktop",
            "IPHONEOS_DEPLOYMENT_TARGET = 13.0",
        ):
            self.assertNotIn(forbidden, project)
        self.assertEqual(
            project.count("DEVELOPMENT_TEAM = Y3P5UNNG23;"),
            3,
        )
        self.assertEqual(
            project.count('CODE_SIGN_IDENTITY = "Apple Distribution";'),
            2,
        )
        self.assertEqual(project.count("CODE_SIGN_STYLE = Manual;"), 2)
        self.assertEqual(
            project.count(
                'PROVISIONING_PROFILE_SPECIFIER = "Mesh Admin App Store";'
            ),
            2,
        )
        self.assertEqual(
            project.count(
                "PRODUCT_BUNDLE_IDENTIFIER = io.rw0.mesh.admin.mobile;"
            ),
            3,
        )
        self.assertEqual(
            project.count(
                "PRODUCT_BUNDLE_IDENTIFIER = "
                "io.rw0.mesh.admin.mobile.RunnerTests;"
            ),
            3,
        )
        self.assertEqual(project.count("IPHONEOS_DEPLOYMENT_TARGET = 17.0"), 3)
        for entitlement in (
            "Development.entitlements",
            "TestFlight.entitlements",
            "AppStore.entitlements",
        ):
            self.assertEqual(
                project.count(f"CODE_SIGN_ENTITLEMENTS = Runner/{entitlement}"),
                1,
            )
        self.assertIn("Managed.entitlements", project)

        build_inputs = json.loads(
            (DESKTOP / "tool" / "apple-build.json").read_text()
        )
        self.assertEqual(
            build_inputs["apple_developer"],
            {
                "approval_status": "registered-and-provisioned",
                "approved_on": "2026-07-24",
                "team_id": "Y3P5UNNG23",
                "program": "Apple Developer Program",
                "enrollment": "individual",
                "macos_admin_application_identifier": "io.rw0.mesh.admin",
                "ios_admin_application_identifier": (
                    "io.rw0.mesh.admin.mobile"
                ),
                "ios_tunnel_application_identifier": (
                    "io.rw0.mesh.tunnel.mobile"
                ),
                "ios_tunnel_extension_identifier": (
                    "io.rw0.mesh.tunnel.mobile.packet-tunnel"
                ),
                "ios_tunnel_application_group": (
                    "group.io.rw0.mesh.tunnel.mobile"
                ),
                "app_store_connect_apps": {
                    "ios_admin": "6794340010",
                    "ios_tunnel": "6794340524",
                },
                "distribution_profiles": {
                    "ios_admin": "Mesh Admin App Store",
                    "ios_tunnel_host": "Mesh Tunnel Host App Store",
                    "ios_tunnel_extension": (
                        "Mesh Packet Tunnel App Store"
                    ),
                },
            },
        )
        self.assertEqual(
            build_inputs["ios_operator"],
            {
                "application_identifier": "io.rw0.mesh.admin.mobile",
                "keychain_access_group": (
                    "$(AppIdentifierPrefix)io.rw0.mesh.admin.mobile"
                ),
                "distribution_entitlements": {
                    "development": "Runner/Development.entitlements",
                    "testflight": "Runner/TestFlight.entitlements",
                    "app_store": "Runner/AppStore.entitlements",
                    "managed": "Runner/Managed.entitlements",
                },
            },
        )

        expected = {
            "keychain-access-groups": [
                "$(AppIdentifierPrefix)io.rw0.mesh.admin.mobile"
            ]
        }
        for name in (
            "Development.entitlements",
            "TestFlight.entitlements",
            "AppStore.entitlements",
            "Managed.entitlements",
        ):
            self.assertEqual(plist(IOS / "Runner" / name), expected)

    def test_ios_runner_is_operator_only_and_privacy_declared(self) -> None:
        info = plist(IOS / "Runner" / "Info.plist")
        self.assertEqual(info["CFBundleDisplayName"], "Mesh Admin")
        self.assertNotIn("UIBackgroundModes", info)
        self.assertEqual(
            plist(IOS / "Runner" / "PrivacyInfo.xcprivacy"),
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
            },
        )
        source = "\n".join(
            path.read_text()
            for path in (
                IOS / "Runner" / "AppDelegate.swift",
                IOS / "Runner" / "SceneDelegate.swift",
                IOS / "Runner" / "Info.plist",
                IOS / "Runner.xcodeproj" / "project.pbxproj",
            )
        )
        for forbidden in (
            "NetworkExtension",
            "NEPacketTunnel",
            "com.apple.developer.networking.vpn.api",
            "com.apple.developer.networking.networkextension",
            "AppGroup",
            "group.io.rw0",
        ):
            self.assertNotIn(forbidden, source)

    def test_ios_tunnel_is_separate_fail_closed_product_source(self) -> None:
        project = (
            IOS_TUNNEL / "MeshTunnel.xcodeproj" / "project.pbxproj"
        ).read_text()
        self.assertIn(
            "PRODUCT_BUNDLE_IDENTIFIER = io.rw0.mesh.tunnel.mobile;",
            project,
        )
        self.assertIn(
            "PRODUCT_BUNDLE_IDENTIFIER = "
            "io.rw0.mesh.tunnel.mobile.packet-tunnel;",
            project,
        )
        self.assertEqual(project.count("IPHONEOS_DEPLOYMENT_TARGET = 17.0;"), 9)
        self.assertEqual(project.count("CURRENT_PROJECT_VERSION = 2;"), 6)
        self.assertNotIn("CURRENT_PROJECT_VERSION = 1;", project)
        self.assertEqual(project.count("MARKETING_VERSION = 0.1.0;"), 6)
        self.assertEqual(
            project.count("DEVELOPMENT_TEAM = Y3P5UNNG23;"),
            6,
        )
        self.assertEqual(
            project.count('CODE_SIGN_IDENTITY = "Apple Distribution";'),
            4,
        )
        self.assertEqual(project.count("CODE_SIGN_STYLE = Manual;"), 4)
        self.assertEqual(
            project.count(
                'PROVISIONING_PROFILE_SPECIFIER = '
                '"Mesh Tunnel Host App Store";'
            ),
            2,
        )
        self.assertEqual(
            project.count(
                'PROVISIONING_PROFILE_SPECIFIER = '
                '"Mesh Packet Tunnel App Store";'
            ),
            2,
        )
        for relative in (
            "MeshTunnelHost/Development.entitlements",
            "MeshTunnelHost/TestFlight.entitlements",
            "MeshTunnelHost/CustomApp.entitlements",
            "PacketTunnel/Development.entitlements",
            "PacketTunnel/TestFlight.entitlements",
            "PacketTunnel/CustomApp.entitlements",
        ):
            self.assertEqual(
                project.count(f"CODE_SIGN_ENTITLEMENTS = {relative};"),
                1,
            )

        app_group = ["group.io.rw0.mesh.tunnel.mobile"]
        handoff_group = [
            "$(AppIdentifierPrefix)io.rw0.mesh.tunnel.mobile.handoff"
        ]
        identity_group = (
            "$(AppIdentifierPrefix)io.rw0.mesh.tunnel.mobile.identity"
        )
        for name in (
            "Development.entitlements",
            "TestFlight.entitlements",
            "CustomApp.entitlements",
        ):
            host = plist(IOS_TUNNEL / "MeshTunnelHost" / name)
            self.assertEqual(
                host,
                {
                    "com.apple.developer.networking.networkextension": [
                        "packet-tunnel-provider"
                    ],
                    "com.apple.security.application-groups": app_group,
                    "keychain-access-groups": handoff_group,
                },
            )
            extension = plist(IOS_TUNNEL / "PacketTunnel" / name)
            self.assertEqual(
                extension,
                {
                    "com.apple.developer.networking.networkextension": [
                        "packet-tunnel-provider"
                    ],
                    "com.apple.security.application-groups": app_group,
                    "keychain-access-groups": handoff_group + [identity_group],
                },
            )

        provider = (
            IOS_TUNNEL / "PacketTunnel" / "PacketTunnelProvider.swift"
        ).read_text()
        contract = (
            IOS_TUNNEL / "Shared" / "TunnelContract.swift"
        ).read_text()
        for required in (
            'mesh-ios-tunnel-configuration-v4',
            'mesh-ios-tunnel-envelope-v4',
            'mesh-ios-lifecycle-refresh-v1',
            'mesh-ios-nebula-engine-configuration-v1',
            '"tunnelRemoteAddress"',
            "networkSettings.remoteEndpointRoute",
            "try networkSettings.validateRemoteAddress(tunnelRemoteAddress)",
            "requireNestedObject(",
            'key: "nebula"',
            "guard observedConfigDigest == configDigest",
            "guard observedCADigest == caCertificateSHA256",
            "configIssued < certificateExpires",
            "certificateRenews < certificateExpires",
        ):
            self.assertIn(required, contract)
        self.assertIn("final class PacketTunnelProvider", provider)
        self.assertIn("engine-unavailable", provider)
        self.assertIn("import Network", provider)
        self.assertIn("NWPathMonitor()", provider)
        self.assertIn("TunnelRuntimeCoordinator(", provider)
        self.assertIn("TunnelEngineSessionFactory.make(", provider)
        self.assertIn("TunnelLifecycleSessionFactory.make()", provider)
        self.assertIn("case .deferred:", provider)
        self.assertIn("case .unauthorized:", provider)
        self.assertIn("ProviderPacketFlowSession(", provider)
        self.assertIn("self.startPacketLoops(", provider)
        self.assertIn("try await packetFlow.read()", provider)
        self.assertIn(
            "try await coordinator.sendFromApple(packets)",
            provider,
        )
        self.assertIn(
            "try await coordinator.receiveForApple()",
            provider,
        )
        self.assertIn("try packetFlow.write(packets)", provider)
        self.assertIn(
            "self.startPathMonitoring(coordinator: coordinator)",
            provider,
        )
        self.assertIn("try await coordinator.rebind()", provider)
        self.assertIn("stopPathMonitoring()", provider)
        self.assertIn(
            'cancelTunnelWithError(Self.failure("network-rebind-failed"))',
            provider,
        )
        self.assertNotIn("setTunnelNetworkSettings", provider)
        self.assertNotIn("provider.packetFlow", provider)
        packet_pump = (
            IOS_TUNNEL / "Shared" / "TunnelPacketFlowPump.swift"
        ).read_text()
        for required in (
            "public actor TunnelPacketFlowPump",
            "public enum TunnelPacketFlowBatchCodec",
            "decodeAppleRead(",
            "encodeAppleWrite(",
            "case backpressured",
            "discardedOnStop",
            "maximumQueuedPackets - packets.count",
            "maximumQueuedBytes - batchBytes",
        ):
            self.assertIn(required, packet_pump)
        self.assertNotIn("NetworkExtension", packet_pump)
        self.assertNotIn("NEPacketTunnelFlow", packet_pump)
        apple_settings = (
            IOS_TUNNEL / "Shared" / "TunnelAppleNetworkSettings.swift"
        ).read_text()
        for required in (
            "NEPacketTunnelNetworkSettings(",
            "NEIPv4Settings(",
            "NEIPv6Settings(",
            "NEDNSSettings(",
            "tunnelRemoteAddress: TunnelRemoteAddress",
        ):
            self.assertIn(required, apple_settings)
        self.assertNotIn("setTunnelNetworkSettings", apple_settings)
        self.assertNotIn("packetFlow", apple_settings)
        self.assertNotIn("TunnelAppleNetworkSettingsFactory", provider)
        runtime = (
            IOS_TUNNEL / "Shared" / "TunnelRuntimeCoordinator.swift"
        ).read_text()
        for required in (
            "public actor TunnelRuntimeCoordinator",
            "try await engine.prepare(configuration: configuration)",
            "try await networkSettings.apply(",
            "try await pump.start()",
            "try await engine.start()",
            "public func rebind() async throws",
            "try await engine.rebind()",
            "await pump.stop()",
            "await engine.stop()",
            "await networkSettings.clear()",
        ):
            self.assertIn(required, runtime)
        self.assertLess(
            runtime.index(
                "try await engine.prepare(configuration: configuration)"
            ),
            runtime.index("try await networkSettings.apply("),
        )
        self.assertLess(
            runtime.index("try await networkSettings.apply("),
            runtime.index("try await pump.start()"),
        )
        self.assertLess(
            runtime.index("try await pump.start()"),
            runtime.index("try await engine.start()"),
        )
        adapters = (
            IOS_TUNNEL / "PacketTunnel" / "TunnelRuntimeAdapters.swift"
        ).read_text()
        for required in (
            "final class UnavailableTunnelEngineSession",
            "throw TunnelEngineAdapterError.unavailable",
            "final class ProviderNetworkSettingsSession",
            "TunnelAppleNetworkSettingsFactory.make(",
            "provider.setTunnelNetworkSettings(settings)",
            "provider?.setTunnelNetworkSettings(nil)",
            "final class ProviderPacketFlowSession",
            "flow.readPackets",
            "flow.writePackets(",
            "TunnelPacketFlowBatchCodec",
            "func rebind() async throws",
        ):
            self.assertIn(required, adapters)
        self.assertEqual(
            project.count("TunnelRuntimeCoordinator.swift in Sources"),
            2,
        )
        self.assertEqual(
            project.count("TunnelRuntimeAdapters.swift in Sources"),
            2,
        )
        self.assertEqual(
            project.count("GoTunnelEngineSession.swift in Sources"),
            2,
        )
        self.assertEqual(
            project.count("Assets.xcassets in Resources"),
            2,
        )
        self.assertEqual(
            project.count(
                "ASSETCATALOG_COMPILER_APPICON_NAME = AppIcon;"
            ),
            3,
        )
        self.assertIn("<string>AppIcon</string>", (
            IOS_TUNNEL / "MeshTunnelHost" / "Info.plist"
        ).read_text())
        self.assertIs(
            plist(IOS_TUNNEL / "MeshTunnelHost" / "Info.plist")[
                "ITSAppUsesNonExemptEncryption"
            ],
            False,
        )
        go_adapter = (
            IOS_TUNNEL / "PacketTunnel" / "GoTunnelEngineSession.swift"
        ).read_text()
        for required in (
            "@preconcurrency import MeshMobile",
            "protocol TunnelEnrollmentSession: Sendable",
            "protocol TunnelLifecycleSession: Sendable",
            "IosmobileNewEnrollmentSession(",
            "IosmobileNewLifecycleSession(",
            "TunnelIdentityScope.primaryID",
            "session.enroll(",
            "TunnelConfigurationPayload.decodeExact",
            "enum TunnelEnrollmentSessionFactory",
            "enum TunnelLifecycleSessionFactory",
            "IosmobileNewEngineSession(",
            "session.prepare(document)",
            "session.rebind()",
            "session.send(packet)",
            "session.receive()",
            "enum TunnelEngineSessionFactory",
        ):
            self.assertIn(required, go_adapter)
        host = (
            IOS_TUNNEL / "MeshTunnelHost" / "MeshTunnelViewController.swift"
        ).read_text()
        for required in (
            "loadAllFromPreferences",
            "saveToPreferences",
            "TunnelEnrollmentRequest.normalizedOrigin(",
            "request.encoded()",
            "ASWebAuthenticationSession",
            "URLSessionConfiguration.ephemeral",
            "HTTPCookieStorage()",
            'path: "/api/v1/auth/desktop/start"',
            "createSelfEnrollment(",
            "NETunnelProviderSession",
            "session.startTunnel(options:",
            "eraseTransientEnrollment()",
            "manager.isOnDemandEnabled = false",
            "removeFromPreferences",
            "requireEnabled: false",
            "try await enableManager(",
            "manager.isEnabled = true",
        ):
            self.assertIn(required, host)
        for required in (
            "func protectForInactivity()",
            "func protectForBackground()",
            "eraseTransientEnrollment()",
        ):
            self.assertIn(required, host)
        tunnel_scene = (
            IOS_TUNNEL / "MeshTunnelHost" / "SceneDelegate.swift"
        ).read_text()
        resign_body = tunnel_scene.split(
            "func sceneWillResignActive", 1
        )[1].split("func sceneDidEnterBackground", 1)[0]
        self.assertIn(".protectForInactivity()", resign_body)
        self.assertNotIn(".protectForBackground()", resign_body)
        background_body = tunnel_scene.split(
            "func sceneDidEnterBackground", 1
        )[1].split("func sceneDidBecomeActive", 1)[0]
        self.assertIn(".protectForBackground()", background_body)
        for forbidden in ("startVPNTunnel",):
            self.assertNotIn(forbidden, host)

        store = (
            IOS_TUNNEL / "Shared" / "TunnelConfigurationStore.swift"
        ).read_text()
        for required in (
            "O_NOFOLLOW",
            "renameat(",
            "fsync(",
            "effectiveHighWater",
            "candidate.monotonicCounter > effectiveHighWater",
            "public func nextMonotonicCounter() throws -> UInt64",
            "return floor + 1",
        ):
            self.assertIn(required, store)
        handoff = (
            IOS_TUNNEL / "Shared" / "TunnelHandoffKeychain.swift"
        ).read_text()
        highwater = (
            IOS_TUNNEL / "PacketTunnel" / "TunnelHighWaterKeychain.swift"
        ).read_text()
        for source in (handoff, highwater):
            self.assertIn(
                "kSecAttrSynchronizable as String: kCFBooleanFalse!",
                source,
            )
            self.assertIn(
                "kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly",
                source,
            )
            self.assertIn(
                "kSecUseDataProtectionKeychain as String: kCFBooleanTrue!",
                source,
            )

        lifecycle_gate = (
            IOS_TUNNEL / "Shared" / "TunnelProviderLifecycleGate.swift"
        ).read_text()
        for required in (
            "public final class TunnelProviderLifecycleGate",
            "case alreadyStarting",
            "case alreadyRunning",
            "public func mayContinueStart() -> Bool",
            "public func markRunning() -> Bool",
            "public func latchStop() -> Bool",
        ):
            self.assertIn(required, lifecycle_gate)
        provider = (
            IOS_TUNNEL / "PacketTunnel" / "PacketTunnelProvider.swift"
        ).read_text()
        for required in (
            "lifecycleGate.beginStart()",
            "lifecycleGate.mayContinueStart()",
            "lifecycleGate.markRunning()",
            "lifecycleGate.latchStop()",
            '"start-already-in-progress"',
            '"start-cancelled"',
        ):
            self.assertIn(required, provider)
        self.assertEqual(
            project.count("TunnelProviderLifecycleGate.swift in Sources"),
            2,
        )

    def test_ios_tunnel_logging_accepts_only_fixed_reviewed_codes(self) -> None:
        source = (
            IOS_TUNNEL / "PacketTunnel" / "TunnelLog.swift"
        ).read_text()
        self.assertIn("import OSLog", source)
        self.assertIn(
            "static func record(_ event: TunnelLogEvent)",
            source,
        )
        self.assertNotIn("\\(", source)
        self.assertNotIn("func record(_ event: String)", source)
        self.assertEqual(
            re.findall(r'case \w+ = "([^"]+)"', source),
            [
                "start-requested",
                "configuration-container-unavailable",
                "configuration-unavailable",
                "configuration-invalid",
                "enrollment-request-rejected",
                "enrollment-failed",
                "lifecycle-refresh-deferred",
                "lifecycle-refresh-failed",
                "agent-authorization-rejected",
                "engine-unavailable",
                "network-rebind-failed",
                "packet-flow-failed",
                "stop-requested",
                "status-request-accepted",
                "status-request-rejected",
                "identity-removal-requested",
                "identity-removal-completed",
                "identity-removal-failed",
            ],
        )
        project = (
            IOS_TUNNEL / "MeshTunnel.xcodeproj" / "project.pbxproj"
        ).read_text()
        self.assertEqual(project.count("TunnelLog.swift in Sources"), 2)

    def test_ios_tunnel_contract_and_build_mapping_are_explicit(self) -> None:
        build_inputs = json.loads(
            (DESKTOP / "tool" / "apple-build.json").read_text()
        )
        tunnel = build_inputs["ios_tunnel"]
        self.assertEqual(
            tunnel["engine_status"],
            "extension-enrollment-lifecycle-renewal-credential-rotation-"
            "mobile-evidence-identity-removal-signed-config-packet-session-"
            "source-wired",
        )
        self.assertEqual(tunnel["engine_framework"], "MeshMobile.xcframework")
        self.assertEqual(
            tunnel["gomobile"],
            {
                "module": "golang.org/x/mobile",
                "version": "v0.0.0-20260709172247-6129f5bee9d5",
                "upstream_url": "https://go.googlesource.com/mobile",
                "upstream_commit": (
                    "6129f5bee9d516e31842c9815bf24f60fa682b6e"
                ),
                "module_sum": (
                    "h1:Mn1OzFmF0ZKX/ZayHz/UdnWHufPp1wlD9lZ5U8LRDFY="
                ),
                "go_mod_sum": (
                    "h1:YX+n47s+53POxN3dx9cIGxG3hGUm/lD64hvrRJFbcSA="
                ),
                "framework_schema": "mesh-ios-mobile-framework-v5",
                "capability": (
                    "extension-enrollment-lifecycle-renewal-credential-rotation-"
                    "mobile-evidence-identity-removal-signed-config-packet-session"
                ),
                "minimum_ios": "17.0",
            },
        )
        self.assertEqual(
            tunnel["engine_source"]["upstream_commit"],
            "f573e8a26695278f9d71587390fbfe0d0933aa21",
        )
        self.assertEqual(tunnel["engine_source"]["mesh_patch"], "none")
        self.assertEqual(
            tunnel["packet_bridge"],
            {
                "nebula_adapter": (
                    "github.com/slackhq/nebula/overlay.UserDevice"
                ),
                "apple_transport": "NEPacketTunnelFlow callbacks",
                "status": "authenticated-udp-exported-source-wired",
            },
        )
        self.assertEqual(
            tunnel["runtime_startup"],
            {
                "configuration_schema": (
                    "mesh-ios-tunnel-configuration-v4"
                ),
                "envelope_schema": "mesh-ios-tunnel-envelope-v4",
                "remote_endpoint": "authenticated-canonical-underlay-ip",
                "order": [
                    "engine-identity",
                    "engine-prepare",
                    "apple-network-settings",
                    "packet-pump",
                    "engine-start",
                ],
                "status": (
                    "static-linked-simulator-build-proven-device-pending"
                ),
            },
        )
        self.assertEqual(
            tunnel["framework_build"]["flags"],
            [
                "-trimpath",
                "-ldflags=-buildid=",
                "-target=ios",
                "-iosversion=17.0",
            ],
        )
        self.assertEqual(
            tunnel["framework_build"]["source_staging_schema"],
            "mesh-ios-mobile-framework-source-staging-v1",
        )
        self.assertEqual(
            tunnel["framework_build"]["canonical_source_root"],
            "/private/var/tmp/mesh-apple-ios-mobile-source-v5",
        )
        self.assertEqual(
            set(tunnel["distribution_entitlements"]),
            {"development", "testflight", "custom_app"},
        )
        contract = (IOS_TUNNEL / "Shared" / "TunnelContract.swift").read_text()
        for required in (
            "mesh-ios-tunnel-control-v1",
            "mesh-ios-tunnel-enrollment-v1",
            "mesh-ios-tunnel-configuration-v4",
            "mesh-ios-tunnel-envelope-v4",
            "mesh-ios-lifecycle-refresh-v1",
            "mesh-ios-nebula-engine-configuration-v1",
            "mesh-ios-tunnel-evidence-v1",
            "TunnelNetworkSettingsPlan",
            "networkSettings.routeConflict",
            "requireNestedArrayObjects",
            'key: "nebula"',
            "guard observedConfigDigest == configDigest",
            "guard observedCADigest == caCertificateSHA256",
            "configIssued < certificateExpires",
            "certificateRenews < certificateExpires",
            "(1280...1500).contains(mtu)",
            "HMAC<SHA256>",
            "authenticationFailed",
            "runningEvidence",
            'public static let startOptionKey = "meshEnrollmentRequest"',
            'public static let primaryID = "primary"',
            "public static func normalizedOrigin(",
        ):
            self.assertIn(required, contract)
        for forbidden in ("privateKey", "recoveryCode", "sessionCookie"):
            self.assertNotIn(forbidden, contract)
        build_script = (
            ROOT / "scripts" / "apple-ios-tunnel-source-build.sh"
        ).read_text()
        for required in (
            "swift test",
            "CODE_SIGNING_ALLOWED=NO",
            "CODE_SIGN_ENTITLEMENTS=",
            "FRAMEWORK_SEARCH_PATHS=",
            "-framework MeshMobile",
            "--mobile-framework-receipt",
            "--platform ios-tunnel-simulator",
            "MESH_SOURCE_KEYCHAIN",
        ):
            self.assertIn(required, build_script)
        self.assertNotIn("DEVELOPMENT_TEAM=", build_script)
        artifact_receipt = (
            ROOT / "scripts" / "apple_source_artifact_receipt.py"
        ).read_text()
        for required in (
            "authenticated-validated-source-proven",
            "coordinator-gated-provider-adapter-source-wired",
            "authenticated-canonical-required",
            "bounded-apple-flow-source-wired-static-engine",
            "coordinator-apple-flow-extension-enrollment-lifecycle-mobile-",
            "evidence-identity-removal-static-engine-network-path-source-wired",
            "gomobile-extension-enrollment-lifecycle-renewal-credential-",
            "rotation-mobile-evidence-identity-removal-signed-config-packet-",
            "session-source-wired",
            "ordered-rebind-cleanup-source-proven",
            "physical_device_validated",
        ):
            self.assertIn(required, artifact_receipt)

        engine = IOS_TUNNEL / "engine"
        go_mod = (engine / "go.mod").read_text()
        self.assertIn("github.com/slackhq/nebula v1.10.3", go_mod)
        self.assertIn(
            "golang.org/x/mobile v0.0.0-20260709172247-6129f5bee9d5",
            go_mod,
        )
        mobile = (engine / "mobile.go").read_text()
        self.assertIn("func FrameworkIdentity()", mobile)
        self.assertIn("func FrameworkIdentitySHA256()", mobile)
        self.assertIn("func EnsureIdentity(", mobile)
        for forbidden in (
            "func PrivateKey",
            "func Start",
            "func Stop",
            "func Configure",
        ):
            self.assertNotIn(forbidden, mobile)
        session = (engine / "engine_session.go").read_text()
        for required in (
            "type EngineSession struct",
            "func NewEngineSession(",
            "func (s *EngineSession) Prepare(",
            "func (s *EngineSession) Start(",
            "func (s *EngineSession) Send(",
            "func (s *EngineSession) Receive(",
            "func (s *EngineSession) Rebind(",
            "func (s *EngineSession) Stop(",
        ):
            self.assertIn(required, session)
        lifecycle = (engine / "lifecycle.go").read_text()
        for required in (
            "type LifecycleSession struct",
            "func NewLifecycleSession(",
            "func (s *LifecycleSession) Refresh(",
            "func (s *LifecycleSession) ReportRuntime(",
            'origin+"/api/v1/agent/bootstrap"',
            'origin+"/api/v1/agent/certificate/renew"',
            'origin+"/api/v1/agent/credentials/rotate"',
            'origin+"/api/v1/agent/mobile-runtime"',
            "lifecycleRefreshUnauthorized",
            "lifecycleRefreshDeferred",
        ):
            self.assertIn(required, lifecycle)
        identity_removal = (engine / "identity_removal.go").read_text()
        for required in (
            "type IdentityRemovalSession struct",
            "func NewIdentityRemovalSession(",
            "func (s *IdentityRemovalSession) Remove() error",
            "deleteSecret(",
            "pendingAgentCredentialService",
        ):
            self.assertIn(required, identity_removal)
        vault = (engine / "vault_ios.go").read_text()
        for required in (
            "kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly",
            "kSecAttrSynchronizable, kCFBooleanFalse",
            "kSecUseDataProtectionKeychain, kCFBooleanTrue",
        ):
            self.assertIn(required, vault)
        packet_bridge = (engine / "packet_bridge.go").read_text()
        self.assertIn("overlay.NewUserDevice", packet_bridge)
        self.assertIn("validateAndCopyPacket", packet_bridge)
        self.assertNotIn("func NewPacket", packet_bridge)
        feasibility = (engine / "engine_feasibility_test.go").read_text()
        for required in (
            "newEngineTestSession",
            "session.Prepare",
            "session.Start",
            "session.Send",
            "session.Receive",
            "GetCertByVpnIp",
            "CurrentRelaysToMe",
            "session.Rebind",
            "icmpv4Packet",
        ):
            self.assertIn(required, feasibility)

        framework_build = (
            ROOT / "scripts" / "apple-ios-mobile-framework-build.sh"
        ).read_text()
        for required in (
            "go install golang.org/x/mobile/cmd/gobind",
            "go install golang.org/x/mobile/cmd/gomobile",
            "-target=ios",
            "-iosversion=17.0",
            "-ldflags=-buildid=",
            "-count=20",
            'canonical_source_root="/private/var/tmp/mesh-apple-ios-mobile-source-v5"',
            "stage_source_file",
            'cd "${canonical_engine_root}"',
            "apple_mobile_framework_normalize.py",
            "apple_mobile_framework_receipt.py",
        ):
            self.assertIn(required, framework_build)

    def test_ios_native_custody_and_source_build_are_bounded(self) -> None:
        delegate = (IOS / "Runner" / "AppDelegate.swift").read_text()
        for required in (
            "protectedDataWillBecomeUnavailableNotification",
            'signalDart("protectedDataUnavailable")',
            'signalDart("processTerminating")',
            "copyExpiringSecret",
            ".localOnly: true",
            ".expirationDate:",
        ):
            self.assertIn(required, delegate)
        scene = (IOS / "Runner" / "SceneDelegate.swift").read_text()
        for required in (
            "sceneWillResignActive",
            "sceneDidEnterBackground",
            "sceneDidBecomeActive",
            "sceneDidDisconnect",
            "PrivacyShieldController",
            "accessibilityViewIsModal = true",
        ):
            self.assertIn(required, scene)
        native_test = (IOS / "RunnerTests" / "RunnerTests.swift").read_text()
        for required in (
            "testPrivacyShieldCoversAndRestores",
            "testPrivacyShieldCoverIsIdempotent",
            "testDeviceOnlyKeychainRoundTripWhenSignedForSimulator",
            "kSecAttrAccessibleWhenUnlockedThisDeviceOnly",
            "kSecAttrSynchronizable: false",
            "kSecUseDataProtectionKeychain: true",
            "SecItemAdd",
            "SecItemCopyMatching",
            "SecItemDelete",
            "errSecItemNotFound",
        ):
            self.assertIn(required, native_test)
        self.assertNotIn("kSecAttrAccessGroup", native_test)

        build = (ROOT / "scripts" / "apple-ios-source-build.sh").read_text()
        for required in (
            "security find-identity -v -p codesigning",
            "0 valid identities found",
            "build ios --simulator --debug --config-only",
            "generic/platform=iOS Simulator",
            "CODE_SIGNING_ALLOWED=NO",
            "CODE_SIGN_ENTITLEMENTS=",
            "--platform ios-simulator",
            "MESH_APP_VERSION=0.1.0",
            "MESH_APP_BUILD=1",
            "MESH_SOURCE_COMMIT=${source_commit}",
            "Apple input receipt source commit is invalid",
        ):
            self.assertIn(required, build)
        self.assertNotIn("security default-keychain", build)
        self.assertNotIn("security list-keychains", build)
        workflow = (ROOT / ".github" / "workflows" / "apple.yml").read_text()
        self.assertIn(
            "- name: Install the pinned iOS 18.6 simulator runtime",
            workflow,
        )
        self.assertIn(
            "xcodebuild -downloadPlatform iOS -buildVersion 18.6",
            workflow,
        )
        ios_test_start = workflow.index("- name: Run native iOS runner tests")
        ios_test_end = workflow.index(
            "- name: Upload the sanitized source receipt",
            ios_test_start,
        )
        ios_test_step = workflow[ios_test_start:ios_test_end]
        self.assertNotIn("CODE_SIGNING_ALLOWED=NO", ios_test_step)
        self.assertNotIn("CODE_SIGN_ENTITLEMENTS=", ios_test_step)
        self.assertIn("codesign --verify --deep --strict", ios_test_step)
        self.assertIn(
            "xcrun xcresulttool get test-results summary",
            ios_test_step,
        )
        self.assertIn(
            "mesh-ios-native-test-summary.json",
            ios_test_step,
        )
        self.assertIn(
            "${{ runner.temp }}/mesh-ios-native-test-summary.json",
            workflow,
        )
        upload_start = workflow.index("- name: Upload the sanitized source receipt")
        upload_step = workflow[upload_start:]
        self.assertNotIn(".raw.json", upload_step)
        self.assertEqual(
            workflow.count("--schema-version 0.1.0"),
            2,
        )
        self.assertEqual(
            workflow.count("scripts/apple_native_test_summary.py"),
            4,
        )
        self.assertEqual(
            workflow.count("scripts/apple_source_matrix_receipt.py"),
            3,
        )
        self.assertIn(
            "${{ runner.temp }}/mesh-apple-source-matrix.json",
            upload_step,
        )
        mac_test_start = workflow.index("- name: Run native macOS runner tests")
        mac_test_end = workflow.index(
            "- name: Run native iOS runner tests",
            mac_test_start,
        )
        mac_test_step = workflow[mac_test_start:mac_test_end]
        self.assertIn(
            "xcrun xcresulttool get test-results summary",
            mac_test_step,
        )
        self.assertIn(
            "mesh-macos-native-test-summary.json",
            mac_test_step,
        )
        self.assertIn(
            "${{ runner.temp }}/mesh-macos-native-test-summary.json",
            workflow,
        )
        mobile_security = (
            DESKTOP / "lib" / "core" / "platform" / "mobile_security.dart"
        ).read_text()
        self.assertIn("nothing was copied", mobile_security)
        self.assertNotIn(
            "} on MissingPluginException {\n      await Clipboard.setData",
            mobile_security,
        )
        diagnostics = (
            DESKTOP
            / "lib"
            / "core"
            / "support"
            / "apple_admin_diagnostic_bundle.dart"
        ).read_text()
        for required in (
            "mesh-apple-admin-diagnostic-v2",
            "maximumBytes = 16 * 1024",
            "'automatic_collection': false",
            "'automatic_upload': false",
            "'application_persistence': false",
            "'channel': 'system-clipboard'",
            "'expires_after_seconds': 120",
            "'recipient_deletion_enforced_by_mesh': false",
            "packet-path-unverified",
            "raw-error-text",
            "logs-and-arbitrary-files",
        ):
            self.assertIn(required, diagnostics)
        for platform in ("ios", "macos"):
            apple_log = (
                DESKTOP / platform / "Runner" / "MeshAdminLog.swift"
            ).read_text()
            for required in (
                "import OSLog",
                "MeshAdminLogEvent",
                "static func record(_ event: MeshAdminLogEvent)",
                'logger.notice("application-started")',
                'logger.error("expiring-copy-rejected")',
            ):
                self.assertIn(required, apple_log)
            notifications = (
                DESKTOP
                / platform
                / "Runner"
                / "AppleAdminNotifications.swift"
            ).read_text()
            for required in (
                "fleet-warning",
                "fleet-critical",
                "Open Mesh Admin to review fresh authoritative evidence.",
                "arguments.count == 1",
            ):
                self.assertIn(required, notifications)
            project = (
                DESKTOP
                / platform
                / "Runner.xcodeproj"
                / "project.pbxproj"
            ).read_text()
            self.assertEqual(
                project.count("AppleAdminNotifications.swift in Sources"),
                2,
            )
            self.assertNotIn("\\(", apple_log)
            self.assertNotIn("func record(_ event: String)", apple_log)
        mac_custody = (
            MACOS / "Runner" / "MacCustodyEvents.swift"
        ).read_text()
        for required in (
            "com.apple.screenIsLocked",
            "NSWorkspace.screensDidSleepNotification",
            "NSWorkspace.willSleepNotification",
            "NSApplication.didHideNotification",
            "NSWindow.willCloseNotification",
            "NSApplication.willTerminateNotification",
            'return "protectedDataUnavailable"',
            'return "processTerminating"',
            "arguments: nil",
        ):
            self.assertIn(required, mac_custody)
        self.assertEqual(
            (MACOS / "Runner.xcodeproj" / "project.pbxproj")
            .read_text()
            .count("MacCustodyEvents.swift in Sources"),
            2,
        )
        mac_menu = (MACOS / "Runner" / "MacAdminMenu.swift").read_text()
        for required in (
            'channelName = "io.rw0.mesh.admin/macos-menu-v1"',
            'return "refresh"',
            'return "preferences"',
            "arguments: nil",
        ):
            self.assertIn(required, mac_menu)
        self.assertEqual(
            (MACOS / "Runner.xcodeproj" / "project.pbxproj")
            .read_text()
            .count("MacAdminMenu.swift in Sources"),
            2,
        )

    def test_unsigned_build_is_bound_to_an_empty_explicit_keychain(self) -> None:
        build = (ROOT / "scripts" / "apple-source-build.sh").read_text()
        for required in (
            "security find-identity -v -p codesigning",
            "0 valid identities found",
            "CODE_SIGNING_ALLOWED=NO",
            "CODE_SIGN_ENTITLEMENTS=",
            "OTHER_CODE_SIGN_FLAGS=--keychain",
            "MESH_APP_VERSION=0.1.0",
            "MESH_APP_BUILD=1",
            "MESH_SOURCE_COMMIT=${source_commit}",
            "Apple input receipt source commit is invalid",
        ):
            self.assertIn(required, build)
        self.assertNotIn("security default-keychain", build)
        self.assertNotIn("security list-keychains", build)

    def test_native_keychain_test_is_bound_to_the_isolated_keychain(self) -> None:
        runner_test = (MACOS / "RunnerTests" / "RunnerTests.swift").read_text()
        self.assertIn("SecKeychainCreate", runner_test)
        self.assertIn("SecKeychainAddGenericPassword", runner_test)
        self.assertIn("SecKeychainItemDelete", runner_test)
        self.assertIn("SecKeychainCopySearchList", runner_test)
        self.assertIn("SecKeychainSetSearchList", runner_test)

    def test_desktop_e2e_uses_the_real_bounded_control_plane_fixture(self) -> None:
        fixture = (
            ROOT
            / "internal"
            / "httpapi"
            / "cmd"
            / "desktop-e2e-fixture"
            / "main.go"
        ).read_text()
        for required in (
            '"mesh/internal/control"',
            '"mesh/internal/httpapi"',
            '"mesh/internal/identity"',
            '"mesh/internal/runtimetelemetry"',
            'net.Listen("tcp4", "127.0.0.1:0")',
            '"X-Mesh-Fixture-Token"',
            'exec.Command("go", "tool", "-n", "nebula-cert")',
            '"Version: 1.10.3\\n"',
        ):
            self.assertIn(required, fixture)
        workflow = (ROOT / ".github" / "workflows" / "apple.yml").read_text()
        self.assertEqual(
            workflow.count(
                '"internal/httpapi/cmd/desktop-e2e-fixture/**"'
            ),
            2,
        )
        for required in (
            "go test ./cmd/mesh-darwin-codesign-verify",
            "./internal/nebulaartifact",
            "./internal/darwinnodepackage",
            'echo "GOCACHE=$RUNNER_TEMP/mesh-go-build-cache" >> "$GITHUB_ENV"',
            'echo "GOMODCACHE=$RUNNER_TEMP/mesh-go-module-cache" >> "$GITHUB_ENV"',
            'echo "PUB_CACHE=$RUNNER_TEMP/mesh-pub-cache" >> "$GITHUB_ENV"',
            'export GOCACHE="$RUNNER_TEMP/mesh-linux-go-build-cache"',
            'export GOMODCACHE="$RUNNER_TEMP/mesh-linux-go-module-cache"',
            "windows-regression:",
            "go test -buildvcs=false ./...",
            "cache: false",
            "go test ./internal/postgresconfig -run '^$' -count=1",
            "TestVerifyDarwinNodePackageReleaseBindsFinalBytesAndPolicies",
            "TestDarwinNativeChildIdentityAndDetachedCycleContext",
            "TestDarwinNativeChildForcedGroupKillAndReap",
            "scripts/apple_protected_node_package_release_test.py",
            "scripts/apple_node_package_verify_test.py",
        ):
            self.assertIn(required, workflow)
        self.assertNotIn("GOCACHE: ${{ runner.temp }}", workflow)
        self.assertNotIn("GOMODCACHE: ${{ runner.temp }}", workflow)
        self.assertNotIn("PUB_CACHE: ${{ runner.temp }}", workflow)
        self.assertEqual(workflow.count('"**/*.go"'), 2)
        for trigger in (
            '"cmd/mesh-darwin-codesign-verify/**"',
            '"cmd/meshctl/agent_supervised_runtime*.go"',
            '"internal/darwincodesign/**"',
            '"internal/darwinnodepackage/**"',
            '"internal/nebulaartifact/**"',
            '"internal/postgresconfig/**"',
            '"scripts/apple-node-package-verify.py"',
            '"scripts/apple_node_package_verify_test.py"',
            '"scripts/apple_managed_configuration_verify.py"',
            '"scripts/apple_managed_configuration_verify_test.py"',
            '"scripts/apple_native_test_summary.py"',
            '"scripts/apple_native_test_summary_test.py"',
            '"scripts/apple_source_matrix_receipt.py"',
            '"scripts/apple_source_matrix_receipt_test.py"',
            '"scripts/apple-protected-node-package-release.py"',
            '"scripts/apple_protected_node_package_release_test.py"',
        ):
            self.assertEqual(workflow.count(trigger), 2)
        makefile = (ROOT / "Makefile").read_text()
        for required in (
            "./cmd/mesh-darwin-codesign-verify",
            "./internal/nebulaartifact",
            "./internal/darwinnodepackage",
            "go test ./internal/postgresconfig -run '^$$' -count=1",
            "TestVerifyDarwinNodePackageReleaseBindsFinalBytesAndPolicies",
            "TestDarwinNativeChildIdentityAndDetachedCycleContext",
            "TestDarwinNativeChildForcedGroupKillAndReap",
            "python3 scripts/apple_native_test_summary_test.py",
            "python3 scripts/apple_source_matrix_receipt_test.py",
        ):
            self.assertIn(required, makefile)
        darwin_packages = {
            path.parent.relative_to(ROOT).as_posix()
            for path in ROOT.rglob("*_darwin.go")
            if "bin" not in path.relative_to(ROOT).parts
        }
        self.assertTrue(darwin_packages)
        for package in sorted(darwin_packages):
            with self.subTest(darwin_package=package):
                self.assertIn(f"./{package}", workflow)
                self.assertIn(f"./{package}", makefile)
        desktop_test = (
            DESKTOP
            / "test"
            / "integration"
            / "mesh_api_real_control_plane_test.dart"
        ).read_text()
        for operation in (
            "startDesktopAuthorization",
            "completeDesktopAuthorization",
            "createNetwork",
            "createNode",
            "reissuePendingEnrollment",
            "rotateNodeCertificate",
            "revokeNode",
            "revokeSession",
            "createRecoveryAccess",
        ):
            self.assertIn(operation, desktop_test)
        external_test = (
            DESKTOP
            / "test"
            / "integration"
            / "mesh_api_external_control_plane_test.dart"
        ).read_text()
        for required in (
            "MESH_APPLE_EXTERNAL_CONTROL_PLANE",
            "MESH_URL",
            "MESH_ADMIN_TOKEN",
            "'hybrid-oidc'",
            "api.authenticationMethods",
            "LegacyAdministratorBearer(token)",
            "api.currentSession",
            "api.networks",
            "transport.cookieJar.isComplete, isFalse",
        ):
            self.assertIn(required, external_test)
        for forbidden in (
            "api.loginWithLegacyToken",
            "restoredApi",
            "api.logout",
        ):
            self.assertNotIn(forbidden, external_test)

    def test_darwin_installer_command_composes_only_reviewed_primitives(self) -> None:
        command = (ROOT / "cmd" / "mesh-install" / "main_darwin.go").read_text()
        for required in (
            "darwininstall.ApplyProductionDarwinOnline",
            "darwininstall.ApplyProductionDarwinSnapshot",
            "darwininstall.RecoverProductionDarwinInstallation",
            "darwininstall.ActivateProductionDarwinRuntime",
            "darwininstall.UninstallProductionDarwinRuntime",
            "darwininstall.RollbackProductionDarwinInstallation",
        ):
            self.assertIn(required, command)
        installer = (
            ROOT / "internal" / "darwininstall" / "installer_darwin.go"
        ).read_text()
        for required in (
            "onlinerelease.CanonicalBundleURL",
            "AuthenticateProductionDarwinCandidate",
            "FetchProductionDarwinArtifact",
            "ImportProductionDarwinSnapshot",
            "StageAcceptedIntake",
            "BeginAcceptedIntake",
            "ResumeProductionJournalWithLaunchctl",
            "BeginRollbackTo",
            "controller.Kickstart()",
        ):
            self.assertIn(required, installer)
        uninstall = (
            ROOT
            / "internal"
            / "darwininstall"
            / "runtime_uninstall_darwin.go"
        ).read_text()
        for required in (
            "deactivateDarwinRuntime",
            "controller.Bootout()",
            "publisher.RemoveExact()",
            "current.RemoveSelected()",
            "RejectCurrentTransactionTemporaries()",
            "DeactivateRuntime()",
            "ReleaseDataRemovalApplied: false",
            "AgentStateRemovalApplied: false",
        ):
            self.assertIn(required, uninstall)
        for forbidden in (
            "exec.Command(",
            "os.Getenv(",
            "/bin/sh",
            "/bin/bash",
            "launchctl print",
        ):
            self.assertNotIn(forbidden, installer)
        enrollment = (
            ROOT
            / "internal"
            / "darwininstall"
            / "enrollment_validation_darwin.go"
        ).read_text()
        for required in (
            'ProductionDarwinAgentStatePath       = "/private/var/db/mesh-agent/state.json"',
            'ProductionDarwinAgentOutputDirectory = "/private/var/db/mesh-agent/runtime"',
            "LoadProvisionalEnrollment",
            "LoadRecoveryKeyPair",
            "CurrentBundle",
            "InspectDarwinPackagedExecutable",
            "command.Env = []string{}",
            'command.Dir = "/"',
        ):
            self.assertIn(required, enrollment)

    def test_darwin_production_enrollment_authenticates_then_stays_gated(self) -> None:
        runtime = (ROOT / "cmd" / "meshctl" / "enrollment_runtime.go").read_text()
        resolve = runtime.index("resolveInstalledEnrollmentRuntimeDirectory(")
        validate = runtime.index("validateInstalledRuntimeDirectory(binaryDirectory)")
        inspect = runtime.index("inspectEnrollmentRuntime(")
        self.assertLess(resolve, validate)
        self.assertLess(validate, inspect)

        darwin = (
            ROOT / "cmd" / "meshctl" / "enrollment_runtime_darwin.go"
        ).read_text()
        self.assertIn(
            "darwininstall.ValidateProductionDarwinInstalledRuntime",
            darwin,
        )
        self.assertIn(
            "Darwin production enrollment remains disabled until clean-host "
            "native lifecycle, signing, notarization, and installed-host "
            "evidence pass",
            darwin,
        )
        validator = (
            ROOT
            / "internal"
            / "darwininstall"
            / "installed_runtime_darwin.go"
        ).read_text()
        for required in (
            "OpenReleaseLayout(ProductionMeshRoot)",
            "ProductionInstallerJournalStore()",
            "lock.LoadInstallState()",
            "layout.InspectPublishedAuthority(*state.Active)",
            "current.ProveSelected()",
            "publisher.Inspect()",
            "ProductionRuntimeGate()",
            "gate.Inspect()",
        ):
            self.assertIn(required, validator)
        workflow = (ROOT / ".github" / "workflows" / "apple.yml").read_text()
        self.assertEqual(
            workflow.count('"cmd/meshctl/enrollment_runtime*.go"'),
            2,
        )

    def test_darwin_signature_admission_is_compiled_and_precedes_execution(self) -> None:
        policy = (ROOT / "internal" / "darwincodesign" / "policy.go").read_text()
        for required in (
            "mesh-development-no-darwin-codesign-policy",
            "mesh_install_identifier",
            "MeshInstallRole",
            "RequireAppleAnchor:",
            "RequireDeveloperID: true",
            "RequireStrict: true",
            "certificate leaf[subject.OU]",
        ):
            self.assertIn(required, policy)
        contract = (
            ROOT / "internal" / "darwincodesign" / "contract.go"
        ).read_text()
        for required in (
            'CodesignPath        = "/usr/bin/codesign"',
            '"--verify", "--strict=all", "--test-requirement"',
            "codesignSelfVerificationArguments",
        ):
            self.assertIn(required, contract)
        verifier = (
            ROOT / "internal" / "darwincodesign" / "verify_darwin.go"
        ).read_text()
        for required in (
            "nodeagent.InspectDarwinPackagedExecutable",
            "command.Env = []string{}",
            'command.Dir = "/"',
            "VerifyRelease",
        ):
            self.assertIn(required, verifier)
        installer = (
            ROOT / "internal" / "darwininstall" / "installer_darwin.go"
        ).read_text()
        self.assertLess(
            installer.index("verifyDarwinReleaseSignatures(stage.Path()"),
            installer.index("NewInstallerJournalFor(stage"),
        )
        launchctl = (
            ROOT / "internal" / "darwininstall" / "launchctl_controller_darwin.go"
        ).read_text()
        self.assertIn("admit launchctl bootstrap release code signatures", launchctl)
        self.assertIn("admit launchctl kickstart release code signatures", launchctl)

    def test_darwin_node_package_policy_remains_fail_closed(self) -> None:
        policy = (
            ROOT / "internal" / "darwinnodepackage" / "policy.go"
        ).read_text()
        for required in (
            "mesh-development-no-darwin-node-package-policy",
            "mesh-darwin-node-package-policy-v2",
            "RequireCompiledPostinstall: true",
            "RequireRootWheel:",
            "RequireNotarization:",
            '"/Library/Application Support/Mesh"',
            "PackageRootPath",
        ):
            self.assertIn(required, policy)
        release = (ROOT / "cmd" / "mesh-release" / "main.go").read_text()
        for required in (
            '"darwin-node-package-policy"',
            '"package-identifier"',
            '"package-root-path"',
            '"installed-bootstrap-path"',
            '"package-snapshot-path"',
        ):
            self.assertIn(required, release)
        protected = (
            ROOT / "scripts" / "apple-protected-node-package-release.py"
        ).read_text()
        for required in (
            "parse_package_policy",
            "parse_codesign_policy",
            "parse_codesign_receipt",
            "parse_bundle_security_receipt",
            "validate_installer_identity",
            "validate_bootstrap",
            "inspect_package",
            '"--keychain-profile"',
            '"--check-signature"',
            '"--type", "install"',
            "exclusive_json",
        ):
            self.assertIn(required, protected)
        self.assertLess(
            protected.index('"submit",'),
            protected.index('"staple", "-q"'),
        )
        self.assertLess(
            protected.index('"staple", "-q"'),
            protected.rindex("package_identity = hash_file(output"),
        )
        native_verify = (
            ROOT / "scripts" / "apple-node-package-verify.py"
        ).read_text()
        for required in (
            "parse_package_policy",
            "parse_codesign_policy",
            "parse_receipt",
            "authenticate_tools",
            "inspect_package",
            '"verify-darwin-node-package-release"',
            '"--check-signature"',
            '"validate", "-q"',
            '"--type", "install"',
            "exclusive_json",
        ):
            self.assertIn(required, native_verify)
        self.assertLess(
            native_verify.index('"verify-darwin-node-package-release"'),
            native_verify.index('"--check-signature"'),
        )
        self.assertLess(
            native_verify.index('"--check-signature"'),
            native_verify.rindex("exclusive_json("),
        )

    def test_final_darwin_bundle_binds_signatures_before_release_authoring(self) -> None:
        signed_build = (
            ROOT / "internal" / "darwinbundle" / "signed_build.go"
        ).read_text()
        for required in (
            "VerifySignedMachOReplacement",
            "darwincodesign.ParseReceipt",
            "receipt.Match",
            "SignedSchema",
        ):
            self.assertIn(required, signed_build)
        manifest = (
            ROOT / "cmd" / "mesh-release" / "manifest_generation_linux.go"
        ).read_text()
        for required in (
            '"darwin-codesign-receipt"',
            "darwinbundle.InspectCandidateArchive",
            "darwinbundle.SignedSchema",
            "darwinCodesignArtifactIdentities",
        ):
            self.assertIn(required, manifest)
        native = (
            ROOT / "scripts" / "apple-native-app-verify.py"
        ).read_text()
        for required in (
            "verify-published-apple-app",
            "mesh_release_verifier_sha256",
            "network_has_nonloopback_unicast",
            "require_network_isolation",
            "stapler",
            '"/usr/sbin/spctl"',
            "verify_code",
            "signed_tree_sha256",
        ):
            self.assertIn(required, native)
        native_receipt = (
            ROOT / "internal" / "appleapprelease" / "native_receipt.go"
        ).read_text()
        for required in (
            "NativeReceiptSchema",
            "ParseNativeReceipt",
            "RequireNetworkIsolated",
            "pre-and-post-no-default-route-or-nonloopback-unicast",
            "validateSignatureDigests",
        ):
            self.assertIn(required, native_receipt)
        package_gate = (
            ROOT / "internal" / "darwinpackagesecurity" / "receipt.go"
        ).read_text()
        self.assertIn('"mesh-darwin-node-bundle-v2"', package_gate)

    def test_darwin_bundle_smoke_prepares_offline_nebula_graph_safely(
        self,
    ) -> None:
        smoke = (ROOT / "scripts" / "darwin-bundle-smoke.sh").read_text()
        for required in (
            "prefetch_source=",
            "GOFLAGS=-mod=readonly",
            "GOSUMDB=sum.golang.org",
            "go mod download github.com/slackhq/nebula@v1.10.3",
            'cp -a -- "${nebula_source}" "${prefetch_source}"',
            'git -C "${prefetch_source}" apply --check',
            'git -C "${prefetch_source}" apply --whitespace=error-all',
            "go mod download all",
        ):
            self.assertIn(required, smoke)
        self.assertNotIn('cd -- "${nebula_source}"', smoke)
        self.assertLess(
            smoke.index("go mod download all"),
            smoke.index("Building release, package, dependency"),
        )
        producer = (
            ROOT / "internal" / "nebulaobserverartifact" / "build.go"
        ).read_text()
        self.assertIn('"GOPROXY": "off"', producer)
        self.assertIn("hashSourceTree(sourcePath)", producer)
        self.assertIn("hashSourceTree(sourceCopy)", producer)

    def test_protected_admin_release_is_inside_out_and_fail_closed(self) -> None:
        release = (
            ROOT / "scripts" / "apple-protected-app-release.py"
        ).read_text()
        for required in (
            "parse_identity_output",
            'APP_TEAM_ID = "Y3P5UNNG23"',
            'result.add_argument("--team-id", required=True)',
            "authenticate_release_tools",
            '"--options",',
            '"runtime"',
            "for code in standalone",
            "for bundle in bundles",
            "sign_code(app",
            '"notarytool"',
            '"stapler"',
            '"/usr/sbin/spctl"',
            "tree_identity(app)",
            'output_identity["sha256"]',
            "validate_security_receipt",
            "security_receipt_sha256",
            "embedded.provisionprofile",
            "validate_provisioning_profile",
            '"--provisioning-profile"',
        ):
            self.assertIn(required, release)
        self.assertNotIn("--policy-frame", release)
        self.assertLess(
            release.index("for code in standalone"),
            release.index("sign_code(app"),
        )
        self.assertLess(
            release.index('"staple", "-q"'),
            release.rindex('output_identity["sha256"]'),
        )
        for required in (
            "EXPECTED_NESTED_CODE",
            "source\", {}).get(\"clean\") is not True",
            "file_identity(keychain)",
            "file_identity(output)",
            "require_success=False",
        ):
            self.assertIn(required, release)
        portable = (
            ROOT / "internal" / "appleapprelease" / "receipt.go"
        ).read_text()
        for required in (
            "ReceiptSchema",
            "DisallowUnknownFields",
            "ApplicationEntitlementsSHA",
            "validateNestedCode",
            "validateTools",
            "func (receipt Receipt) Match",
        ):
            self.assertIn(required, portable)
        entitlements = plist(MACOS / "Runner" / "Release.entitlements")
        entitlement_digest = hashlib.sha256(
            plistlib.dumps(
                entitlements,
                fmt=plistlib.FMT_XML,
                sort_keys=True,
            )
        ).hexdigest()
        self.assertIn(
            f'ApplicationEntitlementsSHA = "{entitlement_digest}"',
            portable,
        )
        command = (
            ROOT / "cmd" / "mesh-release" / "apple_app_release.go"
        ).read_text()
        self.assertIn("hashStableAppleApplicationArchive", command)
        self.assertIn("does not replace native Apple signature", command)
        self.assertIn("verifyPublishedAppleApp", command)
        self.assertIn("independently authenticated root", command)
        manifest = (
            ROOT / "cmd" / "mesh-release" / "manifest_generation_linux.go"
        ).read_text()
        for required in (
            "macos-admin",
            "macos-admin-evidence",
            "validateAppleAppReleaseReceipt",
            "MatchForPublication",
            "apple-app-source-receipt-sha256",
        ):
            self.assertIn(required, manifest)

    def test_release_trust_documents_apple_identity_lifecycle(self) -> None:
        trust = (ROOT / "docs" / "release-trust.md").read_text()
        section_start = trust.index(
            "## Rotate or revoke Apple signing identities"
        )
        section_end = trust.index("## Rotate or revoke keys", section_start)
        section = trust[section_start:section_end]
        normalized = " ".join(section.split())
        for required in (
            "separate trust domain",
            "exact fingerprint, never by display name or common name alone",
            "exactly one Developer ID Application identity",
            "Developer ID Installer SHA-1 fingerprint explicitly",
            "Mesh Admin, the Mesh Tunnel host, and the Packet Tunnel extension",
            "Renew before the earliest certificate or profile expiration",
            "An expired identity or provisioning profile is prohibited",
            "new create-only output paths",
            "Never overwrite, re-sign in place",
            "public re-download and clean-host verification",
            "Notarization credential rotation is independent",
            "Stop signing, notarization, export, and channel promotion",
            "successor threshold-signed Mesh metadata",
            "Never retain private keys, keychain passwords, API keys",
        ):
            self.assertIn(required, normalized)
        self.assertLess(section.index("For a planned rotation:"), section.index(
            "If a signing private key"
        ))

    def test_admin_security_gate_is_pinned_offline_and_precedes_signing(
        self,
    ) -> None:
        baseline = (
            ROOT / "scripts" / "apple-admin-security-baseline.sh"
        ).read_text()
        for required in (
            "docker info",
            "--network=none",
            "SYFT_CHECK_FOR_APP_UPDATE=false",
            "GRYPE_CHECK_FOR_APP_UPDATE=false",
            "syft@sha256:86fde6445b483d",
            "grype@sha256:391bfda62888",
            "gitleaks@sha256:c00b6bd0aeb",
            "secret-scan text from every regular app-bundle file",
            "normalize_code_resources",
            "source-receipt.json",
            "pub-deps.json",
            "NOTICES.Z",
        ):
            self.assertIn(required, baseline)
        gitleaks = (ROOT / ".gitleaks-image.toml").read_text()
        self.assertIn(
            "6b00be81b6c391946b86245b3ac8b7b99bac9e3d09b0c87caa84b9169bd7ce2e",
            gitleaks,
        )
        protected = (
            ROOT / "scripts" / "apple-protected-app-release.py"
        ).read_text()
        produce = protected[protected.index("def produce") :]
        self.assertLess(
            produce.index("validate_security_receipt("),
            produce.index("sign_code(app"),
        )
        self.assertIn(
            'result.add_argument("--security-receipt", required=True)',
            protected,
        )

    def test_mobile_framework_security_gate_is_pinned_and_bounded(
        self,
    ) -> None:
        baseline = (
            ROOT
            / "scripts"
            / "apple-mobile-framework-security-baseline.sh"
        ).read_text()
        for required in (
            "docker info",
            "--network=none",
            "SYFT_CHECK_FOR_APP_UPDATE=false",
            "GRYPE_CHECK_FOR_APP_UPDATE=false",
            "syft@sha256:86fde6445b483d",
            "grype@sha256:391bfda62888",
            "gitleaks@sha256:c00b6bd0aeb",
            "runtime module graph differs from the reviewed allowlist",
            "secret-scan strings from every framework file",
            "source-receipt.json",
            "runtime-modules.json",
            ".gitleaks-apple-mobile.toml",
        ):
            self.assertIn(required, baseline)
        verifier = (
            ROOT
            / "scripts"
            / "apple_mobile_framework_security_verify.py"
        ).read_text()
        for required in (
            "mesh-apple-ios-mobile-framework-security-receipt-v1",
            '"embedded_in_tunnel": False',
            '"physical_device_validated": False',
            "exact-inventory-present-legal-review-pending",
            ".gitleaks-apple-mobile.toml",
        ):
            self.assertIn(required, verifier)

    def test_ios_admin_security_gate_is_pinned_and_simulator_only(
        self,
    ) -> None:
        baseline = (
            ROOT / "scripts" / "apple-ios-admin-security-baseline.sh"
        ).read_text()
        for required in (
            "docker info",
            "--network=none",
            "SYFT_CHECK_FOR_APP_UPDATE=false",
            "GRYPE_CHECK_FOR_APP_UPDATE=false",
            "syft@sha256:86fde6445b483d",
            "grype@sha256:391bfda62888",
            "gitleaks@sha256:c00b6bd0aeb",
            "secret-scan text from every regular iOS app file",
            "normalize_code_resources",
            "source-receipt.json",
            "pub-deps.json",
            "NOTICES.Z",
            ".gitleaks-apple-ios-admin.toml",
        ):
            self.assertIn(required, baseline)
        verifier = (
            ROOT / "scripts" / "apple_ios_admin_security_verify.py"
        ).read_text()
        for required in (
            "mesh-apple-ios-admin-simulator-security-receipt-v1",
            '"physical_device_validated": False',
            '"distribution_validated": False',
            "packaged-inventory-reviewed-final-store-declarations-pending",
            ".gitleaks-apple-ios-admin.toml",
        ):
            self.assertIn(required, verifier)

    def test_ios_tunnel_security_gate_binds_static_engine_and_simulator_limits(
        self,
    ) -> None:
        baseline = (
            ROOT / "scripts" / "apple-ios-tunnel-security-baseline.sh"
        ).read_text()
        for required in (
            "docker info",
            "--network=none",
            "SYFT_CHECK_FOR_APP_UPDATE=false",
            "GRYPE_CHECK_FOR_APP_UPDATE=false",
            "syft@sha256:86fde6445b483d",
            "grype@sha256:391bfda62888",
            "gitleaks@sha256:c00b6bd0aeb",
            "Swift dependency graph is not the reviewed empty graph",
            "secret-scan strings from all ten product files",
            "source-receipt.json",
            "swift-dependencies.json",
            ".gitleaks-apple-ios-tunnel.toml",
        ):
            self.assertIn(required, baseline)
        verifier = (
            ROOT / "scripts" / "apple_ios_tunnel_security_verify.py"
        ).read_text()
        for required in (
            "mesh-apple-ios-tunnel-simulator-security-receipt-v1",
            '"engine_embedded": True',
            '"engine_linkage": "static"',
            "static_engine_runtime_module_count",
            '"packet_flow_connected": False',
            '"network_settings_applied": False',
            '"physical_device_validated": False',
            "reviewed-static-engine-runtime-module-inventory",
        ):
            self.assertIn(required, verifier)


if __name__ == "__main__":
    unittest.main()
