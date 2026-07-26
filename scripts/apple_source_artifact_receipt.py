#!/usr/bin/env python3
"""Inspect one unsigned macOS or iOS simulator app and emit a build receipt."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import pathlib
import platform
import plistlib
import re
import stat
import subprocess
import sys


MAXIMUM_FILES = 4096
MAXIMUM_BYTES = 1024 * 1024 * 1024
MAXIMUM_RECEIPT_BYTES = 64 * 1024
ROOT = pathlib.Path(__file__).resolve().parents[1]
IOS_TUNNEL = ROOT / "ios-tunnel"
FLUTTER_SDK_DECLARATION = ROOT / "desktop" / "tool" / "flutter-sdk.json"
DESKTOP_LOCK = ROOT / "desktop" / "pubspec.lock"
OBJECTIVE_C_VERSION = "9.4.1"
OBJECTIVE_C_SHA256 = "6cb691c686fa2838c6deb34980d426145c2a5d537491cb83d463c33cdbc726ed"
OBJECTIVE_C_ASSET_ID = "package:objective_c/objective_c.dylib"
OBJECTIVE_C_FRAMEWORK_PATH = "objective_c.framework/objective_c"
OBJECTIVE_C_INSTALL_NAME = "@rpath/objective_c.framework/objective_c"
MACOS_SOURCE_SCHEMA = "mesh-apple-macos-source-artifact-receipt-v2"
CANONICAL_SYMLINK_MODE = 0o777


class ReceiptError(RuntimeError):
    pass


def digest_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def command(*arguments: str) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            arguments,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
            env={"PATH": os.environ.get("PATH", ""), "LANG": "C"},
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ReceiptError(f"could not inspect Apple source artifact: {arguments[0]}") from exc


def declared_flutter_sdk() -> dict[str, object]:
    try:
        value = json.loads(FLUTTER_SDK_DECLARATION.read_text())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReceiptError("declared Flutter SDK input is invalid") from exc
    archives = value.get("archives") if isinstance(value, dict) else None
    if (
        not isinstance(value, dict)
        or value.get("version") != "3.44.8"
        or value.get("framework_commit")
        != "058e0af2c2b57e369d905a03ac9748b0ebf543c6"
        or not isinstance(archives, dict)
    ):
        raise ReceiptError("declared Flutter SDK input is not the reviewed release")
    return value


def locked_objective_c() -> dict[str, str]:
    try:
        lock = DESKTOP_LOCK.read_text()
    except OSError as exc:
        raise ReceiptError("desktop dependency lock is unavailable") from exc
    match = re.search(
        r"(?ms)^  objective_c:\n"
        r"    dependency: transitive\n"
        r"    description:\n"
        r"      name: objective_c\n"
        r'      sha256: "([0-9a-f]{64})"\n'
        r'      url: "https://pub\.dev"\n'
        r"    source: hosted\n"
        r'    version: "([^"]+)"\n',
        lock,
    )
    if (
        match is None
        or match.group(1) != OBJECTIVE_C_SHA256
        or match.group(2) != OBJECTIVE_C_VERSION
    ):
        raise ReceiptError("objective_c is not the reviewed locked dependency")
    return {"version": match.group(2), "sha256": match.group(1)}


def canonical_tree_mode(raw_mode: int) -> int:
    if stat.S_ISLNK(raw_mode):
        return CANONICAL_SYMLINK_MODE
    return stat.S_IMODE(raw_mode)


def tree_identity(root: pathlib.Path) -> tuple[str, int, int]:
    digest = hashlib.sha256()
    files = 0
    total = 0
    root_resolved = root.resolve(strict=True)
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        metadata = path.lstat()
        mode = canonical_tree_mode(metadata.st_mode)
        if stat.S_ISLNK(metadata.st_mode):
            # macOS archive tools do not preserve symlink permission bits.
            # They are not authorization bits on Darwin, so bind every
            # validated bundle symlink to one portable canonical mode.
            mode = CANONICAL_SYMLINK_MODE
            target = os.readlink(path)
            if os.path.isabs(target):
                raise ReceiptError(f"absolute bundle symlink is prohibited: {relative}")
            resolved = path.resolve(strict=True)
            if root_resolved != resolved and root_resolved not in resolved.parents:
                raise ReceiptError(f"bundle symlink escapes the application: {relative}")
            record = f"l {mode:04o} {target} {relative}\n"
        elif stat.S_ISDIR(metadata.st_mode):
            record = f"d {mode:04o} {relative}\n"
        elif stat.S_ISREG(metadata.st_mode):
            files += 1
            total += metadata.st_size
            if files > MAXIMUM_FILES or total > MAXIMUM_BYTES:
                raise ReceiptError("Apple source application exceeds its receipt bounds")
            record = (
                f"f {mode:04o} {metadata.st_size} {digest_file(path)} {relative}\n"
            )
        else:
            raise ReceiptError(f"unsupported application object: {relative}")
        digest.update(record.encode())
    return digest.hexdigest(), files, total


def load_receipt(path: pathlib.Path) -> tuple[dict[str, object], str]:
    if not path.is_file() or path.is_symlink():
        raise ReceiptError("Apple input receipt must be one physical regular file")
    before = path.stat()
    raw = path.read_bytes()
    after = path.stat()
    if (
        not raw
        or len(raw) > MAXIMUM_RECEIPT_BYTES
        or len(raw) != before.st_size
        or (before.st_dev, before.st_ino, before.st_mode, before.st_size, before.st_mtime_ns)
        != (after.st_dev, after.st_ino, after.st_mode, after.st_size, after.st_mtime_ns)
    ):
        raise ReceiptError("Apple input receipt is empty or oversized")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReceiptError("Apple input receipt is invalid") from exc
    source = value.get("source") if isinstance(value, dict) else None
    host = value.get("host") if isinstance(value, dict) else None
    inputs = value.get("inputs") if isinstance(value, dict) else None
    flutter = declared_flutter_sdk()
    flutter_archives = flutter["archives"]
    assert isinstance(flutter_archives, dict)
    declared_archive_digests = {
        str(archive.get("sha256"))
        for archive in flutter_archives.values()
        if isinstance(archive, dict)
    }
    if (
        not isinstance(value, dict)
        or value.get("schema") != "mesh-apple-source-build-receipt-v1"
        or not isinstance(source, dict)
        or re.fullmatch(r"[0-9a-f]{40}", str(source.get("commit", ""))) is None
        or not isinstance(source.get("clean"), bool)
        or not isinstance(host, dict)
        or host.get("xcode_version") != "26.5"
        or host.get("xcode_build") != "17F42"
        or host.get("flutter_version") != flutter["version"]
        or host.get("flutter_commit") != flutter["framework_commit"]
        or host.get("developer_directory")
        not in {
            "/Applications/Xcode.app/Contents/Developer",
            "/Applications/Xcode_26.5.0.app/Contents/Developer",
        }
        or not isinstance(inputs, dict)
        or any(
            re.fullmatch(r"[0-9a-f]{64}", str(inputs.get(name, ""))) is None
            for name in (
                "apple_build_sha256",
                "flutter_sdk_sha256",
                "flutter_archive_sha256",
                "nebula_certificate_tool_sha256",
            )
        )
        or inputs.get("flutter_archive_sha256") not in declared_archive_digests
        or value.get("preflight", {}).get("release_credentials_present") is not False
        or value.get("preflight", {}).get("source_keychain_code_signing_identities") != 0
    ):
        raise ReceiptError("Apple input receipt has the wrong schema or credential state")
    canonical = (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode()
    if raw != canonical:
        raise ReceiptError("Apple input receipt is not canonical JSON")
    return value, hashlib.sha256(raw).hexdigest()


def load_mobile_framework_receipt(
    path: pathlib.Path,
    *,
    input_receipt: dict[str, object],
    input_receipt_sha256: str,
) -> tuple[dict[str, object], str]:
    if not path.is_absolute() or not path.is_file() or path.is_symlink():
        raise ReceiptError(
            "MeshMobile source receipt must be one absolute physical file"
        )
    before = path.stat()
    raw = path.read_bytes()
    after = path.stat()
    if (
        not raw
        or len(raw) > 256 * 1024
        or stat.S_IMODE(before.st_mode) & 0o022
        or (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_size,
            before.st_mtime_ns,
        )
        != (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_size,
            after.st_mtime_ns,
        )
    ):
        raise ReceiptError("MeshMobile source receipt is unsafe or changed")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReceiptError("MeshMobile source receipt is invalid JSON") from exc
    canonical = (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode()
    source = value.get("source") if isinstance(value, dict) else None
    engine = value.get("engine") if isinstance(value, dict) else None
    framework = value.get("framework") if isinstance(value, dict) else None
    scope = value.get("scope") if isinstance(value, dict) else None
    if (
        not isinstance(value, dict)
        or raw != canonical
        or value.get("schema")
        != "mesh-apple-ios-mobile-framework-source-receipt-v1"
        or source != input_receipt["source"]
        or value.get("build_host") != input_receipt["host"]
        or value.get("build_inputs") != input_receipt["inputs"]
        or value.get("input_receipt_sha256") != input_receipt_sha256
        or not isinstance(engine, dict)
        or engine.get("framework_schema")
        != "mesh-ios-mobile-framework-v5"
        or engine.get("capability")
        != (
            "extension-enrollment-lifecycle-renewal-credential-rotation-"
            "mobile-evidence-identity-removal-signed-config-packet-session"
        )
        or engine.get("private_key_exported") is not False
        or not isinstance(framework, dict)
        or framework.get("name") != "MeshMobile.xcframework"
        or framework.get("exports")
        != [
            "IosmobileEnsureIdentity",
            "IosmobileFrameworkIdentity",
            "IosmobileFrameworkIdentitySHA256",
            "IosmobileNewEngineSession",
            "IosmobileNewEnrollmentSession",
            "IosmobileNewIdentityRemovalSession",
            "IosmobileNewLifecycleSession",
        ]
        or framework.get("signed") is not False
        or framework.get("reproducible") is not True
        or re.fullmatch(
            r"[0-9a-f]{64}",
            str(framework.get("tree_sha256", "")),
        )
        is None
        or not isinstance(scope, dict)
        or scope.get("embedded_in_tunnel") is not False
        or scope.get("packet_transport_implemented") is not True
        or scope.get("static_tunnel_link_validated") is not False
        or scope.get("physical_device_validated") is not False
        or scope.get("production_signing_used") is not False
    ):
        raise ReceiptError("MeshMobile source receipt boundary is not exact")
    return value, hashlib.sha256(raw).hexdigest()


def inspect_admin_native_assets(
    app: pathlib.Path,
    *,
    ios_admin: bool,
    architectures: list[str],
    input_receipt: dict[str, object],
) -> dict[str, object]:
    """Bound Flutter's known fat-asset naming warning to an exact safe output."""
    locked = locked_objective_c()
    host = input_receipt["host"]
    inputs = input_receipt["inputs"]
    assert isinstance(host, dict)
    assert isinstance(inputs, dict)
    flutter = declared_flutter_sdk()
    if (
        host.get("flutter_version") != flutter["version"]
        or host.get("flutter_commit") != flutter["framework_commit"]
    ):
        raise ReceiptError("native assets were not built by the reviewed Flutter SDK")

    framework_root = (
        app / "Frameworks" if ios_admin else app / "Contents" / "Frameworks"
    )
    expected_frameworks = (
        {"App.framework", "Flutter.framework", "objective_c.framework"}
        if ios_admin
        else {"App.framework", "FlutterMacOS.framework", "objective_c.framework"}
    )
    if (
        not framework_root.is_dir()
        or framework_root.is_symlink()
        or {
            path.name
            for path in framework_root.iterdir()
            if path.is_dir() and path.name.endswith(".framework")
        }
        != expected_frameworks
    ):
        raise ReceiptError("Mesh Admin framework inventory is not the reviewed minimum")

    framework = framework_root / "objective_c.framework"
    binary = (
        framework / "objective_c"
        if ios_admin
        else framework / "Versions" / "A" / "objective_c"
    )
    info_path = (
        framework / "Info.plist"
        if ios_admin
        else framework / "Versions" / "A" / "Resources" / "Info.plist"
    )
    manifest_path = (
        framework_root / "App.framework" / "flutter_assets" / "NativeAssetsManifest.json"
        if ios_admin
        else framework_root
        / "App.framework"
        / "Versions"
        / "A"
        / "Resources"
        / "flutter_assets"
        / "NativeAssetsManifest.json"
    )
    if (
        not binary.is_file()
        or binary.is_symlink()
        or not info_path.is_file()
        or info_path.is_symlink()
        or not manifest_path.is_file()
        or manifest_path.is_symlink()
    ):
        raise ReceiptError("reviewed objective_c native asset is incomplete")
    try:
        info = plistlib.loads(info_path.read_bytes())
        manifest = json.loads(manifest_path.read_bytes())
    except (OSError, plistlib.InvalidFileException, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReceiptError("objective_c native asset metadata is invalid") from exc
    if any(
        info.get(field) != value
        for field, value in {
            "CFBundleExecutable": "objective_c",
            "CFBundleIdentifier": "io.flutter.flutter.native-assets.objective-c",
            "CFBundleName": "objective_c",
            "CFBundlePackageType": "FMWK",
        }.items()
    ):
        raise ReceiptError("objective_c framework identity is unexpected")

    platform_prefix = "ios" if ios_admin else "macos"
    expected_targets: dict[str, object] = {}
    for architecture in architectures:
        suffix = "arm64" if architecture == "arm64" else "x64" if architecture == "x86_64" else None
        if suffix is None:
            raise ReceiptError("objective_c has an unsupported architecture")
        expected_targets[f"{platform_prefix}_{suffix}"] = {
            OBJECTIVE_C_ASSET_ID: ["absolute", OBJECTIVE_C_FRAMEWORK_PATH]
        }
    expected_manifest = {
        "format-version": [1, 0, 0],
        "native-assets": expected_targets,
    }
    if manifest != expected_manifest:
        raise ReceiptError("objective_c native asset manifest is not architecture-stable")

    lipo = command("lipo", "-archs", str(binary))
    if (
        lipo.returncode != 0
        or set(lipo.stdout.strip().split()) != set(architectures)
    ):
        raise ReceiptError("objective_c framework architectures are incomplete")
    install_names = command("otool", "-D", str(binary))
    names = [
        line.strip()
        for line in install_names.stdout.splitlines()
        if line.strip().startswith("@")
    ]
    if (
        install_names.returncode != 0
        or len(names) != len(architectures)
        or set(names) != {OBJECTIVE_C_INSTALL_NAME}
    ):
        raise ReceiptError("objective_c install names are not architecture-stable")
    if bundle_contains(app, b"objective_c1.framework"):
        raise ReceiptError("Flutter's transient objective_c1 name leaked into the bundle")

    return {
        "status": "verified-known-flutter-fat-asset-grouping-warning",
        "flutter_version": host["flutter_version"],
        "flutter_commit": host["flutter_commit"],
        "flutter_sdk_sha256": inputs["flutter_sdk_sha256"],
        "package": {
            "name": "objective_c",
            **locked,
        },
        "asset_id": OBJECTIVE_C_ASSET_ID,
        "framework_path": OBJECTIVE_C_FRAMEWORK_PATH,
        "install_name": OBJECTIVE_C_INSTALL_NAME,
        "architectures": sorted(architectures),
        "manifest_sha256": digest_file(manifest_path),
        "binary_sha256": digest_file(binary),
        "unexpected_transient_framework_present": False,
        "physical_execution_validated": False,
    }


def inspect_tunnel_source_boundary() -> dict[str, object]:
    paths = {
        "contract": IOS_TUNNEL / "Shared" / "TunnelContract.swift",
        "configuration_store": (
            IOS_TUNNEL / "Shared" / "TunnelConfigurationStore.swift"
        ),
        "apple_settings": (
            IOS_TUNNEL / "Shared" / "TunnelAppleNetworkSettings.swift"
        ),
        "packet_pump": IOS_TUNNEL / "Shared" / "TunnelPacketFlowPump.swift",
        "runtime_coordinator": (
            IOS_TUNNEL / "Shared" / "TunnelRuntimeCoordinator.swift"
        ),
        "provider_lifecycle_gate": (
            IOS_TUNNEL / "Shared" / "TunnelProviderLifecycleGate.swift"
        ),
        "provider": IOS_TUNNEL / "PacketTunnel" / "PacketTunnelProvider.swift",
        "runtime_adapters": (
            IOS_TUNNEL / "PacketTunnel" / "TunnelRuntimeAdapters.swift"
        ),
        "go_adapter": (
            IOS_TUNNEL / "PacketTunnel" / "GoTunnelEngineSession.swift"
        ),
        "host_controller": (
            IOS_TUNNEL
            / "MeshTunnelHost"
            / "MeshTunnelViewController.swift"
        ),
        "tunnel_log": IOS_TUNNEL / "PacketTunnel" / "TunnelLog.swift",
        "project": IOS_TUNNEL / "MeshTunnel.xcodeproj" / "project.pbxproj",
        "app_icon_manifest": (
            IOS_TUNNEL
            / "MeshTunnelHost"
            / "Assets.xcassets"
            / "AppIcon.appiconset"
            / "Contents.json"
        ),
    }
    icon_root = (
        IOS_TUNNEL
        / "MeshTunnelHost"
        / "Assets.xcassets"
        / "AppIcon.appiconset"
    )
    paths.update(
        {
            f"app_icon_{path.stem.replace('-', '_').replace('@', '_')}"
            f"{path.suffix.replace('.', '_')}": path
            for path in sorted(icon_root.glob("*.png"))
        }
    )
    try:
        sources = {name: path.read_text() for name, path in paths.items()}
    except UnicodeDecodeError:
        sources = {
            name: path.read_text()
            for name, path in paths.items()
            if path.suffix != ".png"
        }
    except OSError as exc:
        raise ReceiptError("Mesh Tunnel source boundary is unavailable") from exc
    for required in (
        'mesh-ios-tunnel-configuration-v4',
        'mesh-ios-tunnel-envelope-v4',
        'mesh-ios-tunnel-enrollment-v1',
        'mesh-ios-tunnel-control-outcome-v1',
        'mesh-ios-tunnel-evidence-v1',
        'mesh-ios-lifecycle-refresh-v1',
        'mesh-ios-nebula-engine-configuration-v1',
        'public static let startOptionKey = "meshEnrollmentRequest"',
        "public static let maximumDocumentBytes = 8 * 1024",
        "public static let primaryID = \"primary\"",
        "public static func normalizedOrigin(",
        "public let controlPlaneOrigin: String",
        "public let agentCredentialGeneration: UInt64",
        "public let agentCredentialExpiresAt: String",
        "public enum TunnelLifecycleRefreshStatus:",
        "public struct TunnelLifecycleRefreshOutcome:",
        "public struct TunnelControlOutcome:",
        "public static func decodeExact(_ data: Data) throws -> Self",
        'throw TunnelContractError.invalidField("runningEvidence")',
        'throw TunnelContractError.invalidField("nonRunningEvidence")',
        "try ContractField.httpsOrigin(",
        "try ContractField.base64URL(",
        "TunnelNebulaConfiguration",
        "TunnelNetworkSettingsPlan",
        "TunnelRemoteAddress",
        '"tunnelRemoteAddress"',
        "networkSettings.routeConflict",
        "networkSettings.remoteEndpointRoute",
        "try networkSettings.validateRemoteAddress(tunnelRemoteAddress)",
        "requireNestedObject(",
        'key: "nebula"',
        "let observedConfigDigest = Data(",
        "guard observedConfigDigest == configDigest",
        "let observedCADigest = Data(",
        "guard observedCADigest == caCertificateSHA256",
        "configIssued < certificateExpires",
        "certificateRenews < certificateExpires",
        "(1280...1500).contains(mtu)",
    ):
        if required not in sources["contract"]:
            raise ReceiptError("Mesh Tunnel settings contract is incomplete")
    for required in (
        "public func nextMonotonicCounter() throws -> UInt64",
        "let floor = max(",
        "try highWater.load()",
        "current?.monotonicCounter ?? 0",
        "guard floor < UInt64.max",
        "return floor + 1",
    ):
        if required not in sources["configuration_store"]:
            raise ReceiptError("Mesh Tunnel monotonic configuration store is incomplete")
    for required in (
        "NEPacketTunnelNetworkSettings(",
        "NEIPv4Settings(",
        "NEIPv6Settings(",
        "NEDNSSettings(",
        "tunnelRemoteAddress: TunnelRemoteAddress",
    ):
        if required not in sources["apple_settings"]:
            raise ReceiptError("Mesh Tunnel Apple settings mapping is incomplete")
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
        if required not in sources["packet_pump"]:
            raise ReceiptError("Mesh Tunnel packet pump boundary is incomplete")
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
        "TunnelRuntimeCoordinatorError.engineIdentityMismatch",
    ):
        if required not in sources["runtime_coordinator"]:
            raise ReceiptError("Mesh Tunnel runtime coordination is incomplete")
    if not (
        sources["runtime_coordinator"].index(
            "try await engine.prepare(configuration: configuration)"
        )
        < sources["runtime_coordinator"].index(
            "try await networkSettings.apply("
        )
        < sources["runtime_coordinator"].index("try await pump.start()")
        < sources["runtime_coordinator"].index("try await engine.start()")
    ):
        raise ReceiptError("Mesh Tunnel startup ordering is invalid")
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
        if required not in sources["runtime_adapters"]:
            raise ReceiptError("Mesh Tunnel provider adapters are incomplete")
    for required in (
        "@preconcurrency import MeshMobile",
        "protocol TunnelEnrollmentSession: Sendable",
        "protocol TunnelLifecycleSession: Sendable",
        "protocol TunnelIdentityRemovalSession: Sendable",
        "final class GoTunnelEnrollmentSession",
        "final class GoTunnelLifecycleSession",
        "final class GoTunnelIdentityRemovalSession",
        "IosmobileNewEnrollmentSession(",
        "IosmobileNewLifecycleSession(",
        "IosmobileNewIdentityRemovalSession(",
        "TunnelIdentityScope.primaryID",
        "session.enroll(",
        "lifecycle.reportRuntime(",
        "session.remove()",
        "TunnelConfigurationPayload.decodeExact",
        "enum TunnelEnrollmentSessionFactory",
        "enum TunnelLifecycleSessionFactory",
        "enum TunnelIdentityRemovalSessionFactory",
        "return try GoTunnelEnrollmentSession(",
        "return try GoTunnelLifecycleSession(",
        "return try GoTunnelIdentityRemovalSession(",
        "final class GoTunnelEngineSession",
        "IosmobileNewEngineSession(",
        "session.frameworkIdentity()",
        "session.prepare(document)",
        "session.start()",
        "session.rebind()",
        "session.send(packet)",
        "session.receive()",
        "session.stop()",
        "enum TunnelEngineSessionFactory",
        "return try GoTunnelEngineSession(",
    ):
        if required not in sources["go_adapter"]:
            raise ReceiptError("Mesh Tunnel Go engine adapter is incomplete")
    for forbidden in (
        "privateKey",
        "shell",
        "Process(",
        "executableURL",
    ):
        if forbidden in sources["go_adapter"]:
            raise ReceiptError("Mesh Tunnel Go adapter exposes a prohibited surface")
    for required in (
        "engine-unavailable",
        "private func resolveConfiguration(",
        "options.count == 1",
        "TunnelEnrollmentRequest.startOptionKey",
        "TunnelEnrollmentRequest.decodeExact",
        "store.nextMonotonicCounter()",
        "TunnelLifecycleSessionFactory.make()",
        "case .deferred:",
        "case .unauthorized:",
        "TunnelEnrollmentSessionFactory.make()",
        "store.stage(configuration)",
        "store.activateCandidate()",
        'code: "enrollment-request-rejected"',
        'code: "enrollment-failed"',
        "import Network",
        "NWPathMonitor()",
        "TunnelRuntimeCoordinator(",
        "TunnelEngineSessionFactory.make(",
        "ProviderPacketFlowSession(",
        "self.startPacketLoops(",
        "try await packetFlow.read()",
        "try await coordinator.sendFromApple(packets)",
        "try await coordinator.receiveForApple()",
        "try packetFlow.write(packets)",
        "self.startPathMonitoring(coordinator: coordinator)",
        "try await coordinator.rebind()",
        "stopPathMonitoring()",
        "cancelTunnelWithError(Self.failure(\"network-rebind-failed\"))",
        "cancelTunnelWithError(Self.failure(\"packet-flow-failed\"))",
        "let request = try? TunnelControlRequest.decodeExact(messageData)",
        "responseRuntime.runtimeEvidence(",
        "TunnelControlOutcome(",
        "requestID: request.requestID",
        "lifecycleGate.beginStart()",
        "lifecycleGate.mayContinueStart()",
        "lifecycleGate.markRunning()",
        "lifecycleGate.latchStop()",
        '"start-already-in-progress"',
        '"start-cancelled"',
    ):
        if required not in sources["provider"]:
            raise ReceiptError("Mesh Tunnel provider flow wiring is incomplete")
    for required in (
        "public final class TunnelProviderLifecycleGate",
        "case alreadyStarting",
        "case alreadyRunning",
        "public func mayContinueStart() -> Bool",
        "public func markRunning() -> Bool",
        "public func latchStop() -> Bool",
    ):
        if required not in sources["provider_lifecycle_gate"]:
            raise ReceiptError("Mesh Tunnel provider lifecycle gate is incomplete")
    provider_start_index = sources["provider"].index(
        "try await coordinator.start()"
    )
    provider_completion_index = sources["provider"].index(
        "completionHandler(nil)",
        provider_start_index,
    )
    if not (
        provider_start_index
        < sources["provider"].index(
            "self.startPathMonitoring(coordinator: coordinator)",
            provider_start_index,
        )
        < provider_completion_index
        < sources["provider"].index(
            "self.startPacketLoops(",
            provider_completion_index,
        )
    ):
        raise ReceiptError("Mesh Tunnel provider starts packet flow too early")
    if (
        "setTunnelNetworkSettings" in sources["provider"]
        or "provider.packetFlow" in sources["provider"]
        or "TunnelAppleNetworkSettingsFactory" in sources["provider"]
        or "setTunnelNetworkSettings" in sources["apple_settings"]
        or "packetFlow" in sources["apple_settings"]
        or "NetworkExtension" in sources["packet_pump"]
        or "NEPacketTunnelFlow" in sources["packet_pump"]
        or "packetFlow" in sources["runtime_coordinator"]
    ):
        raise ReceiptError("Mesh Tunnel provider is not fail-closed")
    for required in (
        "NETunnelProviderManager.loadAllFromPreferences",
        "TunnelEnrollmentRequest.normalizedOrigin(",
        "TunnelEnrollmentRequest(",
        "request.encoded()",
        "eraseTransientEnrollment()",
        "NETunnelProviderSession",
        "session.startTunnel(options:",
        "TunnelEnrollmentRequest.startOptionKey: data as NSData",
        "tunnelProtocol.serverAddress = origin",
        "tunnelProtocol.providerConfiguration = [",
        '"schema": TunnelEnrollmentRequest.schema',
        "manager.isOnDemandEnabled = false",
        "manager.onDemandRules = nil",
        "startExistingTunnel",
        "stopTunnel",
        "session.startTunnel()",
        "manager.connection.stopVPNTunnel()",
        "TunnelControlRequest(",
        "TunnelControlOutcome.decodeExact(response)",
        "outcome.requestID == request.requestID",
        "evidence.packetsRead",
        "evidence.packetsWritten",
        "do not by themselves prove",
        "UIScrollView()",
        "requireEnabled: false",
        "try await enableManager(",
        "manager.isEnabled = true",
        "if let manager = matches.first {",
        "prepareManagerBeforeAuthorization(",
        "confirmStaleManagerReplacement(",
        'title: "Replace disabled VPN configuration?"',
        'title: "Replace VPN configuration"',
        "try requireNoLocalIdentity()",
        "TunnelConfigurationStore.currentSlot",
        "TunnelConfigurationStore.candidateSlot",
        "TunnelConfigurationStore.recoverySlot",
        "guard !manager.isEnabled else {",
        "replaceStaleManager(",
        "try await remove(currentManager)",
        "return try await createManager(",
        "stage = .preparingManager",
        "stage = .verifyingManager",
        "guard setupTask == nil else {",
        "if completed {",
    ):
        if required not in sources["host_controller"]:
            raise ReceiptError("Mesh Tunnel host enrollment handoff is incomplete")
    setup_index = sources["host_controller"].index(
        "private func runAutomaticSetup("
    )
    setup_end = sources["host_controller"].index(
        "private func beginAuthorizationBrowser(",
        setup_index,
    )
    setup_source = sources["host_controller"][setup_index:setup_end]
    if not (
        setup_source.index("prepareManagerBeforeAuthorization(")
        < setup_source.index("TunnelUserEnrollmentClient(")
        < setup_source.index("startAuthorization()")
        < setup_source.index("createSelfEnrollment(")
    ):
        raise ReceiptError(
            "Mesh Tunnel does not stage manager readiness before authorization"
        )
    if not (
        setup_source.index("guard try validatedOrigin(for: manager) == origin")
        < setup_source.index("createSelfEnrollment(")
    ):
        raise ReceiptError(
            "Mesh Tunnel can request enrollment before manager readiness"
        )
    preflight_index = sources["host_controller"].index(
        "private func prepareManagerBeforeAuthorization("
    )
    preflight_end = sources["host_controller"].index(
        "private func confirmStaleManagerReplacement(",
        preflight_index,
    )
    preflight_source = sources["host_controller"][
        preflight_index:preflight_end
    ]
    if (
        "save(manager)" in preflight_source
        or "remove(" in preflight_source
        or not (
            preflight_source.index("guard !manager.isEnabled else {")
            < preflight_source.index("confirmStaleManagerReplacement(")
            < preflight_source.index("replaceStaleManager(")
        )
    ):
        raise ReceiptError(
            "Mesh Tunnel stale-manager preflight is not confirmation-gated"
        )
    replacement_index = sources["host_controller"].index(
        "private func replaceStaleManager("
    )
    replacement_end = sources["host_controller"].index(
        "private func createManager(",
        replacement_index,
    )
    replacement_source = sources["host_controller"][
        replacement_index:replacement_end
    ]
    remove_index = replacement_source.index(
        "try await remove(currentManager)"
    )
    if not (
        replacement_source.index("try requireNoLocalIdentity()")
        < remove_index
        and replacement_source.index("guard !expectedManager.isEnabled")
        < remove_index
        and "guard matches.count == 1" in replacement_source
        and "guard remaining.isEmpty else {" in replacement_source
        and replacement_source.count("try requireNoLocalIdentity()") >= 2
        and replacement_source.count("requireEnabled: false") >= 2
    ):
        raise ReceiptError(
            "Mesh Tunnel stale-manager replacement is not fail-closed"
        )
    for forbidden in (
        '"token":',
        '"enrollmentToken":',
        "providerConfiguration = [\n            \"schema\": "
        "TunnelEnrollmentRequest.schema,\n            \"token\"",
    ):
        if forbidden in sources["host_controller"]:
            raise ReceiptError(
                "Mesh Tunnel host stores enrollment credentials in VPN preferences"
            )
    for source_name in (
        "TunnelAppleNetworkSettings.swift",
        "TunnelPacketFlowPump.swift",
        "TunnelConfigurationStore.swift",
    ):
        if sources["project"].count(f"{source_name} in Sources") != 4:
            raise ReceiptError("Mesh Tunnel source is not compiled by both targets")
    for source_name in (
        "TunnelRuntimeCoordinator.swift",
        "TunnelRuntimeAdapters.swift",
        "GoTunnelEngineSession.swift",
        "TunnelProviderLifecycleGate.swift",
    ):
        if sources["project"].count(f"{source_name} in Sources") != 2:
            raise ReceiptError("Mesh Tunnel runtime source is not compiled by extension")
    if sources["project"].count("MeshTunnelViewController.swift in Sources") != 2:
        raise ReceiptError("Mesh Tunnel enrollment host is not compiled by the app")
    for required in (
        "import OSLog",
        "enum TunnelLogEvent: String, CaseIterable",
        "static func record(_ event: TunnelLogEvent)",
        'logger.notice("start-requested")',
        'logger.error("configuration-container-unavailable")',
        'logger.error("configuration-unavailable")',
        'logger.error("configuration-invalid")',
        'logger.error("enrollment-request-rejected")',
        'logger.error("enrollment-failed")',
        'logger.error("engine-unavailable")',
        'logger.error("network-rebind-failed")',
        'logger.error("packet-flow-failed")',
        'logger.notice("stop-requested")',
        'logger.notice("status-request-accepted")',
        'logger.error("status-request-rejected")',
        'logger.notice("identity-removal-requested")',
        'logger.notice("identity-removal-completed")',
        'logger.error("identity-removal-failed")',
    ):
        if required not in sources["tunnel_log"]:
            raise ReceiptError("Mesh Tunnel logging boundary is incomplete")
    if (
        "\\(" in sources["tunnel_log"]
        or "func record(_ event: String)" in sources["tunnel_log"]
        or sources["project"].count("TunnelLog.swift in Sources") != 2
    ):
        raise ReceiptError("Mesh Tunnel logging accepts dynamic text")
    for event in (
        ".startRequested",
        ".configurationContainerUnavailable",
        ".configurationUnavailable",
        ".configurationInvalid",
        ".enrollmentRequestRejected",
        ".enrollmentFailed",
        ".lifecycleRefreshDeferred",
        ".lifecycleRefreshFailed",
        ".agentAuthorizationRejected",
        ".engineUnavailable",
        ".networkRebindFailed",
        ".packetFlowFailed",
        ".stopRequested",
        ".statusRequestAccepted",
        ".statusRequestRejected",
        ".identityRemovalRequested",
        ".identityRemovalCompleted",
        ".identityRemovalFailed",
    ):
        if (
            f"TunnelLog.record({event})" not in sources["provider"]
            and f"event: {event}" not in sources["provider"]
        ):
            raise ReceiptError("Mesh Tunnel provider logging is incomplete")
    return {
        "network_settings_plan": "authenticated-validated-source-proven",
        "apple_settings_mapping": "coordinator-gated-provider-adapter-source-wired",
        "remote_endpoint": "authenticated-canonical-required",
        "packet_pump": "bounded-apple-flow-source-wired-static-engine",
        "runtime_coordinator": "ordered-rebind-cleanup-source-proven",
        "provider": (
            "coordinator-apple-flow-extension-enrollment-lifecycle-mobile-"
            "evidence-identity-removal-static-engine-network-path-source-wired"
        ),
        "engine_adapter": (
            "gomobile-extension-enrollment-lifecycle-renewal-credential-"
            "rotation-mobile-evidence-identity-removal-signed-config-packet-"
            "session-source-wired"
        ),
        "extension_logging": "fixed-reviewed-18-event-codes-only",
        "host_runtime_controls": (
            "request-bound-real-evidence-start-stop-inspect-source-proven"
        ),
        "host_manager_recovery": (
            "preauth-confirmed-disabled-no-identity-exact-replacement-source-proven"
        ),
        "physical_device_validated": False,
        "source_sha256": {
            name: digest_file(path)
            for name, path in paths.items()
        },
    }


def bundle_contains(root: pathlib.Path, marker: bytes) -> bool:
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        carry = b""
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                candidate = carry + chunk
                if marker in candidate:
                    return True
                carry = candidate[-max(len(marker) - 1, 0) :]
    return False


def inspect_admin_source_boundary() -> dict[str, object]:
    paths = {
        "diagnostic": (
            ROOT
            / "desktop"
            / "lib"
            / "core"
            / "support"
            / "apple_admin_diagnostic_bundle.dart"
        ),
        "controller": (
            ROOT / "desktop" / "lib" / "integration" / "mesh_app_controller.dart"
        ),
        "secure_session_store": (
            ROOT
            / "desktop"
            / "lib"
            / "core"
            / "auth"
            / "secure_session_store.dart"
        ),
        "secure_session_store_test": (
            ROOT
            / "desktop"
            / "test"
            / "core"
            / "auth"
            / "secure_session_store_test.dart"
        ),
        "controller_test": (
            ROOT
            / "desktop"
            / "test"
            / "integration"
            / "mesh_app_controller_test.dart"
        ),
        "presentation_models": (
            ROOT
            / "desktop"
            / "lib"
            / "shared"
            / "models"
            / "presentation_models.dart"
        ),
        "permission_gate": (
            ROOT
            / "desktop"
            / "lib"
            / "shared"
            / "widgets"
            / "permission_gate.dart"
        ),
        "networks_directory": (
            ROOT
            / "desktop"
            / "lib"
            / "features"
            / "network"
            / "networks_directory_screen.dart"
        ),
        "network_screen": (
            ROOT
            / "desktop"
            / "lib"
            / "features"
            / "network"
            / "network_screen.dart"
        ),
        "nodes_screen": (
            ROOT
            / "desktop"
            / "lib"
            / "features"
            / "nodes"
            / "nodes_screen.dart"
        ),
        "controller_authority_test": (
            ROOT
            / "desktop"
            / "test"
            / "integration"
            / "mesh_app_controller_browser_test.dart"
        ),
        "browser_api_test": (
            ROOT
            / "desktop"
            / "test"
            / "integration"
            / "mesh_api_auth_test.dart"
        ),
        "json_transport": (
            ROOT
            / "desktop"
            / "lib"
            / "core"
            / "transport"
            / "json_transport.dart"
        ),
        "json_transport_test": (
            ROOT
            / "desktop"
            / "test"
            / "core"
            / "transport"
            / "json_transport_test.dart"
        ),
        "real_control_plane_test": (
            ROOT
            / "desktop"
            / "test"
            / "integration"
            / "mesh_api_real_control_plane_test.dart"
        ),
        "external_control_plane_test": (
            ROOT
            / "desktop"
            / "test"
            / "integration"
            / "mesh_api_external_control_plane_test.dart"
        ),
        "permission_presentation_test": (
            ROOT
            / "desktop"
            / "test"
            / "widget"
            / "app_shell_test.dart"
        ),
        "mobile_security": (
            ROOT
            / "desktop"
            / "lib"
            / "core"
            / "platform"
            / "mobile_security.dart"
        ),
        "managed_configuration": (
            ROOT
            / "desktop"
            / "lib"
            / "core"
            / "platform"
            / "apple_managed_configuration.dart"
        ),
        "managed_configuration_test": (
            ROOT
            / "desktop"
            / "test"
            / "core"
            / "platform"
            / "apple_managed_configuration_test.dart"
        ),
        "notifications": (
            ROOT
            / "desktop"
            / "lib"
            / "core"
            / "platform"
            / "apple_admin_notifications.dart"
        ),
        "notifications_test": (
            ROOT
            / "desktop"
            / "test"
            / "core"
            / "platform"
            / "apple_admin_notifications_test.dart"
        ),
        "connection_screen": (
            ROOT
            / "desktop"
            / "lib"
            / "features"
            / "auth"
            / "connection_screen.dart"
        ),
        "preferences": (
            ROOT
            / "desktop"
            / "lib"
            / "features"
            / "preferences"
            / "preferences_screen.dart"
        ),
        "app_shell": ROOT / "desktop" / "lib" / "app" / "app_shell.dart",
        "theme": (
            ROOT / "desktop" / "lib" / "shared" / "theme" / "mesh_theme.dart"
        ),
        "fleet": (
            ROOT
            / "desktop"
            / "lib"
            / "features"
            / "fleet"
            / "fleet_screen.dart"
        ),
        "evidence_badge": (
            ROOT
            / "desktop"
            / "lib"
            / "shared"
            / "widgets"
            / "evidence_badge.dart"
        ),
        "mobile_accessibility_test": (
            ROOT
            / "desktop"
            / "test"
            / "widget"
            / "mobile_accessibility_test.dart"
        ),
        "ios_log": (
            ROOT / "desktop" / "ios" / "Runner" / "MeshAdminLog.swift"
        ),
        "ios_managed_configuration": (
            ROOT
            / "desktop"
            / "ios"
            / "Runner"
            / "AppleManagedConfiguration.swift"
        ),
        "ios_app_delegate": (
            ROOT / "desktop" / "ios" / "Runner" / "AppDelegate.swift"
        ),
        "ios_notifications": (
            ROOT
            / "desktop"
            / "ios"
            / "Runner"
            / "AppleAdminNotifications.swift"
        ),
        "macos_log": (
            ROOT / "desktop" / "macos" / "Runner" / "MeshAdminLog.swift"
        ),
        "macos_managed_configuration": (
            ROOT
            / "desktop"
            / "macos"
            / "Runner"
            / "AppleManagedConfiguration.swift"
        ),
        "macos_main_window": (
            ROOT / "desktop" / "macos" / "Runner" / "MainFlutterWindow.swift"
        ),
        "macos_notifications": (
            ROOT
            / "desktop"
            / "macos"
            / "Runner"
            / "AppleAdminNotifications.swift"
        ),
        "macos_custody_events": (
            ROOT
            / "desktop"
            / "macos"
            / "Runner"
            / "MacCustodyEvents.swift"
        ),
        "macos_admin_menu": (
            ROOT / "desktop" / "macos" / "Runner" / "MacAdminMenu.swift"
        ),
        "dart_admin_menu": (
            ROOT
            / "desktop"
            / "lib"
            / "core"
            / "platform"
            / "macos_admin_menu.dart"
        ),
        "main_entry": ROOT / "desktop" / "lib" / "main.dart",
        "macos_runner_tests": (
            ROOT / "desktop" / "macos" / "RunnerTests" / "RunnerTests.swift"
        ),
        "ios_project": (
            ROOT / "desktop" / "ios" / "Runner.xcodeproj" / "project.pbxproj"
        ),
        "macos_project": (
            ROOT / "desktop" / "macos" / "Runner.xcodeproj" / "project.pbxproj"
        ),
        "macos_build": ROOT / "scripts" / "apple-source-build.sh",
        "ios_build": ROOT / "scripts" / "apple-ios-source-build.sh",
        "ios_managed_application_configuration": (
            ROOT
            / "packaging"
            / "apple"
            / "managed-configuration"
            / "ios-admin-managed-configuration.plist"
        ),
        "macos_managed_profile": (
            ROOT
            / "packaging"
            / "apple"
            / "managed-configuration"
            / "macos-admin.mobileconfig"
        ),
        "managed_configuration_readme": (
            ROOT
            / "packaging"
            / "apple"
            / "managed-configuration"
            / "README.md"
        ),
        "managed_configuration_verifier": (
            ROOT / "scripts" / "apple_managed_configuration_verify.py"
        ),
        "pubspec_lock": DESKTOP_LOCK,
        "flutter_sdk_declaration": FLUTTER_SDK_DECLARATION,
        "source_artifact_receipt": pathlib.Path(__file__).resolve(),
    }
    try:
        sources = {name: path.read_text() for name, path in paths.items()}
    except OSError as exc:
        raise ReceiptError("Mesh Admin source boundary is unavailable") from exc
    for required in (
        "mesh-apple-admin-diagnostic-v2",
        "maximumBytes = 16 * 1024",
        "'automatic_collection': false",
        "'automatic_upload': false",
        "'application_persistence': false",
        "'channel': 'system-clipboard'",
        "'expires_after_seconds': 120",
        "'recipient_deletion_enforced_by_mesh': false",
        "raw-error-text",
        "logs-and-arbitrary-files",
    ):
        if required not in sources["diagnostic"]:
            raise ReceiptError("Mesh Admin diagnostic contract is incomplete")
    for required in (
        "fleet-warning",
        "fleet-critical",
        "requestAuthorization",
        "deliver",
    ):
        if required not in sources["notifications"]:
            raise ReceiptError("Mesh Admin notification contract is incomplete")
    for required in (
        "api.currentSession()",
        "_sameSessionIdentity",
        "_samePermissions",
        "_eraseOneTimeMaterial()",
        "The Mesh session expired. Sign in again.",
        "The Mesh session identity changed unexpectedly. Sign in again.",
    ):
        if required not in sources["controller"]:
            raise ReceiptError("Mesh Admin session-authority refresh is incomplete")
    for required in (
        "mesh.desktop.connection-profiles.v1",
        "mesh-desktop-connection-profiles-v1",
        "maximumConnectionProfiles = 8",
        "Future<void> clear() => _storage.delete(storageKey)",
        "Future<void> clearConnectionProfiles()",
    ):
        if required not in sources["secure_session_store"]:
            raise ReceiptError("Mesh Admin saved-profile custody is incomplete")
    for required in (
        "_loadConnectionProfiles()",
        "_persistConnectionProfiles()",
        "await _sessionStore.clear().catchError",
        "await _sessionStore.saveConnectionProfiles",
    ):
        if required not in sources["controller"]:
            raise ReceiptError("Mesh Admin saved-profile lifecycle is incomplete")
    for required in (
        "clearing a session preserves saved connection profiles",
        "fails closed on malformed saved profiles without exposing data",
        "refuses duplicate or excessive saved connection profiles",
    ):
        if required not in sources["secure_session_store_test"]:
            raise ReceiptError("Mesh Admin saved-profile storage tests are incomplete")
    if (
        "saved control plane survives sign-out and controller restart without a session"
        not in sources["controller_test"]
    ):
        raise ReceiptError("Mesh Admin saved-profile restart test is incomplete")
    for name in (
        "app_shell",
        "networks_directory",
        "network_screen",
        "nodes_screen",
        "permission_gate",
    ):
        if "permissions" not in sources[name]:
            raise ReceiptError("Mesh Admin exact permission presentation is incomplete")
    for required in (
        "authoritative refresh applies permission downgrade",
        "server-side session revocation signs out",
        "transient completion interruption retries within the original expiry",
        "transient completion interruption cannot extend the original expiry",
        "oneTimeSecret",
        "isNot(contains(SecureSessionStore.storageKey))",
    ):
        if required not in sources["controller_authority_test"]:
            raise ReceiptError("Mesh Admin session-authority tests are incomplete")
    for required in (
        "error.statusCode == 429 || error.statusCode == 503",
        "!attempt.isExpiredAt(_now().toUtc())",
    ):
        if required not in sources["controller"]:
            raise ReceiptError("Mesh Admin browser interruption handling is incomplete")
    if (
        "https://other.example/?mesh_desktop_request=$_requestId"
        not in sources["browser_api_test"]
    ):
        raise ReceiptError("Mesh Admin cross-origin browser test is incomplete")
    if (
        "..set(HttpHeaders.acceptEncodingHeader, 'identity')"
        not in sources["json_transport"]
        or "encodings.single.toLowerCase() != 'identity'"
        not in sources["json_transport"]
        or "expect(seen.first['accept_encoding'], 'identity')"
        not in sources["json_transport_test"]
    ):
        raise ReceiptError("Mesh Admin bounded response-encoding policy is incomplete")
    for required in (
        "browserApi.completeDesktopAuthorization(browserAttempt)",
        "HttpStatus.unauthorized",
    ):
        if required not in sources["real_control_plane_test"]:
            raise ReceiptError("Mesh Admin authorization replay test is incomplete")
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
        if required not in sources["external_control_plane_test"]:
            raise ReceiptError("Mesh Admin external control-plane test is incomplete")
    for forbidden in (
        "api.loginWithLegacyToken",
        "restoredApi",
        "api.logout",
    ):
        if forbidden in sources["external_control_plane_test"]:
            raise ReceiptError("Mesh Admin external control-plane test is unsafe")
    for required in (
        "exact server permissions override role-derived privileged affordances",
        "permissions: const <MeshPermission>{MeshPermission.networksRead}",
        "find.byKey(const Key('new-network-button'))",
    ):
        if required not in sources["permission_presentation_test"]:
            raise ReceiptError("Mesh Admin exact permission UI test is incomplete")
    for name in ("ios_notifications", "macos_notifications"):
        for required in (
            "AppleAdminNotificationEvent: String, CaseIterable",
            "Open Mesh Admin to review fresh authoritative evidence.",
            "arguments.count == 1",
            "UNNotificationRequest(",
        ):
            if required not in sources[name]:
                raise ReceiptError("Mesh Admin native notification boundary is incomplete")
    if (
        sources["ios_project"].count("AppleAdminNotifications.swift in Sources") != 2
        or sources["macos_project"].count("AppleAdminNotifications.swift in Sources")
        != 2
    ):
        raise ReceiptError("Mesh Admin notification source is not compiled")
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
        if required not in sources["macos_custody_events"]:
            raise ReceiptError("Mesh Admin macOS custody events are incomplete")
    if sources["macos_project"].count("MacCustodyEvents.swift in Sources") != 2:
        raise ReceiptError("Mesh Admin macOS custody source is not compiled")
    for required in (
        'channelName = "io.rw0.mesh.admin/macos-menu-v1"',
        'return "refresh"',
        'return "preferences"',
        'title: "Refresh"',
        "arguments: nil",
    ):
        if required not in sources["macos_admin_menu"]:
            raise ReceiptError("Mesh Admin native menu boundary is incomplete")
    for required in (
        "enum MacAdminMenuCommand { refresh, preferences }",
        "'refresh' => MacAdminMenuCommand.refresh",
        "'preferences' => MacAdminMenuCommand.preferences",
    ):
        if required not in sources["dart_admin_menu"]:
            raise ReceiptError("Mesh Admin Dart menu boundary is incomplete")
    if (
        "defaultTargetPlatform == TargetPlatform.macOS"
        not in sources["main_entry"]
        or "const Stream<MacAdminMenuCommand>.empty()"
        not in sources["main_entry"]
    ):
        raise ReceiptError("Mesh Admin native menu is not isolated to macOS")
    for required in (
        "fixed native macOS menu commands refresh and open preferences",
        "testMacAdminMenuInstallsNativePreferencesAndRefreshActions",
        "testMacCustodyEventsMapOnlyLockSleepHideCloseAndTermination",
    ):
        if (
            required not in sources["permission_presentation_test"]
            and required not in sources["macos_runner_tests"]
        ):
            raise ReceiptError("Mesh Admin macOS menu/custody tests are incomplete")
    if sources["macos_project"].count("MacAdminMenu.swift in Sources") != 2:
        raise ReceiptError("Mesh Admin native menu source is not compiled")
    for required in (
        "copyDiagnosticBundle",
        "MESH_APP_VERSION",
        "MESH_APP_BUILD",
        "MESH_SOURCE_COMMIT",
        "did not upload or persist",
        "void selectNetwork(String networkId) {\n    _eraseOneTimeMaterial();",
        "void clearSelectedNetwork() {\n    _eraseOneTimeMaterial();",
    ):
        if required not in sources["controller"]:
            raise ReceiptError("Mesh Admin diagnostic controller is incomplete")
    if (
        "nothing was copied" not in sources["mobile_security"]
        or "} on MissingPluginException {\n      await Clipboard.setData"
        in sources["mobile_security"]
    ):
        raise ReceiptError("Mesh Admin iOS clipboard boundary is not fail-closed")
    if (
        "Copy bounded diagnostic bundle" not in sources["preferences"]
        or "never uploaded automatically" not in sources["preferences"]
    ):
        raise ReceiptError("Mesh Admin diagnostic action is incomplete")
    for required in (
        "Future<void> clearAll() async",
        "await clear();",
        "await clearConnectionProfiles();",
        "Secure local data could not be fully erased.",
    ):
        if required not in sources["secure_session_store"]:
            raise ReceiptError("Mesh Admin exact local-data erasure is incomplete")
    for required in (
        "void eraseLocalData()",
        "await _sessionStore.clearAll();",
        "Server-side session revocation could not be confirmed",
        "separately installed Mesh Node",
    ):
        if required not in sources["controller"]:
            raise ReceiptError("Mesh Admin local-data erasure controller is incomplete")
    for required in (
        "erase-local-data-button",
        "confirm-erase-local-data-button",
        "Erase local Mesh Admin data?",
        "organization-managed",
        "operating-system permissions",
        "separately installed Mesh Node",
    ):
        if required not in sources["preferences"]:
            raise ReceiptError("Mesh Admin local-data erasure action is incomplete")
    for required in (
        "clearAll attempts and deletes both exact secure-storage records",
        "clearAll still attempts the second record after a delete failure",
        "current Admin loads and preserves frozen v1 Keychain state from an earlier build",
        "future or unknown local-state schemas fail closed during upgrade",
    ):
        if required not in sources["secure_session_store_test"]:
            raise ReceiptError(
                "Mesh Admin local-data erasure or upgrade storage tests are incomplete"
            )
    for required in (
        "confirmed local erasure removes both exact secure records",
        "revocation could not be confirmed",
    ):
        if required not in sources["controller_test"]:
            raise ReceiptError("Mesh Admin local-data erasure controller tests are incomplete")
    if (
        "Apple local-data erasure requires exact confirmation"
        not in sources["permission_presentation_test"]
    ):
        raise ReceiptError("Mesh Admin local-data erasure UI test is incomplete")
    for required in (
        "MeshWindowMetrics.iosNavigationBreakpoint",
        "iosLandscapeHeightBreakpoint",
        "TargetPlatform.iOS",
    ):
        if required not in sources["app_shell"]:
            raise ReceiptError("Mesh Admin iOS navigation boundary is incomplete")
    if (
        "iosNavigationBreakpoint = 1100" not in sources["theme"]
        or "iosLandscapeHeightBreakpoint = 600" not in sources["theme"]
        or "WrapCrossAlignment.center" not in sources["fleet"]
        or "TextOverflow.ellipsis" in sources["evidence_badge"]
        or "maxLines: 1" in sources["evidence_badge"]
    ):
        raise ReceiptError("Mesh Admin enlarged-text layout is incomplete")
    for required in (
        "const Size(390, 844)",
        "const Size(844, 390)",
        "const Size(694, 1024)",
        "const Size(1024, 1366)",
        "const Size(1366, 1024)",
        "<double>[1, 2, 3.2]",
        "FakeAccessibilityFeatures.allOn",
        "labeledTapTargetGuideline",
        "iOSTapTargetGuideline",
        "textContrastGuideline",
    ):
        if required not in sources["mobile_accessibility_test"]:
            raise ReceiptError("Mesh Admin mobile accessibility evidence is incomplete")
    for name in ("ios_log", "macos_log"):
        for required in (
            "import OSLog",
            "private static let logger = Logger(",
            "static func record(_ event: MeshAdminLogEvent)",
            'logger.notice("application-started")',
            'logger.error("expiring-copy-rejected")',
        ):
            if required not in sources[name]:
                raise ReceiptError("Mesh Admin Unified Logging boundary is incomplete")
        if "\\(" in sources[name] or "func record(_ event: String)" in sources[name]:
            raise ReceiptError("Mesh Admin Unified Logging accepts dynamic text")
    if (
        sources["ios_project"].count("MeshAdminLog.swift in Sources") != 2
        or sources["macos_project"].count("MeshAdminLog.swift in Sources") != 2
    ):
        raise ReceiptError("Mesh Admin Unified Logging is not compiled")
    for required in (
        "mesh-apple-managed-configuration-v1",
        "ControlPlaneOrigin",
        "AllowOriginChanges",
        "ReleaseChannel",
        "UpdateRing",
        "ShowLocalStatus",
        "NotificationsEnabled",
        "value.keys.any",
        "enforceControlPlaneOrigin",
    ):
        if required not in sources["managed_configuration"]:
            raise ReceiptError("Mesh Admin managed-configuration boundary is incomplete")
    for name in ("ios_managed_configuration", "macos_managed_configuration"):
        for required in (
            "mesh-apple-managed-configuration-v1",
            "static let allowedKeys: Set<String>",
            "Set(raw.keys).isSubset(of: allowedKeys)",
            "CFBooleanGetTypeID()",
            'components.scheme == "https"',
        ):
            if required not in sources[name]:
                raise ReceiptError("Native managed-configuration validation is incomplete")
    if (
        "com.apple.configuration.managed"
        not in sources["ios_managed_configuration"]
        or "managedValues("
        not in sources["macos_managed_configuration"]
        or "defaults.dictionaryRepresentation()"
        not in sources["macos_managed_configuration"]
        or "objectIsForced(forKey: key, inDomain: bundleIdentifier)"
        not in sources["macos_managed_configuration"]
        or "io.rw0.mesh.admin/managed-configuration-v1"
        not in sources["ios_app_delegate"]
        or "io.rw0.mesh.admin/managed-configuration-v1"
        not in sources["macos_main_window"]
        or sources["ios_project"].count(
            "AppleManagedConfiguration.swift in Sources"
        )
        != 2
        or sources["macos_project"].count(
            "AppleManagedConfiguration.swift in Sources"
        )
        != 2
    ):
        raise ReceiptError("Native managed-configuration bridge is not compiled")
    if (
        "locked managed origin removes the local connection form"
        not in sources["connection_screen"]
        and "originLocked" not in sources["connection_screen"]
    ):
        raise ReceiptError("Managed origin is not represented in the connection UI")
    try:
        managed_verification = subprocess.run(
            [
                sys.executable,
                str(paths["managed_configuration_verifier"]),
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
            env={"PATH": os.environ.get("PATH", ""), "LANG": "C"},
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ReceiptError(
            "Apple managed-configuration verification was unavailable"
        ) from exc
    if (
        managed_verification.returncode != 0
        or managed_verification.stdout
        != "apple managed-configuration source examples verified\n"
    ):
        raise ReceiptError("Apple managed-configuration examples are invalid")
    for name in ("macos_build", "ios_build"):
        for required in (
            "MESH_APP_VERSION=0.1.0",
            "MESH_APP_BUILD=1",
            "MESH_SOURCE_COMMIT=${source_commit}",
            "Apple input receipt source commit is invalid",
        ):
            if required not in sources[name]:
                raise ReceiptError("Mesh Admin build identity binding is incomplete")
    return {
        "diagnostic_schema": "mesh-apple-admin-diagnostic-v2",
        "diagnostic_maximum_bytes": 16 * 1024,
        "diagnostic_copy": (
            "operator-initiated-platform-retention-disclosed-not-uploaded-not-persisted"
        ),
        "notifications": "fixed-warning-critical-foreground-poll-transitions",
        "macos_lock_sleep_custody": "fixed-data-free-native-events-source-proven",
        "macos_hide_close_custody": (
            "fixed-data-free-native-events-source-proven"
        ),
        "macos_menu": "fixed-refresh-preferences-data-free-source-proven",
        "network_context_custody": "operator-selection-erases-one-time-material",
        "session_authority": (
            "foreground-poll-exact-permissions-revocation-fail-closed"
        ),
        "browser_authorization": (
            "same-origin-expiring-transient-retry-one-time-completion"
        ),
        "ios_clipboard": "local-only-expiring-fail-closed",
        "unified_logging": "fixed-reviewed-event-codes-only",
        "mobile_accessibility": (
            "widget-matrix-source-proven-physical-review-pending"
        ),
        "managed_configuration": (
            "strict-non-secret-source-proven-unsigned-profile"
        ),
        "local_data_erasure": (
            "exact-session-profile-keychain-deletion-confirmed-retention-"
            "disclosed-source-proven"
        ),
        "local_state_upgrade": (
            "frozen-v1-session-profile-compatibility-unknown-schema-"
            "fail-closed-source-proven"
        ),
        "release_identity_embedded": True,
        "physical_device_validated": False,
        "source_sha256": {
            name: digest_file(path)
            for name, path in paths.items()
        },
    }


def inspect(args: argparse.Namespace) -> dict[str, object]:
    app = pathlib.Path(args.app)
    if not app.is_absolute() or not app.is_dir() or app.is_symlink():
        raise ReceiptError("Apple source application must be one physical bundle")
    input_receipt, input_digest = load_receipt(pathlib.Path(args.input_receipt))
    ios_admin = args.platform == "ios-simulator"
    ios_tunnel = args.platform == "ios-tunnel-simulator"
    ios_simulator = ios_admin or ios_tunnel
    mobile_framework: dict[str, object] | None = None
    mobile_framework_digest: str | None = None
    if ios_tunnel:
        raw_framework_receipt = getattr(
            args,
            "mobile_framework_receipt",
            None,
        )
        raw_framework = getattr(args, "mobile_framework", None)
        if (
            not isinstance(raw_framework_receipt, str)
            or not raw_framework_receipt
            or not isinstance(raw_framework, str)
            or not raw_framework
        ):
            raise ReceiptError(
                "iOS Tunnel source receipt requires MeshMobile and its source receipt"
            )
        mobile_framework, mobile_framework_digest = (
            load_mobile_framework_receipt(
                pathlib.Path(raw_framework_receipt),
                input_receipt=input_receipt,
                input_receipt_sha256=input_digest,
            )
        )
        framework_path = pathlib.Path(raw_framework)
        if (
            not framework_path.is_absolute()
            or not framework_path.is_dir()
            or framework_path.is_symlink()
            or framework_path.name != "MeshMobile.xcframework"
        ):
            raise ReceiptError("MeshMobile must be one absolute physical XCFramework")
        framework_identity = tree_identity(framework_path)
        framework_record = mobile_framework["framework"]
        assert isinstance(framework_record, dict)
        if framework_identity != (
            framework_record["tree_sha256"],
            framework_record["regular_files"],
            framework_record["regular_file_bytes"],
        ):
            raise ReceiptError(
                "MeshMobile differs from its source receipt before tunnel link"
            )
    elif (
        getattr(args, "mobile_framework_receipt", None) is not None
        or getattr(args, "mobile_framework", None) is not None
    ):
        raise ReceiptError(
            "MeshMobile inputs are accepted only for the iOS Tunnel source build"
        )
    info_path = app / ("Info.plist" if ios_simulator else "Contents/Info.plist")
    try:
        info = plistlib.loads(info_path.read_bytes())
    except (OSError, plistlib.InvalidFileException) as exc:
        raise ReceiptError("Apple source application Info.plist is invalid") from exc
    expected = (
        {
            "CFBundleDisplayName": "Mesh Admin",
            "CFBundleIdentifier": "io.rw0.mesh.admin.mobile",
            "CFBundleExecutable": "Runner",
            "MinimumOSVersion": "17.0",
            "DTPlatformName": "iphonesimulator",
            "DTXcode": "2650",
            "DTXcodeBuild": "17F42",
            "DTSDKName": "iphonesimulator26.5",
        }
        if ios_admin
        else {
            "CFBundleDisplayName": "Mesh Tunnel",
            "CFBundleIdentifier": "io.rw0.mesh.tunnel.mobile",
            "CFBundleExecutable": "Mesh Tunnel",
            "MinimumOSVersion": "17.0",
            "DTPlatformName": "iphonesimulator",
            "DTXcode": "2650",
            "DTXcodeBuild": "17F42",
            "DTSDKName": "iphonesimulator26.5",
        }
        if ios_tunnel
        else {
            "CFBundleDisplayName": "Mesh Admin",
            "CFBundleIdentifier": "io.rw0.mesh.admin",
            "CFBundleExecutable": "Mesh Admin",
            "LSMinimumSystemVersion": "14.0",
            "DTXcode": "2650",
            "DTXcodeBuild": "17F42",
            "DTSDKName": "macosx26.5",
        }
    )
    for field, value in expected.items():
        if info.get(field) != value:
            raise ReceiptError(f"Apple source application has unexpected {field}")

    executable = (
        app / expected["CFBundleExecutable"]
        if ios_simulator
        else app / "Contents" / "MacOS" / "Mesh Admin"
    )
    if not executable.is_file() or executable.is_symlink():
        raise ReceiptError("Apple source application executable is missing")
    lipo = command("lipo", "-archs", str(executable))
    if lipo.returncode != 0:
        raise ReceiptError("Apple source application architecture inspection failed")
    architectures = lipo.stdout.strip().split()
    expected_privacy = {
        "NSPrivacyAccessedAPITypes": (
            [
                {
                    "NSPrivacyAccessedAPIType": (
                        "NSPrivacyAccessedAPICategoryUserDefaults"
                    ),
                    "NSPrivacyAccessedAPITypeReasons": ["AC6B.1"],
                }
            ]
            if not ios_tunnel
            else []
        ),
        "NSPrivacyCollectedDataTypes": [],
        "NSPrivacyTracking": False,
        "NSPrivacyTrackingDomains": [],
    }
    privacy_path = (
        app / "PrivacyInfo.xcprivacy"
        if ios_simulator
        else app / "Contents" / "Resources" / "PrivacyInfo.xcprivacy"
    )
    try:
        privacy = plistlib.loads(privacy_path.read_bytes())
    except (OSError, plistlib.InvalidFileException) as exc:
        raise ReceiptError("Apple source privacy manifest is invalid") from exc
    if privacy != expected_privacy:
        raise ReceiptError(
            "Apple source privacy manifest is not the reviewed minimum"
        )

    if ios_simulator:
        if args.configuration != "debug":
            raise ReceiptError("iOS simulator source receipt requires Debug")
        if set(architectures) != {"arm64", "x86_64"}:
            raise ReceiptError("iOS simulator source application is not universal")
        if info.get("CFBundleSupportedPlatforms") != ["iPhoneSimulator"]:
            raise ReceiptError("iOS source application is not simulator-only")
        if info.get("UIDeviceFamily") != [1, 2]:
            raise ReceiptError("iOS source application does not support iPhone and iPad")
        extension_receipt: dict[str, object] | None = None
        if ios_tunnel:
            assert mobile_framework is not None
            assert mobile_framework_digest is not None
            extension_receipt = inspect_tunnel_extension(
                app,
                architectures,
                mobile_framework=mobile_framework,
                mobile_framework_sha256=mobile_framework_digest,
            )
    elif args.configuration == "release":
        if set(architectures) != {"arm64", "x86_64"}:
            raise ReceiptError("release source application is not universal")
    elif architectures != [platform.machine()]:
        raise ReceiptError("debug source application does not match the native host")

    signature = command("codesign", "--verify", "--deep", "--strict", str(app))
    if signature.returncode == 0:
        raise ReceiptError("unsigned source application unexpectedly has a valid signature")

    admin_source_boundary: dict[str, object] | None = None
    native_assets: dict[str, object] | None = None
    if not ios_tunnel:
        admin_source_boundary = inspect_admin_source_boundary()
        native_assets = inspect_admin_native_assets(
            app,
            ios_admin=ios_admin,
            architectures=architectures,
            input_receipt=input_receipt,
        )
        diagnostic_schema = b"mesh-apple-admin-diagnostic-v2"
        for marker in (
            diagnostic_schema,
            str(input_receipt["source"]["commit"]).encode(),
        ):
            if not bundle_contains(app, marker):
                raise ReceiptError(
                    "Mesh Admin build omitted its diagnostic or source identity"
                )
        if diagnostic_schema.decode() != admin_source_boundary[
            "diagnostic_schema"
        ]:
            raise ReceiptError("Mesh Admin diagnostic identity is inconsistent")

    tree_digest, file_count, total_bytes = tree_identity(app)
    return {
        "schema": (
            "mesh-apple-ios-tunnel-simulator-source-artifact-receipt-v1"
            if ios_tunnel
            else "mesh-apple-ios-simulator-source-artifact-receipt-v1"
            if ios_admin
            else MACOS_SOURCE_SCHEMA
        ),
        **({"platform": args.platform} if ios_simulator else {}),
        "configuration": args.configuration,
        "source": input_receipt["source"],
        "build_host": input_receipt["host"],
        "build_inputs": input_receipt["inputs"],
        "input_receipt_sha256": input_digest,
        "bundle": {
            "identifier": expected["CFBundleIdentifier"],
            "display_name": expected["CFBundleDisplayName"],
            "version": info.get("CFBundleShortVersionString"),
            "build": info.get("CFBundleVersion"),
            (
                "minimum_ios"
                if ios_simulator
                else "minimum_macos"
            ): (
                expected["MinimumOSVersion"]
                if ios_simulator
                else expected["LSMinimumSystemVersion"]
            ),
            "architectures": architectures,
            "executable_sha256": digest_file(executable),
            "tree_sha256": tree_digest,
            "regular_files": file_count,
            "regular_file_bytes": total_bytes,
            "release_signature": "absent",
            "entitlements_applied": False,
        },
        **({"extension": extension_receipt} if ios_tunnel else {}),
        **(
            {"source_boundary": inspect_tunnel_source_boundary()}
            if ios_tunnel
            else {}
        ),
        **(
            {"source_boundary": admin_source_boundary}
            if admin_source_boundary is not None
            else {}
        ),
        **({"native_assets": native_assets} if native_assets is not None else {}),
        "privacy_manifest": {
            "sha256": digest_file(privacy_path),
            "accessed_api_types": privacy["NSPrivacyAccessedAPITypes"],
            "collected_data_types": [],
            "tracking": False,
            "tracking_domains": [],
            "status": "source-reviewed-final-dependency-reconciliation-pending",
        },
        "completed_at": dt.datetime.now(dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
    }


def inspect_tunnel_extension(
    app: pathlib.Path,
    host_architectures: list[str],
    *,
    mobile_framework: dict[str, object],
    mobile_framework_sha256: str,
) -> dict[str, object]:
    plugins = app / "PlugIns"
    if (
        not plugins.is_dir()
        or plugins.is_symlink()
        or {path.name for path in plugins.iterdir()} != {"MeshPacketTunnel.appex"}
    ):
        raise ReceiptError("Mesh Tunnel must embed exactly one reviewed extension")
    extension = plugins / "MeshPacketTunnel.appex"
    if not extension.is_dir() or extension.is_symlink():
        raise ReceiptError("Mesh Packet Tunnel extension is missing")
    try:
        info = plistlib.loads((extension / "Info.plist").read_bytes())
        privacy = plistlib.loads((extension / "PrivacyInfo.xcprivacy").read_bytes())
    except (OSError, plistlib.InvalidFileException) as exc:
        raise ReceiptError("Mesh Packet Tunnel metadata is invalid") from exc
    expected = {
        "CFBundleDisplayName": "Mesh Packet Tunnel",
        "CFBundleIdentifier": "io.rw0.mesh.tunnel.mobile.packet-tunnel",
        "CFBundleExecutable": "MeshPacketTunnel",
        "MinimumOSVersion": "17.0",
        "DTPlatformName": "iphonesimulator",
        "DTXcode": "2650",
        "DTXcodeBuild": "17F42",
        "DTSDKName": "iphonesimulator26.5",
    }
    for field, value in expected.items():
        if info.get(field) != value:
            raise ReceiptError(f"Mesh Packet Tunnel has unexpected {field}")
    if info.get("CFBundleSupportedPlatforms") != ["iPhoneSimulator"]:
        raise ReceiptError("Mesh Packet Tunnel is not simulator-only")
    if info.get("UIDeviceFamily") != [1, 2]:
        raise ReceiptError("Mesh Packet Tunnel does not support iPhone and iPad")
    if info.get("NSExtension") != {
        "NSExtensionPointIdentifier": "com.apple.networkextension.packet-tunnel",
        "NSExtensionPrincipalClass": "MeshPacketTunnel.PacketTunnelProvider",
    }:
        raise ReceiptError("Mesh Packet Tunnel extension point is not exact")
    if privacy != {
        "NSPrivacyAccessedAPITypes": [],
        "NSPrivacyCollectedDataTypes": [],
        "NSPrivacyTracking": False,
        "NSPrivacyTrackingDomains": [],
    }:
        raise ReceiptError("Mesh Packet Tunnel privacy manifest is not minimal")
    frameworks = [
        path.relative_to(app).as_posix()
        for path in app.rglob("*.framework")
    ]
    if frameworks:
        raise ReceiptError(
            "Mesh Tunnel source proof must not embed an unreviewed engine framework"
        )
    executable = extension / "MeshPacketTunnel"
    if not executable.is_file() or executable.is_symlink():
        raise ReceiptError("Mesh Packet Tunnel executable is missing")
    lipo = command("lipo", "-archs", str(executable))
    if lipo.returncode != 0 or set(lipo.stdout.strip().split()) != set(
        host_architectures
    ):
        raise ReceiptError("Mesh Packet Tunnel architectures differ from its host")
    symbols = command("nm", "-gU", str(executable))
    required_symbols = {
        "_IosmobileNewEngineSession",
        "_IosmobileNewEnrollmentSession",
        "_IosmobileNewIdentityRemovalSession",
        "_IosmobileNewLifecycleSession",
        "_proxyiosmobile_EnrollmentSession_Enroll",
        "_proxyiosmobile_IdentityRemovalSession_Remove",
        "_proxyiosmobile_LifecycleSession_ReportRuntime",
        "_proxyiosmobile_LifecycleSession_Refresh",
        "_proxyiosmobile_EngineSession_FrameworkIdentity",
        "_proxyiosmobile_EngineSession_Prepare",
        "_proxyiosmobile_EngineSession_Rebind",
        "_proxyiosmobile_EngineSession_Receive",
        "_proxyiosmobile_EngineSession_Send",
        "_proxyiosmobile_EngineSession_Start",
        "_proxyiosmobile_EngineSession_Stop",
    }
    if (
        symbols.returncode != 0
        or any(symbol not in symbols.stdout for symbol in required_symbols)
    ):
        raise ReceiptError(
            "Mesh Packet Tunnel is missing its static Go engine session"
        )
    dependencies = command("otool", "-L", str(executable))
    if (
        dependencies.returncode != 0
        or "MeshMobile.framework" in dependencies.stdout
    ):
        raise ReceiptError("Mesh Packet Tunnel engine linkage is not static")
    strings = command("strings", "-a", str(executable))
    if (
        strings.returncode != 0
        or any(
            marker not in strings.stdout
            for marker in (
                "mesh-ios-mobile-framework-v5",
                (
                    "extension-enrollment-lifecycle-renewal-credential-rotation-"
                    "mobile-evidence-identity-removal-signed-config-packet-session"
                ),
                "mesh-ios-tunnel-configuration-v4",
                "mesh-ios-lifecycle-refresh-v1",
                "mesh-ios-nebula-engine-configuration-v1",
            )
        )
    ):
        raise ReceiptError("Mesh Packet Tunnel engine identity is incomplete")
    signature = command("codesign", "--verify", "--strict", str(extension))
    if signature.returncode == 0:
        raise ReceiptError("unsigned Mesh Packet Tunnel unexpectedly has a signature")
    tree_digest, file_count, total_bytes = tree_identity(extension)
    framework = mobile_framework["framework"]
    assert isinstance(framework, dict)
    return {
        "identifier": expected["CFBundleIdentifier"],
        "display_name": expected["CFBundleDisplayName"],
        "minimum_ios": expected["MinimumOSVersion"],
        "architectures": host_architectures,
        "executable_sha256": digest_file(executable),
        "tree_sha256": tree_digest,
        "regular_files": file_count,
        "regular_file_bytes": total_bytes,
        "extension_point": "com.apple.networkextension.packet-tunnel",
        "release_signature": "absent",
        "entitlements_applied": False,
        "engine_frameworks": [],
        "engine_linkage": "static",
        "engine_dynamic_dependency": False,
        "engine_exports": sorted(required_symbols),
        "engine_framework_source_receipt_sha256": (
            mobile_framework_sha256
        ),
        "engine_framework_tree_sha256": framework["tree_sha256"],
        "engine_framework_reproducible": True,
        "physical_device_validated": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--platform",
        choices=("macos", "ios-simulator", "ios-tunnel-simulator"),
        default="macos",
    )
    parser.add_argument("--configuration", choices=("debug", "release"), required=True)
    parser.add_argument("--app", required=True)
    parser.add_argument("--input-receipt", required=True)
    parser.add_argument("--mobile-framework")
    parser.add_argument("--mobile-framework-receipt")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    output = pathlib.Path(args.output)
    if not output.is_absolute() or output.exists():
        raise ReceiptError("Apple artifact receipt output must be a new absolute path")
    raw = (
        json.dumps(inspect(args), sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()
    if len(raw) > MAXIMUM_RECEIPT_BYTES:
        raise ReceiptError("Apple artifact receipt exceeds its size bound")
    with output.open("xb") as target:
        target.write(raw)
        target.flush()
        os.fsync(target.fileno())
    print(f"Apple {args.configuration} source artifact verified: {output}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ReceiptError as exc:
        print(f"Apple source artifact receipt: {exc}", file=sys.stderr)
        raise SystemExit(1)
