#!/usr/bin/env python3
"""Inspect two normalized MeshMobile XCFramework builds and emit a receipt."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import pathlib
import plistlib
import re
import stat
import subprocess
import sys
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
BUILD_INPUTS = ROOT / "desktop" / "tool" / "apple-build.json"
ENGINE = ROOT / "ios-tunnel" / "engine"
MAXIMUM_FILE_BYTES = 512 * 1024 * 1024
MAXIMUM_TREE_BYTES = 1024 * 1024 * 1024
MAXIMUM_FILES = 64
MAXIMUM_RECEIPT_BYTES = 64 * 1024
EXPECTED_SLICES = {
    "ios-arm64": {
        "architectures": ["arm64"],
        "platform": "IOS",
        "variant": None,
    },
    "ios-arm64_x86_64-simulator": {
        "architectures": ["arm64", "x86_64"],
        "platform": "IOSSIMULATOR",
        "variant": "simulator",
    },
}
EXPECTED_EXPORTS = [
    "IosmobileEnsureIdentity",
    "IosmobileFrameworkIdentity",
    "IosmobileFrameworkIdentitySHA256",
    "IosmobileNewEngineSession",
    "IosmobileNewEnrollmentSession",
    "IosmobileNewIdentityRemovalSession",
    "IosmobileNewLifecycleSession",
]
EXPECTED_SESSION_METHODS = [
    "frameworkIdentity",
    "prepare",
    "rebind",
    "receive",
    "send",
    "start",
    "stop",
]
EXPECTED_ENROLLMENT_SESSION_METHODS = ["enroll", "recover"]
EXPECTED_LIFECYCLE_SESSION_METHODS = ["refresh", "reportRuntime"]
EXPECTED_IDENTITY_REMOVAL_SESSION_METHODS = ["remove"]


class ReceiptError(RuntimeError):
    pass


def canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode()


def digest_file(path: pathlib.Path) -> str:
    if not path.is_file() or path.is_symlink():
        raise ReceiptError(f"framework input is not one physical file: {path.name}")
    if path.stat().st_size > MAXIMUM_FILE_BYTES:
        raise ReceiptError(f"framework input exceeds its size bound: {path.name}")
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run(
    *arguments: str,
    cwd: pathlib.Path | None = None,
    timeout: int = 60,
) -> str:
    environment = {"PATH": os.environ.get("PATH", ""), "LANG": "C"}
    for name in ("HOME", "LOGNAME", "TMPDIR", "USER"):
        if os.environ.get(name):
            environment[name] = os.environ[name]
    for name in (
        "GOCACHE",
        "GOENV",
        "GOMODCACHE",
        "GOPATH",
        "GOTOOLCHAIN",
    ):
        if os.environ.get(name):
            environment[name] = os.environ[name]
    try:
        result = subprocess.run(
            arguments,
            cwd=cwd,
            check=True,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=environment,
        )
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or "").strip().replace("\n", " ")[:400]
        raise ReceiptError(
            f"framework inspection failed: {arguments[0]}: {detail}"
        ) from exc
    except (OSError, subprocess.SubprocessError) as exc:
        raise ReceiptError(f"framework inspection failed: {arguments[0]}") from exc
    return result.stdout


def load_json(path: pathlib.Path) -> tuple[dict[str, object], bytes]:
    if not path.is_file() or path.is_symlink():
        raise ReceiptError("receipt input must be one physical regular file")
    raw = path.read_bytes()
    if not raw or len(raw) > MAXIMUM_RECEIPT_BYTES:
        raise ReceiptError("receipt input is empty or oversized")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReceiptError("receipt input is invalid JSON") from exc
    if not isinstance(value, dict) or raw != canonical_json(value):
        raise ReceiptError("receipt input is not one canonical JSON object")
    return value, raw


def load_inputs() -> tuple[dict[str, object], str]:
    raw = BUILD_INPUTS.read_bytes()
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReceiptError("Apple build inputs are invalid JSON") from exc
    if not isinstance(value, dict) or not raw or len(raw) > MAXIMUM_RECEIPT_BYTES:
        raise ReceiptError("Apple build inputs are empty, oversized, or not one object")
    tunnel = value.get("ios_tunnel")
    gomobile = tunnel.get("gomobile") if isinstance(tunnel, dict) else None
    engine_source = (
        tunnel.get("engine_source") if isinstance(tunnel, dict) else None
    )
    nebula = value.get("nebula")
    if (
        value.get("schema") != "mesh-apple-build-inputs-v1"
        or value.get("go_version") != "1.26.5"
        or not isinstance(tunnel, dict)
        or tunnel.get("engine_framework") != "MeshMobile.xcframework"
        or tunnel.get("engine_status")
        != (
            "extension-enrollment-lifecycle-renewal-credential-rotation-"
            "mobile-evidence-identity-removal-signed-config-packet-session-"
            "source-wired"
        )
        or tunnel.get("identity_keychain_group")
        != "$(AppIdentifierPrefix)io.rw0.mesh.tunnel.mobile.identity"
        or not isinstance(gomobile, dict)
        or gomobile
        != {
            "module": "golang.org/x/mobile",
            "version": "v0.0.0-20260709172247-6129f5bee9d5",
            "upstream_url": "https://go.googlesource.com/mobile",
            "upstream_commit": "6129f5bee9d516e31842c9815bf24f60fa682b6e",
            "module_sum": "h1:Mn1OzFmF0ZKX/ZayHz/UdnWHufPp1wlD9lZ5U8LRDFY=",
            "go_mod_sum": "h1:YX+n47s+53POxN3dx9cIGxG3hGUm/lD64hvrRJFbcSA=",
            "framework_schema": "mesh-ios-mobile-framework-v5",
            "capability": (
                "extension-enrollment-lifecycle-renewal-credential-rotation-"
                "mobile-evidence-identity-removal-signed-config-packet-session"
            ),
            "minimum_ios": "17.0",
        }
        or engine_source
        != {
            "upstream_url": "https://github.com/slackhq/nebula",
            "upstream_tag": "v1.10.3",
            "upstream_commit": "f573e8a26695278f9d71587390fbfe0d0933aa21",
            "module_sum": "h1:EstYj8ODEcv6T0R9X5BVq1zgWZnyU5gtPzk99QF1PMU=",
            "go_mod_sum": "h1:IL5TUQm4x9IFx2kCKPYm1gP47pwd5b8QGnnBH2RHnvs=",
            "license": "MIT",
            "license_sha256": (
                "aefd0cce553f24945ce1c692c3c4f9fda581f078ba82977845715cd18565b3bd"
            ),
            "mesh_patch": "none",
            "mesh_patch_sha256": (
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            ),
            "module_graph_sha256": (
                "900aee5c8ee4441da7a3bc7932c6b29f1468670cdfdc6615b75bb82fe905810f"
            ),
        }
        or tunnel.get("framework_build")
        != {
            "flags": [
                "-trimpath",
                "-ldflags=-buildid=",
                "-target=ios",
                "-iosversion=17.0",
            ],
            "normalization_schema": (
                "mesh-ios-mobile-framework-normalization-v1"
            ),
            "source_staging_schema": (
                "mesh-ios-mobile-framework-source-staging-v1"
            ),
            "canonical_source_root": (
                "/private/var/tmp/mesh-apple-ios-mobile-source-v5"
            ),
        }
        or tunnel.get("packet_bridge")
        != {
            "nebula_adapter": (
                "github.com/slackhq/nebula/overlay.NewFdDeviceFromConfig"
            ),
            "apple_transport": "NetworkExtension utun descriptor",
            "status": "mobile-nebula-native-utun-source-wired",
        }
        or tunnel.get("runtime_startup")
        != {
            "configuration_schema": "mesh-ios-tunnel-configuration-v4",
            "envelope_schema": "mesh-ios-tunnel-envelope-v4",
            "remote_endpoint": "authenticated-canonical-underlay-ip",
            "order": [
                "engine-identity",
                "engine-prepare",
                "apple-network-settings",
                "engine-start",
            ],
            "status": "static-linked-simulator-build-proven-device-pending",
        }
        or not isinstance(nebula, dict)
        or nebula.get("module") != "github.com/slackhq/nebula"
        or nebula.get("version") != "1.10.3"
    ):
        raise ReceiptError("Apple mobile framework inputs are not exact")
    return value, hashlib.sha256(raw).hexdigest()


def load_source_receipt(
    path: pathlib.Path, apple_build_digest: str
) -> tuple[dict[str, object], str]:
    value, raw = load_json(path)
    source = value.get("source")
    host = value.get("host")
    inputs = value.get("inputs")
    preflight = value.get("preflight")
    if (
        value.get("schema") != "mesh-apple-source-build-receipt-v1"
        or not isinstance(source, dict)
        or re.fullmatch(r"[0-9a-f]{40}", str(source.get("commit", ""))) is None
        or not isinstance(source.get("clean"), bool)
        or not isinstance(host, dict)
        or host.get("go_version") != "1.26.5"
        or host.get("xcode_version") != "26.5"
        or host.get("xcode_build") != "17F42"
        or not isinstance(inputs, dict)
        or inputs.get("apple_build_sha256") != apple_build_digest
        or not isinstance(preflight, dict)
        or preflight.get("release_credentials_present") is not False
        or preflight.get("source_keychain_code_signing_identities") != 0
    ):
        raise ReceiptError("source receipt has the wrong tool or credential state")
    return value, hashlib.sha256(raw).hexdigest()


def tree_identity(root: pathlib.Path) -> tuple[str, int, int]:
    digest = hashlib.sha256()
    files = 0
    total = 0
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        metadata = path.lstat()
        mode = stat.S_IMODE(metadata.st_mode)
        if stat.S_ISDIR(metadata.st_mode):
            record = f"d {mode:04o} {relative}\n"
        elif stat.S_ISREG(metadata.st_mode):
            files += 1
            total += metadata.st_size
            if files > MAXIMUM_FILES or total > MAXIMUM_TREE_BYTES:
                raise ReceiptError("framework tree exceeds its receipt bounds")
            record = (
                f"f {mode:04o} {metadata.st_size} {digest_file(path)} {relative}\n"
            )
        else:
            raise ReceiptError(f"framework tree contains a prohibited object: {relative}")
        digest.update(record.encode())
    return digest.hexdigest(), files, total


def exact_inventory(root: pathlib.Path) -> None:
    expected = {"Info.plist"}
    for identifier in EXPECTED_SLICES:
        prefix = f"{identifier}/MeshMobile.framework"
        expected.update(
            {
                f"{prefix}/Headers/Iosmobile.objc.h",
                f"{prefix}/Headers/MeshMobile.h",
                f"{prefix}/Headers/Universe.objc.h",
                f"{prefix}/Headers/ref.h",
                f"{prefix}/Info.plist",
                f"{prefix}/MeshMobile",
                f"{prefix}/Modules/module.modulemap",
            }
        )
    actual = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and not path.is_symlink()
    }
    if actual != expected:
        raise ReceiptError("framework file inventory is not exact")


def inspect_object_version(
    binary: pathlib.Path, architecture: str, platform_name: str
) -> dict[str, str]:
    with tempfile.TemporaryDirectory(prefix="mesh-mobile-receipt-") as raw_root:
        temporary = pathlib.Path(raw_root)
        archive = temporary / "slice.a"
        architectures = run("lipo", "-archs", str(binary)).strip().split()
        if len(architectures) == 1:
            archive.write_bytes(binary.read_bytes())
        else:
            run(
                "lipo",
                "-thin",
                architecture,
                str(binary),
                "-output",
                str(archive),
            )
        members = [
            line.strip()
            for line in run("ar", "-t", str(archive)).splitlines()
            if line.strip() and not line.startswith("__.SYMDEF")
        ]
        if (
            "go.o" not in members
            or len(members) > 4096
            or len(set(members)) != len(members)
            or any(
                re.fullmatch(r"(?:go|[0-9]{6})\.o", member) is None
                for member in members
            )
        ):
            raise ReceiptError("framework archive member inventory is invalid")
        run("ar", "-x", str(archive), cwd=temporary)
        output = run("vtool", "-show-build", str(temporary / "go.o"))
    observed = dict(
        re.findall(r"^\s*(platform|minos|sdk)\s+(\S+)\s*$", output, re.MULTILINE)
    )
    expected = {"platform": platform_name, "minos": "17.0", "sdk": "26.5"}
    if observed != expected:
        raise ReceiptError(
            f"{architecture} object deployment metadata is not exact: {observed}"
        )
    return observed


def inspect_framework(
    root: pathlib.Path, canonical_source_root: str
) -> dict[str, object]:
    if not root.is_absolute() or not root.is_dir() or root.is_symlink():
        raise ReceiptError("framework must be one absolute physical directory")
    exact_inventory(root)
    try:
        outer = plistlib.loads((root / "Info.plist").read_bytes())
    except (OSError, plistlib.InvalidFileException) as exc:
        raise ReceiptError("XCFramework Info.plist is invalid") from exc
    libraries = []
    for identifier, expected in sorted(EXPECTED_SLICES.items()):
        library: dict[str, object] = {
            "BinaryPath": "MeshMobile.framework/MeshMobile",
            "LibraryIdentifier": identifier,
            "LibraryPath": "MeshMobile.framework",
            "SupportedArchitectures": expected["architectures"],
            "SupportedPlatform": "ios",
        }
        if expected["variant"] is not None:
            library["SupportedPlatformVariant"] = expected["variant"]
        libraries.append(library)
    if outer != {
        "AvailableLibraries": libraries,
        "CFBundlePackageType": "XFWK",
        "XCFrameworkFormatVersion": "1.0",
    }:
        raise ReceiptError("XCFramework metadata is not exact")

    slice_receipts: list[dict[str, object]] = []
    reference_header: str | None = None
    reference_headers_digest: str | None = None
    for identifier, expected in sorted(EXPECTED_SLICES.items()):
        framework = root / identifier / "MeshMobile.framework"
        binary = framework / "MeshMobile"
        try:
            inner = plistlib.loads((framework / "Info.plist").read_bytes())
        except (OSError, plistlib.InvalidFileException) as exc:
            raise ReceiptError("framework Info.plist is invalid") from exc
        if inner != {
            "CFBundleExecutable": "MeshMobile",
            "CFBundleIdentifier": "MeshMobile",
            "CFBundlePackageType": "FMWK",
            "CFBundleShortVersionString": "0.1.0",
            "CFBundleVersion": "1",
            "MinimumOSVersion": "100.0",
        }:
            raise ReceiptError("framework bundle metadata is not normalized")
        architectures = run("lipo", "-archs", str(binary)).strip().split()
        if set(architectures) != set(expected["architectures"]):
            raise ReceiptError(f"{identifier} architecture set is not exact")
        header_path = framework / "Headers" / "Iosmobile.objc.h"
        header = header_path.read_text()
        exports = sorted(set(re.findall(r"\b(Iosmobile[A-Za-z0-9_]+)\s*\(", header)))
        if exports != EXPECTED_EXPORTS:
            raise ReceiptError(f"framework Objective-C exports are not exact: {exports}")
        methods = sorted(
            set(
                re.findall(
                    r"^-\s*\([^)]*\)\s*([a-z][A-Za-z0-9_]*)"
                    r"(?:\s*[:;])",
                    header,
                    re.MULTILINE,
                )
            )
            & set(EXPECTED_SESSION_METHODS)
        )
        if methods != EXPECTED_SESSION_METHODS:
            raise ReceiptError(
                f"framework EngineSession methods are not exact: {methods}"
            )
        enrollment_methods = sorted(
            set(
                re.findall(
                    r"^-\s*\([^)]*\)\s*([a-z][A-Za-z0-9_]*)"
                    r"(?:\s*[:;])",
                    header,
                    re.MULTILINE,
                )
            )
            & set(EXPECTED_ENROLLMENT_SESSION_METHODS)
        )
        if enrollment_methods != EXPECTED_ENROLLMENT_SESSION_METHODS:
            raise ReceiptError(
                "framework EnrollmentSession methods are not exact: "
                f"{enrollment_methods}"
            )
        lifecycle_methods = sorted(
            set(
                re.findall(
                    r"^-\s*\([^)]*\)\s*([a-z][A-Za-z0-9_]*)"
                    r"(?:\s*[:;])",
                    header,
                    re.MULTILINE,
                )
            )
            & set(EXPECTED_LIFECYCLE_SESSION_METHODS)
        )
        if lifecycle_methods != EXPECTED_LIFECYCLE_SESSION_METHODS:
            raise ReceiptError(
                "framework LifecycleSession methods are not exact: "
                f"{lifecycle_methods}"
            )
        identity_removal_methods = sorted(
            set(
                re.findall(
                    r"^-\s*\([^)]*\)\s*([a-z][A-Za-z0-9_]*)"
                    r"(?:\s*[:;])",
                    header,
                    re.MULTILINE,
                )
            )
            & set(EXPECTED_IDENTITY_REMOVAL_SESSION_METHODS)
        )
        if identity_removal_methods != EXPECTED_IDENTITY_REMOVAL_SESSION_METHODS:
            raise ReceiptError(
                "framework IdentityRemovalSession methods are not exact: "
                f"{identity_removal_methods}"
            )
        if (
            re.search(
                r"\bIosmobile(?:PrivateKey|PrivatePath|Exec|Command)\s*\(",
                header,
            )
            or re.search(
                r"^-\s*\([^)]*\)\s*"
                r"(?:privateKey|privatePath|exec|command)\b",
                header,
                re.MULTILINE,
            )
            or "start tunnel" in header.lower()
        ):
            raise ReceiptError("framework header describes a prohibited capability")
        header_digests = hashlib.sha256()
        for name in (
            "Iosmobile.objc.h",
            "MeshMobile.h",
            "Universe.objc.h",
            "ref.h",
        ):
            header_digests.update(
                (name + "\0" + digest_file(framework / "Headers" / name) + "\n").encode()
            )
        headers_digest = header_digests.hexdigest()
        if reference_header is None:
            reference_header = header
            reference_headers_digest = headers_digest
        elif header != reference_header or headers_digest != reference_headers_digest:
            raise ReceiptError("framework slice headers differ")
        strings = run("strings", str(binary), timeout=120)
        if (
            canonical_source_root not in strings
            or str(ROOT) in strings
            or re.search(r"(?m)^/Users/", strings)
        ):
            raise ReceiptError(
                "framework binary does not use only the canonical source root"
            )
        for required in (
            "github.com/slackhq/nebula",
            "v1.10.3",
            "mesh-ios-mobile-framework-v5",
            (
                "extension-enrollment-lifecycle-renewal-credential-rotation-"
                "mobile-evidence-identity-removal-signed-config-packet-session"
            ),
            "mesh-ios-tunnel-configuration-v4",
            "mesh-ios-lifecycle-refresh-v1",
            "mesh-ios-nebula-engine-configuration-v1",
        ):
            if required not in strings:
                raise ReceiptError(f"framework binary is missing identity {required}")
        object_versions = {
            architecture: inspect_object_version(
                binary, architecture, str(expected["platform"])
            )
            for architecture in expected["architectures"]
        }
        slice_receipts.append(
            {
                "identifier": identifier,
                "architectures": architectures,
                "binary_sha256": digest_file(binary),
                "headers_sha256": headers_digest,
                "object_build_versions": object_versions,
            }
        )

    tree_digest, files, total = tree_identity(root)
    return {
        "name": "MeshMobile.xcframework",
        "tree_sha256": tree_digest,
        "regular_files": files,
        "regular_file_bytes": total,
        "exports": EXPECTED_EXPORTS,
        "signed": False,
        "slices": slice_receipts,
    }


def inspect_engine_sources(inputs: dict[str, object]) -> dict[str, object]:
    go_mod = (ENGINE / "go.mod").read_text()
    exports = sorted(
        set(
            re.findall(
                r"^func\s+([A-Z][A-Za-z0-9_]*)\s*\(",
                "\n".join(
                    path.read_text()
                    for path in sorted(ENGINE.glob("*.go"))
                    if not path.name.endswith("_test.go")
                ),
                re.MULTILINE,
            )
        )
    )
    gomobile = inputs["ios_tunnel"]["gomobile"]
    engine_source = inputs["ios_tunnel"]["engine_source"]
    framework_build = inputs["ios_tunnel"]["framework_build"]
    packet_bridge = inputs["ios_tunnel"]["packet_bridge"]
    nebula = inputs["nebula"]
    assert all(
        isinstance(value, dict)
        for value in (
            gomobile,
            engine_source,
            framework_build,
            packet_bridge,
            nebula,
        )
    )
    if (
        re.search(
            rf"^\s*{re.escape(str(nebula['module']))}\s+v{re.escape(str(nebula['version']))}\s*$",
            go_mod,
            re.MULTILINE,
        )
        is None
        or re.search(
            rf"^\s*{re.escape(str(gomobile['module']))}\s+{re.escape(str(gomobile['version']))}\s+// indirect\s*$",
            go_mod,
            re.MULTILINE,
        )
        is None
        or exports
        != [
            "EnsureIdentity",
            "FrameworkIdentity",
            "FrameworkIdentitySHA256",
            "NewEngineSession",
            "NewEnrollmentSession",
            "NewIdentityRemovalSession",
            "NewLifecycleSession",
        ]
    ):
        raise ReceiptError("framework source dependency or export boundary is not exact")
    vault = (ENGINE / "vault_ios.go").read_text()
    for required in (
        "kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly",
        "kSecAttrSynchronizable, kCFBooleanFalse",
        "kSecUseDataProtectionKeychain, kCFBooleanTrue",
    ):
        if required not in vault:
            raise ReceiptError("framework source Keychain boundary is incomplete")
    bridge_source = (ENGINE / "packet_bridge.go").read_text()
    for required in (
        "overlay.NewUserDevice",
        "validateAndCopyPacket",
        "maximumPacketBytes",
    ):
        if required not in bridge_source:
            raise ReceiptError("framework packet callback adapter is incomplete")
    if re.search(r"^func\s+[A-Z]", bridge_source, re.MULTILINE):
        raise ReceiptError("framework packet callback adapter is unexpectedly exported")
    utun_source = (ENGINE / "utun_fd_darwin.go").read_text()
    for required in (
        "com.apple.net.utun_control",
        "unix.Getpeername(",
        "unix.IoctlCtlInfo(",
        "maximumProviderFileFD",
    ):
        if required not in utun_source:
            raise ReceiptError("framework native utun discovery is incomplete")
    session_source = (ENGINE / "engine_session.go").read_text()
    session_methods = sorted(
        set(
            re.findall(
                r"^func\s+\([^)]*\*EngineSession\)\s+"
                r"([A-Z][A-Za-z0-9_]*)\s*\(",
                session_source,
                re.MULTILINE,
            )
        )
    )
    if session_methods != [
        "FrameworkIdentity",
        "Prepare",
        "Rebind",
        "Receive",
        "Send",
        "Start",
        "Stop",
    ]:
        raise ReceiptError("framework EngineSession source surface is not exact")
    for required in (
        "configsignature.Verify(",
        "newPacketFlowBridge(",
        "overlay.NewFdDeviceFromConfig(",
        "nativeUTUNDeviceFactory",
        "nebula.Main(",
        "loadPrivateKey(",
    ):
        if (
            required not in session_source
            and required not in (ENGINE / "engine_configuration.go").read_text()
        ):
            raise ReceiptError("framework signed packet session is incomplete")
    enrollment_source = (ENGINE / "enrollment.go").read_text()
    enrollment_methods = sorted(
        set(
            re.findall(
                r"^func\s+\([^)]*\*EnrollmentSession\)\s+"
                r"([A-Z][A-Za-z0-9_]*)\s*\(",
                enrollment_source,
                re.MULTILINE,
            )
        )
    )
    if enrollment_methods != ["Enroll", "Recover"]:
        raise ReceiptError("framework EnrollmentSession source surface is not exact")
    if re.search(
        r'^\s*agentCredentialService\s*=\s*'
        r'"io\.rw0\.mesh\.tunnel\.mobile\.agent\.v1"\s*$',
        enrollment_source,
        re.MULTILINE,
    ) is None:
        raise ReceiptError("framework agent credential service is not exact")
    for required in (
        "loadOrCreatePrivateKey(accessGroup, identityID)",
        "loadOrCreateSecret(",
        "loadPrivateKey(accessGroup, identityID)",
        "loadSecret(",
        "enrollmentRecoveryV1",
        "enrollmentRecoveryUnauthorized",
        "enrollmentRecoveryDeferred",
        'origin+"/api/v1/agent/bootstrap"',
        "configsignature.Verify(",
        "http.ErrUseLastResponse",
        "validEnrollmentBearer(",
        "requestPreflight(",
        "resolvePreflightRemotes(",
        "requestEnrollment(",
        "configurationDocument(",
        "preflightRemotes[remote]",
        "policy.LocalIP != certificateNetwork.Addr().String()",
        "validNativeDNSDomain(",
    ):
        if required not in enrollment_source:
            raise ReceiptError("framework extension enrollment boundary is incomplete")
    for forbidden in (
        r"^func\s+\([^)]*\*EnrollmentSession\)\s+PrivateKey\s*\(",
        r"^func\s+\([^)]*\*EnrollmentSession\)\s+AgentBearer\s*\(",
        r"^func\s+\([^)]*\*EnrollmentSession\)\s+SetHeader\s*\(",
    ):
        if re.search(forbidden, enrollment_source, re.MULTILINE):
            raise ReceiptError(
                "framework extension enrollment exposes a prohibited capability"
            )
    lifecycle_source = (ENGINE / "lifecycle.go").read_text()
    lifecycle_methods = sorted(
        set(
            re.findall(
                r"^func\s+\([^)]*\*LifecycleSession\)\s+"
                r"([A-Z][A-Za-z0-9_]*)\s*\(",
                lifecycle_source,
                re.MULTILINE,
            )
        )
    )
    if lifecycle_methods != ["Refresh", "ReportRuntime"]:
        raise ReceiptError("framework LifecycleSession source surface is not exact")
    for required in (
        "loadPrivateKey(accessGroup, identityID)",
        "loadSecret(",
        'origin+"/api/v1/agent/bootstrap"',
        'origin+"/api/v1/agent/certificate/renew"',
        'origin+"/api/v1/agent/credentials/rotate"',
        'origin+"/api/v1/agent/mobile-runtime"',
        "pendingAgentCredentialService",
        "lifecycleRefreshUnauthorized",
        "lifecycleRefreshDeferred",
        "current.ControlPlaneOrigin != origin",
        "bundle.AgentCredentialGeneration <",
        "configurationDocument(",
    ):
        if required not in lifecycle_source:
            raise ReceiptError("framework lifecycle refresh boundary is incomplete")
    for forbidden in (
        r"^func\s+\([^)]*\*LifecycleSession\)\s+PrivateKey\s*\(",
        r"^func\s+\([^)]*\*LifecycleSession\)\s+AgentBearer\s*\(",
        r"^func\s+\([^)]*\*LifecycleSession\)\s+SetHeader\s*\(",
    ):
        if re.search(forbidden, lifecycle_source, re.MULTILINE):
            raise ReceiptError(
                "framework lifecycle refresh exposes a prohibited capability"
            )
    identity_removal_source = (ENGINE / "identity_removal.go").read_text()
    identity_removal_methods = sorted(
        set(
            re.findall(
                r"^func\s+\([^)]*\*IdentityRemovalSession\)\s+"
                r"([A-Z][A-Za-z0-9_]*)\s*\(",
                identity_removal_source,
                re.MULTILINE,
            )
        )
    )
    if identity_removal_methods != ["Remove"]:
        raise ReceiptError(
            "framework IdentityRemovalSession source surface is not exact"
        )
    for required in (
        "deleteSecret(accessGroup, identityService, identityID)",
        "agentCredentialService",
        "pendingAgentCredentialService",
        "errors.Join(failures...)",
    ):
        if required not in identity_removal_source:
            raise ReceiptError(
                "framework identity-removal boundary is incomplete"
            )
    for forbidden in (
        r"^func\s+\([^)]*\*IdentityRemovalSession\)\s+PrivateKey\s*\(",
        r"^func\s+\([^)]*\*IdentityRemovalSession\)\s+AgentBearer\s*\(",
        r"^func\s+\([^)]*\*IdentityRemovalSession\)\s+Load\s*\(",
        r"^func\s+\([^)]*\*IdentityRemovalSession\)\s+Replace\s*\(",
    ):
        if re.search(forbidden, identity_removal_source, re.MULTILINE):
            raise ReceiptError(
                "framework identity removal exposes a prohibited capability"
            )
    feasibility_source = (ENGINE / "engine_feasibility_test.go").read_text()
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
        "127.0.0.1",
    ):
        if required not in feasibility_source:
            raise ReceiptError("framework authenticated UDP feasibility proof is incomplete")
    module_graph = run("go", "list", "-m", "all", cwd=ENGINE)
    module_graph_digest = hashlib.sha256(module_graph.encode()).hexdigest()
    if module_graph_digest != engine_source["module_graph_sha256"]:
        raise ReceiptError("framework module graph differs from the reviewed graph")
    try:
        nebula_download = json.loads(
            run(
                "go",
                "mod",
                "download",
                "-json",
                f"{nebula['module']}@v{nebula['version']}",
                cwd=ENGINE,
            )
        )
        gomobile_download = json.loads(
            run(
                "go",
                "mod",
                "download",
                "-json",
                f"{gomobile['module']}@{gomobile['version']}",
                cwd=ENGINE,
            )
        )
    except json.JSONDecodeError as exc:
        raise ReceiptError("framework module origin metadata is invalid") from exc
    if (
        nebula_download.get("Sum") != engine_source["module_sum"]
        or nebula_download.get("GoModSum") != engine_source["go_mod_sum"]
        or nebula_download.get("Origin")
        != {
            "VCS": "git",
            "URL": engine_source["upstream_url"],
            "Hash": engine_source["upstream_commit"],
            "Ref": f"refs/tags/{engine_source['upstream_tag']}",
        }
        or gomobile_download.get("Sum") != gomobile["module_sum"]
        or gomobile_download.get("GoModSum") != gomobile["go_mod_sum"]
        or gomobile_download.get("Origin")
        != {
            "VCS": "git",
            "URL": gomobile["upstream_url"],
            "Hash": gomobile["upstream_commit"],
        }
    ):
        raise ReceiptError("framework module origin metadata differs from inputs")
    nebula_directory = pathlib.Path(
        run(
            "go",
            "list",
            "-m",
            "-f",
            "{{.Dir}}",
            str(nebula["module"]),
            cwd=ENGINE,
        ).strip()
    )
    license_path = nebula_directory / "LICENSE"
    if digest_file(license_path) != engine_source["license_sha256"]:
        raise ReceiptError("Nebula license differs from the reviewed source")
    engine_source_names = (
        "go.mod",
        "go.sum",
        "engine_feasibility_test.go",
        "engine_configuration.go",
        "enrollment.go",
        "enrollment_test.go",
        "engine_session.go",
        "engine_session_test.go",
        "identity_removal.go",
        "identity_removal_test.go",
        "lifecycle.go",
        "lifecycle_test.go",
        "mobile.go",
        "mobile_test.go",
        "packet_bridge.go",
        "packet_bridge_test.go",
        "utun_fd_darwin.go",
        "utun_fd_unsupported.go",
        "vault_ios.go",
        "vault_unsupported.go",
    )
    observed_engine_source_names = {
        path.name for path in ENGINE.glob("*.go")
    } | {"go.mod", "go.sum"}
    if observed_engine_source_names != set(engine_source_names):
        raise ReceiptError("framework engine source inventory is not exact")
    source_digests = {
        name: digest_file(ENGINE / name) for name in engine_source_names
    }
    source_digests["shared_configsignature.go"] = digest_file(
        ROOT / "internal" / "configsignature" / "configsignature.go"
    )
    source_digests["shared_mobileruntime_contract.go"] = digest_file(
        ROOT / "internal" / "mobileruntime" / "contract.go"
    )
    return {
        "module": "mesh/iosmobile",
        "go_version": inputs["go_version"],
        "nebula_module": nebula["module"],
        "nebula_version": nebula["version"],
        "nebula_upstream_url": engine_source["upstream_url"],
        "nebula_upstream_tag": engine_source["upstream_tag"],
        "nebula_upstream_commit": engine_source["upstream_commit"],
        "nebula_module_sum": engine_source["module_sum"],
        "nebula_go_mod_sum": engine_source["go_mod_sum"],
        "nebula_license": engine_source["license"],
        "nebula_license_sha256": engine_source["license_sha256"],
        "mesh_patch": engine_source["mesh_patch"],
        "mesh_patch_sha256": engine_source["mesh_patch_sha256"],
        "gomobile_module": gomobile["module"],
        "gomobile_version": gomobile["version"],
        "gomobile_upstream_url": gomobile["upstream_url"],
        "gomobile_upstream_commit": gomobile["upstream_commit"],
        "gomobile_module_sum": gomobile["module_sum"],
        "gomobile_go_mod_sum": gomobile["go_mod_sum"],
        "module_graph_sha256": module_graph_digest,
        "framework_schema": gomobile["framework_schema"],
        "capability": gomobile["capability"],
        "build_flags": framework_build["flags"],
        "normalization_schema": framework_build["normalization_schema"],
        "source_staging_schema": framework_build["source_staging_schema"],
        "canonical_source_root": framework_build["canonical_source_root"],
        "packet_bridge_adapter": packet_bridge["nebula_adapter"],
        "packet_bridge_transport": packet_bridge["apple_transport"],
        "packet_bridge_status": packet_bridge["status"],
        "private_key_exported": False,
        "source_sha256": source_digests,
    }


def collect(args: argparse.Namespace) -> dict[str, object]:
    inputs, build_inputs_digest = load_inputs()
    source_receipt, source_receipt_digest = load_source_receipt(
        pathlib.Path(args.input_receipt), build_inputs_digest
    )
    framework_build = inputs["ios_tunnel"]["framework_build"]
    assert isinstance(framework_build, dict)
    canonical_source_root = str(framework_build["canonical_source_root"])
    primary = inspect_framework(
        pathlib.Path(args.framework), canonical_source_root
    )
    rebuild = inspect_framework(
        pathlib.Path(args.rebuild), canonical_source_root
    )
    if primary["tree_sha256"] != rebuild["tree_sha256"] or primary != rebuild:
        raise ReceiptError("independent normalized framework builds differ")
    primary["reproducible"] = True
    primary["independent_rebuild_tree_sha256"] = rebuild["tree_sha256"]
    return {
        "schema": "mesh-apple-ios-mobile-framework-source-receipt-v1",
        "source": source_receipt["source"],
        "build_host": source_receipt["host"],
        "build_inputs": source_receipt["inputs"],
        "input_receipt_sha256": source_receipt_digest,
        "engine": inspect_engine_sources(inputs),
        "framework": primary,
        "scope": {
            "embedded_in_tunnel": False,
            "authenticated_udp_callback_source_proven": True,
            "packet_callback_adapter_source_proven": True,
            "packet_transport_implemented": True,
            "static_tunnel_link_validated": False,
            "physical_device_validated": False,
            "production_signing_used": False,
        },
        "completed_at": dt.datetime.now(dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--framework")
    parser.add_argument("--rebuild")
    parser.add_argument("--input-receipt", required=True)
    parser.add_argument("--output")
    parser.add_argument("--preflight-only", action="store_true")
    args = parser.parse_args()
    if args.preflight_only:
        if args.framework or args.rebuild or args.output:
            raise ReceiptError("framework preflight does not accept artifact arguments")
        _, build_inputs_digest = load_inputs()
        load_source_receipt(pathlib.Path(args.input_receipt), build_inputs_digest)
        print("Apple mobile framework input preflight passed")
        return 0
    if not args.framework or not args.rebuild or not args.output:
        raise ReceiptError("framework, rebuild, and output are required")
    output = pathlib.Path(args.output)
    if not output.is_absolute() or output.exists() or output.parent.is_symlink():
        raise ReceiptError("framework receipt output must be one new absolute path")
    value = collect(args)
    raw = canonical_json(value)
    if len(raw) > MAXIMUM_RECEIPT_BYTES:
        raise ReceiptError("framework receipt exceeds its size bound")
    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with output.open("xb") as target:
        target.write(raw)
        target.flush()
        os.fsync(target.fileno())
    print(f"Apple mobile framework source receipt passed: {output}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ReceiptError as exc:
        print(f"Apple mobile framework receipt: {exc}", file=sys.stderr)
        raise SystemExit(1)
