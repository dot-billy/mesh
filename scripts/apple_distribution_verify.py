#!/usr/bin/env python3
"""Verify exact Apple distribution profiles and signed iOS archives."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import pathlib
import plistlib
import subprocess
import tempfile
from typing import Any


ROOT = pathlib.Path(__file__).resolve().parents[1]
INPUTS = ROOT / "desktop" / "tool" / "apple-build.json"
TEAM = "Y3P5UNNG23"
GROUP = "group.io.rw0.mesh.tunnel.mobile"
TUNNEL_SHARED_KEYCHAIN_GROUPS = (
    f"{TEAM}.io.rw0.mesh.tunnel.mobile.handoff",
    f"{TEAM}.io.rw0.mesh.tunnel.mobile.identity",
)
PROFILE_SPECS = {
    "admin": {
        "name": "Mesh Admin App Store",
        "uuid": "bbf9a052-cc14-49a1-a7be-af1636efb0cf",
        "application_identifier": f"{TEAM}.io.rw0.mesh.admin.mobile",
        "groups": [],
        "network_extension": False,
    },
    "host": {
        "name": "Mesh Tunnel Host App Store",
        "uuid": "9ae4c36f-22a0-4d67-b078-f40049321616",
        "application_identifier": f"{TEAM}.io.rw0.mesh.tunnel.mobile",
        "groups": [GROUP],
        "network_extension": True,
    },
    "extension": {
        "name": "Mesh Packet Tunnel App Store",
        "uuid": "4201014e-16f3-4836-8da4-04b856709c51",
        "application_identifier": (
            f"{TEAM}.io.rw0.mesh.tunnel.mobile.packet-tunnel"
        ),
        "groups": [GROUP],
        "network_extension": True,
    },
}
TUNNEL_ENGINE_SYMBOLS = {
    "_IosmobileNewEngineSession",
    "_IosmobileNewIdentityRemovalSession",
    "_IosmobileNewLifecycleSession",
    "_proxyiosmobile_IdentityRemovalSession_Remove",
    "_proxyiosmobile_LifecycleSession_ReportRuntime",
    "_proxyiosmobile_EngineSession_FrameworkIdentity",
    "_proxyiosmobile_EngineSession_Prepare",
    "_proxyiosmobile_EngineSession_Rebind",
    "_proxyiosmobile_EngineSession_Receive",
    "_proxyiosmobile_EngineSession_Send",
    "_proxyiosmobile_EngineSession_Start",
    "_proxyiosmobile_EngineSession_Stop",
}
TUNNEL_HOST_SESSION_SYMBOLS = {
    "main.proxyiosmobile__NewEnrollmentSession",
    "main.proxyiosmobile__NewIdentityRemovalSession",
    "main.proxyiosmobile__NewLifecycleSession",
    "main.proxyiosmobile_EnrollmentSession_Enroll",
    "main.proxyiosmobile_EnrollmentSession_Recover",
    "main.proxyiosmobile_IdentityRemovalSession_Remove",
    "main.proxyiosmobile_LifecycleSession_Refresh",
}
TUNNEL_ENGINE_MARKERS = {
    "mesh-ios-mobile-framework-v5",
    (
        "extension-enrollment-lifecycle-renewal-credential-rotation-"
        "mobile-evidence-identity-removal-signed-config-packet-session"
    ),
    "mesh-ios-tunnel-configuration-v4",
    "mesh-ios-lifecycle-refresh-v1",
    "mesh-ios-nebula-engine-configuration-v1",
}


class VerificationError(RuntimeError):
    pass


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def tree_digest(root: pathlib.Path) -> str:
    if not root.is_dir() or root.is_symlink():
        raise VerificationError(f"{root}: expected a non-symlink directory")
    digest = hashlib.sha256()
    files = sorted(path for path in root.rglob("*") if path.is_file())
    for path in files:
        if path.is_symlink():
            raise VerificationError(f"{path}: symlink is forbidden")
        relative = path.relative_to(root).as_posix().encode()
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(path.stat().st_mode.to_bytes(8, "big"))
        digest.update(bytes.fromhex(sha256_file(path)))
    return digest.hexdigest()


def run(*arguments: str, timeout: int = 60) -> subprocess.CompletedProcess[bytes]:
    environment = {
        name: os.environ[name]
        for name in ("HOME", "LOGNAME", "PATH", "TMPDIR", "USER")
        if os.environ.get(name)
    }
    environment["LANG"] = "C"
    try:
        return subprocess.run(
            arguments,
            cwd=ROOT,
            env=environment,
            check=True,
            capture_output=True,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise VerificationError(
            f"command failed: {' '.join(arguments)}: {exc}"
        ) from exc


def load_profile(path: pathlib.Path) -> dict[str, Any]:
    if (
        not path.is_file()
        or path.is_symlink()
        or path.stat().st_size > 1024 * 1024
    ):
        raise VerificationError(f"{path}: invalid provisioning-profile file")
    try:
        value = plistlib.loads(
            run("security", "cms", "-D", "-i", str(path)).stdout
        )
    except plistlib.InvalidFileException as exc:
        raise VerificationError(f"{path}: decoded profile is invalid") from exc
    if not isinstance(value, dict):
        raise VerificationError(f"{path}: profile is not a dictionary")
    return value


def validate_profile(
    value: dict[str, Any],
    spec: dict[str, Any],
    now: dt.datetime,
) -> dict[str, Any]:
    entitlements = value.get("Entitlements")
    if not isinstance(entitlements, dict):
        raise VerificationError("profile entitlements are missing")
    checks = {
        "Name": spec["name"],
        "UUID": spec["uuid"],
        "TeamIdentifier": [TEAM],
        "TeamName": value.get("TeamName"),
    }
    for key, expected in checks.items():
        if key == "TeamName":
            if not isinstance(expected, str) or not expected:
                raise VerificationError("profile TeamName is missing")
        elif value.get(key) != expected:
            raise VerificationError(f"profile {key} does not match")
    expiration = value.get("ExpirationDate")
    if not isinstance(expiration, dt.datetime):
        raise VerificationError("profile expiration is missing")
    if expiration.tzinfo is None:
        expiration = expiration.replace(tzinfo=dt.timezone.utc)
    if expiration <= now:
        raise VerificationError("profile is expired")
    for forbidden in ("ProvisionedDevices", "ProvisionsAllDevices", "LocalProvision"):
        if forbidden in value:
            raise VerificationError(f"profile unexpectedly contains {forbidden}")
    expected_entitlements = {
        "application-identifier": spec["application_identifier"],
        "com.apple.developer.team-identifier": TEAM,
        "get-task-allow": False,
        "beta-reports-active": True,
    }
    for key, expected in expected_entitlements.items():
        if entitlements.get(key) != expected:
            raise VerificationError(f"profile entitlement {key} does not match")
    groups = entitlements.get("com.apple.security.application-groups", [])
    if groups != spec["groups"]:
        raise VerificationError("profile App Groups do not match")
    network_extensions = entitlements.get(
        "com.apple.developer.networking.networkextension", []
    )
    if spec["network_extension"]:
        if (
            not isinstance(network_extensions, list)
            or "packet-tunnel-provider" not in network_extensions
        ):
            raise VerificationError("profile lacks Packet Tunnel capability")
    elif network_extensions:
        raise VerificationError("profile has an unexpected Network Extension")
    keychain = entitlements.get("keychain-access-groups")
    if not isinstance(keychain, list) or f"{TEAM}.*" not in keychain:
        raise VerificationError("profile lacks the Team Keychain wildcard")
    return {
        "name": value["Name"],
        "uuid": value["UUID"],
        "expires_at": expiration.astimezone(dt.timezone.utc).isoformat(),
        "application_identifier": entitlements["application-identifier"],
        "application_groups": groups,
        "packet_tunnel_capability": (
            "packet-tunnel-provider" in network_extensions
        ),
    }


def signed_entitlements(bundle: pathlib.Path) -> dict[str, Any]:
    result = run("codesign", "-d", "--entitlements", ":-", str(bundle))
    raw = result.stdout or result.stderr
    start = raw.find(b"<?xml")
    if start < 0:
        raise VerificationError(f"{bundle}: codesign returned no plist")
    try:
        value = plistlib.loads(raw[start:])
    except plistlib.InvalidFileException as exc:
        raise VerificationError(
            f"{bundle}: signed entitlements are invalid"
        ) from exc
    if not isinstance(value, dict):
        raise VerificationError(f"{bundle}: entitlements are not a dictionary")
    return value


def validate_signed_entitlements(
    actual: dict[str, Any],
    application_identifier: str,
    keychain_groups: list[str],
    application_groups: list[str],
    network_extensions: list[str],
) -> None:
    expected: dict[str, Any] = {
        "application-identifier": f"{TEAM}.{application_identifier}",
        "beta-reports-active": True,
        "com.apple.developer.team-identifier": TEAM,
        "get-task-allow": False,
        "keychain-access-groups": keychain_groups,
    }
    if application_groups:
        expected["com.apple.security.application-groups"] = application_groups
    if network_extensions:
        expected[
            "com.apple.developer.networking.networkextension"
        ] = network_extensions
    if actual != expected:
        raise VerificationError("signed entitlements are not the exact allowlist")


def verify_static_tunnel_engine(
    extension: pathlib.Path,
    host_app: pathlib.Path,
) -> dict[str, Any]:
    try:
        info = plistlib.loads((extension / "Info.plist").read_bytes())
    except (OSError, plistlib.InvalidFileException) as exc:
        raise VerificationError(
            f"{extension}: Packet Tunnel metadata is invalid"
        ) from exc
    if (
        not isinstance(info, dict)
        or info.get("CFBundleExecutable") != "MeshPacketTunnel"
    ):
        raise VerificationError(
            f"{extension}: Packet Tunnel executable identity is invalid"
        )
    executable = extension / "MeshPacketTunnel"
    if (
        not executable.is_file()
        or executable.is_symlink()
        or any(extension.rglob("*.framework"))
    ):
        raise VerificationError(
            f"{extension}: static Packet Tunnel engine layout is invalid"
        )
    symbols = run("nm", "-gU", str(executable), timeout=120).stdout.decode(
        "utf-8",
        "replace",
    )
    if any(symbol not in symbols for symbol in TUNNEL_ENGINE_SYMBOLS):
        raise VerificationError(
            f"{extension}: static Packet Tunnel engine symbols are incomplete"
        )
    host_executable = host_app / "Mesh Tunnel"
    if not host_executable.is_file() or host_executable.is_symlink():
        raise VerificationError(
            f"{host_app}: containing-app executable is missing"
        )
    host_symbols = run(
        "strings",
        "-a",
        str(host_executable),
        timeout=120,
    ).stdout.decode("utf-8", "replace")
    if any(
        symbol not in host_symbols
        for symbol in TUNNEL_HOST_SESSION_SYMBOLS
    ):
        raise VerificationError(
            f"{host_app}: static host enrollment symbols are incomplete"
        )
    dependencies = run(
        "otool",
        "-L",
        str(executable),
        timeout=120,
    ).stdout.decode("utf-8", "replace")
    if "MeshMobile.framework" in dependencies:
        raise VerificationError(
            f"{extension}: Packet Tunnel engine is unexpectedly dynamic"
        )
    strings = run(
        "strings",
        "-a",
        str(executable),
        timeout=120,
    ).stdout.decode("utf-8", "replace")
    if any(marker not in strings for marker in TUNNEL_ENGINE_MARKERS):
        raise VerificationError(
            f"{extension}: static Packet Tunnel engine identity is incomplete"
        )
    return {
        "linkage": "static",
        "dynamic_framework_embedded": False,
        "symbols": sorted(TUNNEL_ENGINE_SYMBOLS),
        "host_session_symbols": sorted(TUNNEL_HOST_SESSION_SYMBOLS),
        "identity_markers": sorted(TUNNEL_ENGINE_MARKERS),
        "executable_sha256": sha256_file(executable),
        "physical_device_packet_path_validated": False,
    }


def verify_archive(
    archive: pathlib.Path,
    app_relative: pathlib.Path,
    application_identifier: str,
    profile_uuid: str,
    keychain_groups: list[str],
    application_groups: list[str],
    network_extensions: list[str],
    extension: tuple[pathlib.Path, str, str, list[str]] | None = None,
) -> dict[str, Any]:
    app = archive / "Products" / "Applications" / app_relative
    if not app.is_dir() or app.is_symlink():
        raise VerificationError(f"{app}: signed application is missing")
    run("codesign", "--verify", "--deep", "--strict", "--verbose=4", str(app))
    validate_signed_entitlements(
        signed_entitlements(app),
        application_identifier,
        keychain_groups,
        application_groups,
        network_extensions,
    )
    embedded = load_profile(app / "embedded.mobileprovision")
    if embedded.get("UUID") != profile_uuid:
        raise VerificationError(f"{app}: embedded profile UUID does not match")
    archive_info = plistlib.loads((archive / "Info.plist").read_bytes())
    properties = archive_info.get("ApplicationProperties", {})
    if (
        properties.get("CFBundleIdentifier") != application_identifier
        or properties.get("Team") != TEAM
        or not str(properties.get("SigningIdentity", "")).startswith(
            "Apple Distribution:"
        )
    ):
        raise VerificationError(f"{archive}: archive properties do not match")
    result: dict[str, Any] = {
        "bundle_identifier": application_identifier,
        "application_tree_sha256": tree_digest(app),
        "embedded_profile_uuid": profile_uuid,
        "strict_signature_verified": True,
    }
    if extension is not None:
        relative, identifier, extension_uuid, extension_keychain = extension
        appex = app / relative
        validate_signed_entitlements(
            signed_entitlements(appex),
            identifier,
            extension_keychain,
            [GROUP],
            ["packet-tunnel-provider"],
        )
        embedded_extension = load_profile(appex / "embedded.mobileprovision")
        if embedded_extension.get("UUID") != extension_uuid:
            raise VerificationError(
                f"{appex}: embedded profile UUID does not match"
            )
        result["extension"] = {
            "bundle_identifier": identifier,
            "embedded_profile_uuid": extension_uuid,
            "packet_tunnel_entitlement": True,
            "engine": verify_static_tunnel_engine(appex, app),
        }
    return result


def verify_exported_ipa(
    ipa: pathlib.Path,
    app_relative: pathlib.Path,
    application_identifier: str,
    profile_uuid: str,
    keychain_groups: list[str],
    application_groups: list[str],
    network_extensions: list[str],
    extension: tuple[pathlib.Path, str, str, list[str]] | None = None,
) -> dict[str, Any]:
    if (
        not ipa.is_file()
        or ipa.is_symlink()
        or ipa.stat().st_size > 1024 * 1024 * 1024
    ):
        raise VerificationError(f"{ipa}: invalid IPA file")
    with tempfile.TemporaryDirectory(prefix="mesh-ipa-verify-") as temporary:
        destination = pathlib.Path(temporary)
        run("ditto", "-x", "-k", str(ipa), str(destination))
        app = destination / "Payload" / app_relative
        if not app.is_dir() or app.is_symlink():
            raise VerificationError(f"{ipa}: expected application is missing")
        run(
            "codesign",
            "--verify",
            "--deep",
            "--strict",
            "--verbose=4",
            str(app),
        )
        validate_signed_entitlements(
            signed_entitlements(app),
            application_identifier,
            keychain_groups,
            application_groups,
            network_extensions,
        )
        if load_profile(app / "embedded.mobileprovision").get("UUID") != (
            profile_uuid
        ):
            raise VerificationError(f"{ipa}: embedded profile does not match")
        result: dict[str, Any] = {
            "bundle_identifier": application_identifier,
            "bytes": ipa.stat().st_size,
            "ipa_sha256": sha256_file(ipa),
            "embedded_profile_uuid": profile_uuid,
            "strict_signature_verified": True,
        }
        if extension is not None:
            relative, identifier, extension_uuid, extension_keychain = extension
            appex = app / relative
            validate_signed_entitlements(
                signed_entitlements(appex),
                identifier,
                extension_keychain,
                [GROUP],
                ["packet-tunnel-provider"],
            )
            if load_profile(appex / "embedded.mobileprovision").get(
                "UUID"
            ) != extension_uuid:
                raise VerificationError(
                    f"{ipa}: extension embedded profile does not match"
                )
            result["extension"] = {
                "bundle_identifier": identifier,
                "embedded_profile_uuid": extension_uuid,
                "packet_tunnel_entitlement": True,
                "engine": verify_static_tunnel_engine(appex, app),
            }
        return result


def create_receipt(path: pathlib.Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    payload = (
        json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n"
    ).encode()
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
    except OSError as exc:
        raise VerificationError(f"cannot create receipt {path}: {exc}") from exc
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(payload)


def selected_products(product: str) -> tuple[str, ...]:
    if product == "all":
        return ("ios-admin", "ios-tunnel")
    if product in ("ios-admin", "ios-tunnel"):
        return (product,)
    raise VerificationError("Apple distribution product selection is invalid")


def receipt_limitations(product: str) -> dict[str, bool]:
    common = {
        "app_store_or_testflight_uploaded": False,
        "physical_device_tested": False,
        "release_authority": False,
    }
    if product == "all":
        return {
            **common,
            "packet_path_verified": False,
        }
    if product == "ios-admin":
        return {
            **common,
            "managed_distribution_tested": False,
            "real_browser_authentication_tested": False,
        }
    if product == "ios-tunnel":
        return {
            **common,
            "lifecycle_validated": False,
            "network_settings_applied": False,
            "packet_path_verified": False,
        }
    raise VerificationError("Apple distribution product selection is invalid")


def require_arguments(
    parser: argparse.ArgumentParser,
    args: argparse.Namespace,
    names: tuple[str, ...],
) -> None:
    missing = [
        f"--{name.replace('_', '-')}"
        for name in names
        if getattr(args, name) is None
    ]
    if missing:
        parser.error(
            f"{args.product} verification requires {', '.join(missing)}"
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--product",
        choices=("all", "ios-admin", "ios-tunnel"),
        default="all",
    )
    parser.add_argument("--admin-profile", type=pathlib.Path)
    parser.add_argument("--host-profile", type=pathlib.Path)
    parser.add_argument("--extension-profile", type=pathlib.Path)
    parser.add_argument("--admin-archive", type=pathlib.Path)
    parser.add_argument("--tunnel-archive", type=pathlib.Path)
    parser.add_argument("--admin-ipa", type=pathlib.Path)
    parser.add_argument("--tunnel-ipa", type=pathlib.Path)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    products = selected_products(args.product)
    if "ios-admin" in products:
        require_arguments(
            parser,
            args,
            ("admin_profile", "admin_archive", "admin_ipa"),
        )
    if "ios-tunnel" in products:
        require_arguments(
            parser,
            args,
            (
                "host_profile",
                "extension_profile",
                "tunnel_archive",
                "tunnel_ipa",
            ),
        )
    now = dt.datetime.now(dt.timezone.utc)
    profile_paths: dict[str, pathlib.Path] = {}
    if "ios-admin" in products:
        profile_paths["admin"] = args.admin_profile
    if "ios-tunnel" in products:
        profile_paths["host"] = args.host_profile
        profile_paths["extension"] = args.extension_profile
    profiles: dict[str, Any] = {}
    for name, path in profile_paths.items():
        profiles[name] = validate_profile(
            load_profile(path), PROFILE_SPECS[name], now
        )
        profiles[name]["sha256"] = sha256_file(path)
    archives: dict[str, Any] = {}
    exports: dict[str, Any] = {}
    if "ios-admin" in products:
        archives["ios_admin"] = verify_archive(
            args.admin_archive,
            pathlib.Path("Runner.app"),
            "io.rw0.mesh.admin.mobile",
            PROFILE_SPECS["admin"]["uuid"],
            [f"{TEAM}.io.rw0.mesh.admin.mobile"],
            [],
            [],
        )
        exports["ios_admin"] = verify_exported_ipa(
            args.admin_ipa,
            pathlib.Path("Runner.app"),
            "io.rw0.mesh.admin.mobile",
            PROFILE_SPECS["admin"]["uuid"],
            [f"{TEAM}.io.rw0.mesh.admin.mobile"],
            [],
            [],
        )
    if "ios-tunnel" in products:
        extension = (
            pathlib.Path("PlugIns/MeshPacketTunnel.appex"),
            "io.rw0.mesh.tunnel.mobile.packet-tunnel",
            PROFILE_SPECS["extension"]["uuid"],
            list(TUNNEL_SHARED_KEYCHAIN_GROUPS),
        )
        archives["ios_tunnel"] = verify_archive(
            args.tunnel_archive,
            pathlib.Path("Mesh Tunnel.app"),
            "io.rw0.mesh.tunnel.mobile",
            PROFILE_SPECS["host"]["uuid"],
            list(TUNNEL_SHARED_KEYCHAIN_GROUPS),
            [GROUP],
            ["packet-tunnel-provider"],
            extension,
        )
        exports["ios_tunnel"] = verify_exported_ipa(
            args.tunnel_ipa,
            pathlib.Path("Mesh Tunnel.app"),
            "io.rw0.mesh.tunnel.mobile",
            PROFILE_SPECS["host"]["uuid"],
            list(TUNNEL_SHARED_KEYCHAIN_GROUPS),
            [GROUP],
            ["packet-tunnel-provider"],
            extension,
        )
    receipt = {
        "schema": (
            "mesh-apple-ios-distribution-verification-receipt-v2"
            if args.product == "all"
            else "mesh-apple-ios-product-distribution-receipt-v3"
        ),
        "verified_at": now.replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        "team_id": TEAM,
        "build_inputs_sha256": sha256_file(INPUTS),
        "profiles": profiles,
        "archives": archives,
        "app_store_exports": exports,
        "limitations": receipt_limitations(args.product),
    }
    if args.product != "all":
        receipt["product"] = args.product
    create_receipt(args.output, receipt)
    print(f"Apple iOS distribution inputs verified: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
