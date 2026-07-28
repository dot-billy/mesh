#!/usr/bin/env python3
"""Validate pinned Apple build inputs and emit a bounded source-build receipt."""

from __future__ import annotations

import argparse
import datetime as dt
import email.utils
import hashlib
import json
import os
import pathlib
import platform
import re
import shutil
import stat
import subprocess
import sys
import urllib.request
from collections.abc import Callable


ROOT = pathlib.Path(__file__).resolve().parents[1]
INPUTS_PATH = ROOT / "desktop" / "tool" / "apple-build.json"
MAXIMUM_INPUT_BYTES = 64 * 1024
SOURCE_SECRET_NAMES = {
    "AC_PASSWORD",
    "APPLE_ID",
    "APPLE_TEAM_ID",
    "APP_STORE_CONNECT_API_KEY",
    "APP_STORE_CONNECT_API_KEY_ID",
    "APP_STORE_CONNECT_ISSUER_ID",
    "DEVELOPER_ID_APPLICATION",
    "DEVELOPER_ID_INSTALLER",
    "FASTLANE_PASSWORD",
    "MATCH_PASSWORD",
    "NOTARY_PASSWORD",
    "NOTARY_PROFILE",
}


class PreflightError(RuntimeError):
    pass


def canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode()


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: pathlib.Path) -> tuple[dict[str, object], str]:
    raw = path.read_bytes()
    if not raw or len(raw) > MAXIMUM_INPUT_BYTES:
        raise PreflightError(f"{path} is empty or exceeds its size bound")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PreflightError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise PreflightError(f"{path} must contain one JSON object")
    return value, hashlib.sha256(raw).hexdigest()


def run(*arguments: str) -> str:
    environment = {
        name: os.environ[name]
        for name in ("HOME", "LOGNAME", "PATH", "TMPDIR", "USER")
        if os.environ.get(name)
    }
    environment["LANG"] = "C"
    try:
        result = subprocess.run(
            arguments,
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
            env=environment,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise PreflightError(f"command failed: {' '.join(arguments)}: {exc}") from exc
    return result.stdout.strip()


def require_equal(name: str, actual: str, expected: str) -> None:
    if actual != expected:
        raise PreflightError(f"{name} is {actual!r}, expected {expected!r}")


def require_configuration(inputs: dict[str, object], flutter: dict[str, object]) -> None:
    if inputs.get("schema") != "mesh-apple-build-inputs-v1":
        raise PreflightError("Apple build-input schema is unsupported")
    if inputs.get("apple_developer") != {
        "approval_status": "registered-and-provisioned",
        "approved_on": "2026-07-24",
        "team_id": "Y3P5UNNG23",
        "program": "Apple Developer Program",
        "enrollment": "individual",
        "macos_admin_application_identifier": "io.rw0.mesh.admin",
        "ios_admin_application_identifier": "io.rw0.mesh.admin.mobile",
        "ios_tunnel_application_identifier": "io.rw0.mesh.tunnel.mobile",
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
            "ios_tunnel_extension": "Mesh Packet Tunnel App Store",
        },
    }:
        raise PreflightError("approved Apple Developer configuration is invalid")
    flutter_input = inputs.get("flutter")
    if not isinstance(flutter_input, dict):
        raise PreflightError("Apple Flutter input is missing")
    require_equal(
        "Flutter version",
        str(flutter_input.get("version", "")),
        str(flutter.get("version", "")),
    )
    require_equal(
        "Flutter framework commit",
        str(flutter_input.get("framework_commit", "")),
        str(flutter.get("framework_commit", "")),
    )
    archives = flutter.get("archives")
    archive_map = flutter_input.get("macos_archives")
    if not isinstance(archives, dict) or not isinstance(archive_map, dict):
        raise PreflightError("macOS Flutter archive mapping is missing")
    for architecture in ("arm64", "x86_64"):
        key = archive_map.get(architecture)
        entry = archives.get(key) if isinstance(key, str) else None
        if (
            not isinstance(entry, dict)
            or not re.fullmatch(r"flutter_macos(?:_arm64)?_[0-9.]+-stable\.zip", str(entry.get("file", "")))
            or not re.fullmatch(r"[0-9a-f]{64}", str(entry.get("sha256", "")))
        ):
            raise PreflightError(f"Flutter archive for {architecture} is invalid")
    nebula = inputs.get("nebula")
    if (
        not isinstance(nebula, dict)
        or nebula.get("module") != "github.com/slackhq/nebula"
        or not re.fullmatch(
            r"[0-9]+\.[0-9]+\.[0-9]+", str(nebula.get("version", ""))
        )
        or nebula.get("certificate_tool") != "nebula-cert"
    ):
        raise PreflightError("Nebula build input is invalid")
    ios_tunnel = inputs.get("ios_tunnel")
    gomobile = (
        ios_tunnel.get("gomobile") if isinstance(ios_tunnel, dict) else None
    )
    engine_source = (
        ios_tunnel.get("engine_source")
        if isinstance(ios_tunnel, dict)
        else None
    )
    if (
        not isinstance(ios_tunnel, dict)
        or ios_tunnel.get("engine_framework") != "MeshMobile.xcframework"
        or ios_tunnel.get("engine_status")
        != (
            "extension-enrollment-lifecycle-renewal-credential-rotation-"
            "mobile-evidence-identity-removal-signed-config-packet-session-"
            "source-wired"
        )
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
        or not isinstance(engine_source, dict)
        or engine_source.get("upstream_url")
        != "https://github.com/slackhq/nebula"
        or engine_source.get("upstream_tag") != "v1.10.3"
        or engine_source.get("upstream_commit")
        != "f573e8a26695278f9d71587390fbfe0d0933aa21"
        or engine_source.get("module_graph_sha256")
        != "900aee5c8ee4441da7a3bc7932c6b29f1468670cdfdc6615b75bb82fe905810f"
        or ios_tunnel.get("framework_build")
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
        or ios_tunnel.get("packet_bridge")
        != {
            "nebula_adapter": (
                "github.com/slackhq/nebula/overlay.NewFdDeviceFromConfig"
            ),
            "apple_transport": "NetworkExtension utun descriptor",
            "status": "mobile-nebula-native-utun-source-wired",
        }
        or ios_tunnel.get("runtime_startup")
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
    ):
        raise PreflightError("iOS Tunnel mobile framework input is invalid")


def validate_source_keychain(
    path: pathlib.Path, identity_lookup: Callable[..., str] = run
) -> None:
    if (
        not path.is_absolute()
        or not path.is_file()
        or path.is_symlink()
        or stat.S_IMODE(path.stat().st_mode) & 0o077
    ):
        raise PreflightError("source build Keychain must be one private physical file")
    identities = identity_lookup(
        "security",
        "find-identity",
        "-v",
        "-p",
        "codesigning",
        str(path),
    )
    if "0 valid identities found" not in identities:
        raise PreflightError("source build Keychain contains a code-signing identity")


def network_clock(url: str, maximum_skew: int) -> tuple[str, int]:
    request = urllib.request.Request(url, method="HEAD")
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            date_header = response.headers.get("Date", "")
            final_url = response.geturl()
    except OSError as exc:
        raise PreflightError(f"Apple build network preflight failed: {exc}") from exc
    if not final_url.startswith("https://") or not date_header:
        raise PreflightError("Apple build network preflight returned no authenticated time")
    remote = email.utils.parsedate_to_datetime(date_header)
    if remote.tzinfo is None:
        raise PreflightError("Apple build network time has no timezone")
    now = dt.datetime.now(dt.timezone.utc)
    skew = round(abs((now - remote).total_seconds()))
    if skew > maximum_skew:
        raise PreflightError(
            f"host clock differs from authenticated network time by {skew} seconds"
        )
    return final_url, skew


def select_archive(
    inputs: dict[str, object], flutter: dict[str, object], machine: str
) -> tuple[str, dict[str, object]]:
    flutter_input = inputs["flutter"]
    assert isinstance(flutter_input, dict)
    mapping = flutter_input["macos_archives"]
    archives = flutter["archives"]
    assert isinstance(mapping, dict) and isinstance(archives, dict)
    architecture = "arm64" if machine == "arm64" else "x86_64" if machine == "x86_64" else ""
    if not architecture:
        raise PreflightError(f"unsupported Apple build architecture {machine!r}")
    key = mapping[architecture]
    entry = archives[key]
    assert isinstance(key, str) and isinstance(entry, dict)
    return key, entry


def collect(args: argparse.Namespace) -> dict[str, object]:
    found_secrets = sorted(name for name in SOURCE_SECRET_NAMES if os.environ.get(name))
    if found_secrets:
        raise PreflightError(
            f"unsigned source gate received release credential variables: {found_secrets}"
        )
    inputs, inputs_digest = load_json(INPUTS_PATH)
    flutter_path = ROOT / str(inputs.get("flutter", {}).get("pin_file", ""))
    flutter, flutter_digest = load_json(flutter_path)
    require_configuration(inputs, flutter)

    validate_source_keychain(pathlib.Path(args.source_keychain))

    machine = platform.machine()
    archive_key, archive = select_archive(inputs, flutter, machine)
    archive_path = pathlib.Path(args.flutter_archive).resolve()
    if not archive_path.is_file() or archive_path.is_symlink():
        raise PreflightError("Flutter archive must be one physical regular file")
    archive_digest = sha256_file(archive_path)
    require_equal("Flutter archive SHA-256", archive_digest, str(archive["sha256"]))

    xcode = inputs["xcode"]
    sdks = inputs["sdks"]
    swift = inputs["swift"]
    preflight = inputs["preflight"]
    assert all(isinstance(value, dict) for value in (xcode, sdks, swift, preflight))

    developer_directory = run("xcode-select", "-p")
    developer_directories = xcode.get("developer_directories")
    if (
        not isinstance(developer_directories, list)
        or developer_directory not in developer_directories
    ):
        raise PreflightError(
            f"DEVELOPER_DIR is {developer_directory!r}, expected one pinned path"
        )
    xcode_lines = run("xcodebuild", "-version").splitlines()
    if len(xcode_lines) != 2:
        raise PreflightError("Xcode version output is not exact")
    require_equal("Xcode version", xcode_lines[0], f"Xcode {xcode['version']}")
    require_equal("Xcode build", xcode_lines[1], f"Build version {xcode['build']}")
    observed_sdks = {
        name: run("xcrun", "--sdk", name, "--show-sdk-version")
        for name in ("macosx", "iphoneos", "iphonesimulator")
    }
    for name, actual in observed_sdks.items():
        require_equal(f"{name} SDK", actual, str(sdks[name]))

    swift_output = run("swift", "--version")
    if (
        f"Apple Swift version {swift['version']}" not in swift_output
        or str(swift["build"]) not in swift_output
    ):
        raise PreflightError("Swift compiler identity differs from the build inputs")

    go_output = run("go", "version")
    expected_go = f"go version go{inputs['go_version']} darwin/{'arm64' if machine == 'arm64' else 'amd64'}"
    require_equal("Go version", go_output, expected_go)
    nebula = inputs["nebula"]
    assert isinstance(nebula, dict)
    require_equal(
        "Nebula module version",
        run("go", "list", "-m", "-f", "{{.Version}}", str(nebula["module"])),
        f"v{nebula['version']}",
    )
    nebula_tool_path = pathlib.Path(
        run("go", "tool", "-n", str(nebula["certificate_tool"]))
    )
    if (
        not nebula_tool_path.is_absolute()
        or not nebula_tool_path.is_file()
        or nebula_tool_path.is_symlink()
    ):
        raise PreflightError("Nebula certificate tool is not one physical executable")
    require_equal(
        "nebula-cert version",
        run(str(nebula_tool_path), "-version"),
        f"Version: {nebula['version']}",
    )

    try:
        flutter_machine = json.loads(run(args.flutter, "--version", "--machine"))
    except json.JSONDecodeError as exc:
        raise PreflightError("Flutter machine identity is not one JSON value") from exc
    require_equal("installed Flutter version", str(flutter_machine.get("frameworkVersion", "")), str(inputs["flutter"]["version"]))
    require_equal("installed Flutter commit", str(flutter_machine.get("frameworkRevision", "")), str(inputs["flutter"]["framework_commit"]))

    runtimes = json.loads(run("xcrun", "simctl", "list", "runtimes", "--json"))
    available = {
        item.get("identifier")
        for item in runtimes.get("runtimes", [])
        if item.get("isAvailable") is True
    }
    required_runtimes = set(inputs["required_simulator_runtimes"])
    missing = sorted(required_runtimes - available)
    if missing:
        raise PreflightError(f"required simulator runtimes are unavailable: {missing}")

    free_bytes = shutil.disk_usage(ROOT).free
    if free_bytes < int(preflight["minimum_free_bytes"]):
        raise PreflightError("Apple build host has insufficient free disk space")

    final_url, clock_skew = network_clock(
        str(preflight["network_probe_url"]),
        int(preflight["maximum_clock_skew_seconds"]),
    )
    source_commit = run("git", "rev-parse", "HEAD")
    if not re.fullmatch(r"[0-9a-f]{40}", source_commit):
        raise PreflightError("source commit is not canonical")
    source_status = run("git", "status", "--porcelain")
    if args.require_clean and source_status:
        raise PreflightError("Apple source gate requires a clean checkout")

    return {
        "schema": "mesh-apple-source-build-receipt-v1",
        "source": {
            "commit": source_commit,
            "clean": not bool(source_status),
        },
        "inputs": {
            "apple_build_sha256": inputs_digest,
            "flutter_sdk_sha256": flutter_digest,
            "flutter_archive_key": archive_key,
            "flutter_archive_file": archive["file"],
            "flutter_archive_sha256": archive_digest,
            "nebula_certificate_tool_sha256": sha256_file(nebula_tool_path),
        },
        "host": {
            "architecture": machine,
            "macos": platform.mac_ver()[0],
            "xcode_version": xcode["version"],
            "xcode_build": xcode["build"],
            "developer_directory": developer_directory,
            "sdks": observed_sdks,
            "swift_version": swift["version"],
            "swift_build": swift["build"],
            "go_version": inputs["go_version"],
            "nebula_version": nebula["version"],
            "flutter_version": inputs["flutter"]["version"],
            "flutter_commit": inputs["flutter"]["framework_commit"],
            "simulator_runtimes": sorted(required_runtimes),
            "free_bytes": free_bytes,
        },
        "preflight": {
            "network_url": final_url,
            "clock_skew_seconds": clock_skew,
            "release_credentials_present": False,
            "source_keychain_code_signing_identities": 0,
        },
        "completed_at": dt.datetime.now(dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--flutter", required=True)
    parser.add_argument("--flutter-archive", required=True)
    parser.add_argument("--source-keychain", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--require-clean", action="store_true")
    args = parser.parse_args()
    output = pathlib.Path(args.output)
    if not output.is_absolute() or output.exists() or output.parent.is_symlink():
        raise PreflightError("receipt output must be a new absolute path")
    receipt = collect(args)
    raw = canonical_json(receipt)
    if len(raw) > MAXIMUM_INPUT_BYTES:
        raise PreflightError("Apple source-build receipt exceeds its size bound")
    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with output.open("xb") as target:
        target.write(raw)
        target.flush()
        os.fsync(target.fileno())
    print(f"Apple source-build preflight passed: {output}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except PreflightError as exc:
        print(f"Apple build preflight: {exc}", file=sys.stderr)
        raise SystemExit(1)
