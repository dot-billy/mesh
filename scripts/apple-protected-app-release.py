#!/usr/bin/env python3
"""Sign, notarize, staple, verify, and archive one Mesh Admin macOS app."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import pathlib
import plistlib
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import uuid
from typing import Any


SCHEMA = "mesh-apple-macos-protected-release-receipt-v3"
SOURCE_SCHEMA = "mesh-apple-macos-source-artifact-receipt-v2"
SECURITY_SCHEMA = "mesh-apple-admin-security-receipt-v1"
APP_TEAM_ID = "Y3P5UNNG23"
APP_IDENTIFIER = "io.rw0.mesh.admin"
APP_NAME = "Mesh Admin.app"
CANONICAL_SYMLINK_MODE = 0o777
MAXIMUM_FILES = 4096
MAXIMUM_BYTES = 1024 * 1024 * 1024
MAXIMUM_RECEIPT_BYTES = 128 * 1024
MAXIMUM_COMMAND_OUTPUT = 256 * 1024
TEAM_ID = re.compile(r"^[A-Z0-9]{10}$")
SHA1 = re.compile(r"^[0-9A-F]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
PROFILE_UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
NOTARY_PROFILE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
APP_VERSION = re.compile(r"^[0-9]+(?:\.[0-9]+){0,3}$")
APP_BUILD = re.compile(r"^[0-9]+$")
RUNTIME_FLAGS = re.compile(rb"flags=0x[0-9a-fA-F]+\([^)\r\n]*runtime[^)\r\n]*\)")
IDENTITY_LINE = re.compile(
    r'^\s*\d+\)\s+([0-9A-F]{40})\s+"Developer ID Application: .+ \(([A-Z0-9]{10})\)"\s*$'
)
CODE_BUNDLE_SUFFIXES = {".app", ".appex", ".framework", ".plugin", ".xpc"}
EXPECTED_NESTED_CODE = {
    "Contents/Frameworks/App.framework": "io.flutter.flutter.app",
    "Contents/Frameworks/FlutterMacOS.framework": "io.flutter.flutter-macos",
    "Contents/Frameworks/objective_c.framework": "io.flutter.flutter.native-assets.objective-c",
}
MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce",
    b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf",
    b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",
    b"\xbe\xba\xfe\xca",
    b"\xca\xfe\xba\xbf",
    b"\xbf\xba\xfe\xca",
}
FIXED_ENV = {
    "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
    "LANG": "C",
    "LC_ALL": "C",
}
APPLE_TOOL_IDENTIFIERS = {
    "/usr/bin/codesign": "com.apple.security.codesign",
    "/usr/bin/ditto": "com.apple.ditto",
    "/usr/bin/lipo": "com.apple.dt.xcode_select.tool-shim-public",
    "/usr/bin/security": "com.apple.security",
    "/usr/bin/xcrun": "com.apple.xcrun",
    "/usr/sbin/spctl": "com.apple.spctl",
}
XCODE_TOOL_IDENTIFIERS = {
    "notarytool": "com.apple.gke.notary.tool",
    "stapler": "com.apple.stapler",
}


class ReleaseError(RuntimeError):
    pass


def digest_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def digest_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def file_identity(path: pathlib.Path) -> dict[str, Any]:
    if not path.is_absolute() or not path.is_file() or path.is_symlink():
        raise ReleaseError(f"protected release input is not one physical file: {path}")
    metadata = path.stat()
    return {
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "mode": metadata.st_mode,
        "size": metadata.st_size,
        "mtime_ns": metadata.st_mtime_ns,
        "sha256": digest_file(path),
    }


def bounded_read(path: pathlib.Path, maximum: int, label: str) -> bytes:
    if not path.is_file() or path.is_symlink():
        raise ReleaseError(f"{label} must be one physical regular file")
    metadata = path.stat()
    if metadata.st_size < 1 or metadata.st_size > maximum:
        raise ReleaseError(f"{label} is empty or oversized")
    raw = path.read_bytes()
    if len(raw) != metadata.st_size:
        raise ReleaseError(f"{label} changed while reading")
    return raw


def validate_team_id(value: str) -> str:
    if TEAM_ID.fullmatch(value) is None or value != APP_TEAM_ID:
        raise ReleaseError(
            "Apple Admin Team ID differs from the approved application contract"
        )
    return value


def parse_identity_output(raw: str, team_id: str) -> str:
    matches = []
    for line in raw.splitlines():
        match = IDENTITY_LINE.fullmatch(line)
        if match and match.group(2) == team_id:
            matches.append(match.group(1))
    if len(matches) != 1 or not SHA1.fullmatch(matches[0]):
        raise ReleaseError(
            "private release Keychain must contain exactly one Developer ID "
            "Application identity for the compiled Team ID"
        )
    return matches[0]


def parse_notary_result(raw: bytes) -> str:
    if len(raw) < 2 or len(raw) > MAXIMUM_COMMAND_OUTPUT:
        raise ReleaseError("notarytool result is empty or oversized")
    try:
        result = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseError("notarytool result is not valid JSON") from exc
    identifier = result.get("id") if isinstance(result, dict) else None
    try:
        canonical_id = str(uuid.UUID(str(identifier)))
    except (ValueError, AttributeError) as exc:
        raise ReleaseError("notarytool result has no canonical submission ID") from exc
    if result.get("status") != "Accepted" or canonical_id != identifier:
        raise ReleaseError("Apple notarization was not accepted")
    return canonical_id


def canonical_tree_mode(raw_mode: int) -> int:
    if stat.S_ISLNK(raw_mode):
        return CANONICAL_SYMLINK_MODE
    return stat.S_IMODE(raw_mode)


def tree_identity(root: pathlib.Path) -> tuple[str, int, int]:
    digest = hashlib.sha256()
    files = 0
    total = 0
    resolved_root = root.resolve(strict=True)
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        metadata = path.lstat()
        mode = canonical_tree_mode(metadata.st_mode)
        if stat.S_ISLNK(metadata.st_mode):
            # ditto does not preserve symlink permission bits across its ZIP
            # boundary. Darwin does not use those bits for authorization, so
            # bind symlinks to one portable canonical mode.
            mode = CANONICAL_SYMLINK_MODE
            target = os.readlink(path)
            if os.path.isabs(target):
                raise ReleaseError(f"absolute application symlink is prohibited: {relative}")
            resolved = path.resolve(strict=True)
            if resolved != resolved_root and resolved_root not in resolved.parents:
                raise ReleaseError(f"application symlink escapes its bundle: {relative}")
            record = f"l {mode:04o} {target} {relative}\n"
        elif stat.S_ISDIR(metadata.st_mode):
            record = f"d {mode:04o} {relative}\n"
        elif stat.S_ISREG(metadata.st_mode):
            files += 1
            total += metadata.st_size
            if files > MAXIMUM_FILES or total > MAXIMUM_BYTES:
                raise ReleaseError("macOS application exceeds its release bounds")
            record = f"f {mode:04o} {metadata.st_size} {digest_file(path)} {relative}\n"
        else:
            raise ReleaseError(f"unsupported application object: {relative}")
        digest.update(record.encode())
    return digest.hexdigest(), files, total


def run(
    arguments: list[str],
    *,
    timeout: int = 60,
    allow_output: bool = False,
    require_success: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    try:
        result = subprocess.run(
            arguments,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
            timeout=timeout,
            env=FIXED_ENV,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ReleaseError(f"protected Apple tool failed to execute: {arguments[0]}") from exc
    if len(result.stdout) > MAXIMUM_COMMAND_OUTPUT or len(result.stderr) > MAXIMUM_COMMAND_OUTPUT:
        raise ReleaseError(f"protected Apple tool output exceeded its bound: {arguments[0]}")
    if require_success and result.returncode != 0:
        raise ReleaseError(
            f"protected Apple tool failed: {arguments[0]} "
            f"stdout_sha256={digest_bytes(result.stdout)} "
            f"stderr_sha256={digest_bytes(result.stderr)}"
        )
    if not allow_output and (result.stdout or result.stderr):
        raise ReleaseError(
            f"protected Apple tool emitted unexpected output: {arguments[0]} "
            f"stdout_sha256={digest_bytes(result.stdout)} "
            f"stderr_sha256={digest_bytes(result.stderr)}"
        )
    return result


def authenticate_apple_tool(path: pathlib.Path, identifier: str) -> dict[str, Any]:
    if not path.is_absolute() or not path.is_file() or path.is_symlink():
        raise ReleaseError(f"Apple release tool is not one physical file: {path}")
    requirement = f'anchor apple and identifier "{identifier}"'
    run(
        [
            "/usr/bin/codesign",
            "--verify",
            "--strict=all",
            "--test-requirement",
            "=" + requirement,
            str(path),
        ]
    )
    metadata = path.stat()
    return {
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "mode": metadata.st_mode,
        "size": metadata.st_size,
        "mtime_ns": metadata.st_mtime_ns,
        "sha256": digest_file(path),
    }


def authenticate_release_tools(developer_directory: str) -> tuple[dict[str, pathlib.Path], dict[str, dict[str, Any]]]:
    developer = pathlib.Path(developer_directory)
    if (
        not developer.is_absolute()
        or developer not in {
            pathlib.Path("/Applications/Xcode.app/Contents/Developer"),
            pathlib.Path("/Applications/Xcode_26.5.0.app/Contents/Developer"),
        }
        or not developer.is_dir()
        or developer.is_symlink()
        or developer.resolve(strict=True) != developer
    ):
        raise ReleaseError("source receipt does not bind one approved Xcode developer directory")
    paths = {path: pathlib.Path(path) for path in APPLE_TOOL_IDENTIFIERS}
    for name in XCODE_TOOL_IDENTIFIERS:
        resolved = run(["/usr/bin/xcrun", "--find", name], allow_output=True)
        raw_path = resolved.stdout.decode("utf-8", "strict").strip()
        path = pathlib.Path(raw_path)
        expected = developer / "usr" / "bin" / name
        if raw_path != str(expected) or path != expected:
            raise ReleaseError(f"xcrun resolved an unexpected protected Apple tool: {name}")
        paths[name] = path
    identities = {}
    for name, path in paths.items():
        identifier = (
            APPLE_TOOL_IDENTIFIERS[name]
            if name in APPLE_TOOL_IDENTIFIERS
            else XCODE_TOOL_IDENTIFIERS[name]
        )
        identities[name] = authenticate_apple_tool(path, identifier)
    return paths, identities


def is_macho(path: pathlib.Path) -> bool:
    if not path.is_file() or path.is_symlink() or path.stat().st_size < 4:
        return False
    with path.open("rb") as source:
        return source.read(4) in MACHO_MAGICS


def nested_code(app: pathlib.Path) -> tuple[list[pathlib.Path], list[pathlib.Path]]:
    bundles = [
        path
        for path in app.rglob("*")
        if path.is_dir() and not path.is_symlink() and path.suffix in CODE_BUNDLE_SUFFIXES
    ]
    bundles = [path for path in bundles if path != app]
    bundles.sort(key=lambda path: (-len(path.relative_to(app).parts), path.as_posix()))
    standalone = []
    main = app / "Contents" / "MacOS" / "Mesh Admin"
    for path in app.rglob("*"):
        if path == main or not is_macho(path):
            continue
        if any(bundle == path or bundle in path.parents for bundle in bundles):
            continue
        standalone.append(path)
    standalone.sort(key=lambda path: path.relative_to(app).as_posix())
    observed = {path.relative_to(app).as_posix() for path in bundles}
    if observed != set(EXPECTED_NESTED_CODE) or standalone:
        raise ReleaseError(
            "unsigned application nested-code inventory differs from the approved release contract"
        )
    return bundles, standalone


def entitlement_document(raw: bytes) -> dict[str, Any]:
    if not raw:
        return {}
    try:
        document = plistlib.loads(raw)
    except plistlib.InvalidFileException as exc:
        raise ReleaseError("signed-code entitlements are not a valid plist") from exc
    if not isinstance(document, dict):
        raise ReleaseError("signed-code entitlements are not one dictionary")
    return document


def architectures(path: pathlib.Path) -> list[str]:
    result = run(["/usr/bin/lipo", "-archs", str(path)], allow_output=True)
    values = result.stdout.decode("utf-8", "strict").strip().split()
    if set(values) != {"arm64", "x86_64"} or len(values) != 2:
        raise ReleaseError(f"signed macOS code is not exactly universal: {path}")
    return sorted(values)


def code_executable(path: pathlib.Path) -> pathlib.Path:
    if path.is_file():
        return path
    names = [path.stem]
    info_candidates = [
        path / "Contents" / "Info.plist",
        path / "Resources" / "Info.plist",
        path / "Versions" / "Current" / "Resources" / "Info.plist",
    ]
    for info_path in info_candidates:
        try:
            resolved = info_path.resolve(strict=True)
            root = path.resolve(strict=True)
            if resolved != root and root not in resolved.parents:
                continue
            document = plistlib.loads(resolved.read_bytes())
        except (OSError, plistlib.InvalidFileException):
            continue
        executable = document.get("CFBundleExecutable") if isinstance(document, dict) else None
        if isinstance(executable, str) and executable and executable not in names:
            names.insert(0, executable)
    candidates = []
    for name in names:
        candidates.extend(
            [
                path / "Contents" / "MacOS" / name,
                path / "Versions" / "Current" / name,
                path / name,
            ]
        )
    for candidate in candidates:
        try:
            resolved = candidate.resolve(strict=True)
            root = path.resolve(strict=True)
        except OSError:
            continue
        if root not in resolved.parents or not resolved.is_file() or not is_macho(resolved):
            continue
        return resolved
    raise ReleaseError(f"could not identify signed bundle executable: {path}")


def verify_code(
    path: pathlib.Path,
    requirement: str,
    entitlements: dict[str, Any],
    identifier: str,
) -> dict[str, Any]:
    run(
        [
            "/usr/bin/codesign",
            "--verify",
            "--strict=all",
            "--test-requirement",
            "=" + requirement,
            str(path),
        ]
    )
    display = run(
        ["/usr/bin/codesign", "--display", "--verbose=4", str(path)],
        allow_output=True,
    )
    diagnostic = display.stdout + display.stderr
    if RUNTIME_FLAGS.search(diagnostic) is None:
        raise ReleaseError(f"signed code lacks hardened-runtime evidence: {path}")
    extracted = run(
        ["/usr/bin/codesign", "--display", "--entitlements", "-", "--xml", str(path)],
        allow_output=True,
    )
    if entitlement_document(extracted.stdout) != entitlements:
        raise ReleaseError(f"signed code has unexpected entitlements: {path}")
    return {
        "architectures": architectures(code_executable(path)),
        "entitlements_sha256": digest_bytes(
            plistlib.dumps(entitlements, fmt=plistlib.FMT_XML, sort_keys=True)
            if entitlements
            else b""
        ),
        "identifier": identifier,
    }


def validate_source(app: pathlib.Path, receipt_path: pathlib.Path) -> tuple[dict[str, Any], str]:
    raw = bounded_read(receipt_path, MAXIMUM_RECEIPT_BYTES, "Apple source receipt")
    try:
        receipt = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseError("Apple source receipt is invalid") from exc
    if (
        not isinstance(receipt, dict)
        or receipt.get("schema") != SOURCE_SCHEMA
        or receipt.get("configuration") != "release"
        or receipt.get("source", {}).get("clean") is not True
        or re.fullmatch(
            r"[0-9a-f]{40}", str(receipt.get("source", {}).get("commit", ""))
        )
        is None
        or receipt.get("bundle", {}).get("identifier") != APP_IDENTIFIER
        or APP_VERSION.fullmatch(str(receipt.get("bundle", {}).get("version", "")))
        is None
        or APP_BUILD.fullmatch(str(receipt.get("bundle", {}).get("build", ""))) is None
        or receipt.get("bundle", {}).get("release_signature") != "absent"
        or receipt.get("bundle", {}).get("entitlements_applied") is not False
        or receipt.get("build_host", {}).get("xcode_version") != "26.5"
        or receipt.get("build_host", {}).get("xcode_build") != "17F42"
        or receipt.get("build_host", {}).get("developer_directory")
        not in {
            "/Applications/Xcode.app/Contents/Developer",
            "/Applications/Xcode_26.5.0.app/Contents/Developer",
        }
    ):
        raise ReleaseError("Apple source receipt is not an unsigned release-app receipt")
    inputs = receipt.get("build_inputs")
    if (
        not isinstance(inputs, dict)
        or set(inputs)
        != {
            "apple_build_sha256",
            "flutter_sdk_sha256",
            "flutter_archive_key",
            "flutter_archive_file",
            "flutter_archive_sha256",
            "nebula_certificate_tool_sha256",
        }
        or any(
            not SHA256.fullmatch(str(inputs.get(name, "")))
            for name in (
                "apple_build_sha256",
                "flutter_sdk_sha256",
                "flutter_archive_sha256",
                "nebula_certificate_tool_sha256",
            )
        )
    ):
        raise ReleaseError("Apple source receipt does not bind the complete pinned build inputs")
    if (json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n").encode() != raw:
        raise ReleaseError("Apple source receipt is not canonical JSON")
    tree_sha, files, total = tree_identity(app)
    bundle = receipt["bundle"]
    if (
        tree_sha != bundle.get("tree_sha256")
        or files != bundle.get("regular_files")
        or total != bundle.get("regular_file_bytes")
    ):
        raise ReleaseError("unsigned application differs from its source receipt")
    return receipt, digest_bytes(raw)


def validate_security_receipt(
    receipt_path: pathlib.Path,
    source_receipt_sha: str,
    source_tree_sha: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    identity = file_identity(receipt_path)
    raw = bounded_read(
        receipt_path, MAXIMUM_RECEIPT_BYTES, "Apple Admin security receipt"
    )
    try:
        receipt = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseError("Apple Admin security receipt is invalid") from exc
    if (
        not isinstance(receipt, dict)
        or receipt.get("schema") != SECURITY_SCHEMA
        or receipt.get("artifact", {}).get("tree_sha256") != source_tree_sha
        or receipt.get("artifact", {}).get("source_receipt", {}).get("sha256")
        != source_receipt_sha
        or receipt.get("dependencies", {}).get(
            "runtime_hosted_package_count", 0
        )
        < 1
        or receipt.get("licenses", {}).get("status")
        != "inventory-present-legal-review-pending"
        or receipt.get("privacy", {}).get("status")
        != "source-reviewed-final-distribution-reconciliation-pending"
        or receipt.get("sbom", {}).get("syft_version") != "1.44.0"
        or receipt.get("sbom", {}).get("spdx_version") != "SPDX-2.3"
        or receipt.get("secret_scan", {}).get("gitleaks_version") != "v8.30.1"
        or receipt.get("vulnerability_scan", {}).get("grype_version")
        != "0.112.0"
    ):
        raise ReleaseError(
            "Apple Admin security receipt does not bind the complete reviewed gate"
        )
    script_dir = pathlib.Path(__file__).resolve().parent
    expected_gate_files = {
        "baseline": script_dir / "apple-admin-security-baseline.sh",
        "gitleaks_policy": script_dir.parent / ".gitleaks-image.toml",
        "verifier": script_dir / "apple_admin_security_verify.py",
    }
    gate = receipt.get("gate")
    if not isinstance(gate, dict) or set(gate) != set(expected_gate_files):
        raise ReleaseError("Apple Admin security receipt gate provenance is incomplete")
    for name, path in expected_gate_files.items():
        raw_gate_file = bounded_read(
            path, 4 << 20, f"Apple Admin security gate {name}"
        )
        if gate.get(name) != {
            "sha256": digest_bytes(raw_gate_file),
            "size": len(raw_gate_file),
        }:
            raise ReleaseError(
                "Apple Admin security receipt was produced by different gate source"
            )
    for section, field in (
        ("sbom", "syft_json"),
        ("sbom", "spdx_json"),
        ("secret_scan", "metadata_report"),
        ("secret_scan", "app_strings_report"),
        ("vulnerability_scan", "database_status"),
        ("vulnerability_scan", "report"),
    ):
        record = receipt.get(section, {}).get(field)
        if (
            not isinstance(record, dict)
            or SHA256.fullmatch(str(record.get("sha256", ""))) is None
            or not isinstance(record.get("size"), int)
            or record["size"] < 1
        ):
            raise ReleaseError("Apple Admin security receipt evidence is incomplete")
    try:
        verified_at = dt.datetime.fromisoformat(
            str(receipt.get("verified_at", "")).replace("Z", "+00:00")
        ).astimezone(dt.timezone.utc)
    except (ValueError, AttributeError) as exc:
        raise ReleaseError("Apple Admin security receipt time is invalid") from exc
    canonical_time = (
        verified_at.replace(microsecond=0).isoformat().replace("+00:00", "Z")
    )
    now = dt.datetime.now(dt.timezone.utc)
    if (
        receipt.get("verified_at") != canonical_time
        or verified_at > now + dt.timedelta(minutes=5)
        or now - verified_at > dt.timedelta(hours=24)
    ):
        raise ReleaseError(
            "Apple Admin security receipt is stale or has a noncanonical time"
        )
    if (json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n").encode() != raw:
        raise ReleaseError("Apple Admin security receipt is not canonical JSON")
    return receipt, identity


def sign_code(path: pathlib.Path, identity: str, keychain: pathlib.Path, entitlements: pathlib.Path | None) -> None:
    arguments = [
        "/usr/bin/codesign",
        "--force",
        "--sign",
        identity,
        "--keychain",
        str(keychain),
        "--timestamp",
        "--options",
        "runtime",
    ]
    if entitlements is not None:
        arguments.extend(["--entitlements", str(entitlements)])
    arguments.append(str(path))
    result = run(arguments, allow_output=True)
    expected_diagnostic = f"{path}: replacing existing signature\n".encode()
    if result.stdout or result.stderr not in {b"", expected_diagnostic}:
        raise ReleaseError(
            "codesign emitted an unexpected successful-signing diagnostic"
        )


def ensure_new_output(path: pathlib.Path) -> None:
    if not path.is_absolute() or path.exists() or path.name in {"", ".", ".."}:
        raise ReleaseError("protected Apple output must be one new absolute path")
    if not path.parent.is_dir() or path.parent.is_symlink():
        raise ReleaseError("protected Apple output parent must be one physical directory")


def app_info(app: pathlib.Path) -> dict[str, Any]:
    raw = bounded_read(app / "Contents" / "Info.plist", 1 << 20, "application Info.plist")
    try:
        info = plistlib.loads(raw)
    except plistlib.InvalidFileException as exc:
        raise ReleaseError("application Info.plist is invalid") from exc
    if (
        not isinstance(info, dict)
        or info.get("CFBundleIdentifier") != APP_IDENTIFIER
        or info.get("CFBundleExecutable") != "Mesh Admin"
        or info.get("LSMinimumSystemVersion") != "14.0"
    ):
        raise ReleaseError("application identity differs from the approved release contract")
    return info


def validate_provisioning_document(
    document: Any,
    team_id: str,
    identity_sha1: str,
    *,
    now: dt.datetime | None = None,
) -> dict[str, str]:
    expected_application_identifier = f"{team_id}.{APP_IDENTIFIER}"
    expected_profile_entitlements = {
        "com.apple.application-identifier": expected_application_identifier,
        "com.apple.developer.team-identifier": team_id,
        "keychain-access-groups": [f"{team_id}.*"],
    }
    if (
        not isinstance(document, dict)
        or document.get("ProvisionsAllDevices") is not True
        or document.get("Platform") != ["OSX"]
        or document.get("TeamIdentifier") != [team_id]
        or document.get("ApplicationIdentifierPrefix") != [team_id]
        or document.get("Entitlements") != expected_profile_entitlements
    ):
        raise ReleaseError(
            "Developer ID provisioning profile differs from the exact application contract"
        )
    profile_uuid = document.get("UUID")
    expiration = document.get("ExpirationDate")
    certificates = document.get("DeveloperCertificates")
    if (
        not isinstance(profile_uuid, str)
        or PROFILE_UUID.fullmatch(profile_uuid.lower()) is None
        or not isinstance(expiration, dt.datetime)
        or not isinstance(certificates, list)
        or not certificates
        or any(not isinstance(certificate, bytes) for certificate in certificates)
        or identity_sha1
        not in {hashlib.sha1(certificate).hexdigest().upper() for certificate in certificates}
    ):
        raise ReleaseError(
            "Developer ID provisioning profile identity is invalid"
        )
    expiration_utc = (
        expiration.replace(tzinfo=dt.timezone.utc)
        if expiration.tzinfo is None
        else expiration.astimezone(dt.timezone.utc)
    )
    current = (now or dt.datetime.now(dt.timezone.utc)).astimezone(
        dt.timezone.utc
    )
    if expiration_utc <= current:
        raise ReleaseError("Developer ID provisioning profile is expired")
    return {
        "expiration": expiration_utc.replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        "uuid": profile_uuid.lower(),
    }


def validate_provisioning_profile(
    path: pathlib.Path,
    team_id: str,
    identity_sha1: str,
) -> dict[str, str]:
    decoded = run(
        ["/usr/bin/security", "cms", "-D", "-i", str(path)],
        allow_output=True,
    )
    try:
        document = plistlib.loads(decoded.stdout)
    except plistlib.InvalidFileException as exc:
        raise ReleaseError(
            "Developer ID provisioning profile is not a valid CMS plist"
        ) from exc
    return validate_provisioning_document(document, team_id, identity_sha1)


def produce(args: argparse.Namespace) -> dict[str, Any]:
    if sys.platform != "darwin":
        raise ReleaseError("protected Apple release requires a native Mac")
    source = pathlib.Path(args.app)
    source_receipt_path = pathlib.Path(args.source_receipt)
    security_receipt_path = pathlib.Path(args.security_receipt)
    output = pathlib.Path(args.output)
    receipt_path = pathlib.Path(args.receipt)
    keychain = pathlib.Path(args.keychain)
    entitlements_path = pathlib.Path(args.entitlements)
    provisioning_profile_path = pathlib.Path(args.provisioning_profile)
    for path in (output, receipt_path):
        ensure_new_output(path)
    if output.suffix != ".zip" or receipt_path.parent != output.parent:
        raise ReleaseError("protected application output must be a new .zip with an adjacent receipt")
    if not source.is_absolute() or not source.is_dir() or source.is_symlink() or source.name != APP_NAME:
        raise ReleaseError("unsigned release application must be the physical Mesh Admin.app")
    source_receipt, source_receipt_sha = validate_source(source, source_receipt_path)
    _, security_receipt_identity = validate_security_receipt(
        security_receipt_path,
        source_receipt_sha,
        source_receipt["bundle"]["tree_sha256"],
    )
    app_info(source)
    unsigned_app = run(
        ["/usr/bin/codesign", "--verify", "--deep", "--strict=all", str(source)],
        allow_output=True,
        require_success=False,
    )
    if unsigned_app.returncode == 0:
        raise ReleaseError("unsigned source application unexpectedly has a valid signature")
    tool_paths, tool_identities = authenticate_release_tools(
        source_receipt["build_host"]["developer_directory"]
    )
    team_id = validate_team_id(args.team_id)
    if (
        not keychain.is_absolute()
        or not keychain.is_file()
        or keychain.is_symlink()
        or stat.S_IMODE(keychain.stat().st_mode) != 0o600
    ):
        raise ReleaseError("protected release Keychain must be one absolute mode-0600 file")
    keychain_identity = file_identity(keychain)
    entitlements_identity = file_identity(entitlements_path)
    expected_entitlements = plistlib.loads(
        bounded_read(entitlements_path, 64 << 10, "release entitlement policy")
    )
    if expected_entitlements != {
        "com.apple.security.app-sandbox": True,
        "com.apple.security.network.client": True,
        "keychain-access-groups": ["Y3P5UNNG23.io.rw0.mesh.admin"],
    }:
        raise ReleaseError("release entitlement policy differs from the exact approved set")
    identity_output = run(
        ["/usr/bin/security", "find-identity", "-v", "-p", "codesigning", str(keychain)],
        allow_output=True,
    )
    identity = parse_identity_output(
        (identity_output.stdout + identity_output.stderr).decode("utf-8", "strict"),
        team_id,
    )
    if (
        not provisioning_profile_path.is_absolute()
        or not provisioning_profile_path.is_file()
        or provisioning_profile_path.is_symlink()
        or stat.S_IMODE(provisioning_profile_path.stat().st_mode) != 0o600
    ):
        raise ReleaseError(
            "Developer ID provisioning profile must be one absolute mode-0600 file"
        )
    provisioning_profile_identity = file_identity(provisioning_profile_path)
    validate_provisioning_profile(provisioning_profile_path, team_id, identity)
    with tempfile.TemporaryDirectory(
        prefix="mesh-apple-protected-release-", dir="/private/var/tmp"
    ) as temporary:
        workspace = pathlib.Path(temporary)
        os.chmod(workspace, 0o700)
        app = workspace / APP_NAME
        run(["/usr/bin/ditto", str(source), str(app)])
        copied_tree, copied_files, copied_bytes = tree_identity(app)
        if (
            copied_tree != source_receipt["bundle"]["tree_sha256"]
            or copied_files != source_receipt["bundle"]["regular_files"]
            or copied_bytes != source_receipt["bundle"]["regular_file_bytes"]
        ):
            raise ReleaseError("protected application copy differs from its source receipt")
        embedded_profile = app / "Contents" / "embedded.provisionprofile"
        shutil.copyfile(provisioning_profile_path, embedded_profile)
        os.chmod(embedded_profile, 0o644)
        if digest_file(embedded_profile) != provisioning_profile_identity["sha256"]:
            raise ReleaseError(
                "embedded Developer ID provisioning profile differs from its protected input"
            )
        validate_provisioning_profile(embedded_profile, team_id, identity)
        bundles, standalone = nested_code(app)
        for code in [*standalone, *bundles]:
            unsigned = run(
                ["/usr/bin/codesign", "--verify", "--strict=all", str(code)],
                allow_output=True,
                require_success=False,
            )
            if unsigned.returncode == 0:
                raise ReleaseError(
                    f"unsigned source unexpectedly contains signed nested code: {code}"
                )
        for code in standalone:
            sign_code(code, identity, keychain, None)
        for bundle in bundles:
            sign_code(bundle, identity, keychain, None)
        sign_code(app, identity, keychain, entitlements_path)
        app_requirement = (
            f'anchor apple generic and identifier "{APP_IDENTIFIER}" '
            "and certificate 1[field.1.2.840.113635.100.6.2.6] exists "
            "and certificate leaf[field.1.2.840.113635.100.6.1.13] exists "
            f'and certificate leaf[subject.OU] = "{team_id}"'
        )
        code_records = []
        for code in [*standalone, *bundles]:
            relative = code.relative_to(app).as_posix()
            identifier = EXPECTED_NESTED_CODE[relative]
            nested_requirement = (
                f'anchor apple generic and identifier "{identifier}" '
                "and certificate 1[field.1.2.840.113635.100.6.2.6] exists "
                "and certificate leaf[field.1.2.840.113635.100.6.1.13] exists "
                f'and certificate leaf[subject.OU] = "{team_id}"'
            )
            record = verify_code(code, nested_requirement, {}, identifier)
            record["path"] = relative
            code_records.append(record)
        app_record = verify_code(
            app, app_requirement, expected_entitlements, APP_IDENTIFIER
        )
        validate_provisioning_profile(embedded_profile, team_id, identity)
        run(["/usr/bin/codesign", "--verify", "--deep", "--strict=all", str(app)])
        submission = workspace / "submission.zip"
        run(
            [
                "/usr/bin/ditto",
                "-c",
                "-k",
                "--sequesterRsrc",
                "--keepParent",
                str(app),
                str(submission),
            ]
        )
        notary = run(
            [
                str(tool_paths["notarytool"]),
                "submit",
                str(submission),
                "--keychain-profile",
                args.notary_profile,
                "--keychain",
                str(keychain),
                "--wait",
                "--timeout",
                "30m",
                "--output-format",
                "json",
                "--no-progress",
            ],
            timeout=31 * 60,
            allow_output=True,
        )
        submission_id = parse_notary_result(notary.stdout)
        run([str(tool_paths["stapler"]), "staple", "-q", str(app)])
        run([str(tool_paths["stapler"]), "validate", "-q", str(app)])
        run(["/usr/sbin/spctl", "--assess", "--type", "execute", str(app)])
        app_record = verify_code(
            app, app_requirement, expected_entitlements, APP_IDENTIFIER
        )
        validate_provisioning_profile(embedded_profile, team_id, identity)
        run(["/usr/bin/codesign", "--verify", "--deep", "--strict=all", str(app)])
        signed_tree, signed_files, signed_bytes = tree_identity(app)
        run(
            [
                "/usr/bin/ditto",
                "-c",
                "-k",
                "--sequesterRsrc",
                "--keepParent",
                str(app),
                str(output),
            ]
        )
        round_trip_root = workspace / "archive-round-trip"
        round_trip_root.mkdir(mode=0o700)
        run(
            [
                "/usr/bin/ditto",
                "-x",
                "-k",
                str(output),
                str(round_trip_root),
            ]
        )
        round_trip_roots = list(round_trip_root.iterdir())
        if (
            len(round_trip_roots) != 1
            or round_trip_roots[0].name != APP_NAME
            or not round_trip_roots[0].is_dir()
            or round_trip_roots[0].is_symlink()
        ):
            raise ReleaseError(
                "protected archive does not round-trip to exactly one physical application"
            )
        round_trip_app = round_trip_roots[0]
        app_info(round_trip_app)
        round_trip_tree, round_trip_files, round_trip_bytes = tree_identity(
            round_trip_app
        )
        if (
            round_trip_tree != signed_tree
            or round_trip_files != signed_files
            or round_trip_bytes != signed_bytes
        ):
            raise ReleaseError(
                "protected archive extraction differs from its signed application tree"
            )
        round_trip_bundles, round_trip_standalone = nested_code(round_trip_app)
        if round_trip_standalone:
            raise ReleaseError(
                "protected archive extraction contains unexpected standalone code"
            )
        round_trip_code_records = []
        for code in round_trip_bundles:
            relative = code.relative_to(round_trip_app).as_posix()
            identifier = EXPECTED_NESTED_CODE[relative]
            nested_requirement = (
                f'anchor apple generic and identifier "{identifier}" '
                "and certificate 1[field.1.2.840.113635.100.6.2.6] exists "
                "and certificate leaf[field.1.2.840.113635.100.6.1.13] exists "
                f'and certificate leaf[subject.OU] = "{team_id}"'
            )
            record = verify_code(code, nested_requirement, {}, identifier)
            record["path"] = relative
            round_trip_code_records.append(record)
        round_trip_app_record = verify_code(
            round_trip_app,
            app_requirement,
            expected_entitlements,
            APP_IDENTIFIER,
        )
        if (
            round_trip_app_record != app_record
            or sorted(round_trip_code_records, key=lambda item: item["path"])
            != sorted(code_records, key=lambda item: item["path"])
        ):
            raise ReleaseError(
                "protected archive extraction changed signed-code evidence"
            )
        round_trip_profile = (
            round_trip_app / "Contents" / "embedded.provisionprofile"
        )
        if (
            not round_trip_profile.is_file()
            or round_trip_profile.is_symlink()
            or stat.S_IMODE(round_trip_profile.stat().st_mode) & 0o022
            or digest_file(round_trip_profile)
            != provisioning_profile_identity["sha256"]
        ):
            raise ReleaseError(
                "protected archive extraction changed its provisioning profile"
            )
        validate_provisioning_profile(round_trip_profile, team_id, identity)
        run(
            [
                "/usr/bin/codesign",
                "--verify",
                "--deep",
                "--strict=all",
                str(round_trip_app),
            ]
        )
        run(
            [
                str(tool_paths["stapler"]),
                "validate",
                "-q",
                str(round_trip_app),
            ]
        )
        run(
            [
                "/usr/sbin/spctl",
                "--assess",
                "--type",
                "execute",
                str(round_trip_app),
            ]
        )
        if tree_identity(round_trip_app) != (
            round_trip_tree,
            round_trip_files,
            round_trip_bytes,
        ):
            raise ReleaseError(
                "protected archive round-trip verification changed the application tree"
            )
    output_identity = file_identity(output)
    distribution_size = output_identity["size"]
    if distribution_size < 1 or distribution_size > MAXIMUM_BYTES:
        raise ReleaseError("protected application archive is empty or oversized")
    _, tool_identities_after = authenticate_release_tools(
        source_receipt["build_host"]["developer_directory"]
    )
    if tool_identities_after != tool_identities:
        raise ReleaseError("an authenticated Apple release tool changed during the protected job")
    if file_identity(keychain) != keychain_identity:
        raise ReleaseError("protected release Keychain changed during the protected job")
    if file_identity(entitlements_path) != entitlements_identity:
        raise ReleaseError("release entitlement policy changed during the protected job")
    if file_identity(provisioning_profile_path) != provisioning_profile_identity:
        raise ReleaseError(
            "Developer ID provisioning profile changed during the protected job"
        )
    if file_identity(security_receipt_path) != security_receipt_identity:
        raise ReleaseError("Apple Admin security receipt changed during the protected job")
    if file_identity(output) != output_identity:
        raise ReleaseError("protected application archive changed during the protected job")
    return {
        "schema": SCHEMA,
        "application": {
            "architectures": app_record["architectures"],
            "bundle_identifier": APP_IDENTIFIER,
            "build": source_receipt["bundle"]["build"],
            "minimum_macos": "14.0",
            "signed_tree_sha256": signed_tree,
            "signed_regular_files": signed_files,
            "signed_regular_file_bytes": signed_bytes,
            "version": source_receipt["bundle"]["version"],
        },
        "distribution": {
            "extracted_regular_file_bytes": round_trip_bytes,
            "extracted_regular_files": round_trip_files,
            "extracted_tree_sha256": round_trip_tree,
            "format": "ditto-zip",
            "round_trip_verified": True,
            "sha256": output_identity["sha256"],
            "size": distribution_size,
        },
        "notarization": {
            "gatekeeper_assessment": "accepted",
            "staple": "validated",
            "status": "Accepted",
            "submission_id": submission_id,
        },
        "signing": {
            "application_entitlements_sha256": app_record["entitlements_sha256"],
            "hardened_runtime": True,
            "identity_sha1": identity,
            "nested_code": sorted(code_records, key=lambda item: item["path"]),
            "team_id": team_id,
        },
        "source": {
            "receipt_sha256": source_receipt_sha,
            "security_receipt_sha256": security_receipt_identity["sha256"],
            "tree_sha256": source_receipt["bundle"]["tree_sha256"],
        },
        "tools": {
            name: {"sha256": identity["sha256"], "size": identity["size"]}
            for name, identity in sorted(tool_identities.items())
        },
        "verified_at": dt.datetime.now(dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
    }


def write_receipt(path: pathlib.Path, document: dict[str, Any]) -> None:
    raw = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if len(raw) > MAXIMUM_RECEIPT_BYTES:
        raise ReleaseError("protected Apple release receipt exceeds its size bound")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
    with os.fdopen(descriptor, "wb") as target:
        target.write(raw)
        target.flush()
        os.fsync(target.fileno())


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--app", required=True)
    result.add_argument("--source-receipt", required=True)
    result.add_argument("--security-receipt", required=True)
    result.add_argument("--team-id", required=True)
    result.add_argument("--keychain", required=True)
    result.add_argument("--notary-profile", required=True)
    result.add_argument("--entitlements", required=True)
    result.add_argument("--provisioning-profile", required=True)
    result.add_argument("--output", required=True)
    result.add_argument("--receipt", required=True)
    return result


def main() -> int:
    os.umask(0o077)
    args = parser().parse_args()
    if (
        NOTARY_PROFILE.fullmatch(args.notary_profile) is None
    ):
        raise ReleaseError("notary profile name is invalid")
    document = produce(args)
    write_receipt(pathlib.Path(args.receipt), document)
    print(
        "Protected Mesh Admin release verified: "
        f"{args.output} ({document['distribution']['sha256']})"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ReleaseError as exc:
        print(f"Apple protected application release: {exc}", file=sys.stderr)
        raise SystemExit(1)
