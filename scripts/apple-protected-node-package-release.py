#!/usr/bin/env python3
"""Build, sign, notarize, staple, and verify one Mesh Node flat package."""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import gzip
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
import xml.etree.ElementTree as ET
from typing import Any


RECEIPT_SCHEMA = "mesh-darwin-node-package-release-receipt-v1"
PACKAGE_POLICY_SCHEMA = "mesh-darwin-node-package-policy-v2"
PACKAGE_POLICY_PREFIX = "MESH_DARWIN_NODE_PACKAGE_V2."
PACKAGE_POLICY_SUFFIX = ".END_MESH_DARWIN_NODE_PACKAGE_V2"
CODESIGN_POLICY_SCHEMA = "mesh-darwin-codesign-policy-v2"
CODESIGN_POLICY_PREFIX = "MESH_DARWIN_CODESIGN_V2."
CODESIGN_POLICY_SUFFIX = ".END_MESH_DARWIN_CODESIGN_V2"
CODESIGN_RECEIPT_SCHEMA = "mesh-darwin-codesign-receipt-v2"
BUNDLE_SECURITY_SCHEMA = "mesh-darwin-package-security-receipt-v2"
INSTALL_LOCATION = "/Library/Application Support/Mesh"
MAX_OUTPUT = 256 * 1024
MAX_PACKAGE = 512 * 1024 * 1024
MAX_INPUT = 272 * 1024 * 1024
SHA1 = re.compile(r"^[0-9A-F]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
TEAM_ID = re.compile(r"^[A-Z0-9]{10}$")
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{2,127}$")
VERSION = re.compile(r"^[0-9]+(?:\.[0-9]+){0,3}$")
PROFILE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
RUNTIME_FLAGS = re.compile(rb"flags=0x[0-9a-fA-F]+\([^)\r\n]*runtime[^)\r\n]*\)")
INSTALLER_IDENTITY = re.compile(
    r'^\s*\d+\)\s+([0-9A-F]{40})\s+"Developer ID Installer: .+ \(([A-Z0-9]{10})\)"\s*$'
)
CERTIFICATE_HASHES = re.compile(
    r"SHA-256 hash: ([0-9A-F]{64})\s+SHA-1 hash: ([0-9A-F]{40})"
)
APPLE_TOOLS = {
    "/usr/bin/codesign": "com.apple.security.codesign",
    "/usr/bin/lsbom": "com.apple.lsbom",
    "/usr/bin/lipo": "com.apple.dt.xcode_select.tool-shim-public",
    "/usr/bin/pkgbuild": "com.apple.pkgbuild",
    "/usr/bin/productsign": "com.apple.productsign",
    "/usr/bin/security": "com.apple.security",
    "/usr/bin/xcrun": "com.apple.xcrun",
    "/usr/sbin/pkgutil": "com.apple.pkgutil",
    "/usr/sbin/spctl": "com.apple.spctl",
}
XCODE_TOOLS = {
    "notarytool": "com.apple.gke.notary.tool",
    "stapler": "com.apple.stapler",
}
SNAPSHOT_FILES = ("bundle.json", "install.json", "mesh-darwin-bundle.tar")


class ReleaseError(RuntimeError):
    pass


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def hash_file(path: pathlib.Path, maximum: int = MAX_INPUT) -> dict[str, Any]:
    if not path.is_absolute() or not path.is_file() or path.is_symlink():
        raise ReleaseError(f"release input is not one physical file: {path}")
    before = path.stat()
    if before.st_size < 1 or before.st_size > maximum or before.st_nlink != 1:
        raise ReleaseError(f"release input is empty, oversized, or multiply linked: {path}")
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    after = path.stat()
    if (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_size,
        before.st_mtime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_size,
        after.st_mtime_ns,
    ):
        raise ReleaseError(f"release input changed while hashing: {path}")
    return {"sha256": digest.hexdigest(), "size": before.st_size}


def bounded_read(path: pathlib.Path, maximum: int, label: str) -> bytes:
    identity = hash_file(path, maximum)
    raw = path.read_bytes()
    if len(raw) != identity["size"] or sha256_bytes(raw) != identity["sha256"]:
        raise ReleaseError(f"{label} changed while reading")
    return raw


def canonical_document(raw: bytes, maximum: int, label: str) -> dict[str, Any]:
    if len(raw) < 2 or len(raw) > maximum:
        raise ReleaseError(f"{label} is empty or oversized")
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseError(f"{label} is not valid JSON") from exc
    if (
        not isinstance(document, dict)
        or (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()
        != raw
    ):
        raise ReleaseError(f"{label} is not canonical sorted compact JSON")
    return document


def parse_frame(
    frame: str,
    *,
    prefix: str,
    suffix: str,
    schema: str,
    fields: set[str],
    label: str,
) -> tuple[dict[str, Any], str]:
    if (
        not frame.startswith(prefix)
        or not frame.endswith(suffix)
        or len(frame) > 16 * 1024
    ):
        raise ReleaseError(f"{label} frame is invalid")
    encoded = frame[len(prefix) : -len(suffix)]
    if not encoded or "=" in encoded:
        raise ReleaseError(f"{label} frame is not canonical base64url")
    try:
        raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        document = json.loads(raw)
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseError(f"{label} payload is invalid") from exc
    if (
        base64.urlsafe_b64encode(raw).decode().rstrip("=") != encoded
        or not isinstance(document, dict)
        or set(document) != fields
        or document.get("schema") != schema
        or json.dumps(document, separators=(",", ":")).encode() != raw
    ):
        raise ReleaseError(f"{label} security contract is invalid")
    return document, sha256_bytes(raw)


def parse_package_policy(frame: str) -> tuple[dict[str, Any], str]:
    document, digest = parse_frame(
        frame,
        prefix=PACKAGE_POLICY_PREFIX,
        suffix=PACKAGE_POLICY_SUFFIX,
        schema=PACKAGE_POLICY_SCHEMA,
        fields={
            "schema",
            "package_identifier",
            "package_install_location",
            "package_root_path",
            "installed_bootstrap_path",
            "package_snapshot_path",
            "require_compiled_postinstall",
            "require_root_wheel",
            "require_notarization",
        },
        label="Darwin node package policy",
    )
    root = str(document.get("package_root_path", ""))
    bootstrap = str(document.get("installed_bootstrap_path", ""))
    snapshot = str(document.get("package_snapshot_path", ""))
    if (
        not IDENTIFIER.fullmatch(str(document.get("package_identifier", "")))
        or document.get("package_install_location") != INSTALL_LOCATION
        or pathlib.PurePosixPath(root).parent.as_posix() != INSTALL_LOCATION
        or pathlib.PurePosixPath(bootstrap).parent.as_posix() != root
        or pathlib.PurePosixPath(bootstrap).name != "mesh-install"
        or pathlib.PurePosixPath(snapshot).parent.as_posix() != root
        or pathlib.PurePosixPath(snapshot).name != "snapshot"
        or document.get("require_compiled_postinstall") is not True
        or document.get("require_root_wheel") is not True
        or document.get("require_notarization") is not True
    ):
        raise ReleaseError("Darwin node package policy paths or requirements are invalid")
    return document, digest


def parse_codesign_policy(frame: str) -> tuple[dict[str, Any], str]:
    document, digest = parse_frame(
        frame,
        prefix=CODESIGN_POLICY_PREFIX,
        suffix=CODESIGN_POLICY_SUFFIX,
        schema=CODESIGN_POLICY_SCHEMA,
        fields={
            "schema",
            "team_id",
            "mesh_install_identifier",
            "meshctl_identifier",
            "nebula_identifier",
            "nebula_cert_identifier",
            "require_apple_anchor",
            "require_developer_id",
            "require_strict_verification",
        },
        label="Darwin code-signing policy",
    )
    identifiers = [
        str(document.get(name, ""))
        for name in (
            "mesh_install_identifier",
            "meshctl_identifier",
            "nebula_identifier",
            "nebula_cert_identifier",
        )
    ]
    if (
        not TEAM_ID.fullmatch(str(document.get("team_id", "")))
        or len(set(identifiers)) != 4
        or any(
            not IDENTIFIER.fullmatch(value)
            or ".." in value
            or value.endswith(".")
            for value in identifiers
        )
        or document.get("require_apple_anchor") is not True
        or document.get("require_developer_id") is not True
        or document.get("require_strict_verification") is not True
    ):
        raise ReleaseError("Darwin code-signing policy requirements are invalid")
    return document, digest


def canonical_time(value: Any) -> dt.datetime:
    if not isinstance(value, str):
        raise ReleaseError("receipt time is absent")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ReleaseError("receipt time is invalid") from exc
    if (
        parsed.tzinfo is None
        or parsed.astimezone(dt.timezone.utc).replace(microsecond=0).isoformat().replace(
            "+00:00", "Z"
        )
        != value
    ):
        raise ReleaseError("receipt time is not canonical UTC RFC3339")
    return parsed


def require_fresh(value: Any, label: str) -> None:
    parsed = canonical_time(value)
    now = dt.datetime.now(dt.timezone.utc)
    if parsed > now + dt.timedelta(minutes=5) or now - parsed > dt.timedelta(hours=24):
        raise ReleaseError(f"{label} is not fresh")


def parse_codesign_receipt(
    raw: bytes,
    policy: dict[str, Any],
    policy_sha: str,
    architecture: str,
    bootstrap: dict[str, Any],
) -> dict[str, Any]:
    receipt = canonical_document(raw, 24 * 1024, "Darwin code-signing receipt")
    if (
        receipt.get("schema") != CODESIGN_RECEIPT_SCHEMA
        or receipt.get("architecture") != architecture
        or receipt.get("policy_sha256") != policy_sha
        or receipt.get("team_id") != policy.get("team_id")
    ):
        raise ReleaseError("Darwin code-signing receipt authority differs")
    require_fresh(receipt.get("verified_at"), "Darwin code-signing receipt")
    files = receipt.get("files")
    expected = (
        ("mesh-install", "mesh-install", "mesh_install_identifier"),
        ("bin/meshctl", "meshctl", "meshctl_identifier"),
        ("bin/nebula", "nebula", "nebula_identifier"),
        ("bin/nebula-cert", "nebula-cert", "nebula_cert_identifier"),
    )
    if not isinstance(files, list) or len(files) != len(expected):
        raise ReleaseError("Darwin code-signing receipt file set is incomplete")
    for item, (path, role, identifier_key) in zip(files, expected):
        if (
            not isinstance(item, dict)
            or set(item) != {"identifier", "path", "role", "sha256", "size"}
            or item.get("path") != path
            or item.get("role") != role
            or item.get("identifier") != policy.get(identifier_key)
            or not SHA256.fullmatch(str(item.get("sha256", "")))
            or not isinstance(item.get("size"), int)
            or item["size"] < 512
        ):
            raise ReleaseError("Darwin code-signing receipt file evidence is invalid")
    if (
        files[0]["sha256"] != bootstrap["sha256"]
        or files[0]["size"] != bootstrap["size"]
    ):
        raise ReleaseError("signed mesh-install differs from its native receipt")
    return receipt


def parse_bundle_security_receipt(
    raw: bytes, architecture: str, snapshot_artifact: dict[str, Any]
) -> dict[str, Any]:
    receipt = canonical_document(
        raw, 128 * 1024, "Darwin bundle-security receipt"
    )
    candidate = receipt.get("candidate")
    if (
        receipt.get("schema") != BUNDLE_SECURITY_SCHEMA
        or not isinstance(candidate, dict)
        or candidate.get("architecture") != architecture
        or receipt.get("artifact") != snapshot_artifact
    ):
        raise ReleaseError("Darwin bundle-security receipt differs from package snapshot")
    require_fresh(receipt.get("verified_at"), "Darwin bundle-security receipt")
    return receipt


def run(
    arguments: list[str],
    *,
    environment: dict[str, str],
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
            env=environment,
            cwd="/",
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ReleaseError(f"protected Apple tool failed to execute: {arguments[0]}") from exc
    if len(result.stdout) > MAX_OUTPUT or len(result.stderr) > MAX_OUTPUT:
        raise ReleaseError(f"protected Apple tool output exceeded its bound: {arguments[0]}")
    if require_success and result.returncode != 0:
        raise ReleaseError(
            f"protected Apple tool failed: {arguments[0]} "
            f"stdout_sha256={sha256_bytes(result.stdout)} "
            f"stderr_sha256={sha256_bytes(result.stderr)}"
        )
    if not allow_output and (result.stdout or result.stderr):
        raise ReleaseError(
            f"protected Apple tool emitted unexpected output: {arguments[0]} "
            f"stdout_sha256={sha256_bytes(result.stdout)} "
            f"stderr_sha256={sha256_bytes(result.stderr)}"
        )
    return result


def authenticate_tool(
    path: pathlib.Path, identifier: str, environment: dict[str, str]
) -> dict[str, Any]:
    identity = hash_file(path, 256 * 1024 * 1024)
    run(
        [
            "/usr/bin/codesign",
            "--verify",
            "--strict=all",
            "--test-requirement",
            f'=anchor apple and identifier "{identifier}"',
            str(path),
        ],
        environment=environment,
    )
    if hash_file(path, 256 * 1024 * 1024) != identity:
        raise ReleaseError(f"protected Apple tool changed during authentication: {path}")
    return identity


def authenticate_tools(
    developer_directory: pathlib.Path, environment: dict[str, str]
) -> tuple[dict[str, pathlib.Path], dict[str, dict[str, Any]]]:
    approved = {
        pathlib.Path("/Applications/Xcode.app/Contents/Developer"),
        pathlib.Path("/Applications/Xcode_26.5.0.app/Contents/Developer"),
    }
    if (
        developer_directory not in approved
        or not developer_directory.is_dir()
        or developer_directory.is_symlink()
        or developer_directory.resolve(strict=True) != developer_directory
    ):
        raise ReleaseError("protected package requires one approved Xcode developer directory")
    paths = {name: pathlib.Path(name) for name in APPLE_TOOLS}
    for name in XCODE_TOOLS:
        result = run(
            ["/usr/bin/xcrun", "--find", name],
            environment=environment,
            allow_output=True,
        )
        resolved = pathlib.Path(result.stdout.decode("utf-8", "strict").strip())
        expected = developer_directory / "usr" / "bin" / name
        if resolved != expected:
            raise ReleaseError(f"xcrun resolved an unexpected tool: {name}")
        paths[name] = resolved
    identities = {
        name: authenticate_tool(
            path,
            APPLE_TOOLS[name] if name in APPLE_TOOLS else XCODE_TOOLS[name],
            environment,
        )
        for name, path in paths.items()
    }
    return paths, identities


def validate_keychain(path: pathlib.Path) -> dict[str, Any]:
    identity = hash_file(path, 128 * 1024 * 1024)
    if stat.S_IMODE(path.stat().st_mode) != 0o600:
        raise ReleaseError("private release Keychain must be mode 0600")
    return identity


def validate_installer_identity(
    keychain: pathlib.Path,
    fingerprint: str,
    team_id: str,
    environment: dict[str, str],
) -> str:
    result = run(
        ["/usr/bin/security", "find-identity", "-v", str(keychain)],
        environment=environment,
        allow_output=True,
    )
    matches = []
    for line in result.stdout.decode("utf-8", "strict").splitlines():
        match = INSTALLER_IDENTITY.fullmatch(line)
        if match and match.group(2) == team_id:
            matches.append(match.group(1))
    if matches.count(fingerprint) != 1 or len(matches) != 1:
        raise ReleaseError(
            "private release Keychain must contain exactly the selected "
            "Developer ID Installer identity for the compiled Team ID"
        )
    certificates = run(
        ["/usr/bin/security", "find-certificate", "-a", "-Z", str(keychain)],
        environment=environment,
        allow_output=True,
    )
    pairs = CERTIFICATE_HASHES.findall(
        (certificates.stdout + certificates.stderr).decode("utf-8", "strict")
    )
    selected = [sha256 for sha256, sha1 in pairs if sha1 == fingerprint]
    if len(selected) != 1:
        raise ReleaseError(
            "private release Keychain must expose one certificate for the "
            "selected Developer ID Installer identity"
        )
    return selected[0].lower()


def validate_bootstrap(
    bootstrap: pathlib.Path,
    architecture: str,
    policy: dict[str, Any],
    codesign_policy_sha: str,
    package_policy_sha: str,
    environment: dict[str, str],
) -> dict[str, Any]:
    identity = hash_file(bootstrap, 132 * 1024 * 1024)
    arch = "x86_64" if architecture == "amd64" else "arm64"
    result = run(
        ["/usr/bin/lipo", "-archs", str(bootstrap)],
        environment=environment,
        allow_output=True,
    )
    if result.stdout.decode("utf-8", "strict").strip().split() != [arch]:
        raise ReleaseError("signed mesh-install architecture differs from package")
    identifier = str(policy["mesh_install_identifier"])
    team_id = str(policy["team_id"])
    requirement = (
        f'anchor apple generic and certificate leaf[subject.OU] = "{team_id}" '
        f'and identifier "{identifier}"'
    )
    run(
        [
            "/usr/bin/codesign",
            "--verify",
            "--strict=all",
            "--test-requirement",
            "=" + requirement,
            str(bootstrap),
        ],
        environment=environment,
    )
    display = run(
        ["/usr/bin/codesign", "--display", "--verbose=4", str(bootstrap)],
        environment=environment,
        allow_output=True,
    )
    if RUNTIME_FLAGS.search(display.stdout + display.stderr) is None:
        raise ReleaseError("signed mesh-install lacks hardened runtime")
    entitlements = run(
        ["/usr/bin/codesign", "--display", "--entitlements", "-", "--xml", str(bootstrap)],
        environment=environment,
        allow_output=True,
    )
    if entitlements.stdout:
        try:
            document = plistlib.loads(entitlements.stdout)
        except plistlib.InvalidFileException as exc:
            raise ReleaseError("mesh-install entitlements are invalid") from exc
        if document:
            raise ReleaseError("mesh-install must not have entitlements")
    version = run([str(bootstrap), "version"], environment=environment, allow_output=True)
    try:
        version_document = json.loads(version.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseError("mesh-install version output is invalid") from exc
    if (
        version_document.get("darwin_code_signing_policy_sha256")
        != codesign_policy_sha
        or version_document.get("darwin_node_package_policy_sha256")
        != package_policy_sha
    ):
        raise ReleaseError("mesh-install compiled policies differ from protected inputs")
    if hash_file(bootstrap, 132 * 1024 * 1024) != identity:
        raise ReleaseError("signed mesh-install changed during verification")
    return identity


def validate_snapshot(path: pathlib.Path) -> dict[str, dict[str, Any]]:
    if not path.is_absolute() or not path.is_dir() or path.is_symlink():
        raise ReleaseError("package snapshot must be one physical directory")
    metadata = path.stat()
    if (
        metadata.st_uid != os.getuid()
        or metadata.st_gid != os.getgid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or metadata.st_nlink < 2
    ):
        raise ReleaseError("package snapshot must be root:wheel mode 0700")
    observed = sorted(item.name for item in path.iterdir())
    if observed != list(SNAPSHOT_FILES):
        raise ReleaseError("package snapshot file inventory is not exact")
    result = {}
    for name in SNAPSHOT_FILES:
        item = path / name
        info = item.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_gid != os.getgid()
            or stat.S_IMODE(info.st_mode) != 0o400
            or info.st_nlink != 1
            or os.listxattr(item, follow_symlinks=False)
        ):
            raise ReleaseError(f"package snapshot file metadata is invalid: {name}")
        result[name] = hash_file(item)
    descriptor = canonical_document(
        bounded_read(path / "install.json", 4096, "snapshot descriptor"),
        4096,
        "snapshot descriptor",
    )
    if descriptor != {
        "artifact": "mesh-darwin-bundle.tar",
        "online_bundle": "bundle.json",
        "schema": "mesh-darwin-install-snapshot-v1",
    }:
        raise ReleaseError("package snapshot descriptor is invalid")
    return result


def copy_payload(
    bootstrap: pathlib.Path,
    snapshot: pathlib.Path,
    root: pathlib.Path,
    scripts: pathlib.Path,
    package_policy: dict[str, Any],
) -> None:
    relative_root = pathlib.PurePosixPath(
        str(package_policy["package_root_path"])
    ).relative_to(INSTALL_LOCATION)
    package_root = root / pathlib.Path(relative_root.as_posix())
    snapshot_root = package_root / "snapshot"
    snapshot_root.mkdir(parents=True, mode=0o700)
    scripts.mkdir(mode=0o700)
    shutil.copyfile(bootstrap, package_root / "mesh-install")
    shutil.copyfile(bootstrap, scripts / "postinstall")
    for name in SNAPSHOT_FILES:
        shutil.copyfile(snapshot / name, snapshot_root / name)
    os.chmod(package_root, 0o700)
    os.chmod(snapshot_root, 0o700)
    os.chmod(package_root / "mesh-install", 0o555)
    os.chmod(scripts / "postinstall", 0o555)
    for name in SNAPSHOT_FILES:
        os.chmod(snapshot_root / name, 0o400)


def tree_sha(root: pathlib.Path) -> tuple[str, int, int]:
    digest = hashlib.sha256()
    files = 0
    directories = 0
    for item in sorted(root.rglob("*"), key=lambda value: value.relative_to(root).as_posix()):
        relative = item.relative_to(root).as_posix()
        info = item.lstat()
        mode = stat.S_IMODE(info.st_mode)
        if stat.S_ISDIR(info.st_mode):
            directories += 1
            record = f"d {mode:04o} {relative}\n"
        elif stat.S_ISREG(info.st_mode):
            files += 1
            identity = hash_file(item)
            record = f"f {mode:04o} {identity['size']} {identity['sha256']} {relative}\n"
        else:
            raise ReleaseError(f"package contains unsupported object: {relative}")
        digest.update(record.encode())
    return digest.hexdigest(), directories, files


def inspect_package(
    package: pathlib.Path,
    workspace: pathlib.Path,
    policy: dict[str, Any],
    version: str,
    bootstrap_sha: str,
    environment: dict[str, str],
) -> dict[str, Any]:
    workspace.mkdir(mode=0o700)
    raw = workspace / "expanded"
    full = workspace / "expanded-full"
    run(
        ["/usr/sbin/pkgutil", "--expand", str(package), str(raw)],
        environment=environment,
        allow_output=True,
    )
    run(
        ["/usr/sbin/pkgutil", "--expand-full", str(package), str(full)],
        environment=environment,
        allow_output=True,
    )
    if sorted(item.name for item in raw.iterdir()) != ["Bom", "PackageInfo", "Payload", "Scripts"]:
        raise ReleaseError("flat package top-level inventory is not exact")
    package_info_raw = bounded_read(raw / "PackageInfo", 64 * 1024, "PackageInfo")
    try:
        package_info = ET.fromstring(package_info_raw)
    except ET.ParseError as exc:
        raise ReleaseError("PackageInfo XML is invalid") from exc
    if (
        package_info.tag != "pkg-info"
        or package_info.attrib.get("identifier") != policy["package_identifier"]
        or package_info.attrib.get("version") != version
        or package_info.attrib.get("install-location") != INSTALL_LOCATION
        or package_info.attrib.get("auth") != "root"
        or package_info.attrib.get("relocatable") != "false"
    ):
        raise ReleaseError("PackageInfo identity or install policy is invalid")
    bom_result = run(
        ["/usr/bin/lsbom", "-pfmug", str(raw / "Bom")],
        environment=environment,
        allow_output=True,
    )
    root_name = pathlib.PurePosixPath(str(policy["package_root_path"])).name
    expected_bom = [
        ".\t40755\t0\t0",
        f"./{root_name}\t40700\t0\t0",
        f"./{root_name}/mesh-install\t100555\t0\t0",
        f"./{root_name}/snapshot\t40700\t0\t0",
        f"./{root_name}/snapshot/bundle.json\t100400\t0\t0",
        f"./{root_name}/snapshot/install.json\t100400\t0\t0",
        f"./{root_name}/snapshot/mesh-darwin-bundle.tar\t100400\t0\t0",
    ]
    observed_bom = bom_result.stdout.decode("utf-8", "strict").splitlines()
    if observed_bom != expected_bom:
        raise ReleaseError("package BOM differs from the exact root:wheel payload plan")
    scripts_archive = bounded_read(raw / "Scripts", 132 * 1024 * 1024, "scripts archive")
    try:
        scripts_cpio = gzip.decompress(scripts_archive)
    except (OSError, EOFError) as exc:
        raise ReleaseError("package scripts archive is not canonical gzip") from exc
    if len(scripts_cpio) > 132 * 1024 * 1024 or b"._postinstall\x00" in scripts_cpio:
        raise ReleaseError("package scripts archive contains unexpected extended metadata")
    payload = full / "Payload"
    payload_sha, directory_count, file_count = tree_sha(payload)
    if directory_count != 2 or file_count != 4:
        raise ReleaseError("expanded package payload count is invalid")
    postinstall = full / "Scripts" / "postinstall"
    postinstall_identity = hash_file(postinstall, 132 * 1024 * 1024)
    if postinstall_identity["sha256"] != bootstrap_sha:
        raise ReleaseError("compiled postinstall differs from signed mesh-install")
    return {
        "bom": hash_file(raw / "Bom"),
        "directory_count": directory_count,
        "file_count": file_count,
        "package_info": {
            "sha256": sha256_bytes(package_info_raw),
            "size": len(package_info_raw),
        },
        "payload_tree_sha256": payload_sha,
        "postinstall_sha256": postinstall_identity["sha256"],
        "scripts_archive": {
            "sha256": sha256_bytes(scripts_archive),
            "size": len(scripts_archive),
        },
        "unexpected_xattrs": 0,
    }


def parse_notary_result(raw: bytes) -> str:
    try:
        document = json.loads(raw)
        submission_id = str(uuid.UUID(str(document.get("id"))))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, AttributeError) as exc:
        raise ReleaseError("notarytool result is invalid") from exc
    if document.get("status") != "Accepted" or document.get("id") != submission_id:
        raise ReleaseError("Apple notarization was not accepted")
    return submission_id


def exclusive_json(path: pathlib.Path, document: dict[str, Any]) -> None:
    raw = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    with os.fdopen(descriptor, "wb") as output:
        output.write(raw)
        output.flush()
        os.fsync(output.fileno())


def finalize(args: argparse.Namespace) -> None:
    architecture = args.arch
    if architecture not in {"arm64", "amd64"} or not VERSION.fullmatch(args.version):
        raise ReleaseError("package architecture or version is invalid")
    if not SHA1.fullmatch(args.installer_identity) or not PROFILE.fullmatch(args.notary_profile):
        raise ReleaseError("Installer identity fingerprint or notary profile is invalid")
    package_policy, package_policy_sha = parse_package_policy(args.package_policy)
    codesign_policy, codesign_policy_sha = parse_codesign_policy(args.codesign_policy)
    developer = pathlib.Path(args.developer_directory)
    environment = {
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "LANG": "C",
        "LC_ALL": "C",
        "DEVELOPER_DIR": str(developer),
    }
    tools, tool_evidence = authenticate_tools(developer, environment)
    keychain = pathlib.Path(args.keychain)
    keychain_identity = validate_keychain(keychain)
    installer_certificate_sha256 = validate_installer_identity(
        keychain,
        args.installer_identity,
        str(codesign_policy["team_id"]),
        environment,
    )
    bootstrap_path = pathlib.Path(args.bootstrap)
    bootstrap = validate_bootstrap(
        bootstrap_path,
        architecture,
        codesign_policy,
        codesign_policy_sha,
        package_policy_sha,
        environment,
    )
    snapshot_path = pathlib.Path(args.snapshot)
    snapshot = validate_snapshot(snapshot_path)
    codesign_receipt_path = pathlib.Path(args.codesign_receipt)
    codesign_receipt_raw = bounded_read(
        codesign_receipt_path, 24 * 1024, "Darwin code-signing receipt"
    )
    parse_codesign_receipt(
        codesign_receipt_raw,
        codesign_policy,
        codesign_policy_sha,
        architecture,
        bootstrap,
    )
    security_receipt_path = pathlib.Path(args.bundle_security_receipt)
    security_receipt_raw = bounded_read(
        security_receipt_path, 128 * 1024, "Darwin bundle-security receipt"
    )
    security_receipt = parse_bundle_security_receipt(
        security_receipt_raw, architecture, snapshot["mesh-darwin-bundle.tar"]
    )
    if security_receipt["candidate"].get("version") != args.version:
        raise ReleaseError("bundle-security receipt version differs from package")
    output = pathlib.Path(args.output)
    receipt_path = pathlib.Path(args.receipt)
    if (
        not output.is_absolute()
        or not receipt_path.is_absolute()
        or output.exists()
        or receipt_path.exists()
        or output.parent != receipt_path.parent
        or output.parent.is_symlink()
    ):
        raise ReleaseError("package and receipt outputs must be new siblings in one physical directory")
    with tempfile.TemporaryDirectory(
        prefix=".mesh-node-package-", dir=output.parent
    ) as temporary:
        workspace = pathlib.Path(temporary)
        os.chmod(workspace, 0o700)
        root, scripts = workspace / "root", workspace / "scripts"
        root.mkdir(mode=0o700)
        copy_payload(bootstrap_path, snapshot_path, root, scripts, package_policy)
        unsigned = workspace / "unsigned.pkg"
        signed = workspace / "signed.pkg"
        run(
            [
                str(tools["/usr/bin/pkgbuild"]),
                "--root",
                str(root),
                "--scripts",
                str(scripts),
                "--identifier",
                str(package_policy["package_identifier"]),
                "--version",
                args.version,
                "--install-location",
                INSTALL_LOCATION,
                "--ownership",
                "recommended",
                str(unsigned),
            ],
            environment=environment,
            allow_output=True,
        )
        inspect_package(
            unsigned, workspace / "inspect-unsigned", package_policy,
            args.version, bootstrap["sha256"], environment,
        )
        run(
            [
                str(tools["/usr/bin/productsign"]),
                "--sign",
                args.installer_identity,
                "--keychain",
                str(keychain),
                str(unsigned),
                str(signed),
            ],
            environment=environment,
            allow_output=True,
        )
        signature = run(
            ["/usr/sbin/pkgutil", "--check-signature", str(signed)],
            environment=environment,
            allow_output=True,
        )
        signature_text = (signature.stdout + signature.stderr).decode("utf-8", "strict")
        if str(codesign_policy["team_id"]) not in signature_text:
            raise ReleaseError("signed package output does not name the compiled Team ID")
        notary = run(
            [
                str(tools["notarytool"]),
                "submit",
                str(signed),
                "--keychain-profile",
                args.notary_profile,
                "--wait",
                "--output-format",
                "json",
            ],
            environment=environment,
            timeout=1800,
            allow_output=True,
        )
        submission_id = parse_notary_result(notary.stdout)
        run(
            [str(tools["stapler"]), "staple", "-q", str(signed)],
            environment=environment,
            allow_output=True,
        )
        run(
            [str(tools["stapler"]), "validate", "-q", str(signed)],
            environment=environment,
            allow_output=True,
        )
        run(
            ["/usr/sbin/spctl", "--assess", "--type", "install", "--verbose=4", str(signed)],
            environment=environment,
            allow_output=True,
        )
        contents = inspect_package(
            signed, workspace / "inspect-final", package_policy,
            args.version, bootstrap["sha256"], environment,
        )
        if validate_keychain(keychain) != keychain_identity:
            raise ReleaseError("private release Keychain changed during package production")
        for name, path in tools.items():
            if hash_file(path, 256 * 1024 * 1024) != tool_evidence[name]:
                raise ReleaseError(f"protected Apple tool changed during package production: {name}")
        os.link(signed, output)
        signed.unlink()
        package_identity = hash_file(output, MAX_PACKAGE)
        receipt = {
            "bootstrap": {
                "code_identifier": codesign_policy["mesh_install_identifier"],
                **bootstrap,
            },
            "contents": contents,
            "notarization": {
                "gatekeeper_assessment": "accepted",
                "staple": "validated",
                "status": "Accepted",
                "submission_id": submission_id,
            },
            "package": {
                "architecture": architecture,
                "identifier": package_policy["package_identifier"],
                "install_location": INSTALL_LOCATION,
                "package_root": package_policy["package_root_path"],
                **package_identity,
                "version": args.version,
            },
            "schema": RECEIPT_SCHEMA,
            "signing": {
                "installer_certificate_sha256": installer_certificate_sha256,
                "installer_identity_sha1": args.installer_identity,
                "team_id": codesign_policy["team_id"],
            },
            "snapshot": {
                "artifact": snapshot["mesh-darwin-bundle.tar"],
                "bundle_json": snapshot["bundle.json"],
                "install_json": snapshot["install.json"],
            },
            "source": {
                "bundle_security_receipt": {
                    "sha256": sha256_bytes(security_receipt_raw),
                    "size": len(security_receipt_raw),
                },
                "codesign_policy_sha256": codesign_policy_sha,
                "codesign_receipt": {
                    "sha256": sha256_bytes(codesign_receipt_raw),
                    "size": len(codesign_receipt_raw),
                },
                "package_policy_sha256": package_policy_sha,
            },
            "tools": tool_evidence,
            "verified_at": dt.datetime.now(dt.timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z"),
        }
        exclusive_json(receipt_path, receipt)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--arch", required=True)
    result.add_argument("--version", required=True)
    result.add_argument("--bootstrap", required=True)
    result.add_argument("--snapshot", required=True)
    result.add_argument("--codesign-receipt", required=True)
    result.add_argument("--bundle-security-receipt", required=True)
    result.add_argument("--codesign-policy", required=True)
    result.add_argument("--package-policy", required=True)
    result.add_argument("--developer-directory", required=True)
    result.add_argument("--keychain", required=True)
    result.add_argument("--installer-identity", required=True)
    result.add_argument("--notary-profile", required=True)
    result.add_argument("--output", required=True)
    result.add_argument("--receipt", required=True)
    return result


def main() -> int:
    try:
        finalize(parser().parse_args())
    except ReleaseError as exc:
        print(f"protected Darwin node package release: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
