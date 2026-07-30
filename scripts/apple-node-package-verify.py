#!/usr/bin/env python3
"""Independently verify a downloaded Mesh Node flat package on macOS."""

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
import stat
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from typing import Any


RECEIPT_SCHEMA = "mesh-darwin-node-package-release-receipt-v1"
NATIVE_RECEIPT_SCHEMA = "mesh-darwin-node-package-native-verification-v1"
PACKAGE_POLICY_SCHEMA = "mesh-darwin-node-package-policy-v2"
PACKAGE_POLICY_PREFIX = "MESH_DARWIN_NODE_PACKAGE_V2."
PACKAGE_POLICY_SUFFIX = ".END_MESH_DARWIN_NODE_PACKAGE_V2"
CODESIGN_POLICY_SCHEMA = "mesh-darwin-codesign-policy-v2"
CODESIGN_POLICY_PREFIX = "MESH_DARWIN_CODESIGN_V2."
CODESIGN_POLICY_SUFFIX = ".END_MESH_DARWIN_CODESIGN_V2"
INSTALL_LOCATION = "/Library/Application Support/Mesh"
MAX_OUTPUT = 256 * 1024
MAX_PACKAGE = 512 * 1024 * 1024
SHA1 = re.compile(r"^[0-9A-F]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
TEAM_ID = re.compile(r"^[A-Z0-9]{10}$")
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{2,127}$")
VERSION = re.compile(r"^[0-9]+(?:\.[0-9]+){0,3}$")
RUNTIME_FLAGS = re.compile(rb"flags=0x[0-9a-fA-F]+\([^)\r\n]*runtime[^)\r\n]*\)")
SYSTEM_TOOLS = {
    "/usr/bin/codesign": "com.apple.security.codesign",
    "/usr/bin/lipo": "com.apple.dt.xcode_select.tool-shim-public",
    "/usr/bin/lsbom": "com.apple.lsbom",
    "/usr/bin/xcrun": "com.apple.xcrun",
    "/usr/sbin/pkgutil": "com.apple.pkgutil",
    "/usr/sbin/spctl": "com.apple.spctl",
}
XCODE_TOOLS = {"stapler": "com.apple.stapler"}
SNAPSHOT_FILES = ("bundle.json", "install.json", "mesh-darwin-bundle.tar")


class VerificationError(RuntimeError):
    pass


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def hash_file(path: pathlib.Path, maximum: int = MAX_PACKAGE) -> dict[str, Any]:
    if not path.is_absolute() or not path.is_file() or path.is_symlink():
        raise VerificationError(f"verification input is not one physical file: {path}")
    before = path.stat()
    if before.st_size < 1 or before.st_size > maximum or before.st_nlink != 1:
        raise VerificationError(f"verification input is empty, oversized, or multiply linked: {path}")
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
        raise VerificationError(f"verification input changed while hashing: {path}")
    return {"sha256": digest.hexdigest(), "size": before.st_size}


def bounded_read(path: pathlib.Path, maximum: int, label: str) -> bytes:
    identity = hash_file(path, maximum)
    raw = path.read_bytes()
    if len(raw) != identity["size"] or sha256_bytes(raw) != identity["sha256"]:
        raise VerificationError(f"{label} changed while reading")
    return raw


def canonical_document(raw: bytes, maximum: int, label: str) -> dict[str, Any]:
    if len(raw) < 2 or len(raw) > maximum:
        raise VerificationError(f"{label} is empty or oversized")
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VerificationError(f"{label} is not valid JSON") from exc
    if (
        not isinstance(document, dict)
        or (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()
        != raw
    ):
        raise VerificationError(f"{label} is not canonical sorted compact JSON")
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
    if not frame.startswith(prefix) or not frame.endswith(suffix) or len(frame) > 16 * 1024:
        raise VerificationError(f"{label} frame is invalid")
    encoded = frame[len(prefix) : -len(suffix)]
    if not encoded or "=" in encoded:
        raise VerificationError(f"{label} frame is not canonical base64url")
    try:
        raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        document = json.loads(raw)
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VerificationError(f"{label} payload is invalid") from exc
    if (
        base64.urlsafe_b64encode(raw).decode().rstrip("=") != encoded
        or not isinstance(document, dict)
        or set(document) != fields
        or document.get("schema") != schema
        or json.dumps(document, separators=(",", ":")).encode() != raw
    ):
        raise VerificationError(f"{label} security contract is invalid")
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
    root = pathlib.PurePosixPath(str(document.get("package_root_path", "")))
    if (
        not IDENTIFIER.fullmatch(str(document.get("package_identifier", "")))
        or document.get("package_install_location") != INSTALL_LOCATION
        or root.parent.as_posix() != INSTALL_LOCATION
        or pathlib.PurePosixPath(str(document.get("installed_bootstrap_path", "")))
        != root / "mesh-install"
        or pathlib.PurePosixPath(str(document.get("package_snapshot_path", "")))
        != root / "snapshot"
        or document.get("require_compiled_postinstall") is not True
        or document.get("require_root_wheel") is not True
        or document.get("require_notarization") is not True
    ):
        raise VerificationError("Darwin node package policy is invalid")
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
        str(document.get(key, ""))
        for key in (
            "mesh_install_identifier",
            "meshctl_identifier",
            "nebula_identifier",
            "nebula_cert_identifier",
        )
    ]
    if (
        not TEAM_ID.fullmatch(str(document.get("team_id", "")))
        or len(set(identifiers)) != 4
        or any(not IDENTIFIER.fullmatch(value) or ".." in value or value.endswith(".") for value in identifiers)
        or document.get("require_apple_anchor") is not True
        or document.get("require_developer_id") is not True
        or document.get("require_strict_verification") is not True
    ):
        raise VerificationError("Darwin code-signing policy is invalid")
    return document, digest


def canonical_time(value: Any) -> None:
    if not isinstance(value, str):
        raise VerificationError("package receipt time is absent")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise VerificationError("package receipt time is invalid") from exc
    canonical = parsed.astimezone(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    now = dt.datetime.now(dt.timezone.utc)
    if (
        parsed.tzinfo is None
        or canonical != value
        or parsed > now + dt.timedelta(minutes=5)
        or now - parsed > dt.timedelta(hours=24)
    ):
        raise VerificationError("package receipt is noncanonical, future-dated, or stale")


def digest_evidence(value: Any, label: str) -> None:
    if (
        not isinstance(value, dict)
        or set(value) != {"sha256", "size"}
        or not SHA256.fullmatch(str(value.get("sha256", "")))
        or not isinstance(value.get("size"), int)
        or value["size"] < 1
        or value["size"] > MAX_PACKAGE
    ):
        raise VerificationError(f"package receipt {label} evidence is invalid")


def parse_receipt(
    raw: bytes,
    package: dict[str, Any],
    codesign: dict[str, Any],
    package_sha: str,
    codesign_sha: str,
    architecture: str,
    version: str,
    package_identity: dict[str, Any],
    codesign_receipt_sha: str,
    bundle_security_receipt_sha: str,
) -> dict[str, Any]:
    receipt = canonical_document(raw, 96 * 1024, "Darwin node package release receipt")
    required = {
        "bootstrap",
        "contents",
        "notarization",
        "package",
        "schema",
        "signing",
        "snapshot",
        "source",
        "tools",
        "verified_at",
    }
    if set(receipt) != required or receipt.get("schema") != RECEIPT_SCHEMA:
        raise VerificationError("Darwin node package release receipt schema is invalid")
    canonical_time(receipt.get("verified_at"))
    artifact = receipt.get("package")
    signing = receipt.get("signing")
    source = receipt.get("source")
    bootstrap = receipt.get("bootstrap")
    contents = receipt.get("contents")
    notarization = receipt.get("notarization")
    if (
        not isinstance(artifact, dict)
        or artifact.get("architecture") != architecture
        or artifact.get("version") != version
        or artifact.get("identifier") != package["package_identifier"]
        or artifact.get("install_location") != INSTALL_LOCATION
        or artifact.get("package_root") != package["package_root_path"]
        or artifact.get("sha256") != package_identity["sha256"]
        or artifact.get("size") != package_identity["size"]
        or not isinstance(signing, dict)
        or signing.get("team_id") != codesign["team_id"]
        or not SHA256.fullmatch(str(signing.get("installer_certificate_sha256", "")))
        or not SHA1.fullmatch(str(signing.get("installer_identity_sha1", "")))
        or not isinstance(source, dict)
        or source.get("package_policy_sha256") != package_sha
        or source.get("codesign_policy_sha256") != codesign_sha
        or not isinstance(bootstrap, dict)
        or bootstrap.get("code_identifier") != codesign["mesh_install_identifier"]
        or not SHA256.fullmatch(str(bootstrap.get("sha256", "")))
        or not isinstance(bootstrap.get("size"), int)
        or bootstrap["size"] < 512
        or not isinstance(contents, dict)
        or contents.get("directory_count") != 2
        or contents.get("file_count") != 4
        or contents.get("unexpected_xattrs") != 0
        or contents.get("postinstall_sha256") != bootstrap.get("sha256")
        or not isinstance(notarization, dict)
        or notarization.get("status") != "Accepted"
        or notarization.get("staple") != "validated"
        or notarization.get("gatekeeper_assessment") != "accepted"
    ):
        raise VerificationError("Darwin node package release receipt authority is invalid")
    digest_evidence(source.get("codesign_receipt"), "code-signing receipt")
    digest_evidence(source.get("bundle_security_receipt"), "bundle-security receipt")
    if (
        source["codesign_receipt"]["sha256"] != codesign_receipt_sha
        or source["bundle_security_receipt"]["sha256"] != bundle_security_receipt_sha
    ):
        raise VerificationError("package receipt upstream receipt digests differ")
    for key in ("bom", "package_info", "scripts_archive"):
        digest_evidence(contents.get(key), key)
    snapshot = receipt.get("snapshot")
    if not isinstance(snapshot, dict) or set(snapshot) != {"artifact", "bundle_json", "install_json"}:
        raise VerificationError("package receipt snapshot evidence is invalid")
    for key in snapshot:
        digest_evidence(snapshot[key], f"snapshot {key}")
    tools = receipt.get("tools")
    if not isinstance(tools, dict) or not tools:
        raise VerificationError("package receipt protected tool inventory is invalid")
    for key, value in tools.items():
        if not isinstance(key, str):
            raise VerificationError("package receipt protected tool name is invalid")
        digest_evidence(value, f"tool {key}")
    return receipt


def run(
    arguments: list[str],
    *,
    environment: dict[str, str],
    timeout: int = 60,
    allow_output: bool = False,
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
        raise VerificationError(f"native verification tool failed to execute: {arguments[0]}") from exc
    if len(result.stdout) > MAX_OUTPUT or len(result.stderr) > MAX_OUTPUT:
        raise VerificationError(f"native verification tool output exceeded its bound: {arguments[0]}")
    if result.returncode != 0:
        raise VerificationError(
            f"native verification tool failed: {arguments[0]} "
            f"stdout_sha256={sha256_bytes(result.stdout)} "
            f"stderr_sha256={sha256_bytes(result.stderr)}"
        )
    if not allow_output and (result.stdout or result.stderr):
        raise VerificationError(f"native verification tool emitted unexpected output: {arguments[0]}")
    return result


def authenticate_tool(path: pathlib.Path, identifier: str, environment: dict[str, str]) -> dict[str, Any]:
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
        raise VerificationError(f"Apple verification tool changed during authentication: {path}")
    return identity


def authenticate_tools(
    developer: pathlib.Path, environment: dict[str, str]
) -> tuple[dict[str, pathlib.Path], dict[str, dict[str, Any]]]:
    approved = {
        pathlib.Path("/Applications/Xcode.app/Contents/Developer"),
        pathlib.Path("/Applications/Xcode_26.5.0.app/Contents/Developer"),
    }
    if (
        developer not in approved
        or not developer.is_dir()
        or developer.is_symlink()
        or developer.resolve(strict=True) != developer
    ):
        raise VerificationError("native verifier requires one approved Xcode developer directory")
    paths = {name: pathlib.Path(name) for name in SYSTEM_TOOLS}
    for name in XCODE_TOOLS:
        found = run(["/usr/bin/xcrun", "--find", name], environment=environment, allow_output=True)
        resolved = pathlib.Path(found.stdout.decode("utf-8", "strict").strip())
        if resolved != developer / "usr" / "bin" / name:
            raise VerificationError(f"xcrun resolved an unexpected verification tool: {name}")
        paths[name] = resolved
    evidence = {
        name: authenticate_tool(
            path,
            SYSTEM_TOOLS[name] if name in SYSTEM_TOOLS else XCODE_TOOLS[name],
            environment,
        )
        for name, path in paths.items()
    }
    return paths, evidence


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
            raise VerificationError(f"package contains unsupported object: {relative}")
        digest.update(record.encode())
    return digest.hexdigest(), directories, files


def inspect_package(
    package_path: pathlib.Path,
    workspace: pathlib.Path,
    receipt: dict[str, Any],
    package_policy: dict[str, Any],
    codesign_policy: dict[str, Any],
    package_policy_sha: str,
    codesign_policy_sha: str,
    architecture: str,
    version: str,
    environment: dict[str, str],
) -> dict[str, Any]:
    raw, full = workspace / "expanded", workspace / "expanded-full"
    run(["/usr/sbin/pkgutil", "--expand", str(package_path), str(raw)], environment=environment, allow_output=True)
    run(["/usr/sbin/pkgutil", "--expand-full", str(package_path), str(full)], environment=environment, allow_output=True)
    if sorted(item.name for item in raw.iterdir()) != ["Bom", "PackageInfo", "Payload", "Scripts"]:
        raise VerificationError("flat package top-level inventory is not exact")
    package_info_raw = bounded_read(raw / "PackageInfo", 64 * 1024, "PackageInfo")
    try:
        package_info = ET.fromstring(package_info_raw)
    except ET.ParseError as exc:
        raise VerificationError("PackageInfo XML is invalid") from exc
    if (
        package_info.tag != "pkg-info"
        or package_info.attrib.get("identifier") != package_policy["package_identifier"]
        or package_info.attrib.get("version") != version
        or package_info.attrib.get("install-location") != INSTALL_LOCATION
        or package_info.attrib.get("auth") != "root"
        or package_info.attrib.get("relocatable") != "false"
    ):
        raise VerificationError("PackageInfo identity or install policy is invalid")
    root_name = pathlib.PurePosixPath(str(package_policy["package_root_path"])).name
    expected_bom = [
        ".\t40755\t0\t0",
        f"./{root_name}\t40700\t0\t0",
        f"./{root_name}/mesh-install\t100555\t0\t0",
        f"./{root_name}/snapshot\t40700\t0\t0",
        f"./{root_name}/snapshot/bundle.json\t100400\t0\t0",
        f"./{root_name}/snapshot/install.json\t100400\t0\t0",
        f"./{root_name}/snapshot/mesh-darwin-bundle.tar\t100400\t0\t0",
    ]
    bom = run(["/usr/bin/lsbom", "-pfmug", str(raw / "Bom")], environment=environment, allow_output=True)
    if bom.stdout.decode("utf-8", "strict").splitlines() != expected_bom:
        raise VerificationError("package BOM differs from the exact root:wheel payload plan")
    scripts_archive = bounded_read(raw / "Scripts", 132 * 1024 * 1024, "scripts archive")
    try:
        scripts_cpio = gzip.decompress(scripts_archive)
    except (OSError, EOFError) as exc:
        raise VerificationError("package scripts archive is invalid") from exc
    if len(scripts_cpio) > 132 * 1024 * 1024 or b"._postinstall\x00" in scripts_cpio:
        raise VerificationError("package scripts contain unexpected extended metadata")
    payload = full / "Payload"
    expected_paths = [
        root_name,
        f"{root_name}/mesh-install",
        f"{root_name}/snapshot",
        f"{root_name}/snapshot/bundle.json",
        f"{root_name}/snapshot/install.json",
        f"{root_name}/snapshot/mesh-darwin-bundle.tar",
    ]
    observed_paths = sorted(item.relative_to(payload).as_posix() for item in payload.rglob("*"))
    if observed_paths != sorted(expected_paths):
        raise VerificationError("expanded package payload inventory is not exact")
    payload_sha, directories, files = tree_sha(payload)
    contents = receipt["contents"]
    if (
        payload_sha != contents["payload_tree_sha256"]
        or directories != contents["directory_count"]
        or files != contents["file_count"]
        or hash_file(raw / "Bom") != contents["bom"]
        or {"sha256": sha256_bytes(package_info_raw), "size": len(package_info_raw)}
        != contents["package_info"]
        or {"sha256": sha256_bytes(scripts_archive), "size": len(scripts_archive)}
        != contents["scripts_archive"]
    ):
        raise VerificationError("expanded package content differs from protected receipt")
    package_root = payload / root_name
    bootstrap_path = package_root / "mesh-install"
    postinstall_path = full / "Scripts" / "postinstall"
    bootstrap = hash_file(bootstrap_path, 132 * 1024 * 1024)
    if bootstrap != {"sha256": receipt["bootstrap"]["sha256"], "size": receipt["bootstrap"]["size"]}:
        raise VerificationError("package bootstrap differs from protected receipt")
    if hash_file(postinstall_path, 132 * 1024 * 1024) != bootstrap:
        raise VerificationError("compiled postinstall differs from package bootstrap")
    for name, receipt_key in (
        ("bundle.json", "bundle_json"),
        ("install.json", "install_json"),
        ("mesh-darwin-bundle.tar", "artifact"),
    ):
        if hash_file(package_root / "snapshot" / name) != receipt["snapshot"][receipt_key]:
            raise VerificationError(f"package snapshot member differs from receipt: {name}")
    descriptor = canonical_document(
        bounded_read(package_root / "snapshot" / "install.json", 4096, "snapshot descriptor"),
        4096,
        "snapshot descriptor",
    )
    if descriptor != {
        "artifact": "mesh-darwin-bundle.tar",
        "online_bundle": "bundle.json",
        "schema": "mesh-darwin-install-snapshot-v1",
    }:
        raise VerificationError("package snapshot descriptor is invalid")
    native_arch = "x86_64" if architecture == "amd64" else "arm64"
    archs = run(["/usr/bin/lipo", "-archs", str(bootstrap_path)], environment=environment, allow_output=True)
    if archs.stdout.decode("utf-8", "strict").strip().split() != [native_arch]:
        raise VerificationError("package bootstrap architecture is invalid")
    requirement = (
        f'anchor apple generic and certificate leaf[subject.OU] = "{codesign_policy["team_id"]}" '
        f'and identifier "{codesign_policy["mesh_install_identifier"]}"'
    )
    run(
        ["/usr/bin/codesign", "--verify", "--strict=all", "--test-requirement", "=" + requirement, str(bootstrap_path)],
        environment=environment,
    )
    display = run(
        ["/usr/bin/codesign", "--display", "--verbose=4", str(bootstrap_path)],
        environment=environment,
        allow_output=True,
    )
    if RUNTIME_FLAGS.search(display.stdout + display.stderr) is None:
        raise VerificationError("package bootstrap lacks hardened runtime")
    entitlements = run(
        ["/usr/bin/codesign", "--display", "--entitlements", "-", "--xml", str(bootstrap_path)],
        environment=environment,
        allow_output=True,
    )
    if entitlements.stdout:
        try:
            entitlement_document = plistlib.loads(entitlements.stdout)
        except plistlib.InvalidFileException as exc:
            raise VerificationError("package bootstrap entitlements are invalid") from exc
        if entitlement_document:
            raise VerificationError("package bootstrap must not have entitlements")
    version_output = run([str(bootstrap_path), "version"], environment=environment, allow_output=True)
    try:
        version_document = json.loads(version_output.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VerificationError("package bootstrap version output is invalid") from exc
    if (
        version_document.get("darwin_code_signing_policy_sha256") != codesign_policy_sha
        or version_document.get("darwin_node_package_policy_sha256") != package_policy_sha
    ):
        raise VerificationError("package bootstrap compiled policies differ")
    return {"payload_tree_sha256": payload_sha, "bootstrap": bootstrap}


def exclusive_json(path: pathlib.Path, document: dict[str, Any]) -> None:
    if not path.is_absolute() or path.exists() or path.parent.is_symlink():
        raise VerificationError("native verification receipt must be a new absolute path")
    raw = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    with os.fdopen(descriptor, "wb") as output:
        output.write(raw)
        output.flush()
        os.fsync(output.fileno())


def verify(args: argparse.Namespace) -> None:
    if args.arch not in {"arm64", "amd64"} or not VERSION.fullmatch(args.version):
        raise VerificationError("package architecture or version is invalid")
    if not SHA256.fullmatch(args.portable_verifier_sha256):
        raise VerificationError("portable verifier SHA-256 is invalid")
    if not SHA256.fullmatch(args.codesign_receipt_sha256) or not SHA256.fullmatch(args.bundle_security_receipt_sha256):
        raise VerificationError("upstream receipt SHA-256 is invalid")
    package_policy, package_policy_sha = parse_package_policy(args.package_policy)
    codesign_policy, codesign_policy_sha = parse_codesign_policy(args.codesign_policy)
    package_path = pathlib.Path(args.package)
    package_identity = hash_file(package_path)
    receipt_path = pathlib.Path(args.receipt)
    receipt_raw = bounded_read(receipt_path, 96 * 1024, "Darwin node package release receipt")
    receipt = parse_receipt(
        receipt_raw,
        package_policy,
        codesign_policy,
        package_policy_sha,
        codesign_policy_sha,
        args.arch,
        args.version,
        package_identity,
        args.codesign_receipt_sha256,
        args.bundle_security_receipt_sha256,
    )
    developer = pathlib.Path(args.developer_directory)
    environment = {
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "LANG": "C",
        "LC_ALL": "C",
        "DEVELOPER_DIR": str(developer),
    }
    tools, tool_evidence = authenticate_tools(developer, environment)
    portable = pathlib.Path(args.portable_verifier)
    portable_identity = hash_file(portable, 256 * 1024 * 1024)
    if portable_identity["sha256"] != args.portable_verifier_sha256 or not os.access(portable, os.X_OK):
        raise VerificationError("portable verifier identity or executable mode is invalid")
    run(
        [
            str(portable),
            "verify-darwin-node-package-release",
            "--package",
            str(package_path),
            "--receipt",
            str(receipt_path),
            "--arch",
            args.arch,
            "--version",
            args.version,
            "--codesign-receipt-sha256",
            args.codesign_receipt_sha256,
            "--bundle-security-receipt-sha256",
            args.bundle_security_receipt_sha256,
        ],
        environment=environment,
        allow_output=True,
    )
    signature = run(
        ["/usr/sbin/pkgutil", "--check-signature", str(package_path)],
        environment=environment,
        allow_output=True,
    )
    signature_text = (signature.stdout + signature.stderr).decode("utf-8", "strict")
    if (
        codesign_policy["team_id"] not in signature_text
        or receipt["signing"]["installer_certificate_sha256"].upper() not in signature_text.upper()
    ):
        raise VerificationError("package Installer signature differs from protected receipt")
    run([str(tools["stapler"]), "validate", "-q", str(package_path)], environment=environment, allow_output=True)
    run(
        ["/usr/sbin/spctl", "--assess", "--type", "install", "--verbose=4", str(package_path)],
        environment=environment,
        allow_output=True,
    )
    with tempfile.TemporaryDirectory(prefix=".mesh-node-package-native-") as temporary:
        inspected = inspect_package(
            package_path,
            pathlib.Path(temporary),
            receipt,
            package_policy,
            codesign_policy,
            package_policy_sha,
            codesign_policy_sha,
            args.arch,
            args.version,
            environment,
        )
    if hash_file(package_path) != package_identity or hash_file(portable, 256 * 1024 * 1024) != portable_identity:
        raise VerificationError("package or portable verifier changed during native verification")
    for name, path in tools.items():
        if hash_file(path, 256 * 1024 * 1024) != tool_evidence[name]:
            raise VerificationError(f"Apple verification tool changed during verification: {name}")
    exclusive_json(
        pathlib.Path(args.output),
        {
            "architecture": args.arch,
            "bootstrap": inspected["bootstrap"],
            "package": package_identity,
            "payload_tree_sha256": inspected["payload_tree_sha256"],
            "portable_verifier": portable_identity,
            "release_receipt": {"sha256": sha256_bytes(receipt_raw), "size": len(receipt_raw)},
            "schema": NATIVE_RECEIPT_SCHEMA,
            "team_id": codesign_policy["team_id"],
            "tools": tool_evidence,
            "verified_at": dt.datetime.now(dt.timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z"),
            "version": args.version,
        },
    )


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--package", required=True)
    result.add_argument("--receipt", required=True)
    result.add_argument("--arch", required=True)
    result.add_argument("--version", required=True)
    result.add_argument("--package-policy", required=True)
    result.add_argument("--codesign-policy", required=True)
    result.add_argument("--developer-directory", required=True)
    result.add_argument("--portable-verifier", required=True)
    result.add_argument("--portable-verifier-sha256", required=True)
    result.add_argument("--codesign-receipt-sha256", required=True)
    result.add_argument("--bundle-security-receipt-sha256", required=True)
    result.add_argument("--output", required=True)
    return result


def main() -> int:
    try:
        verify(parser().parse_args())
    except VerificationError as exc:
        print(f"native Darwin node package verification: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
