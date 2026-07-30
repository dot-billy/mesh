#!/usr/bin/env python3
"""Natively re-verify downloaded Mesh Admin bytes and emit local evidence."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import os
import pathlib
import posixpath
import re
import stat
import sys
import tempfile
import unicodedata
import zipfile
from typing import Any


ROOT = pathlib.Path(__file__).resolve().parents[1]
PRODUCER_SPEC = importlib.util.spec_from_file_location(
    "apple_protected_app_release",
    ROOT / "scripts" / "apple-protected-app-release.py",
)
if PRODUCER_SPEC is None or PRODUCER_SPEC.loader is None:
    raise RuntimeError("could not load protected Apple release contract")
PRODUCER = importlib.util.module_from_spec(PRODUCER_SPEC)
PRODUCER_SPEC.loader.exec_module(PRODUCER)

SCHEMA = "mesh-apple-macos-public-native-verification-receipt-v1"
MAXIMUM_RECEIPT_BYTES = 128 * 1024
SHA256 = re.compile(r"^[0-9a-f]{64}$")
APP_IDENTIFIER = PRODUCER.APP_IDENTIFIER
EXPECTED_ENTITLEMENTS = {
    "com.apple.security.app-sandbox": True,
    "com.apple.security.network.client": True,
    "keychain-access-groups": ["Y3P5UNNG23.io.rw0.mesh.admin"],
}


class VerificationError(RuntimeError):
    pass


def digest_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def physical_file(path: pathlib.Path, label: str, maximum: int) -> dict[str, Any]:
    if not path.is_absolute() or not path.is_file() or path.is_symlink():
        raise VerificationError(f"{label} must be one absolute physical regular file")
    metadata = path.stat()
    if metadata.st_size < 1 or metadata.st_size > maximum:
        raise VerificationError(f"{label} is empty or oversized")
    return {
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "mode": metadata.st_mode,
        "size": metadata.st_size,
        "mtime_ns": metadata.st_mtime_ns,
        "sha256": digest_file(path),
    }


def stable_json(path: pathlib.Path, label: str) -> tuple[dict[str, Any], bytes]:
    before = physical_file(path, label, MAXIMUM_RECEIPT_BYTES)
    raw = path.read_bytes()
    after = physical_file(path, label, MAXIMUM_RECEIPT_BYTES)
    if before != after or len(raw) != before["size"]:
        raise VerificationError(f"{label} changed while reading")
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VerificationError(f"{label} is invalid JSON") from exc
    if (
        not isinstance(document, dict)
        or (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()
        != raw
    ):
        raise VerificationError(f"{label} is not canonical JSON")
    return document, raw


def network_has_nonloopback_unicast(raw: bytes) -> bool:
    current = ""
    for line in raw.decode("utf-8", "strict").splitlines():
        if line and not line[0].isspace() and ":" in line:
            current = line.split(":", 1)[0]
            continue
        stripped = line.strip()
        if current == "lo0":
            continue
        if stripped.startswith("inet "):
            return True
        if stripped.startswith("inet6 "):
            address = stripped.split()[1].split("%", 1)[0].lower()
            if not address.startswith("fe80:"):
                return True
    return False


def inspect_archive(path: pathlib.Path) -> None:
    try:
        with zipfile.ZipFile(path, "r") as archive:
            entries = archive.infolist()
            if not entries or len(entries) > 8192:
                raise VerificationError(
                    "downloaded application zip has an invalid entry count"
                )
            names: set[str] = set()
            filesystem_names: set[str] = set()
            total = 0
            for entry in entries:
                name = entry.filename
                if (
                    not name
                    or len(name.encode("utf-8")) > 1024
                    or "\\" in name
                    or "\x00" in name
                    or entry.flag_bits & 0x1
                    or entry.compress_type
                    not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
                ):
                    raise VerificationError(
                        "downloaded application zip has an unsafe entry"
                    )
                parts = pathlib.PurePosixPath(name).parts
                if (
                    not parts
                    or parts[0] not in {PRODUCER.APP_NAME, "__MACOSX"}
                    or parts[0] == "__MACOSX"
                    and len(parts) > 1
                    and parts[1] != PRODUCER.APP_NAME
                    or any(part in {"", ".", ".."} for part in parts)
                ):
                    raise VerificationError(
                        "downloaded application zip entry escapes its exact roots"
                    )
                normalized = posixpath.normpath(name)
                filesystem_name = unicodedata.normalize("NFC", normalized).casefold()
                if normalized in names or filesystem_name in filesystem_names:
                    raise VerificationError(
                        "downloaded application zip has duplicate normalized entries"
                    )
                names.add(normalized)
                filesystem_names.add(filesystem_name)
                total += entry.file_size
                if (
                    entry.file_size < 0
                    or entry.file_size > PRODUCER.MAXIMUM_BYTES
                    or total > 2 * PRODUCER.MAXIMUM_BYTES
                ):
                    raise VerificationError(
                        "downloaded application zip exceeds extraction bounds"
                    )
                mode = (entry.external_attr >> 16) & 0xFFFF
                if not (
                    stat.S_ISDIR(mode)
                    or stat.S_ISREG(mode)
                    or stat.S_ISLNK(mode)
                ):
                    raise VerificationError(
                        "downloaded application zip has an unsupported object"
                    )
                if stat.S_ISLNK(mode):
                    if parts[0] != PRODUCER.APP_NAME or entry.file_size > 1024:
                        raise VerificationError(
                            "downloaded application zip has an unsafe symlink"
                        )
                    target = archive.read(entry).decode("utf-8", "strict")
                    if not target or posixpath.isabs(target):
                        raise VerificationError(
                            "downloaded application zip has an unsafe symlink target"
                        )
                    resolved = posixpath.normpath(
                        posixpath.join(posixpath.dirname(name), target)
                    )
                    if (
                        resolved != PRODUCER.APP_NAME
                        and not resolved.startswith(PRODUCER.APP_NAME + "/")
                    ):
                        raise VerificationError(
                            "downloaded application zip symlink escapes the application"
                        )
    except VerificationError:
        raise
    except (OSError, UnicodeError, zipfile.BadZipFile, RuntimeError) as exc:
        raise VerificationError("downloaded application is not a valid bounded zip") from exc


def require_network_isolation() -> dict[str, str]:
    route = pathlib.Path("/sbin/route")
    ifconfig = pathlib.Path("/sbin/ifconfig")
    route_identity = PRODUCER.authenticate_apple_tool(route, "com.apple.route")
    ifconfig_identity = PRODUCER.authenticate_apple_tool(ifconfig, "com.apple.ifconfig")
    for family in ([], ["-inet6"]):
        result = PRODUCER.run(
            [str(route), "-n", "get", *family, "default"],
            allow_output=True,
            require_success=False,
        )
        if result.returncode != 0 and b"not in table" not in result.stderr:
            raise VerificationError(
                "network-isolation route inspection failed unexpectedly"
            )
        if b"gateway:" in result.stdout or b"interface:" in result.stdout:
            raise VerificationError("network-isolated verification found a default route")
    interfaces = PRODUCER.run([str(ifconfig), "-a"], allow_output=True)
    if network_has_nonloopback_unicast(interfaces.stdout):
        raise VerificationError(
            "network-isolated verification found a non-loopback unicast address"
        )
    if PRODUCER.authenticate_apple_tool(route, "com.apple.route") != route_identity:
        raise VerificationError("authenticated route tool changed during verification")
    if PRODUCER.authenticate_apple_tool(ifconfig, "com.apple.ifconfig") != ifconfig_identity:
        raise VerificationError("authenticated ifconfig tool changed during verification")
    return {
        "ifconfig_sha256": ifconfig_identity["sha256"],
        "route_sha256": route_identity["sha256"],
    }


def application_requirement(team_id: str) -> str:
    return (
        f'anchor apple generic and identifier "{APP_IDENTIFIER}" '
        "and certificate 1[field.1.2.840.113635.100.6.2.6] exists "
        "and certificate leaf[field.1.2.840.113635.100.6.1.13] exists "
        f'and certificate leaf[subject.OU] = "{team_id}"'
    )


def nested_requirement(identifier: str, team_id: str) -> str:
    return (
        f'anchor apple generic and identifier "{identifier}" '
        "and certificate 1[field.1.2.840.113635.100.6.2.6] exists "
        "and certificate leaf[field.1.2.840.113635.100.6.1.13] exists "
        f'and certificate leaf[subject.OU] = "{team_id}"'
    )


def verify(args: argparse.Namespace) -> dict[str, Any]:
    if sys.platform != "darwin":
        raise VerificationError("native Mesh Admin verification requires macOS")
    verifier = pathlib.Path(args.mesh_release_verifier)
    verifier_identity = physical_file(
        verifier, "Mesh release verifier", 256 * 1024 * 1024
    )
    if (
        not SHA256.fullmatch(args.mesh_release_verifier_sha256)
        or verifier_identity["sha256"] != args.mesh_release_verifier_sha256
        or stat.S_IMODE(verifier_identity["mode"]) & 0o022
    ):
        raise VerificationError(
            "Mesh release verifier differs from its independently authenticated digest"
        )
    archive = pathlib.Path(args.archive)
    receipt_path = pathlib.Path(args.receipt)
    archive_identity = physical_file(
        archive, "downloaded Mesh Admin archive", PRODUCER.MAXIMUM_BYTES
    )
    receipt, receipt_raw = stable_json(
        receipt_path, "downloaded protected Mesh Admin receipt"
    )
    receipt_identity = physical_file(
        receipt_path,
        "downloaded protected Mesh Admin receipt",
        MAXIMUM_RECEIPT_BYTES,
    )
    metadata_paths = {
        "root": pathlib.Path(args.root),
        "manifest": pathlib.Path(args.manifest),
    }
    metadata_identities = {
        "root": physical_file(metadata_paths["root"], "trusted release root", 64 << 10),
        "manifest": physical_file(
            metadata_paths["manifest"], "downloaded release manifest", 1 << 20
        ),
    }
    signature_identities = [
        physical_file(
            pathlib.Path(signature),
            f"downloaded release signature {index + 1}",
            4 << 10,
        )
        for index, signature in enumerate(args.signature)
    ]
    command = [
        str(verifier),
        "verify-published-apple-app",
        "--root",
        args.root,
        "--root-sha256",
        args.root_sha256,
        "--manifest",
        args.manifest,
        "--archive",
        args.archive,
        "--receipt",
        args.receipt,
        "--source-receipt-sha256",
        args.source_receipt_sha256,
        "--team-id",
        args.team_id,
    ]
    for signature in args.signature:
        command.extend(["--signature", signature])
    metadata_result = PRODUCER.run(command, allow_output=True)
    if (
        receipt.get("schema") != PRODUCER.SCHEMA
        or receipt.get("signing", {}).get("team_id") != args.team_id
        or receipt.get("source", {}).get("receipt_sha256")
        != args.source_receipt_sha256
        or receipt.get("distribution", {}).get("sha256") != archive_identity["sha256"]
        or receipt.get("distribution", {}).get("size") != archive_identity["size"]
        or receipt.get("distribution", {}).get("round_trip_verified") is not True
    ):
        raise VerificationError(
            "protected receipt differs from the downloaded application contract"
        )
    inspect_archive(archive)
    tool_paths, tool_identities = PRODUCER.authenticate_release_tools(
        args.developer_directory
    )
    isolation_tools: dict[str, str] = {}
    if args.require_network_isolated:
        isolation_tools = require_network_isolation()
    with tempfile.TemporaryDirectory(
        prefix="mesh-apple-native-verify-", dir="/private/var/tmp"
    ) as temporary:
        workspace = pathlib.Path(temporary)
        os.chmod(workspace, 0o700)
        PRODUCER.run(["/usr/bin/ditto", "-x", "-k", str(archive), str(workspace)])
        roots = list(workspace.iterdir())
        if len(roots) != 1 or roots[0].name != PRODUCER.APP_NAME:
            raise VerificationError(
                "downloaded archive does not contain exactly one Mesh Admin application"
            )
        app = roots[0]
        PRODUCER.app_info(app)
        tree_sha, files, total = PRODUCER.tree_identity(app)
        application = receipt["application"]
        distribution = receipt["distribution"]
        if (
            tree_sha != application.get("signed_tree_sha256")
            or files != application.get("signed_regular_files")
            or total != application.get("signed_regular_file_bytes")
            or tree_sha != distribution.get("extracted_tree_sha256")
            or files != distribution.get("extracted_regular_files")
            or total != distribution.get("extracted_regular_file_bytes")
        ):
            raise VerificationError(
                "extracted application differs from its protected signed tree"
            )
        bundles, standalone = PRODUCER.nested_code(app)
        if standalone:
            raise VerificationError("downloaded application contains standalone code")
        code_records = []
        for bundle in bundles:
            relative = bundle.relative_to(app).as_posix()
            identifier = PRODUCER.EXPECTED_NESTED_CODE[relative]
            record = PRODUCER.verify_code(
                bundle, nested_requirement(identifier, args.team_id), {}, identifier
            )
            record["path"] = relative
            code_records.append(record)
        app_record = PRODUCER.verify_code(
            app,
            application_requirement(args.team_id),
            EXPECTED_ENTITLEMENTS,
            APP_IDENTIFIER,
        )
        embedded_profile = app / "Contents" / "embedded.provisionprofile"
        if (
            not embedded_profile.is_file()
            or embedded_profile.is_symlink()
            or stat.S_IMODE(embedded_profile.stat().st_mode) & 0o022
        ):
            raise VerificationError(
                "downloaded application lacks a protected provisioning profile"
            )
        PRODUCER.validate_provisioning_profile(
            embedded_profile,
            args.team_id,
            receipt["signing"]["identity_sha1"],
        )
        PRODUCER.run(
            ["/usr/bin/codesign", "--verify", "--deep", "--strict=all", str(app)]
        )
        PRODUCER.run([str(tool_paths["stapler"]), "validate", "-q", str(app)])
        PRODUCER.run(["/usr/sbin/spctl", "--assess", "--type", "execute", str(app)])
        final_tree = PRODUCER.tree_identity(app)
        if final_tree != (tree_sha, files, total):
            raise VerificationError("native verification changed the application tree")
    if args.require_network_isolated:
        isolation_after = require_network_isolation()
        if isolation_after != isolation_tools:
            raise VerificationError(
                "network-isolation tools changed during native verification"
            )
    _, tool_identities_after = PRODUCER.authenticate_release_tools(
        args.developer_directory
    )
    if tool_identities_after != tool_identities:
        raise VerificationError(
            "authenticated Apple verification tool changed during the native check"
        )
    if (
        physical_file(verifier, "Mesh release verifier", 256 * 1024 * 1024)
        != verifier_identity
        or physical_file(
            archive, "downloaded Mesh Admin archive", PRODUCER.MAXIMUM_BYTES
        )
        != archive_identity
        or physical_file(
            receipt_path,
            "downloaded protected Mesh Admin receipt",
            MAXIMUM_RECEIPT_BYTES,
        )
        != receipt_identity
    ):
        raise VerificationError("downloaded verification input changed during the check")
    for name, path in metadata_paths.items():
        if physical_file(
            path,
            "trusted release root" if name == "root" else "downloaded release manifest",
            64 << 10 if name == "root" else 1 << 20,
        ) != metadata_identities[name]:
            raise VerificationError("downloaded release metadata changed during the check")
    for index, signature in enumerate(args.signature):
        if physical_file(
            pathlib.Path(signature),
            f"downloaded release signature {index + 1}",
            4 << 10,
        ) != signature_identities[index]:
            raise VerificationError("downloaded release signature changed during the check")
    return {
        "application": {
            "architectures": app_record["architectures"],
            "bundle_identifier": APP_IDENTIFIER,
            "signed_tree_sha256": receipt["application"]["signed_tree_sha256"],
        },
        "archive": {
            "sha256": archive_identity["sha256"],
            "size": archive_identity["size"],
        },
        "mesh_release_verifier": {
            "sha256": verifier_identity["sha256"],
            "size": verifier_identity["size"],
        },
        "metadata_verification_stdout_sha256": hashlib.sha256(
            metadata_result.stdout
        ).hexdigest(),
        "release_metadata": {
            "manifest_sha256": metadata_identities["manifest"]["sha256"],
            "root_sha256": metadata_identities["root"]["sha256"],
            "signature_sha256": sorted(
                identity["sha256"] for identity in signature_identities
            ),
        },
        "native": {
            "gatekeeper_assessment": "accepted",
            "network_isolation_check": (
                "pre-and-post-no-default-route-or-nonloopback-unicast"
                if args.require_network_isolated
                else "not-requested"
            ),
            "network_isolation_tools": isolation_tools,
            "staple": "validated",
        },
        "protected_receipt_sha256": hashlib.sha256(receipt_raw).hexdigest(),
        "schema": SCHEMA,
        "signing": {
            "application_entitlements_sha256": app_record["entitlements_sha256"],
            "nested_code": sorted(code_records, key=lambda item: item["path"]),
            "team_id": args.team_id,
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
    if (
        not path.is_absolute()
        or path.exists()
        or not path.parent.is_dir()
        or path.parent.is_symlink()
    ):
        raise VerificationError("native verification receipt must be one new absolute path")
    raw = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if len(raw) > MAXIMUM_RECEIPT_BYTES:
        raise VerificationError("native verification receipt exceeds its size bound")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
    with os.fdopen(descriptor, "wb") as target:
        target.write(raw)
        target.flush()
        os.fsync(target.fileno())


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--mesh-release-verifier", required=True)
    result.add_argument("--mesh-release-verifier-sha256", required=True)
    result.add_argument("--root", required=True)
    result.add_argument("--root-sha256", required=True)
    result.add_argument("--manifest", required=True)
    result.add_argument("--signature", action="append", required=True)
    result.add_argument("--archive", required=True)
    result.add_argument("--receipt", required=True)
    result.add_argument("--source-receipt-sha256", required=True)
    result.add_argument("--team-id", required=True)
    result.add_argument("--developer-directory", required=True)
    result.add_argument("--require-network-isolated", action="store_true")
    result.add_argument("--output", required=True)
    return result


def main() -> int:
    os.umask(0o077)
    args = parser().parse_args()
    if (
        not SHA256.fullmatch(args.source_receipt_sha256)
        or not SHA256.fullmatch(args.root_sha256)
        or PRODUCER.TEAM_ID.fullmatch(args.team_id) is None
    ):
        raise VerificationError("source receipt digest or Team ID is invalid")
    document = verify(args)
    write_receipt(pathlib.Path(args.output), document)
    print(
        "Native downloaded Mesh Admin verification passed: "
        f"{args.archive} ({document['archive']['sha256']})"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (VerificationError, PRODUCER.ReleaseError) as exc:
        print(f"Apple native application verification: {exc}", file=sys.stderr)
        raise SystemExit(1)
