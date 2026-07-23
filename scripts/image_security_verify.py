#!/usr/bin/env python3
"""Validate and bind the Mesh final-image security artifacts."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import io
import json
import os
import pathlib
import re
import stat
import sys
import tarfile
from collections import Counter
from typing import Any


MAX_ARCHIVE_BYTES = 128 * 1024 * 1024
MAX_LAYER_BYTES = 64 * 1024 * 1024
EXPECTED_IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
EXPECTED_BINARY_PATHS = {
    "usr/local/bin/mesh-healthcheck",
    "usr/local/bin/mesh-kube-init",
    "usr/local/bin/mesh-server",
    "usr/local/bin/nebula-cert",
}
EXPECTED_LAYER_ENTRIES = {
    "etc": ("dir", 0o755, 0, 0, 0),
    "etc/ssl": ("dir", 0o755, 0, 0, 0),
    "etc/ssl/certs": ("dir", 0o755, 0, 0, 0),
    "etc/ssl/certs/ca-certificates.crt": ("ca", 0o644, 0, 0, None),
    "run": ("dir", 0o755, 65532, 65532, 0),
    "run/secrets": ("dir", 0o555, 65532, 65532, 0),
    "run/secrets/admin.token": ("empty", 0o400, 65532, 65532, 0),
    "run/secrets/master.key": ("empty", 0o400, 65532, 65532, 0),
    "run/tls": ("dir", 0o555, 65532, 65532, 0),
    "run/tls/ca.crt": ("empty", 0o444, 65532, 65532, 0),
    "run/tls/server.crt": ("empty", 0o444, 65532, 65532, 0),
    "run/tls/server.key": ("empty", 0o400, 65532, 65532, 0),
    "tmp": ("dir", 0o1777, 65532, 65532, 0),
    "var": ("dir", 0o755, 65532, 65532, 0),
    "var/lib": ("dir", 0o755, 65532, 65532, 0),
    "var/lib/mesh": ("dir", 0o700, 65532, 65532, 0),
    "usr": ("dir", 0o755, 65532, 65532, 0),
    "usr/local": ("dir", 0o755, 65532, 65532, 0),
    "usr/local/bin": ("dir", 0o755, 65532, 65532, 0),
    "usr/local/bin/mesh-healthcheck": ("binary", 0o755, 65532, 65532, None),
    "usr/local/bin/mesh-kube-init": ("binary", 0o755, 65532, 65532, None),
    "usr/local/bin/mesh-server": ("binary", 0o755, 65532, 65532, None),
    "usr/local/bin/nebula-cert": ("binary", 0o755, 65532, 65532, None),
}
EXPECTED_ENV = {
    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "NEBULA_CERT_BINARY=/usr/local/bin/nebula-cert",
}
EXPECTED_LABELS = {
    "org.opencontainers.image.description": "Security-first Slack Nebula lifecycle control plane",
    "org.opencontainers.image.title": "Mesh control plane",
}
SEVERITY_ORDER = {
    "unknown": -1,
    "negligible": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


class VerificationError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def read_json(path: pathlib.Path, max_bytes: int = 128 * 1024 * 1024) -> Any:
    validate_regular_file(path, max_bytes=max_bytes)
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VerificationError(f"invalid JSON in {path.name}: {exc}") from exc


def validate_regular_file(path: pathlib.Path, *, max_bytes: int, allow_empty: bool = False) -> os.stat_result:
    try:
        info = path.lstat()
    except OSError as exc:
        raise VerificationError(f"required artifact is unavailable: {path}") from exc
    require(stat.S_ISREG(info.st_mode), f"artifact is not a regular file: {path}")
    require(info.st_size <= max_bytes, f"artifact exceeds its size bound: {path}")
    if not allow_empty:
        require(info.st_size > 0, f"artifact is empty: {path}")
    return info


def hash_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def hash_file(path: pathlib.Path) -> dict[str, Any]:
    info = validate_regular_file(path, max_bytes=MAX_ARCHIVE_BYTES)
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return {"sha256": digest.hexdigest(), "size": info.st_size}


def safe_tar_name(name: str) -> str:
    require(name != "", "archive contains an empty path")
    pure = pathlib.PurePosixPath(name)
    require(not pure.is_absolute(), f"archive contains an absolute path: {name}")
    require(".." not in pure.parts and "." not in pure.parts, f"archive contains a non-canonical path: {name}")
    normalized = str(pure)
    require(normalized == name.rstrip("/"), f"archive path is not canonical: {name}")
    return normalized


def exclusive_write(path: pathlib.Path, payload: bytes, mode: int = 0o600) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, mode)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
    finally:
        os.close(descriptor)


def load_outer_file(archive: tarfile.TarFile, members: dict[str, tarfile.TarInfo], name: str) -> bytes:
    member = members.get(name)
    require(member is not None and member.isreg(), f"image archive is missing regular file {name}")
    source = archive.extractfile(member)
    require(source is not None, f"image archive cannot read {name}")
    return source.read()


def validate_image_config(config: dict[str, Any]) -> None:
    require(config.get("architecture") == "amd64", "image architecture is not amd64")
    require(config.get("os") == "linux", "image OS is not Linux")
    runtime = config.get("config")
    require(isinstance(runtime, dict), "image runtime config is missing")
    require(runtime.get("User") == "65532:65532", "image runtime user is not 65532:65532")
    require(runtime.get("Entrypoint") == ["/usr/local/bin/mesh-server"], "image entrypoint is unexpected")
    require(runtime.get("WorkingDir") == "/", "image working directory is unexpected")
    require(runtime.get("Cmd") in (None, []), "image defines an unexpected command")
    require(runtime.get("Volumes") in (None, {}), "image defines an unexpected volume")
    require(set(runtime.get("Env", [])) == EXPECTED_ENV, "image environment is not the exact public allowlist")
    require(runtime.get("Labels") == EXPECTED_LABELS, "image labels are unexpected")
    require(runtime.get("ExposedPorts") == {"8443/tcp": {}}, "image exposed ports are unexpected")
    rootfs = config.get("rootfs")
    require(isinstance(rootfs, dict) and rootfs.get("type") == "layers", "image rootfs metadata is invalid")
    diff_ids = rootfs.get("diff_ids")
    require(isinstance(diff_ids, list) and len(diff_ids) == 3, "image must contain exactly three rootfs layers")
    require(all(EXPECTED_IMAGE_ID.fullmatch(item or "") for item in diff_ids), "image diff ID is invalid")


def prepare(args: argparse.Namespace) -> None:
    archive_path = pathlib.Path(args.archive)
    output_dir = pathlib.Path(args.output_dir)
    validate_regular_file(archive_path, max_bytes=MAX_ARCHIVE_BYTES)
    require(EXPECTED_IMAGE_ID.fullmatch(args.image_id) is not None, "Docker image ID is invalid")
    require(output_dir.is_dir() and not output_dir.is_symlink(), "prepare output directory is unsafe")
    require(not any(output_dir.iterdir()), "prepare output directory is not empty")

    binaries_dir = output_dir / "binaries"
    text_dir = output_dir / "rootfs-text"
    binaries_dir.mkdir(mode=0o700)
    text_dir.mkdir(mode=0o700)

    archive_digest = hash_file(archive_path)
    file_evidence: dict[str, dict[str, Any]] = {}
    seen_entries: set[str] = set()

    try:
        with tarfile.open(archive_path, "r:*") as outer:
            outer_list = outer.getmembers()
            require(len(outer_list) <= 64, "image archive contains too many outer entries")
            outer_members: dict[str, tarfile.TarInfo] = {}
            for member in outer_list:
                name = safe_tar_name(member.name)
                require(name not in outer_members, f"image archive repeats outer path {name}")
                require(member.isdir() or member.isreg(), f"image archive contains unsafe outer type at {name}")
                outer_members[name] = member

            require({"index.json", "manifest.json", "oci-layout"}.issubset(outer_members), "image archive metadata is incomplete")
            for name, member in outer_members.items():
                if member.isdir():
                    require(name in {"blobs", "blobs/sha256"}, f"image archive contains unexpected directory {name}")
                    continue
                if name in {"index.json", "manifest.json", "oci-layout"}:
                    continue
                require(re.fullmatch(r"blobs/sha256/[0-9a-f]{64}", name) is not None, f"image archive contains unexpected object {name}")
                payload = load_outer_file(outer, outer_members, name)
                require(hash_bytes(payload) == name.rsplit("/", 1)[1], f"image object digest mismatch at {name}")

            index = json.loads(load_outer_file(outer, outer_members, "index.json"))
            descriptors = index.get("manifests") if isinstance(index, dict) else None
            require(isinstance(descriptors, list) and descriptors, "image OCI index has no manifest")
            require(any(item.get("digest") == args.image_id for item in descriptors if isinstance(item, dict)), "Docker image ID is not bound by the saved OCI index")

            legacy_manifest = json.loads(load_outer_file(outer, outer_members, "manifest.json"))
            require(isinstance(legacy_manifest, list) and len(legacy_manifest) == 1, "image archive must contain one saved image")
            saved = legacy_manifest[0]
            require(isinstance(saved, dict), "image save manifest is invalid")
            config_name = saved.get("Config")
            layers = saved.get("Layers")
            require(isinstance(config_name, str) and re.fullmatch(r"blobs/sha256/[0-9a-f]{64}", config_name), "image config reference is invalid")
            require(isinstance(layers, list) and len(layers) == 3 and len(set(layers)) == 3, "image must save exactly three unique layers")
            require(all(isinstance(item, str) and re.fullmatch(r"blobs/sha256/[0-9a-f]{64}", item) for item in layers), "image layer reference is invalid")

            config_payload = load_outer_file(outer, outer_members, config_name)
            config = json.loads(config_payload)
            require(isinstance(config, dict), "image config is not an object")
            validate_image_config(config)

            for layer_name in layers:
                layer_payload = load_outer_file(outer, outer_members, layer_name)
                require(len(layer_payload) <= MAX_LAYER_BYTES, "image layer exceeds its size bound")
                with tarfile.open(fileobj=io.BytesIO(layer_payload), mode="r:*") as layer:
                    members = layer.getmembers()
                    require(len(members) <= 64, "image layer contains too many filesystem entries")
                    for member in members:
                        name = safe_tar_name(member.name)
                        require(name not in seen_entries, f"image layer overwrites path {name}")
                        seen_entries.add(name)
                        expected = EXPECTED_LAYER_ENTRIES.get(name)
                        require(expected is not None, f"image contains unexpected filesystem path {name}")
                        kind, mode, uid, gid, size = expected
                        require(member.mode == mode and member.uid == uid and member.gid == gid, f"image metadata is invalid at {name}")
                        if kind == "dir":
                            require(member.isdir() and member.size == 0, f"image directory is invalid at {name}")
                            continue
                        require(member.isreg(), f"image path is not a regular file: {name}")
                        if size is not None:
                            require(member.size == size, f"image file has an invalid size at {name}")
                        source = layer.extractfile(member)
                        require(source is not None, f"image file cannot be read: {name}")
                        payload = source.read()
                        require(len(payload) == member.size, f"image file is truncated: {name}")
                        if kind == "binary":
                            require(1024 * 1024 <= len(payload) <= 32 * 1024 * 1024, f"image binary size is invalid at {name}")
                            destination = binaries_dir / pathlib.PurePosixPath(name).name
                            exclusive_write(destination, payload)
                        elif kind == "ca":
                            require(64 * 1024 <= len(payload) <= 1024 * 1024, "CA bundle size is invalid")
                            exclusive_write(text_dir / "ca-certificates.crt", payload)
                        else:
                            require(payload == b"", f"credential placeholder is not empty at {name}")
                            exclusive_write(text_dir / pathlib.PurePosixPath(name).name, payload)
                        file_evidence[name] = {"sha256": hash_bytes(payload), "size": len(payload)}
    except (OSError, tarfile.TarError, json.JSONDecodeError) as exc:
        raise VerificationError(f"cannot validate image archive: {exc}") from exc

    require(seen_entries == set(EXPECTED_LAYER_ENTRIES), "image filesystem allowlist is incomplete")
    require(set(file_evidence).issuperset(EXPECTED_BINARY_PATHS), "image binary evidence is incomplete")
    metadata = {
        "schema": "mesh-image-archive-evidence-v1",
        "docker_image_id": args.image_id,
        "archive": archive_digest,
        "config_digest": config_name.rsplit("/", 1)[1],
        "filesystem_entry_count": len(seen_entries),
        "files": dict(sorted(file_evidence.items())),
        "platform": "linux/amd64",
    }
    exclusive_write(output_dir / "image-metadata.json", canonical_json(metadata), mode=0o400)


def artifact_locations(artifact: dict[str, Any]) -> set[str]:
    result = set()
    for location in artifact.get("locations", []):
        if isinstance(location, dict) and isinstance(location.get("path"), str):
            result.add(location["path"])
    return result


def validate_syft(document: dict[str, Any], metadata: dict[str, Any]) -> tuple[set[str], int]:
    descriptor = document.get("descriptor")
    require(isinstance(descriptor, dict) and descriptor.get("name") == "syft", "SBOM descriptor is invalid")
    require(descriptor.get("version") == "1.44.0", "SBOM was not generated by Syft 1.44.0")
    schema = document.get("schema")
    require(isinstance(schema, dict) and schema.get("version") == "16.1.3", "Syft schema version is unexpected")
    source = document.get("source")
    require(isinstance(source, dict) and source.get("type") == "image", "SBOM source is not an image")
    source_metadata = source.get("metadata")
    require(isinstance(source_metadata, dict), "SBOM image metadata is missing")
    require(source_metadata.get("imageID") == f"sha256:{metadata['config_digest']}", "SBOM is not bound to the saved image config")
    require(source_metadata.get("manifestDigest") == f"sha256:{source.get('id')}", "SBOM manifest identity is inconsistent")
    require(source_metadata.get("userInput") == "/work/image.tar", "SBOM source path is unexpected")

    artifacts = document.get("artifacts")
    require(isinstance(artifacts, list) and artifacts, "SBOM package inventory is empty")
    allowed_locations = {f"/{item}" for item in EXPECTED_BINARY_PATHS}
    purls: set[str] = set()
    observed: set[tuple[str, str, str]] = set()
    for artifact in artifacts:
        require(isinstance(artifact, dict) and artifact.get("type") == "go-module", "SBOM contains a non-Go package")
        name = artifact.get("name")
        version = artifact.get("version")
        require(isinstance(name, str) and isinstance(version, str), "SBOM package identity is invalid")
        locations = artifact_locations(artifact)
        require(len(locations) == 1 and locations.issubset(allowed_locations), f"SBOM package has an unexpected location: {name}")
        location = next(iter(locations))
        observed.add((name, version, location))
        purl = artifact.get("purl")
        require(isinstance(purl, str) and purl.startswith("pkg:golang/"), f"SBOM package lacks a Go purl: {name}")
        purls.add(purl)

    for binary in sorted(allowed_locations):
        require(("stdlib", "go1.26.5", binary) in observed, f"SBOM does not prove Go 1.26.5 for {binary}")
    for binary in ("/usr/local/bin/mesh-server", "/usr/local/bin/nebula-cert"):
        require(("github.com/slackhq/nebula", "v1.10.3", binary) in observed, f"SBOM does not prove Nebula v1.10.3 for {binary}")
        require(("golang.org/x/crypto", "v0.53.0", binary) in observed, f"SBOM does not prove fixed x/crypto v0.53.0 for {binary}")
        require(("golang.org/x/sys", "v0.46.0", binary) in observed, f"SBOM does not prove x/sys v0.46.0 for {binary}")
    require(("golang.org/x/text", "v0.39.0", "/usr/local/bin/mesh-server") in observed, "SBOM does not prove fixed x/text v0.39.0 for mesh-server")
    require(("golang.org/x/term", "v0.44.0", "/usr/local/bin/nebula-cert") in observed, "SBOM does not prove x/term v0.44.0 for nebula-cert")
    require(not any(name == "stdlib" and version != "go1.26.5" for name, version, _ in observed), "SBOM contains an unexpected Go toolchain")
    require(not any(name == "golang.org/x/crypto" and version != "v0.53.0" for name, version, _ in observed), "SBOM contains an unexpected x/crypto version")
    require(not any(name == "golang.org/x/net" and version != "v0.56.0" for name, version, _ in observed), "SBOM contains an unexpected x/net version")
    require(not any(name == "golang.org/x/sys" and version != "v0.46.0" for name, version, _ in observed), "SBOM contains an unexpected x/sys version")
    return purls, len(artifacts)


def validate_spdx(document: dict[str, Any], syft_purls: set[str]) -> int:
    require(document.get("spdxVersion") == "SPDX-2.3", "SPDX document version is unexpected")
    require(document.get("dataLicense") == "CC0-1.0", "SPDX data license is unexpected")
    creation = document.get("creationInfo")
    require(isinstance(creation, dict) and "Tool: syft-1.44.0" in creation.get("creators", []), "SPDX creator is unexpected")
    packages = document.get("packages")
    require(isinstance(packages, list) and packages, "SPDX package inventory is empty")
    spdx_purls = set()
    for package in packages:
        if not isinstance(package, dict):
            continue
        for reference in package.get("externalRefs", []):
            if isinstance(reference, dict) and reference.get("referenceType") == "purl":
                locator = reference.get("referenceLocator")
                if isinstance(locator, str):
                    spdx_purls.add(locator)
    require(syft_purls.issubset(spdx_purls), "SPDX and Syft package inventories disagree")
    return len(packages)


def recursive_value(document: Any, wanted: str) -> Any:
    if isinstance(document, dict):
        for key, value in document.items():
            if key.lower() == wanted.lower():
                return value
        for value in document.values():
            found = recursive_value(value, wanted)
            if found is not None:
                return found
    elif isinstance(document, list):
        for value in document:
            found = recursive_value(value, wanted)
            if found is not None:
                return found
    return None


def parse_time(value: str) -> dt.datetime:
    require(isinstance(value, str), "database build time is missing")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise VerificationError("database build time is invalid") from exc
    require(parsed.tzinfo is not None, "database build time lacks a timezone")
    return parsed.astimezone(dt.timezone.utc)


def validate_grype_db(document: dict[str, Any]) -> tuple[str, str]:
    status_value = recursive_value(document, "status")
    valid_value = recursive_value(document, "valid")
    require(
        valid_value is True or (isinstance(status_value, str) and status_value.lower() == "valid"),
        "Grype database is not valid",
    )
    schema_value = recursive_value(document, "schema")
    if schema_value is None:
        schema_value = recursive_value(document, "schemaVersion")
    require(isinstance(schema_value, str) and schema_value.startswith("v6."), "Grype database schema is unexpected")
    built_value = recursive_value(document, "built")
    built = parse_time(built_value)
    now = dt.datetime.now(dt.timezone.utc)
    age = now - built
    require(age >= dt.timedelta(minutes=-5), "Grype database build time is too far in the future")
    require(age <= dt.timedelta(hours=72), "Grype database is more than 72 hours old")
    return schema_value, built.isoformat().replace("+00:00", "Z")


def validate_grype(document: dict[str, Any], syft_purls: set[str]) -> dict[str, Any]:
    descriptor = document.get("descriptor")
    require(isinstance(descriptor, dict) and descriptor.get("name") == "grype", "Grype report descriptor is invalid")
    require(descriptor.get("version") == "0.112.0", "Grype report version is unexpected")
    ignored = document.get("ignoredMatches", [])
    require(ignored == [], "Grype report contains ignored findings")
    matches = document.get("matches")
    require(isinstance(matches, list), "Grype matches are invalid")

    counts: Counter[str] = Counter()
    fixed = []
    high = []
    remaining_ids: set[str] = set()
    for match in matches:
        require(isinstance(match, dict), "Grype match is invalid")
        vulnerability = match.get("vulnerability")
        artifact = match.get("artifact")
        require(isinstance(vulnerability, dict) and isinstance(artifact, dict), "Grype match structure is invalid")
        identifier = vulnerability.get("id")
        severity = vulnerability.get("severity")
        require(isinstance(identifier, str) and isinstance(severity, str), "Grype vulnerability identity is invalid")
        normalized = severity.lower()
        require(normalized in SEVERITY_ORDER, f"Grype severity is unknown: {severity}")
        counts[severity] += 1
        purl = artifact.get("purl")
        require(isinstance(purl, str) and purl in syft_purls, f"Grype finding is not bound to the SBOM: {identifier}")
        fix = vulnerability.get("fix", {})
        versions = fix.get("versions", []) if isinstance(fix, dict) else []
        require(isinstance(versions, list), f"Grype fix metadata is invalid: {identifier}")
        if versions:
            fixed.append(identifier)
        if SEVERITY_ORDER[normalized] >= SEVERITY_ORDER["high"]:
            high.append(identifier)
        remaining_ids.add(identifier)
    require(not high, f"image contains High/Critical vulnerabilities: {', '.join(sorted(set(high)))}")
    require(not fixed, f"image contains vulnerabilities with published fixes: {', '.join(sorted(set(fixed)))}")
    return {
        "match_count": len(matches),
        "counts_by_severity": dict(sorted(counts.items())),
        "remaining_nonfixed_ids": sorted(remaining_ids),
    }


def validate_empty_gitleaks(path: pathlib.Path) -> None:
    report = read_json(path, max_bytes=1024 * 1024)
    require(report == [], f"Gitleaks report is not empty: {path.name}")


def finalize(args: argparse.Namespace) -> None:
    work_dir = pathlib.Path(args.work_dir)
    require(work_dir.is_dir() and not work_dir.is_symlink(), "verification workspace is unsafe")
    metadata = read_json(work_dir / "prepared" / "image-metadata.json", max_bytes=1024 * 1024)
    require(isinstance(metadata, dict) and metadata.get("schema") == "mesh-image-archive-evidence-v1", "image metadata schema is invalid")

    syft_path = work_dir / "sbom.syft.json"
    spdx_path = work_dir / "sbom.spdx.json"
    grype_path = work_dir / "vulnerabilities.json"
    db_path = work_dir / "grype-db-status.json"
    rootfs_secrets_path = work_dir / "rootfs-secrets.json"
    binary_secrets_path = work_dir / "binary-secrets.json"
    syft = read_json(syft_path)
    spdx = read_json(spdx_path)
    grype = read_json(grype_path)
    database = read_json(db_path, max_bytes=1024 * 1024)
    require(all(isinstance(item, dict) for item in (syft, spdx, grype, database)), "scanner output is not an object")

    syft_purls, syft_count = validate_syft(syft, metadata)
    spdx_count = validate_spdx(spdx, syft_purls)
    database_schema, database_built = validate_grype_db(database)
    vulnerability_summary = validate_grype(grype, syft_purls)
    validate_empty_gitleaks(rootfs_secrets_path)
    validate_empty_gitleaks(binary_secrets_path)

    generated_at = dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")
    receipt = {
        "schema": "mesh-image-security-receipt-v1",
        "verified_at": generated_at,
        "image": metadata,
        "sbom": {
            "syft_version": "1.44.0",
            "syft_schema": "16.1.3",
            "syft_package_count": syft_count,
            "syft_json": hash_file(syft_path),
            "spdx_version": "SPDX-2.3",
            "spdx_package_count": spdx_count,
            "spdx_json": hash_file(spdx_path),
        },
        "vulnerability_scan": {
            "grype_version": "0.112.0",
            "database_schema": database_schema,
            "database_built": database_built,
            "policy": "reject High or Critical matches and every match with a published fix",
            "report": hash_file(grype_path),
            **vulnerability_summary,
        },
        "secret_scan": {
            "gitleaks_version": "v8.30.1",
            "policy": "default rules over final rootfs text and binary strings; only the exact public oauth2 v0.36.0 Go checksum is allowlisted",
            "rootfs_report": hash_file(rootfs_secrets_path),
            "binary_strings_report": hash_file(binary_secrets_path),
        },
        "scanner_boundary": {
            "image_archive_and_scan": "networkless, read-only, non-root, capability-free containers without a Docker socket",
            "database_update": "networked scanner with only an empty private database cache mounted",
        },
    }
    receipt_path = pathlib.Path(args.receipt)
    require(receipt_path.parent == work_dir, "receipt must be written inside the verification workspace")
    exclusive_write(receipt_path, canonical_json(receipt), mode=0o400)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="command", required=True)
    prepare_parser = commands.add_parser("prepare", help="validate an image archive and extract bounded scan inputs")
    prepare_parser.add_argument("--archive", required=True)
    prepare_parser.add_argument("--image-id", required=True)
    prepare_parser.add_argument("--output-dir", required=True)
    prepare_parser.set_defaults(function=prepare)
    finalize_parser = commands.add_parser("finalize", help="validate scanner outputs and create the bound receipt")
    finalize_parser.add_argument("--work-dir", required=True)
    finalize_parser.add_argument("--receipt", required=True)
    finalize_parser.set_defaults(function=finalize)
    return result


def main() -> int:
    try:
        args = parser().parse_args()
        args.function(args)
    except VerificationError as exc:
        print(f"image security verification: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
