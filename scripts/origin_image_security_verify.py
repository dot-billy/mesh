#!/usr/bin/env python3
"""Validate and bind the exact Mesh release-origin image security artifacts."""

from __future__ import annotations

import argparse
import datetime as dt
import io
import json
import pathlib
import re
import sys
import tarfile
from typing import Any

from image_security_verify import (
    EXPECTED_IMAGE_ID,
    MAX_ARCHIVE_BYTES,
    MAX_LAYER_BYTES,
    VerificationError,
    artifact_locations,
    canonical_json,
    exclusive_write,
    hash_bytes,
    hash_file,
    read_json,
    require,
    safe_tar_name,
    validate_empty_gitleaks,
    validate_grype,
    validate_grype_db,
    validate_regular_file,
    validate_spdx,
)


EXPECTED_BINARY_PATHS = {
    "usr/local/bin/mesh-healthcheck",
    "usr/local/bin/mesh-origin",
}
EXPECTED_LAYER_ENTRIES = {
    "etc": ("dir", 0o755, 0, 0, 0),
    "etc/ssl": ("dir", 0o755, 0, 0, 0),
    "etc/ssl/certs": ("dir", 0o755, 0, 0, 0),
    "etc/ssl/certs/ca-certificates.crt": ("ca", 0o644, 0, 0, None),
    "run": ("dir", 0o755, 65532, 65532, 0),
    "run/origin": ("dir", 0o555, 65532, 65532, 0),
    "run/origin/index.json": ("empty", 0o444, 65532, 65532, 0),
    "run/tls": ("dir", 0o555, 65532, 65532, 0),
    "run/tls/ca.crt": ("empty", 0o444, 65532, 65532, 0),
    "run/tls/server.crt": ("empty", 0o444, 65532, 65532, 0),
    "run/tls/server.key": ("empty", 0o400, 65532, 65532, 0),
    "srv": ("dir", 0o755, 65532, 65532, 0),
    "srv/repository": ("dir", 0o555, 65532, 65532, 0),
    "usr": ("dir", 0o755, 65532, 65532, 0),
    "usr/local": ("dir", 0o755, 65532, 65532, 0),
    "usr/local/bin": ("dir", 0o755, 65532, 65532, 0),
    "usr/local/bin/mesh-healthcheck": ("binary", 0o755, 65532, 65532, None),
    "usr/local/bin/mesh-origin": ("binary", 0o755, 65532, 65532, None),
}
EXPECTED_ENV = {"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
EXPECTED_LABELS = {
    "org.opencontainers.image.description": "Explicit digest-verified public courier for threshold-authenticated Mesh releases",
    "org.opencontainers.image.title": "Mesh release origin",
}


def load_outer_file(archive: tarfile.TarFile, members: dict[str, tarfile.TarInfo], name: str) -> bytes:
    member = members.get(name)
    require(member is not None and member.isreg(), f"origin image archive is missing regular file {name}")
    source = archive.extractfile(member)
    require(source is not None, f"origin image archive cannot read {name}")
    return source.read()


def validate_image_config(config: dict[str, Any]) -> None:
    require(config.get("architecture") == "amd64", "origin image architecture is not amd64")
    require(config.get("os") == "linux", "origin image OS is not Linux")
    runtime = config.get("config")
    require(isinstance(runtime, dict), "origin image runtime config is missing")
    require(runtime.get("User") == "65532:65532", "origin image runtime user is not 65532:65532")
    require(runtime.get("Entrypoint") == ["/usr/local/bin/mesh-origin"], "origin image entrypoint is unexpected")
    require(runtime.get("WorkingDir") == "/", "origin image working directory is unexpected")
    require(runtime.get("Cmd") in (None, []), "origin image defines an unexpected command")
    require(runtime.get("Volumes") in (None, {}), "origin image defines an unexpected volume")
    require(set(runtime.get("Env", [])) == EXPECTED_ENV, "origin image environment is not the exact public allowlist")
    require(runtime.get("Labels") == EXPECTED_LABELS, "origin image labels are unexpected")
    require(runtime.get("ExposedPorts") == {"8444/tcp": {}}, "origin image exposed ports are unexpected")
    rootfs = config.get("rootfs")
    require(isinstance(rootfs, dict) and rootfs.get("type") == "layers", "origin image rootfs metadata is invalid")
    diff_ids = rootfs.get("diff_ids")
    require(isinstance(diff_ids, list) and len(diff_ids) == 3, "origin image must contain exactly three rootfs layers")
    require(all(EXPECTED_IMAGE_ID.fullmatch(item or "") for item in diff_ids), "origin image diff ID is invalid")


def prepare(args: argparse.Namespace) -> None:
    archive_path = pathlib.Path(args.archive)
    output_dir = pathlib.Path(args.output_dir)
    validate_regular_file(archive_path, max_bytes=MAX_ARCHIVE_BYTES)
    require(EXPECTED_IMAGE_ID.fullmatch(args.image_id) is not None, "Docker origin image ID is invalid")
    require(output_dir.is_dir() and not output_dir.is_symlink(), "origin prepare output directory is unsafe")
    require(not any(output_dir.iterdir()), "origin prepare output directory is not empty")
    binaries_dir = output_dir / "binaries"
    text_dir = output_dir / "rootfs-text"
    binaries_dir.mkdir(mode=0o700)
    text_dir.mkdir(mode=0o700)

    archive_digest = hash_file(archive_path)
    file_evidence: dict[str, dict[str, Any]] = {}
    seen_entries: set[str] = set()
    config_name = ""
    try:
        with tarfile.open(archive_path, "r:*") as outer:
            outer_list = outer.getmembers()
            require(len(outer_list) <= 64, "origin image archive contains too many outer entries")
            outer_members: dict[str, tarfile.TarInfo] = {}
            for member in outer_list:
                name = safe_tar_name(member.name)
                require(name not in outer_members, f"origin image archive repeats outer path {name}")
                require(member.isdir() or member.isreg(), f"origin image archive contains unsafe outer type at {name}")
                outer_members[name] = member
            require({"index.json", "manifest.json", "oci-layout"}.issubset(outer_members), "origin image archive metadata is incomplete")
            for name, member in outer_members.items():
                if member.isdir():
                    require(name in {"blobs", "blobs/sha256"}, f"origin image archive contains unexpected directory {name}")
                    continue
                if name in {"index.json", "manifest.json", "oci-layout"}:
                    continue
                require(re.fullmatch(r"blobs/sha256/[0-9a-f]{64}", name) is not None, f"origin image archive contains unexpected object {name}")
                payload = load_outer_file(outer, outer_members, name)
                require(hash_bytes(payload) == name.rsplit("/", 1)[1], f"origin image object digest mismatch at {name}")

            index = json.loads(load_outer_file(outer, outer_members, "index.json"))
            descriptors = index.get("manifests") if isinstance(index, dict) else None
            require(isinstance(descriptors, list) and descriptors, "origin image OCI index has no manifest")
            require(any(item.get("digest") == args.image_id for item in descriptors if isinstance(item, dict)), "Docker origin image ID is not bound by the saved OCI index")
            legacy_manifest = json.loads(load_outer_file(outer, outer_members, "manifest.json"))
            require(isinstance(legacy_manifest, list) and len(legacy_manifest) == 1, "origin archive must contain one saved image")
            saved = legacy_manifest[0]
            require(isinstance(saved, dict), "origin image save manifest is invalid")
            config_name = saved.get("Config")
            layers = saved.get("Layers")
            require(isinstance(config_name, str) and re.fullmatch(r"blobs/sha256/[0-9a-f]{64}", config_name), "origin image config reference is invalid")
            require(isinstance(layers, list) and len(layers) == 3 and len(set(layers)) == 3, "origin image must save exactly three unique layers")
            require(all(isinstance(item, str) and re.fullmatch(r"blobs/sha256/[0-9a-f]{64}", item) for item in layers), "origin image layer reference is invalid")
            config = json.loads(load_outer_file(outer, outer_members, config_name))
            require(isinstance(config, dict), "origin image config is not an object")
            validate_image_config(config)

            for layer_name in layers:
                layer_payload = load_outer_file(outer, outer_members, layer_name)
                require(len(layer_payload) <= MAX_LAYER_BYTES, "origin image layer exceeds its size bound")
                with tarfile.open(fileobj=io.BytesIO(layer_payload), mode="r:*") as layer:
                    members = layer.getmembers()
                    require(len(members) <= 64, "origin image layer contains too many filesystem entries")
                    for member in members:
                        name = safe_tar_name(member.name)
                        require(name not in seen_entries, f"origin image layer overwrites path {name}")
                        seen_entries.add(name)
                        expected = EXPECTED_LAYER_ENTRIES.get(name)
                        require(expected is not None, f"origin image contains unexpected filesystem path {name}")
                        kind, mode, uid, gid, size = expected
                        require(member.mode == mode and member.uid == uid and member.gid == gid, f"origin image metadata is invalid at {name}")
                        if kind == "dir":
                            require(member.isdir() and member.size == 0, f"origin image directory is invalid at {name}")
                            continue
                        require(member.isreg(), f"origin image path is not a regular file: {name}")
                        if size is not None:
                            require(member.size == size, f"origin image file has an invalid size at {name}")
                        source = layer.extractfile(member)
                        require(source is not None, f"origin image file cannot be read: {name}")
                        payload = source.read()
                        require(len(payload) == member.size, f"origin image file is truncated: {name}")
                        if kind == "binary":
                            require(1024 * 1024 <= len(payload) <= 32 * 1024 * 1024, f"origin image binary size is invalid at {name}")
                            exclusive_write(binaries_dir / pathlib.PurePosixPath(name).name, payload)
                        elif kind == "ca":
                            require(64 * 1024 <= len(payload) <= 1024 * 1024, "origin CA bundle size is invalid")
                            exclusive_write(text_dir / "ca-certificates.crt", payload)
                        else:
                            require(payload == b"", f"origin runtime placeholder is not empty at {name}")
                            exclusive_write(text_dir / pathlib.PurePosixPath(name).name, payload)
                        file_evidence[name] = {"sha256": hash_bytes(payload), "size": len(payload)}
    except (OSError, tarfile.TarError, json.JSONDecodeError) as exc:
        raise VerificationError(f"cannot validate origin image archive: {exc}") from exc

    require(seen_entries == set(EXPECTED_LAYER_ENTRIES), "origin image filesystem allowlist is incomplete")
    require(set(file_evidence).issuperset(EXPECTED_BINARY_PATHS), "origin image binary evidence is incomplete")
    metadata = {
        "schema": "mesh-origin-image-archive-evidence-v1",
        "docker_image_id": args.image_id,
        "archive": archive_digest,
        "config_digest": config_name.rsplit("/", 1)[1],
        "filesystem_entry_count": len(seen_entries),
        "files": dict(sorted(file_evidence.items())),
        "platform": "linux/amd64",
    }
    exclusive_write(output_dir / "image-metadata.json", canonical_json(metadata), mode=0o400)


def validate_syft(document: dict[str, Any], metadata: dict[str, Any]) -> tuple[set[str], int]:
    descriptor = document.get("descriptor")
    require(isinstance(descriptor, dict) and descriptor.get("name") == "syft" and descriptor.get("version") == "1.44.0", "origin SBOM descriptor is invalid")
    schema = document.get("schema")
    require(isinstance(schema, dict) and schema.get("version") == "16.1.3", "origin Syft schema is unexpected")
    source = document.get("source")
    require(isinstance(source, dict) and source.get("type") == "image", "origin SBOM source is not an image")
    source_metadata = source.get("metadata")
    require(isinstance(source_metadata, dict), "origin SBOM image metadata is missing")
    require(source_metadata.get("imageID") == f"sha256:{metadata['config_digest']}", "origin SBOM is not bound to the saved image config")
    require(source_metadata.get("manifestDigest") == f"sha256:{source.get('id')}", "origin SBOM manifest identity is inconsistent")
    require(source_metadata.get("userInput") == "/work/image.tar", "origin SBOM source path is unexpected")
    artifacts = document.get("artifacts")
    require(isinstance(artifacts, list) and len(artifacts) == 5, "origin SBOM must contain exactly five Go package records")
    allowed_locations = {f"/{item}" for item in EXPECTED_BINARY_PATHS}
    observed: set[tuple[str, str, str]] = set()
    purls: set[str] = set()
    for artifact in artifacts:
        require(isinstance(artifact, dict) and artifact.get("type") == "go-module", "origin SBOM contains a non-Go package")
        name = artifact.get("name")
        version = artifact.get("version")
        locations = artifact_locations(artifact)
        require(isinstance(name, str) and isinstance(version, str), "origin SBOM package identity is invalid")
        require(len(locations) == 1 and locations.issubset(allowed_locations), f"origin SBOM package has an unexpected location: {name}")
        location = next(iter(locations))
        observed.add((name, version, location))
        purl = artifact.get("purl")
        require(isinstance(purl, str) and purl.startswith("pkg:golang/"), f"origin SBOM package lacks a Go purl: {name}")
        purls.add(purl)
    expected = {
        ("mesh", "UNKNOWN", "/usr/local/bin/mesh-healthcheck"),
        ("mesh", "UNKNOWN", "/usr/local/bin/mesh-origin"),
        ("stdlib", "go1.26.5", "/usr/local/bin/mesh-healthcheck"),
        ("stdlib", "go1.26.5", "/usr/local/bin/mesh-origin"),
        ("golang.org/x/sys", "v0.46.0", "/usr/local/bin/mesh-origin"),
    }
    require(observed == expected, "origin SBOM package inventory differs from the exact allowlist")
    return purls, len(artifacts)


def finalize(args: argparse.Namespace) -> None:
    work_dir = pathlib.Path(args.work_dir)
    require(work_dir.is_dir() and not work_dir.is_symlink(), "origin verification workspace is unsafe")
    metadata = read_json(work_dir / "prepared" / "image-metadata.json", max_bytes=1024 * 1024)
    require(isinstance(metadata, dict) and metadata.get("schema") == "mesh-origin-image-archive-evidence-v1", "origin image metadata schema is invalid")
    syft_path = work_dir / "sbom.syft.json"
    spdx_path = work_dir / "sbom.spdx.json"
    grype_path = work_dir / "vulnerabilities.json"
    database_path = work_dir / "grype-db-status.json"
    rootfs_secrets_path = work_dir / "rootfs-secrets.json"
    binary_secrets_path = work_dir / "binary-secrets.json"
    syft = read_json(syft_path)
    spdx = read_json(spdx_path)
    grype = read_json(grype_path)
    database = read_json(database_path, max_bytes=1024 * 1024)
    require(all(isinstance(item, dict) for item in (syft, spdx, grype, database)), "origin scanner output is not an object")
    purls, syft_count = validate_syft(syft, metadata)
    spdx_count = validate_spdx(spdx, purls)
    require(spdx_count == 6, "origin SPDX document must contain exactly six packages")
    database_schema, database_built = validate_grype_db(database)
    vulnerability_summary = validate_grype(grype, purls)
    validate_empty_gitleaks(rootfs_secrets_path)
    validate_empty_gitleaks(binary_secrets_path)
    generated_at = dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")
    receipt = {
        "schema": "mesh-origin-image-security-receipt-v1",
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
            "database_status": hash_file(database_path),
            "policy": "reject High or Critical matches and every match with a published fix",
            "report": hash_file(grype_path),
            **vulnerability_summary,
        },
        "secret_scan": {
            "gitleaks_version": "v8.30.1",
            "policy": "default rules over exact origin rootfs text and both binaries' strings; only the exact public oauth2 v0.36.0 Go checksum is allowlisted",
            "rootfs_report": hash_file(rootfs_secrets_path),
            "binary_strings_report": hash_file(binary_secrets_path),
        },
        "scanner_boundary": {
            "image_archive_and_scan": "networkless, read-only, non-root, capability-free containers without a Docker socket",
            "database_update": "networked scanner with only an empty private database cache mounted",
        },
    }
    receipt_path = pathlib.Path(args.receipt)
    require(receipt_path.parent == work_dir, "origin receipt must be written inside the verification workspace")
    exclusive_write(receipt_path, canonical_json(receipt), mode=0o400)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="command", required=True)
    prepare_parser = commands.add_parser("prepare")
    prepare_parser.add_argument("--archive", required=True)
    prepare_parser.add_argument("--image-id", required=True)
    prepare_parser.add_argument("--output-dir", required=True)
    prepare_parser.set_defaults(function=prepare)
    finalize_parser = commands.add_parser("finalize")
    finalize_parser.add_argument("--work-dir", required=True)
    finalize_parser.add_argument("--receipt", required=True)
    finalize_parser.set_defaults(function=finalize)
    return result


def main() -> int:
    try:
        args = parser().parse_args()
        args.function(args)
    except VerificationError as exc:
        print(f"origin image security verification: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
