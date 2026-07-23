#!/usr/bin/env python3
"""Validate and bind security evidence for locked Nebula observer artifacts."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import pathlib
import re
import stat
import sys
from typing import Any

from image_security_verify import (
    VerificationError,
    artifact_locations,
    canonical_json,
    exclusive_write,
    hash_file,
    read_json,
    require,
    validate_empty_gitleaks,
    validate_grype,
    validate_grype_db,
    validate_spdx,
)


ARCHITECTURES = ("amd64", "arm64")
EXPECTED_TOOLCHAIN = "go1.26.5"
EXPECTED_SYFT_COUNT = 41
EXPECTED_SECURITY_PACKAGES = {
    "golang.org/x/crypto": ("v0.53.0", {"/nebula", "/nebula-cert"}),
    "golang.org/x/net": ("v0.56.0", {"/nebula"}),
    "golang.org/x/sys": ("v0.46.0", {"/nebula", "/nebula-cert"}),
    "golang.org/x/term": ("v0.44.0", {"/nebula", "/nebula-cert"}),
}
HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def read_bytes(path: pathlib.Path, maximum: int) -> bytes:
    try:
        info = path.lstat()
    except OSError as exc:
        raise VerificationError(f"required artifact is unavailable: {path}") from exc
    require(stat.S_ISREG(info.st_mode), f"artifact is not a regular file: {path}")
    require(0 < info.st_size <= maximum, f"artifact size is invalid: {path}")
    try:
        payload = path.read_bytes()
    except OSError as exc:
        raise VerificationError(f"cannot read artifact: {path}") from exc
    require(len(payload) == info.st_size, f"artifact changed while reading: {path}")
    return payload


def validate_lock(path: pathlib.Path) -> tuple[dict[str, Any], str]:
    raw = read_bytes(path, 256 * 1024)
    lock = read_json(path, max_bytes=256 * 1024)
    require(isinstance(lock, dict), "observer build lock is not an object")
    pretty = (json.dumps(lock, indent=2, ensure_ascii=False) + "\n").encode()
    require(raw == pretty, "observer build lock is not canonically encoded")
    require(lock.get("schema") == "mesh.nebula-observer-build-lock.v1", "observer build-lock schema is invalid")
    require(lock.get("module") == "github.com/slackhq/nebula", "observer module identity is invalid")
    require(lock.get("version") == "v1.10.3", "observer version is invalid")
    require(lock.get("toolchain") == EXPECTED_TOOLCHAIN, "observer toolchain is not Go 1.26.5")
    dependencies = lock.get("security_dependencies")
    require(isinstance(dependencies, list), "observer security dependency lock is missing")
    actual = {
        item.get("path"): (item.get("version"), item.get("sum"))
        for item in dependencies
        if isinstance(item, dict)
    }
    require(set(actual) == set(EXPECTED_SECURITY_PACKAGES), "observer security dependency set is invalid")
    for path_name, (version, _) in EXPECTED_SECURITY_PACKAGES.items():
        locked = actual[path_name]
        require(locked[0] == version, f"observer dependency {path_name} has an unexpected version")
        require(isinstance(locked[1], str) and locked[1].startswith("h1:"), f"observer dependency {path_name} lacks a module checksum")
    return lock, hashlib.sha256(raw).hexdigest()


def validate_stage(work_dir: pathlib.Path, arch: str, lock: dict[str, Any], policy_digest: str) -> dict[str, Any]:
    stage = work_dir / f"stage-{arch}"
    try:
        stage_info = stage.lstat()
    except OSError as exc:
        raise VerificationError(f"observer stage is unavailable for linux/{arch}") from exc
    require(stat.S_ISDIR(stage_info.st_mode) and not stage.is_symlink(), f"observer stage is unsafe for linux/{arch}")
    require(stat.S_IMODE(stage_info.st_mode) == 0o555, f"observer stage mode is invalid for linux/{arch}")
    require(sorted(item.name for item in stage.iterdir()) == ["nebula", "nebula-cert", "observer-build.json"], f"observer stage contents are invalid for linux/{arch}")

    targets = lock.get("targets")
    require(isinstance(targets, list), "observer targets are missing")
    target = next((item for item in targets if isinstance(item, dict) and item.get("os") == "linux" and item.get("arch") == arch), None)
    require(isinstance(target, dict), f"observer lock lacks linux/{arch}")
    entries = target.get("entries")
    require(isinstance(entries, list) and len(entries) == 2, f"observer lock entries are invalid for linux/{arch}")

    manifest_path = stage / "observer-build.json"
    manifest_raw = read_bytes(manifest_path, 64 * 1024)
    require(stat.S_IMODE(manifest_path.lstat().st_mode) == 0o444, f"observer manifest mode is invalid for linux/{arch}")
    manifest = read_json(manifest_path, max_bytes=64 * 1024)
    require(manifest_raw == (json.dumps(manifest, separators=(",", ":")) + "\n").encode(), f"observer manifest is not canonical for linux/{arch}")
    require(
        manifest == {
            "schema": "mesh.nebula-observer-stage.v1",
            "policy_sha256": policy_digest,
            "target": {"os": "linux", "arch": arch},
            "go_version": EXPECTED_TOOLCHAIN,
            "entries": entries,
        },
        f"observer manifest differs from the lock for linux/{arch}",
    )

    files: dict[str, Any] = {}
    for entry in entries:
        require(isinstance(entry, dict), f"observer entry is invalid for linux/{arch}")
        name = entry.get("name")
        require(name in {"nebula", "nebula-cert"}, f"observer entry name is invalid for linux/{arch}")
        path = stage / name
        payload = read_bytes(path, 96 * 1024 * 1024)
        require(stat.S_IMODE(path.lstat().st_mode) == 0o555, f"observer executable mode is invalid: linux/{arch}/{name}")
        digest = hashlib.sha256(payload).hexdigest()
        require(len(payload) == entry.get("size") and digest == entry.get("sha256"), f"observer executable differs from the lock: linux/{arch}/{name}")
        files[name] = {"sha256": digest, "size": len(payload)}
    return {
        "platform": f"linux/{arch}",
        "manifest": hash_file(manifest_path),
        "files": files,
    }


def validate_syft(document: dict[str, Any], arch: str) -> tuple[set[str], int]:
    descriptor = document.get("descriptor")
    require(isinstance(descriptor, dict) and descriptor.get("name") == "syft" and descriptor.get("version") == "1.44.0", f"Syft identity is invalid for linux/{arch}")
    schema = document.get("schema")
    require(isinstance(schema, dict) and schema.get("version") == "16.1.3", f"Syft schema is invalid for linux/{arch}")
    source = document.get("source")
    require(isinstance(source, dict) and source.get("type") == "directory" and source.get("name") == "/scan", f"Syft source is invalid for linux/{arch}")
    require(isinstance(source.get("id"), str) and HEX_SHA256.fullmatch(source["id"]), f"Syft source ID is invalid for linux/{arch}")
    artifacts = document.get("artifacts")
    require(isinstance(artifacts, list) and len(artifacts) == EXPECTED_SYFT_COUNT, f"Syft package count is invalid for linux/{arch}")
    observed: set[tuple[str, str, str]] = set()
    purls: set[str] = set()
    for artifact in artifacts:
        require(isinstance(artifact, dict) and artifact.get("type") == "go-module", f"Syft contains a non-Go package for linux/{arch}")
        name = artifact.get("name")
        version = artifact.get("version")
        locations = artifact_locations(artifact)
        require(isinstance(name, str) and isinstance(version, str), f"Syft package identity is invalid for linux/{arch}")
        require(len(locations) == 1 and locations.issubset({"/nebula", "/nebula-cert"}), f"Syft package location is invalid for linux/{arch}: {name}")
        location = next(iter(locations))
        observed.add((name, version, location))
        purl = artifact.get("purl")
        require(isinstance(purl, str) and purl.startswith("pkg:golang/"), f"Syft package lacks a Go purl for linux/{arch}: {name}")
        purls.add(purl)
    for location in ("/nebula", "/nebula-cert"):
        require(("stdlib", EXPECTED_TOOLCHAIN, location) in observed, f"Syft does not prove Go 1.26.5 for linux/{arch}{location}")
        require(("github.com/slackhq/nebula", "UNKNOWN", location) in observed, f"Syft does not identify Nebula for linux/{arch}{location}")
    for name, (version, locations) in EXPECTED_SECURITY_PACKAGES.items():
        for location in locations:
            require((name, version, location) in observed, f"Syft does not prove {name} {version} for linux/{arch}{location}")
        require(not any(item_name == name and item_version != version for item_name, item_version, _ in observed), f"Syft contains an unexpected {name} version for linux/{arch}")
    require(not any(name == "stdlib" and version != EXPECTED_TOOLCHAIN for name, version, _ in observed), f"Syft contains an unexpected Go toolchain for linux/{arch}")
    return purls, len(artifacts)


def validate_source_scan(path: pathlib.Path) -> dict[str, Any]:
    raw = read_bytes(path, 1024 * 1024)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise VerificationError("govulncheck output is not UTF-8") from exc
    require("No vulnerabilities found." in text, "observer source scan did not report zero vulnerabilities")
    require("affected by 0 vulnerabilities" in text, "observer source scan result is ambiguous")
    require("Vulnerability #" not in text, "observer source scan contains a reachable vulnerability")
    return hash_file(path)


def finalize(args: argparse.Namespace) -> None:
    work_dir = pathlib.Path(args.work_dir)
    require(work_dir.is_dir() and not work_dir.is_symlink(), "observer verification workspace is unsafe")
    lock, policy_digest = validate_lock(pathlib.Path(args.lock))
    stages = {arch: validate_stage(work_dir, arch, lock, policy_digest) for arch in ARCHITECTURES}
    database_path = work_dir / "grype-db-status.json"
    database = read_json(database_path, max_bytes=1024 * 1024)
    require(isinstance(database, dict), "Grype database status is invalid")
    database_schema, database_built = validate_grype_db(database)

    sboms: dict[str, Any] = {}
    vulnerabilities: dict[str, Any] = {}
    for arch in ARCHITECTURES:
        syft_path = work_dir / f"linux-{arch}.syft.json"
        spdx_path = work_dir / f"linux-{arch}.spdx.json"
        grype_path = work_dir / f"linux-{arch}.vulnerabilities.json"
        syft = read_json(syft_path)
        spdx = read_json(spdx_path)
        grype = read_json(grype_path)
        require(all(isinstance(item, dict) for item in (syft, spdx, grype)), f"scanner output is invalid for linux/{arch}")
        purls, syft_count = validate_syft(syft, arch)
        spdx_count = validate_spdx(spdx, purls)
        require(spdx_count == EXPECTED_SYFT_COUNT + 1, f"SPDX package count is invalid for linux/{arch}")
        vulnerability_summary = validate_grype(grype, purls)
        sboms[arch] = {
            "syft_package_count": syft_count,
            "syft_json": hash_file(syft_path),
            "spdx_package_count": spdx_count,
            "spdx_json": hash_file(spdx_path),
        }
        vulnerabilities[arch] = {"report": hash_file(grype_path), **vulnerability_summary}

    secrets_path = work_dir / "binary-secrets.json"
    validate_empty_gitleaks(secrets_path)
    source_scan_path = work_dir / "source-vulnerabilities.txt"
    source_scan = validate_source_scan(source_scan_path)
    generated_at = dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")
    receipt = {
        "schema": "mesh-observer-security-receipt-v1",
        "verified_at": generated_at,
        "policy": {
            "sha256": policy_digest,
            "module": lock["module"],
            "version": lock["version"],
            "commit": lock["commit"],
            "toolchain": lock["toolchain"],
            "patched_tree_sha256": lock["patched_tree_sha256"],
            "patch_set_sha256": lock["patch_set_sha256"],
            "security_dependencies": lock["security_dependencies"],
        },
        "artifacts": stages,
        "source_vulnerability_scan": {
            "govulncheck_version": "v1.6.0",
            "policy": "reject every reachable vulnerability in the patched Nebula and nebula-cert command graphs",
            "report": source_scan,
        },
        "sbom": {
            "syft_version": "1.44.0",
            "syft_schema": "16.1.3",
            "spdx_version": "SPDX-2.3",
            "architectures": sboms,
        },
        "vulnerability_scan": {
            "grype_version": "0.112.0",
            "database_schema": database_schema,
            "database_built": database_built,
            "database_status": hash_file(database_path),
            "policy": "reject High or Critical matches and every match with a published fix",
            "architectures": vulnerabilities,
        },
        "secret_scan": {
            "gitleaks_version": "v8.30.1",
            "policy": "default rules over strings extracted from all four locked executables; only the exact public oauth2 v0.36.0 Go checksum is allowlisted",
            "binary_strings_report": hash_file(secrets_path),
        },
        "scanner_boundary": {
            "artifact_and_sbom_scans": "networkless, read-only, non-root, capability-free containers without a Docker socket",
            "database_update": "networked scanner with only an empty private database cache mounted",
        },
    }
    receipt_path = pathlib.Path(args.receipt)
    require(receipt_path.parent == work_dir, "receipt must be written inside the observer verification workspace")
    exclusive_write(receipt_path, canonical_json(receipt), mode=0o400)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--work-dir", required=True)
    result.add_argument("--lock", required=True)
    result.add_argument("--receipt", required=True)
    return result


def main() -> int:
    try:
        finalize(parser().parse_args())
    except VerificationError as exc:
        print(f"observer security verification: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
