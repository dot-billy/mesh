#!/usr/bin/env python3
"""Validate and bind one exact final signed Mesh Windows bundle security scan."""

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
    validate_regular_file,
    validate_spdx,
)


DIGEST = re.compile(r"^[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
MESHCTL = "/bin/meshctl.exe"
NEBULA = "/bin/nebula.exe"
NEBULA_CERT = "/bin/nebula-cert.exe"
GO_BINARIES = {MESHCTL, NEBULA, NEBULA_CERT}

UPSTREAM = {
    "amd64": {
        "version": "v1.10.3", "lock_sha256": "9f0515702d74a0911263a160754948220e41b5da7048f48adf67355b3816dd7c",
        "asset_id": 351844826, "asset_name": "nebula-windows-amd64.zip", "archive_size": 16342405,
        "archive_sha256": "7e8f26eef9394c842d4eb73610e3e63b965a93b803e366eb42c9b548bd1a70b8",
    },
    "arm64": {
        "version": "v1.10.3", "lock_sha256": "9f0515702d74a0911263a160754948220e41b5da7048f48adf67355b3816dd7c",
        "asset_id": 351844824, "asset_name": "nebula-windows-arm64.zip", "archive_size": 14936616,
        "archive_sha256": "c8e3c50c54708fed2e519dce7d455b639e5a9c2d124933b1a74aa3c2ba9632ae",
    },
}
RUNTIME = {
    "version": "v1.10.3",
    "commit": "f573e8a26695278f9d71587390fbfe0d0933aa21",
    "upstream_lock_sha256": "9f0515702d74a0911263a160754948220e41b5da7048f48adf67355b3816dd7c",
    "source_build_lock_sha256": "18935f949438c52803309d0b78730531a7947717bdd6e5f37b0c88ff0cb458d9",
    "windows_build_lock_sha256": "abf5790a7c94847dd5d5bb0898fb2b72081e121e32b90e05d333309d33ea212d",
    "source_tree_sha256": "1d1aefeda0b2d9708dfb9bd39d25393351bace2b5e1a91a2021315fe8b410478",
    "patched_tree_sha256": "c35f432bd15d40346b12ec19a33b7a9e6844514f228b4dc5e3853f9033b2f5c6",
    "patch_set_sha256": "5e8a928b2c5c9cc95666642881a853b557b5b1fa8972acdee9c1c74641fcfb5e",
    "go_version": "go1.26.5",
}

PACKAGE_LOCATIONS = {
    ("dario.cat/mergo", "v1.0.2"): {NEBULA},
    ("filippo.io/bigmod", "v0.1.0"): GO_BINARIES,
    ("github.com/anmitsu/go-shlex", "v0.0.0-20200514113438-38f4b401e2be"): {NEBULA},
    ("github.com/armon/go-radix", "v1.0.0"): {NEBULA},
    ("github.com/beorn7/perks", "v1.0.1"): {NEBULA},
    ("github.com/cespare/xxhash/v2", "v2.3.0"): {NEBULA},
    ("github.com/cyberdelia/go-metrics-graphite", "v0.0.0-20161219230853-39f87cc3b432"): {NEBULA},
    ("github.com/flynn/noise", "v1.1.0"): {NEBULA},
    ("github.com/gaissmai/bart", "v0.26.0"): {NEBULA},
    ("github.com/gogo/protobuf", "v1.3.2"): {NEBULA},
    ("github.com/google/gopacket", "v1.1.19"): {NEBULA},
    ("github.com/jackc/pgpassfile", "v1.0.0"): {MESHCTL},
    ("github.com/jackc/pgservicefile", "v0.0.0-20240606120523-5a60cdf6a761"): {MESHCTL},
    ("github.com/jackc/pgx/v5", "v5.10.0"): {MESHCTL},
    ("github.com/jackc/puddle/v2", "v2.2.2"): {MESHCTL},
    ("github.com/miekg/dns", "v1.1.70"): {MESHCTL, NEBULA},
    ("github.com/munnerz/goautoneg", "v0.0.0-20191010083416-a7dc8b61c822"): {NEBULA},
    ("github.com/nbrownus/go-metrics-prometheus", "v0.0.0-20210712211119-974a6260965f"): {NEBULA},
    ("github.com/prometheus/client_golang", "v1.23.2"): {NEBULA},
    ("github.com/prometheus/client_model", "v0.6.2"): {NEBULA},
    ("github.com/prometheus/common", "v0.66.1"): {NEBULA},
    ("github.com/rcrowley/go-metrics", "v0.0.0-20201227073835-cf1acfcdf475"): {NEBULA},
    ("github.com/sirupsen/logrus", "v1.9.4"): {NEBULA},
    ("github.com/skip2/go-qrcode", "v0.0.0-20200617195104-da1b6568686e"): {NEBULA_CERT},
    ("github.com/slackhq/nebula", "UNKNOWN"): {NEBULA, NEBULA_CERT},
    ("github.com/slackhq/nebula", "v1.10.3"): {MESHCTL},
    ("github.com/stefanberger/go-pkcs11uri", "v0.0.0-20230803200340-78284954bff6"): {NEBULA, NEBULA_CERT},
    ("go.yaml.in/yaml/v2", "v2.4.2"): {NEBULA},
    ("go.yaml.in/yaml/v3", "v3.0.4"): {NEBULA},
    ("golang.org/x/crypto", "v0.53.0"): {MESHCTL, NEBULA, NEBULA_CERT},
    ("golang.org/x/net", "v0.56.0"): {NEBULA},
    ("golang.org/x/sync", "v0.21.0"): {MESHCTL},
    ("golang.org/x/sys", "v0.46.0"): {MESHCTL, NEBULA, NEBULA_CERT},
    ("golang.org/x/term", "v0.44.0"): {NEBULA, NEBULA_CERT},
    ("golang.org/x/text", "v0.39.0"): {MESHCTL},
    ("golang.zx2c4.com/wintun", "v0.0.0-20230126152724-0fa3db229ce2"): {NEBULA},
    ("golang.zx2c4.com/wireguard", "v0.0.0-20230325221338-052af4a8072b"): {NEBULA},
    ("golang.zx2c4.com/wireguard/windows", "v0.5.3"): {NEBULA},
    ("google.golang.org/protobuf", "v1.36.11"): GO_BINARIES,
    ("mesh", "UNKNOWN"): {MESHCTL},
    ("stdlib", "go1.26.5"): GO_BINARIES,
}


def exact_keys(document: dict[str, Any], expected: set[str], label: str) -> None:
    require(set(document) == expected, f"{label} fields differ from the exact schema")


def hash_record(path: pathlib.Path, maximum: int) -> dict[str, Any]:
    info = validate_regular_file(path, max_bytes=maximum)
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return {"sha256": digest.hexdigest(), "size": info.st_size}


def canonical_time(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None and parsed.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z") == value


def payload_modes(arch: str) -> dict[str, int]:
    return {
        "bin/dist/windows/wintun/LICENSE.txt": 0o444,
        "bin/dist/windows/wintun/README.md": 0o444,
        f"bin/dist/windows/wintun/bin/{arch}/wintun.dll": 0o444,
        "bin/meshctl.exe": 0o555,
        "bin/nebula-cert.exe": 0o555,
        "bin/nebula.exe": 0o555,
        "share/licenses/nebula/LICENSE": 0o444,
    }


def directory_paths(arch: str) -> set[str]:
    return {
        "bin", "bin/dist", "bin/dist/windows", "bin/dist/windows/wintun", "bin/dist/windows/wintun/bin",
        f"bin/dist/windows/wintun/bin/{arch}", "share", "share/licenses", "share/licenses/nebula",
    }


def validate_inspection(document: dict[str, Any], staged: pathlib.Path, artifact: pathlib.Path) -> dict[str, Any]:
    exact_keys(document, {"schema", "artifact_sha256", "artifact_size", "package_json_sha256", "file_count", "directory_count", "total_bytes", "package"}, "candidate inspection")
    require(document["schema"] == "mesh-windows-security-candidate-inspection-v1", "candidate inspection schema is invalid")
    artifact_record = hash_record(artifact, 272 * 1024 * 1024)
    require(document["artifact_sha256"] == artifact_record["sha256"] and document["artifact_size"] == artifact_record["size"], "candidate inspection is not bound to the exact artifact")
    package = document.get("package")
    require(isinstance(package, dict), "candidate package metadata is missing")
    exact_keys(package, {"schema", "version", "commit", "build_time", "security_floor", "agent_state_read_min", "agent_state_read_max", "agent_state_write_version", "go_version", "target", "nebula", "runtime", "entries"}, "candidate package")
    require(package["schema"] == "mesh-windows-node-bundle-v3", "only final signed Windows bundle schema v3 is accepted")
    require(isinstance(package["version"], str) and 0 < len(package["version"]) <= 128, "candidate version is invalid")
    require(isinstance(package["commit"], str) and COMMIT.fullmatch(package["commit"]), "candidate commit is invalid")
    require(canonical_time(package["build_time"]), "candidate build time is not canonical UTC")
    require(isinstance(package["security_floor"], int) and package["security_floor"] > 0, "candidate security floor is invalid")
    require((package["agent_state_read_min"], package["agent_state_read_max"], package["agent_state_write_version"]) == (2, 2, 2), "candidate agent-state contract is unexpected")
    require(package["go_version"] == "go1.26.5", "candidate Mesh executable does not require Go 1.26.5")
    target = package.get("target")
    require(isinstance(target, dict) and set(target) == {"os", "arch"} and target.get("os") == "windows" and target.get("arch") in {"amd64", "arm64"}, "candidate target is invalid")
    arch = target["arch"]
    require(package.get("nebula") == UPSTREAM[arch], "candidate Wintun/upstream provenance differs from the exact lock")
    require(package.get("runtime") == RUNTIME, "candidate Windows runtime provenance differs from the exact security-patched lock")
    modes = payload_modes(arch)
    entries = package.get("entries")
    require(isinstance(entries, list) and len(entries) == len(modes), "candidate payload inventory is incomplete")
    observed_entries: dict[str, dict[str, Any]] = {}
    for entry in entries:
        require(isinstance(entry, dict) and set(entry) == {"path", "archive_mode", "size", "sha256"}, "candidate payload entry schema is invalid")
        name = entry.get("path")
        require(isinstance(name, str) and name not in observed_entries and modes.get(name) == entry.get("archive_mode"), "candidate payload path or mode is invalid")
        require(isinstance(entry.get("size"), int) and 0 < entry["size"] <= 128 * 1024 * 1024, f"candidate payload size is invalid: {name}")
        require(isinstance(entry.get("sha256"), str) and DIGEST.fullmatch(entry["sha256"]), f"candidate payload digest is invalid: {name}")
        observed_entries[name] = entry
    require(list(observed_entries) == sorted(modes), "candidate payload entries are not in exact path order")
    directories = directory_paths(arch)
    require(staged.is_dir() and not staged.is_symlink() and stat.S_IMODE(staged.stat().st_mode) == 0o555, "staged candidate root is invalid")
    observed_paths: set[str] = set()
    for root, child_directories, files in os.walk(staged, topdown=True, followlinks=False):
        relative_root = pathlib.Path(root).relative_to(staged)
        for name in child_directories + files:
            relative = (relative_root / name).as_posix()
            observed_paths.add(relative)
            info = (staged / relative).lstat()
            require(not stat.S_ISLNK(info.st_mode), f"staged candidate contains a link: {relative}")
            if name in child_directories:
                require(relative in directories and stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o555, f"staged candidate directory is invalid: {relative}")
            else:
                expected_mode = 0o444 if relative == "package.json" else modes.get(relative)
                require(expected_mode is not None and stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == expected_mode and info.st_nlink == 1, f"staged candidate file is invalid: {relative}")
    require(observed_paths == directories | set(modes) | {"package.json"}, "staged candidate exact path set is invalid")
    package_path = staged / "package.json"
    require(hash_file(package_path)["sha256"] == document["package_json_sha256"], "staged package.json differs from candidate inspection")
    require(json.loads(package_path.read_bytes()) == package, "staged package.json metadata differs from candidate inspection")
    files: dict[str, dict[str, Any]] = {"package.json": hash_file(package_path)}
    total = files["package.json"]["size"]
    for name, entry in observed_entries.items():
        record = hash_file(staged / name)
        require(record == {"sha256": entry["sha256"], "size": entry["size"]}, f"staged candidate payload differs from package metadata: {name}")
        files[name] = record
        total += record["size"]
    require(document["file_count"] == 8 and document["directory_count"] == 9 and document["total_bytes"] == total, "candidate inspection counts are inconsistent")
    return {"artifact": artifact_record, "files": dict(sorted(files.items())), "package": package}


def expected_artifacts(arch: str) -> set[tuple[str, str, str, str]]:
    result = {(name, version, "go-module", location) for (name, version), locations in PACKAGE_LOCATIONS.items() for location in locations}
    result |= {
        ("Wintun Driver", "0.14.1", "binary", f"/bin/dist/windows/wintun/bin/{arch}/wintun.dll"),
        ("meshctl", "UNKNOWN", "binary", MESHCTL),
        ("nebula", "UNKNOWN", "binary", NEBULA),
        ("nebula-cert", "UNKNOWN", "binary", NEBULA_CERT),
    }
    return result


def validate_syft(document: dict[str, Any], arch: str) -> tuple[set[str], int]:
    descriptor = document.get("descriptor")
    require(isinstance(descriptor, dict) and descriptor.get("name") == "syft" and descriptor.get("version") == "1.44.0", "Windows package SBOM descriptor is invalid")
    schema = document.get("schema")
    require(isinstance(schema, dict) and schema.get("version") == "16.1.3", "Windows package Syft schema is unexpected")
    source = document.get("source")
    require(isinstance(source, dict) and source.get("type") == "directory", "Windows package SBOM source is not the staged directory")
    artifacts = document.get("artifacts")
    expected = expected_artifacts(arch)
    require(isinstance(artifacts, list) and len(artifacts) == len(expected) == 59, "Windows package SBOM must contain exactly 59 admitted package locations")
    observed: set[tuple[str, str, str, str]] = set()
    purls: set[str] = set()
    for artifact in artifacts:
        require(isinstance(artifact, dict), "Windows package SBOM artifact is invalid")
        name, version, kind = artifact.get("name"), artifact.get("version"), artifact.get("type")
        locations = artifact_locations(artifact)
        require(isinstance(name, str) and isinstance(version, str) and isinstance(kind, str) and len(locations) == 1, "Windows package SBOM identity or location is invalid")
        location = next(iter(locations))
        observed.add((name, version, kind, location))
        purl = artifact.get("purl")
        if kind == "go-module":
            require(isinstance(purl, str) and purl.startswith("pkg:golang/"), f"Windows package SBOM lacks a Go purl: {name}")
            purls.add(purl)
        else:
            require(kind == "binary" and not purl, f"Windows package binary has an unexpected purl: {name}")
    require(observed == expected, "Windows package SBOM inventory differs from the exact allowlist")
    return purls, len(artifacts)


def finalize(args: argparse.Namespace) -> None:
    work = pathlib.Path(args.work_dir)
    require(work.is_dir() and not work.is_symlink(), "Windows package verification workspace is unsafe")
    staged, artifact = work / "staged", work / "bundle.tar"
    validate_regular_file(artifact, max_bytes=272 * 1024 * 1024)
    inspection_path = work / "candidate-inspection.json"
    inspection = read_json(inspection_path, max_bytes=1024 * 1024)
    require(isinstance(inspection, dict), "candidate inspection is not an object")
    candidate = validate_inspection(inspection, staged, artifact)
    arch = candidate["package"]["target"]["arch"]
    syft_path, spdx_path = work / "sbom.syft.json", work / "sbom.spdx.json"
    grype_path, database_path = work / "vulnerabilities.json", work / "grype-db-status.json"
    text_secrets_path, binary_secrets_path = work / "text-secrets.json", work / "binary-secrets.json"
    syft, spdx, grype, database = (read_json(path) for path in (syft_path, spdx_path, grype_path, database_path))
    require(all(isinstance(item, dict) for item in (syft, spdx, grype, database)), "Windows package scanner output is not an object")
    purls, syft_count = validate_syft(syft, arch)
    spdx_count = validate_spdx(spdx, purls)
    require(spdx_count == 60, "Windows package SPDX inventory must contain exactly 60 packages")
    database_schema, database_built = validate_grype_db(database)
    vulnerability_summary = validate_grype(grype, purls)
    validate_empty_gitleaks(text_secrets_path)
    validate_empty_gitleaks(binary_secrets_path)
    receipt = {
        "artifact": candidate["artifact"],
        "candidate": {
            "architecture": arch, "build_time": candidate["package"]["build_time"],
            "commit": candidate["package"]["commit"], "directory_count": inspection["directory_count"],
            "file_count": inspection["file_count"], "files": candidate["files"],
            "go_version": candidate["package"]["go_version"], "inspection": hash_file(inspection_path),
            "package_json_sha256": inspection["package_json_sha256"], "runtime": candidate["package"]["runtime"],
            "schema": candidate["package"]["schema"], "security_floor": candidate["package"]["security_floor"],
            "total_bytes": inspection["total_bytes"], "upstream": candidate["package"]["nebula"],
            "verifier": hash_file(pathlib.Path(args.verifier)), "version": candidate["package"]["version"],
        },
        "sbom": {
            "spdx_json": hash_file(spdx_path), "spdx_package_count": spdx_count, "spdx_version": "SPDX-2.3",
            "syft_json": hash_file(syft_path), "syft_package_count": syft_count, "syft_schema": "16.1.3", "syft_version": "1.44.0",
        },
        "scanner_boundary": {
            "artifact_and_scan": "stable candidate, networkless read-only non-root scanners, no Docker socket",
            "database_update": "networked scanner with only an empty private database cache mounted",
        },
        "schema": "mesh-windows-package-security-receipt-v2",
        "secret_scan": {
            "binary_strings_report": hash_file(binary_secrets_path), "gitleaks_version": "v8.30.1",
            "policy": "default rules over exact package metadata, Wintun notices, license, and all four PEs' strings; only the exact public oauth2 v0.36.0 Go checksum is allowlisted",
            "text_report": hash_file(text_secrets_path),
        },
        "verified_at": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
        "vulnerability_scan": {
            "database_built": database_built, "database_schema": database_schema,
            "database_status": hash_file(database_path), "grype_version": "0.112.0",
            "policy": "reject High or Critical matches and every match with a published fix",
            "report": hash_file(grype_path), **vulnerability_summary,
        },
    }
    receipt_path = pathlib.Path(args.receipt)
    require(receipt_path.parent == work, "Windows package receipt must be written inside the verification workspace")
    exclusive_write(receipt_path, canonical_json(receipt), mode=0o400)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--work-dir", required=True)
    result.add_argument("--verifier", required=True)
    result.add_argument("--receipt", required=True)
    return result


def main() -> int:
    try:
        finalize(parser().parse_args())
    except VerificationError as exc:
        print(f"Windows package security verification: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
