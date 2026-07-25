#!/usr/bin/env python3
"""Validate and bind one exact Mesh Linux node-bundle security scan."""

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
EXPECTED_NEBULA = {
    "version": "v1.10.3",
    "upstream_commit": "f573e8a26695278f9d71587390fbfe0d0933aa21",
    "upstream_lock_sha256": "9f0515702d74a0911263a160754948220e41b5da7048f48adf67355b3816dd7c",
    "observer_lock_sha256": "18935f949438c52803309d0b78730531a7947717bdd6e5f37b0c88ff0cb458d9",
    "source_tree_sha256": "1d1aefeda0b2d9708dfb9bd39d25393351bace2b5e1a91a2021315fe8b410478",
    "patched_tree_sha256": "c35f432bd15d40346b12ec19a33b7a9e6844514f228b4dc5e3853f9033b2f5c6",
    "patch_set_sha256": "5e8a928b2c5c9cc95666642881a853b557b5b1fa8972acdee9c1c74641fcfb5e",
    "go_version": "go1.26.5",
}
PAYLOAD_MODES = {
    "bin/mesh-install": 0o555,
    "bin/meshctl": 0o555,
    "bin/nebula": 0o555,
    "bin/nebula-cert": 0o555,
    "lib/systemd/system/mesh-agent.service": 0o444,
    "lib/systemd/system/mesh-agent.service.d/10-timeout-abort.conf": 0o444,
    "lib/systemd/system/mesh-nebula.service": 0o444,
    "lib/systemd/system/mesh-nebula.service.d/10-timeout-abort.conf": 0o444,
    "share/doc/mesh/systemd/README.md": 0o444,
    "share/licenses/nebula/LICENSE": 0o444,
}
DIRECTORIES = {
    "bin",
    "lib",
    "lib/systemd",
    "lib/systemd/system",
    "lib/systemd/system/mesh-agent.service.d",
    "lib/systemd/system/mesh-nebula.service.d",
    "share",
    "share/doc",
    "share/doc/mesh",
    "share/doc/mesh/systemd",
    "share/licenses",
    "share/licenses/nebula",
}
BINARY_LOCATIONS = {f"/{name}" for name in PAYLOAD_MODES if name.startswith("bin/")}

# Exact package/version locations admitted by the current meshctl and locked
# observer binaries. Each tuple is expanded to one Syft artifact per location.
PACKAGE_LOCATIONS = {
    ("dario.cat/mergo", "v1.0.2"): {"/bin/nebula"},
    ("filippo.io/bigmod", "v0.1.0"): {"/bin/meshctl", "/bin/nebula", "/bin/nebula-cert"},
    ("github.com/anmitsu/go-shlex", "v0.0.0-20200514113438-38f4b401e2be"): {"/bin/nebula"},
    ("github.com/armon/go-radix", "v1.0.0"): {"/bin/nebula"},
    ("github.com/beorn7/perks", "v1.0.1"): {"/bin/nebula"},
    ("github.com/cespare/xxhash/v2", "v2.3.0"): {"/bin/nebula"},
    ("github.com/cyberdelia/go-metrics-graphite", "v0.0.0-20161219230853-39f87cc3b432"): {"/bin/nebula"},
    ("github.com/flynn/noise", "v1.1.0"): {"/bin/nebula"},
    ("github.com/gaissmai/bart", "v0.26.0"): {"/bin/nebula"},
    ("github.com/gogo/protobuf", "v1.3.2"): {"/bin/nebula"},
    ("github.com/google/gopacket", "v1.1.19"): {"/bin/nebula"},
    ("github.com/jackc/pgpassfile", "v1.0.0"): {"/bin/meshctl"},
    ("github.com/jackc/pgservicefile", "v0.0.0-20240606120523-5a60cdf6a761"): {"/bin/meshctl"},
    ("github.com/jackc/pgx/v5", "v5.10.0"): {"/bin/meshctl"},
    ("github.com/jackc/puddle/v2", "v2.2.2"): {"/bin/meshctl"},
    ("github.com/miekg/dns", "v1.1.70"): {"/bin/meshctl", "/bin/nebula"},
    ("github.com/munnerz/goautoneg", "v0.0.0-20191010083416-a7dc8b61c822"): {"/bin/nebula"},
    ("github.com/nbrownus/go-metrics-prometheus", "v0.0.0-20210712211119-974a6260965f"): {"/bin/nebula"},
    ("github.com/prometheus/client_golang", "v1.23.2"): {"/bin/nebula"},
    ("github.com/prometheus/client_model", "v0.6.2"): {"/bin/nebula"},
    ("github.com/prometheus/common", "v0.66.1"): {"/bin/nebula"},
    ("github.com/prometheus/procfs", "v0.16.1"): {"/bin/nebula"},
    ("github.com/rcrowley/go-metrics", "v0.0.0-20201227073835-cf1acfcdf475"): {"/bin/nebula"},
    ("github.com/sirupsen/logrus", "v1.9.4"): {"/bin/nebula"},
    ("github.com/skip2/go-qrcode", "v0.0.0-20200617195104-da1b6568686e"): {"/bin/nebula-cert"},
    ("github.com/slackhq/nebula", "UNKNOWN"): {"/bin/nebula", "/bin/nebula-cert"},
    ("github.com/slackhq/nebula", "v1.10.3"): {"/bin/meshctl"},
    ("github.com/stefanberger/go-pkcs11uri", "v0.0.0-20230803200340-78284954bff6"): {"/bin/nebula", "/bin/nebula-cert"},
    ("github.com/vishvananda/netlink", "v1.3.1"): {"/bin/nebula"},
    ("github.com/vishvananda/netns", "v0.0.5"): {"/bin/nebula"},
    ("go.yaml.in/yaml/v2", "v2.4.2"): {"/bin/nebula"},
    ("go.yaml.in/yaml/v3", "v3.0.4"): {"/bin/nebula"},
    ("golang.org/x/crypto", "v0.53.0"): {"/bin/meshctl", "/bin/nebula", "/bin/nebula-cert"},
    ("golang.org/x/net", "v0.56.0"): {"/bin/meshctl", "/bin/nebula"},
    ("golang.org/x/sync", "v0.21.0"): {"/bin/meshctl"},
    ("golang.org/x/sys", "v0.46.0"): {"/bin/mesh-install", "/bin/meshctl", "/bin/nebula", "/bin/nebula-cert"},
    ("golang.org/x/term", "v0.44.0"): {"/bin/nebula", "/bin/nebula-cert"},
    ("golang.org/x/text", "v0.39.0"): {"/bin/meshctl"},
    ("google.golang.org/protobuf", "v1.36.11"): {"/bin/meshctl", "/bin/nebula", "/bin/nebula-cert"},
    ("mesh", "UNKNOWN"): {"/bin/mesh-install", "/bin/meshctl"},
    ("stdlib", "go1.26.5"): BINARY_LOCATIONS,
}
EXPECTED_PACKAGES = {
    (name, version, location)
    for (name, version), locations in PACKAGE_LOCATIONS.items()
    for location in locations
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


def validate_inspection(document: dict[str, Any], staged: pathlib.Path, artifact: pathlib.Path) -> dict[str, Any]:
    exact_keys(document, {"schema", "artifact_sha256", "artifact_size", "package_json_sha256", "file_count", "total_bytes", "package"}, "candidate inspection")
    require(document["schema"] == "mesh-linux-security-candidate-inspection-v1", "candidate inspection schema is invalid")
    artifact_record = hash_record(artifact, 272 * 1024 * 1024)
    require(document["artifact_sha256"] == artifact_record["sha256"] and document["artifact_size"] == artifact_record["size"], "candidate inspection is not bound to the exact artifact")
    require(0 < document["artifact_size"] <= 272 * 1024 * 1024, "candidate artifact size is invalid")
    package = document.get("package")
    require(isinstance(package, dict), "candidate package metadata is missing")
    exact_keys(package, {
        "schema", "version", "commit", "build_time", "security_floor",
        "agent_state_read_min", "agent_state_read_max", "agent_state_write_version",
        "installer_state_read_min", "installer_state_read_max", "installer_state_write_version",
        "installer_trust_policy_sha256", "go_version", "target", "nebula", "entries",
    }, "candidate package")
    require(package["schema"] == "mesh-linux-node-bundle-v3", "only current Linux bundle schema v3 is accepted")
    require(isinstance(package["version"], str) and 0 < len(package["version"]) <= 128, "candidate version is invalid")
    require(isinstance(package["commit"], str) and COMMIT.fullmatch(package["commit"]), "candidate commit is invalid")
    require(canonical_time(package["build_time"]), "candidate build time is not canonical UTC")
    require(isinstance(package["security_floor"], int) and package["security_floor"] > 0, "candidate security floor is invalid")
    require((package["agent_state_read_min"], package["agent_state_read_max"], package["agent_state_write_version"]) == (2, 2, 2), "candidate agent-state contract is unexpected")
    require((package["installer_state_read_min"], package["installer_state_read_max"], package["installer_state_write_version"]) == (2, 3, 3), "candidate installer-state contract is unexpected")
    require(isinstance(package["installer_trust_policy_sha256"], str) and DIGEST.fullmatch(package["installer_trust_policy_sha256"]), "candidate installer root digest is invalid")
    require(package["go_version"] == "go1.26.5", "candidate package does not require Go 1.26.5")
    target = package.get("target")
    require(isinstance(target, dict) and set(target) == {"os", "arch"} and target.get("os") == "linux" and target.get("arch") in {"amd64", "arm64"}, "candidate target is invalid")
    require(package.get("nebula") == EXPECTED_NEBULA, "candidate Nebula provenance differs from the exact observer lock")
    entries = package.get("entries")
    require(isinstance(entries, list) and len(entries) == len(PAYLOAD_MODES), "candidate payload inventory is incomplete")
    observed_entries: dict[str, dict[str, Any]] = {}
    for entry in entries:
        require(isinstance(entry, dict) and set(entry) == {"path", "mode", "size", "sha256"}, "candidate payload entry schema is invalid")
        path = entry.get("path")
        require(isinstance(path, str) and path not in observed_entries and PAYLOAD_MODES.get(path) == entry.get("mode"), "candidate payload path or mode is invalid")
        require(isinstance(entry.get("size"), int) and 0 < entry["size"] <= 128 * 1024 * 1024, f"candidate payload size is invalid: {path}")
        require(isinstance(entry.get("sha256"), str) and DIGEST.fullmatch(entry["sha256"]), f"candidate payload digest is invalid: {path}")
        observed_entries[path] = entry
    require(list(observed_entries) == sorted(PAYLOAD_MODES), "candidate payload entries are not in exact path order")
    require(staged.is_dir() and not staged.is_symlink() and stat.S_IMODE(staged.stat().st_mode) == 0o555, "staged candidate root is invalid")
    observed_paths: set[str] = set()
    for root, directories, files in os.walk(staged, topdown=True, followlinks=False):
        relative_root = pathlib.Path(root).relative_to(staged)
        for name in directories + files:
            path = (relative_root / name).as_posix()
            observed_paths.add(path)
            info = (staged / path).lstat()
            require(not stat.S_ISLNK(info.st_mode), f"staged candidate contains a link: {path}")
            if name in directories:
                require(path in DIRECTORIES and stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o555, f"staged candidate directory is invalid: {path}")
            else:
                expected_mode = 0o444 if path == "package.json" else PAYLOAD_MODES.get(path)
                require(expected_mode is not None and stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == expected_mode and info.st_nlink == 1, f"staged candidate file is invalid: {path}")
    require(observed_paths == DIRECTORIES | set(PAYLOAD_MODES) | {"package.json"}, "staged candidate exact path set is invalid")
    package_path = staged / "package.json"
    package_raw = package_path.read_bytes()
    require(hash_file(package_path)["sha256"] == document["package_json_sha256"], "staged package.json differs from candidate inspection")
    require(json.loads(package_raw) == package, "staged package.json metadata differs from candidate inspection")
    total = len(package_raw)
    files: dict[str, dict[str, Any]] = {"package.json": hash_file(package_path)}
    for path, entry in observed_entries.items():
        record = hash_file(staged / path)
        require(record == {"sha256": entry["sha256"], "size": entry["size"]}, f"staged candidate payload differs from package metadata: {path}")
        files[path] = record
        total += record["size"]
    require(document["file_count"] == 11 and document["total_bytes"] == total, "candidate inspection counts are inconsistent")
    return {"artifact": artifact_record, "files": dict(sorted(files.items())), "package": package}


def validate_syft(document: dict[str, Any]) -> tuple[set[str], int]:
    descriptor = document.get("descriptor")
    require(isinstance(descriptor, dict) and descriptor.get("name") == "syft" and descriptor.get("version") == "1.44.0", "Linux package SBOM descriptor is invalid")
    schema = document.get("schema")
    require(isinstance(schema, dict) and schema.get("version") == "16.1.3", "Linux package Syft schema is unexpected")
    source = document.get("source")
    require(isinstance(source, dict) and source.get("type") == "directory", "Linux package SBOM source is not the staged directory")
    artifacts = document.get("artifacts")
    require(isinstance(artifacts, list) and len(artifacts) == len(EXPECTED_PACKAGES) == 59, "Linux package SBOM must contain exactly 59 Go package locations")
    observed: set[tuple[str, str, str]] = set()
    purls: set[str] = set()
    for artifact in artifacts:
        require(isinstance(artifact, dict) and artifact.get("type") == "go-module", "Linux package SBOM contains a non-Go package")
        name, version = artifact.get("name"), artifact.get("version")
        locations = artifact_locations(artifact)
        require(isinstance(name, str) and isinstance(version, str) and len(locations) == 1 and locations.issubset(BINARY_LOCATIONS), "Linux package SBOM package identity or location is invalid")
        observed.add((name, version, next(iter(locations))))
        purl = artifact.get("purl")
        require(isinstance(purl, str) and purl.startswith("pkg:golang/"), f"Linux package SBOM lacks a Go purl: {name}")
        purls.add(purl)
    require(observed == EXPECTED_PACKAGES, "Linux package SBOM inventory differs from the exact allowlist")
    return purls, len(artifacts)


def finalize(args: argparse.Namespace) -> None:
    work = pathlib.Path(args.work_dir)
    require(work.is_dir() and not work.is_symlink(), "Linux package verification workspace is unsafe")
    staged = work / "staged"
    artifact = work / "bundle.tar"
    validate_regular_file(artifact, max_bytes=272 * 1024 * 1024)
    inspection_path = work / "candidate-inspection.json"
    inspection = read_json(inspection_path, max_bytes=1024 * 1024)
    require(isinstance(inspection, dict), "candidate inspection is not an object")
    candidate = validate_inspection(inspection, staged, artifact)
    syft_path, spdx_path = work / "sbom.syft.json", work / "sbom.spdx.json"
    grype_path, database_path = work / "vulnerabilities.json", work / "grype-db-status.json"
    text_secrets_path, binary_secrets_path = work / "text-secrets.json", work / "binary-secrets.json"
    syft, spdx, grype, database = (read_json(path) for path in (syft_path, spdx_path, grype_path, database_path))
    require(all(isinstance(item, dict) for item in (syft, spdx, grype, database)), "Linux package scanner output is not an object")
    purls, syft_count = validate_syft(syft)
    spdx_count = validate_spdx(spdx, purls)
    require(spdx_count == 60, "Linux package SPDX inventory must contain exactly 60 packages")
    database_schema, database_built = validate_grype_db(database)
    vulnerability_summary = validate_grype(grype, purls)
    validate_empty_gitleaks(text_secrets_path)
    validate_empty_gitleaks(binary_secrets_path)
    verifier_record = hash_file(pathlib.Path(args.verifier))
    receipt = {
        "artifact": candidate["artifact"],
        "candidate": {
            "architecture": candidate["package"]["target"]["arch"],
            "build_time": candidate["package"]["build_time"],
            "commit": candidate["package"]["commit"],
            "file_count": inspection["file_count"],
            "files": candidate["files"],
            "go_version": candidate["package"]["go_version"],
            "inspection": hash_file(inspection_path),
            "installer_root_sha256": candidate["package"]["installer_trust_policy_sha256"],
            "package_json_sha256": inspection["package_json_sha256"],
            "schema": candidate["package"]["schema"],
            "security_floor": candidate["package"]["security_floor"],
            "total_bytes": inspection["total_bytes"],
            "verifier": verifier_record,
            "version": candidate["package"]["version"],
        },
        "sbom": {
            "spdx_json": hash_file(spdx_path),
            "spdx_package_count": spdx_count,
            "spdx_version": "SPDX-2.3",
            "syft_json": hash_file(syft_path),
            "syft_package_count": syft_count,
            "syft_schema": "16.1.3",
            "syft_version": "1.44.0",
        },
        "scanner_boundary": {
            "artifact_and_scan": "stable candidate, networkless read-only non-root scanners, no Docker socket",
            "database_update": "networked scanner with only an empty private database cache mounted",
        },
        "schema": "mesh-linux-package-security-receipt-v1",
        "secret_scan": {
            "binary_strings_report": hash_file(binary_secrets_path),
            "gitleaks_version": "v8.30.1",
            "policy": "default rules over exact package metadata, service assets, documentation, license, and all four binaries' strings; only the exact public oauth2 v0.36.0 Go checksum is allowlisted",
            "text_report": hash_file(text_secrets_path),
        },
        "verified_at": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
        "vulnerability_scan": {
            "database_built": database_built,
            "database_schema": database_schema,
            "database_status": hash_file(database_path),
            "grype_version": "0.112.0",
            "policy": "reject High or Critical matches and every match with a published fix",
            "report": hash_file(grype_path),
            **vulnerability_summary,
        },
    }
    receipt_path = pathlib.Path(args.receipt)
    require(receipt_path.parent == work, "Linux package receipt must be written inside the verification workspace")
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
        print(f"Linux package security verification: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
