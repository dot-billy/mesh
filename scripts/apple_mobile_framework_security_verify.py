#!/usr/bin/env python3
"""Validate and bind one exact unsigned MeshMobile XCFramework security scan."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import pathlib
import re
import sys
from typing import Any

from apple_mobile_framework_receipt import tree_identity
from image_security_verify import (
    VerificationError,
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
LICENSE_NAME = re.compile(
    r"^(?:LICENSE|COPYING|NOTICE)(?:[.-].*)?$",
    re.IGNORECASE,
)
EXPECTED_MODULES = {
    "dario.cat/mergo": "v1.0.2",
    "filippo.io/bigmod": "v0.1.0",
    "github.com/anmitsu/go-shlex": "v0.0.0-20200514113438-38f4b401e2be",
    "github.com/armon/go-radix": "v1.0.0",
    "github.com/beorn7/perks": "v1.0.1",
    "github.com/cespare/xxhash/v2": "v2.3.0",
    "github.com/cyberdelia/go-metrics-graphite": (
        "v0.0.0-20161219230853-39f87cc3b432"
    ),
    "github.com/flynn/noise": "v1.1.0",
    "github.com/gaissmai/bart": "v0.26.0",
    "github.com/gogo/protobuf": "v1.3.2",
    "github.com/google/gopacket": "v1.1.19",
    "github.com/miekg/dns": "v1.1.70",
    "github.com/munnerz/goautoneg": (
        "v0.0.0-20191010083416-a7dc8b61c822"
    ),
    "github.com/nbrownus/go-metrics-prometheus": (
        "v0.0.0-20210712211119-974a6260965f"
    ),
    "github.com/prometheus/client_golang": "v1.23.2",
    "github.com/prometheus/client_model": "v0.6.2",
    "github.com/prometheus/common": "v0.66.1",
    "github.com/rcrowley/go-metrics": "v0.0.0-20201227073835-cf1acfcdf475",
    "github.com/sirupsen/logrus": "v1.9.4",
    "github.com/slackhq/nebula": "v1.10.3",
    "github.com/stefanberger/go-pkcs11uri": (
        "v0.0.0-20230803200340-78284954bff6"
    ),
    "go.yaml.in/yaml/v2": "v2.4.2",
    "go.yaml.in/yaml/v3": "v3.0.4",
    "golang.org/x/crypto": "v0.54.0",
    "golang.org/x/mobile": "v0.0.0-20260709172247-6129f5bee9d5",
    "golang.org/x/net": "v0.57.0",
    "golang.org/x/sys": "v0.47.0",
    "golang.org/x/term": "v0.45.0",
    "google.golang.org/protobuf": "v1.36.11",
}
EXPECTED_LICENSES = {
    "dario.cat/mergo": {
        "LICENSE": ("cb7684632b729955293cab8a0bbf4134d53d9532a30761c33c8a4878302a7bd3", 1536),
    },
    "filippo.io/bigmod": {
        "LICENSE": ("2d36597f7117c38b006835ae7f537487207d8ec407aa9d9980794b2030cbc067", 1479),
    },
    "github.com/gaissmai/bart": {
        "LICENSE": ("12d27746d111da33969df0ecaa9b799e22c42db7d0b6a5164f383ec934233a41", 1072),
    },
    "github.com/rcrowley/go-metrics": {
        "LICENSE": ("d2571186acad91c8a3121fb31f1aa5963e82ccd08608d00cef3eb3f3a6c8ad38", 1516),
    },
    "github.com/sirupsen/logrus": {
        "LICENSE": ("51a0c9ec7f8b7634181b8d4c03e5b5d204ac21d6e72f46c313973424664b2e6b", 1082),
    },
    "github.com/slackhq/nebula": {
        "LICENSE": ("aefd0cce553f24945ce1c692c3c4f9fda581f078ba82977845715cd18565b3bd", 1088),
    },
    "go.yaml.in/yaml/v3": {
        "LICENSE": ("d18f6323b71b0b768bb5e9616e36da390fbd39369a81807cca352de4e4e6aa0b", 2151),
        "NOTICE": ("f6c2dd3a67b576eafb89b80200b8b1627230bf3821a0c14cb99a22ac19107d00", 560),
    },
    "golang.org/x/crypto": {
        "LICENSE": ("911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad", 1453),
    },
    "golang.org/x/mobile": {
        "LICENSE": ("911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad", 1453),
    },
    "golang.org/x/net": {
        "LICENSE": ("911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad", 1453),
    },
    "golang.org/x/sys": {
        "LICENSE": ("911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad", 1453),
    },
    "google.golang.org/protobuf": {
        "LICENSE": ("4835612df0098ca95f8e7d9e3bffcb02358d435dbb38057c844c99d7f725eb20", 1479),
    },
}


def canonical_source_receipt(path: pathlib.Path) -> dict[str, Any]:
    validate_regular_file(path, max_bytes=256 * 1024)
    raw = path.read_bytes()
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VerificationError("mobile framework source receipt is invalid JSON") from exc
    require(isinstance(value, dict), "mobile framework source receipt is not an object")
    require(raw == canonical_json(value), "mobile framework source receipt is not canonical JSON")
    framework = value.get("framework")
    scope = value.get("scope")
    require(
        value.get("schema") == "mesh-apple-ios-mobile-framework-source-receipt-v1"
        and isinstance(framework, dict)
        and framework.get("name") == "MeshMobile.xcframework"
        and framework.get("reproducible") is True
        and framework.get("signed") is False
        and isinstance(framework.get("tree_sha256"), str)
        and DIGEST.fullmatch(framework["tree_sha256"])
        and isinstance(scope, dict)
        and scope.get("embedded_in_tunnel") is False
        and scope.get("packet_transport_implemented") is True
        and scope.get("static_tunnel_link_validated") is False
        and scope.get("physical_device_validated") is False
        and scope.get("production_signing_used") is False,
        "mobile framework source receipt boundary is invalid",
    )
    return value


def validate_runtime_manifest(
    document: dict[str, Any], runtime_root: pathlib.Path
) -> dict[str, str]:
    require(
        document.get("schema") == "mesh-apple-mobile-runtime-modules-v1"
        and document.get("goos") == "ios"
        and document.get("goarch") == "arm64",
        "mobile runtime module manifest target is invalid",
    )
    modules = document.get("modules")
    require(
        isinstance(modules, list) and len(modules) == len(EXPECTED_MODULES),
        "mobile runtime module inventory count is invalid",
    )
    observed: dict[str, str] = {}
    for index, module in enumerate(modules):
        require(isinstance(module, dict), "mobile runtime module record is invalid")
        name, version = module.get("name"), module.get("version")
        require(
            isinstance(name, str)
            and isinstance(version, str)
            and name not in observed
            and EXPECTED_MODULES.get(name) == version,
            "mobile runtime module identity differs from the reviewed allowlist",
        )
        require(
            isinstance(module.get("sum"), str)
            and module["sum"].startswith("h1:")
            and isinstance(module.get("go_mod_sum"), str)
            and module["go_mod_sum"].startswith("h1:"),
            f"mobile runtime module lacks authenticated sums: {name}",
        )
        licenses = module.get("licenses")
        require(
            isinstance(licenses, list) and 1 <= len(licenses) <= 8,
            f"mobile runtime license inventory is empty or excessive: {name}",
        )
        seen: set[str] = set()
        for license_record in licenses:
            require(isinstance(license_record, dict), "mobile runtime license record is invalid")
            filename = license_record.get("name")
            require(
                isinstance(filename, str)
                and filename not in seen
                and LICENSE_NAME.fullmatch(filename) is not None,
                f"mobile runtime license filename is unexpected: {name}",
            )
            seen.add(filename)
            relative = license_record.get("path")
            require(
                relative == f"licenses/{index:02d}/{filename}",
                f"mobile runtime license path is invalid: {name}",
            )
            path = runtime_root / relative
            record = hash_file(path)
            require(
                isinstance(license_record.get("sha256"), str)
                and DIGEST.fullmatch(license_record["sha256"]) is not None
                and isinstance(license_record.get("size"), int)
                and 0 < license_record["size"] <= 1024 * 1024
                and record
                == {
                    "sha256": license_record["sha256"],
                    "size": license_record["size"],
                },
                f"mobile runtime license differs from reviewed text: {name}/{filename}",
            )
        observed[name] = version
    require(
        list(observed) == sorted(EXPECTED_MODULES),
        "mobile runtime modules are not in canonical order",
    )
    return observed


def validate_syft(
    document: dict[str, Any], expected_modules: dict[str, str]
) -> tuple[set[str], int]:
    descriptor = document.get("descriptor")
    schema = document.get("schema")
    source = document.get("source")
    require(
        isinstance(descriptor, dict)
        and descriptor.get("name") == "syft"
        and descriptor.get("version") == "1.44.0"
        and isinstance(schema, dict)
        and schema.get("version") == "16.1.3"
        and isinstance(source, dict)
        and source.get("type") == "directory",
        "mobile framework Syft metadata is invalid",
    )
    artifacts = document.get("artifacts")
    require(isinstance(artifacts, list) and artifacts, "mobile framework SBOM is empty")
    found: set[tuple[str, str]] = set()
    purls: set[str] = set()
    for artifact in artifacts:
        require(isinstance(artifact, dict), "mobile framework SBOM artifact is invalid")
        name, version = artifact.get("name"), artifact.get("version")
        purl = artifact.get("purl")
        if isinstance(purl, str) and purl:
            purls.add(purl)
        if artifact.get("type") == "go-module" and name in expected_modules:
            require(
                version == expected_modules[name]
                and isinstance(purl, str)
                and purl.startswith("pkg:golang/"),
                f"mobile framework SBOM module identity is invalid: {name}",
            )
            found.add((name, version))
    require(
        found == set(expected_modules.items()),
        "mobile framework SBOM runtime module inventory is incomplete",
    )
    require(purls, "mobile framework SBOM has no package URLs")
    return purls, len(artifacts)


def finalize(args: argparse.Namespace) -> None:
    work = pathlib.Path(args.work_dir)
    require(work.is_dir() and not work.is_symlink(), "mobile framework verification workspace is unsafe")
    framework = work / "scan-root" / "MeshMobile.xcframework"
    require(framework.is_dir() and not framework.is_symlink(), "stable mobile framework snapshot is missing")
    source_path = work / "source-receipt.json"
    source = canonical_source_receipt(source_path)
    observed_tree = tree_identity(framework)
    source_framework = source["framework"]
    require(
        observed_tree
        == (
            source_framework["tree_sha256"],
            source_framework["regular_files"],
            source_framework["regular_file_bytes"],
        ),
        "mobile framework snapshot differs from its source receipt",
    )
    runtime_root = work / "scan-root" / "metadata" / "runtime"
    runtime_path = runtime_root / "runtime-modules.json"
    runtime_document = read_json(runtime_path, max_bytes=1024 * 1024)
    require(isinstance(runtime_document, dict), "mobile runtime manifest is not an object")
    modules = validate_runtime_manifest(runtime_document, runtime_root)

    syft_path, spdx_path = work / "sbom.syft.json", work / "sbom.spdx.json"
    grype_path, database_path = work / "vulnerabilities.json", work / "grype-db-status.json"
    metadata_secrets, framework_secrets = work / "metadata-secrets.json", work / "framework-strings-secrets.json"
    syft, spdx, grype, database = (
        read_json(path) for path in (syft_path, spdx_path, grype_path, database_path)
    )
    require(
        all(isinstance(item, dict) for item in (syft, spdx, grype, database)),
        "mobile framework scanner output is not an object",
    )
    purls, syft_count = validate_syft(syft, modules)
    spdx_count = validate_spdx(spdx, purls)
    database_schema, database_built = validate_grype_db(database)
    vulnerability_summary = validate_grype(grype, purls)
    validate_empty_gitleaks(metadata_secrets)
    validate_empty_gitleaks(framework_secrets)

    script_dir = pathlib.Path(__file__).resolve().parent
    repo_root = script_dir.parent
    receipt = {
        "schema": "mesh-apple-ios-mobile-framework-security-receipt-v1",
        "artifact": {
            "name": "MeshMobile.xcframework",
            "tree_sha256": observed_tree[0],
            "regular_files": observed_tree[1],
            "regular_file_bytes": observed_tree[2],
            "source_receipt": hash_file(source_path),
            "embedded_in_tunnel": False,
            "packet_transport_implemented": True,
            "static_tunnel_link_validated": False,
            "physical_device_validated": False,
        },
        "gate": {
            "baseline": hash_file(script_dir / "apple-mobile-framework-security-baseline.sh"),
            "gitleaks_policy": hash_file(repo_root / ".gitleaks-apple-mobile.toml"),
            "verifier": hash_file(pathlib.Path(__file__).resolve()),
        },
        "dependencies": {
            "runtime_manifest": hash_file(runtime_path),
            "runtime_modules": modules,
            "runtime_module_count": len(modules),
        },
        "licenses": {
            "module_count": len(modules),
            "file_count": sum(
                len(module["licenses"])
                for module in runtime_document["modules"]
            ),
            "status": "exact-inventory-present-legal-review-pending",
        },
        "sbom": {
            "syft_json": hash_file(syft_path),
            "syft_package_count": syft_count,
            "syft_schema": "16.1.3",
            "syft_version": "1.44.0",
            "spdx_json": hash_file(spdx_path),
            "spdx_package_count": spdx_count,
            "spdx_version": "SPDX-2.3",
        },
        "secret_scan": {
            "gitleaks_version": "v8.30.1",
            "metadata_report": hash_file(metadata_secrets),
            "framework_strings_report": hash_file(framework_secrets),
            "policy": "redacted default-rule scan of bound source/module/license metadata and strings from every framework file; only exact reviewed public integrity digests are allowlisted",
        },
        "scanner_boundary": {
            "artifact_and_scan": "stable unsigned framework snapshot; networkless read-only non-root scanners; no Docker socket",
            "database_update": "networked scanner with only an empty private database cache mounted",
            "registry_authentication": "anonymous public pulls through an empty private Docker configuration",
        },
        "vulnerability_scan": {
            "database_built": database_built,
            "database_schema": database_schema,
            "database_status": hash_file(database_path),
            "grype_version": "0.112.0",
            "policy": "reject High or Critical matches and every match with a published fix",
            "report": hash_file(grype_path),
            **vulnerability_summary,
        },
        "verified_at": dt.datetime.now(dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
    }
    output = pathlib.Path(args.receipt)
    require(output.parent == work, "mobile framework security receipt must be written inside the workspace")
    exclusive_write(output, canonical_json(receipt), mode=0o400)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--work-dir", required=True)
    result.add_argument("--receipt", required=True)
    return result


def main() -> int:
    try:
        finalize(parser().parse_args())
    except (VerificationError, OSError) as exc:
        print(f"Apple mobile framework security verification: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
