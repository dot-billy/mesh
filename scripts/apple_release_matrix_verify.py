#!/usr/bin/env python3
"""Verify the canonical Apple release-gate inventory without claiming a release."""

from __future__ import annotations

import json
import pathlib
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
MATRIX = ROOT / "packaging" / "apple" / "release-verification-matrix.json"
SCHEMA = "mesh-apple-release-verification-matrix-v2"

EXPECTED_GATES = {
    "macos-admin": {
        "clean-build",
        "arm64-execution",
        "amd64-execution",
        "signature-and-entitlement-verification",
        "notarization-and-staple",
        "gatekeeper-assessment",
        "release-metadata-binding",
        "authenticated-publication",
        "public-redownload-verification",
        "sanitized-release-receipts",
        "source-and-provenance-binding",
        "independent-verification-without-signing-secrets",
        "browser-authentication",
        "keychain-persistence-and-erasure",
        "every-documented-read",
        "every-documented-mutation",
        "rbac-denial",
        "logout-and-server-session-revocation",
        "one-time-secret-background-erasure",
        "accessibility",
        "upgrade-and-settings-migration",
        "uninstall",
    },
    "macos-node": {
        "authenticated-online-install",
        "authenticated-offline-install",
        "arm64-native-execution",
        "amd64-native-execution",
        "immutable-release-and-path-invariants",
        "launchd-lifecycle",
        "enrollment",
        "signed-revision-convergence",
        "heartbeat-and-runtime-evidence",
        "direct-packets",
        "lighthouse-discovery",
        "relay-packets",
        "dns",
        "firewall-allow-and-deny",
        "routed-prefix-behavior-where-supported",
        "certificate-renewal-and-rotation",
        "permanent-revocation",
        "ca-rotation",
        "stale-state-quarantine",
        "reboot",
        "sleep-wake",
        "network-change",
        "crash-and-forced-kill",
        "upgrade",
        "rollback",
        "interrupted-install-upgrade-recovery",
        "uninstall",
        "signed-bundle-verification",
        "installer-signature-verification",
        "notarization-and-staple",
        "gatekeeper-assessment",
        "release-metadata-binding",
        "authenticated-publication",
        "public-redownload-verification",
        "sanitized-release-receipts",
        "source-and-provenance-binding",
        "independent-verification-without-signing-secrets",
    },
    "ios-admin": {
        "supported-iphone-sizes",
        "supported-ipad-sizes",
        "simulator-build",
        "physical-device-build",
        "browser-authentication",
        "keychain-behavior",
        "background-and-lock-erasure",
        "every-documented-read",
        "every-documented-mutation",
        "rbac-denial",
        "accessibility",
        "network-interruption",
        "upgrade-and-state-migration",
        "distribution-validation",
        "privacy-manifest-and-declaration-review",
        "source-and-provenance-binding",
        "independent-verification-without-signing-secrets",
    },
    "ios-node": {
        "physical-iphone",
        "physical-ipad-if-supported",
        "packet-tunnel-start-and-stop",
        "local-key-generation-and-custody",
        "enrollment",
        "direct-packets",
        "lighthouse-discovery",
        "relay-packets",
        "dns",
        "firewall-allow-and-deny",
        "wifi-and-cellular",
        "wifi-cellular-roaming",
        "lock-and-background",
        "low-power-behavior",
        "extension-crash-and-restart",
        "reboot",
        "signed-revision-convergence",
        "renewal-and-rotation",
        "revocation-cutoff",
        "managed-update",
        "distribution-validation",
        "network-extension-capability-approval",
        "source-and-provenance-binding",
        "independent-verification-without-signing-secrets",
        "identity-removal",
    },
}

SIMULATOR_CLASS = "simulator"


class MatrixError(RuntimeError):
    pass


def load_matrix(path: pathlib.Path = MATRIX) -> dict[str, object]:
    if not path.is_file() or path.is_symlink():
        raise MatrixError("Apple release matrix must be one physical file")
    raw = path.read_bytes()
    if not raw or len(raw) > 128 * 1024:
        raise MatrixError("Apple release matrix is empty or oversized")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MatrixError("Apple release matrix is invalid JSON") from exc
    canonical = (
        json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n"
    ).encode()
    if raw != canonical:
        raise MatrixError("Apple release matrix is not canonical JSON")
    if not isinstance(value, dict):
        raise MatrixError("Apple release matrix must be an object")
    return value


def verify_matrix(value: dict[str, object]) -> None:
    if set(value) != {
        "schema",
        "release_eligible",
        "proof_classes",
        "source_or_simulator_evidence_cannot_satisfy",
        "products",
    }:
        raise MatrixError("Apple release matrix has unexpected top-level fields")
    if value["schema"] != SCHEMA or value["release_eligible"] is not False:
        raise MatrixError("Apple release matrix must remain a non-release inventory")

    proof_classes = value["proof_classes"]
    products = value["products"]
    prohibited = value["source_or_simulator_evidence_cannot_satisfy"]
    if (
        not isinstance(proof_classes, dict)
        or not proof_classes
        or any(
            not isinstance(name, str)
            or not isinstance(description, str)
            or not description
            for name, description in proof_classes.items()
        )
        or not isinstance(prohibited, list)
        or len(prohibited) != len(set(prohibited))
        or any(name not in proof_classes for name in prohibited)
        or set(prohibited) != set(proof_classes) - {SIMULATOR_CLASS}
        or not isinstance(products, dict)
        or set(products) != set(EXPECTED_GATES)
    ):
        raise MatrixError("Apple release proof classes or product inventory is invalid")

    for product_name, expected_gates in EXPECTED_GATES.items():
        product = products[product_name]
        if (
            not isinstance(product, dict)
            or set(product) != {"support_status", "gates"}
            or product["support_status"] != "unsupported"
            or not isinstance(product["gates"], dict)
        ):
            raise MatrixError(f"{product_name} must remain explicitly unsupported")
        actual_gates: list[str] = []
        for proof_class, gates in product["gates"].items():
            if (
                proof_class not in proof_classes
                or not isinstance(gates, list)
                or not gates
                or any(
                    not isinstance(gate, str) or not gate for gate in gates
                )
            ):
                raise MatrixError(f"{product_name} has an invalid proof-class group")
            actual_gates.extend(gates)
        if len(actual_gates) != len(set(actual_gates)):
            raise MatrixError(f"{product_name} repeats a release gate")
        if set(actual_gates) != expected_gates:
            raise MatrixError(f"{product_name} release-gate inventory is incomplete")

    ios_node = products["ios-node"]["gates"]
    if SIMULATOR_CLASS in ios_node:
        raise MatrixError("iOS node support cannot be established by a simulator")

    for product_name, product in products.items():
        if set(product["gates"].get("provenance", [])) != {
            "source-and-provenance-binding",
            "independent-verification-without-signing-secrets",
        }:
            raise MatrixError(f"{product_name} lacks exact final provenance gates")

    for product_name in ("macos-admin", "macos-node"):
        product = products[product_name]
        if set(product["gates"].get("publication", [])) != {
            "release-metadata-binding",
            "authenticated-publication",
            "public-redownload-verification",
            "sanitized-release-receipts",
        }:
            raise MatrixError(f"{product_name} lacks exact publication gates")

    macos_node_protected = products["macos-node"]["gates"].get(
        "protected-release", []
    )
    if set(macos_node_protected) != {
        "signed-bundle-verification",
        "installer-signature-verification",
        "notarization-and-staple",
        "gatekeeper-assessment",
    }:
        raise MatrixError("macos-node lacks exact protected release gates")


def main() -> int:
    try:
        verify_matrix(load_matrix())
    except MatrixError as exc:
        print(f"apple release matrix rejected: {exc}", file=sys.stderr)
        return 1
    print("apple release verification matrix verified; release eligibility remains false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
