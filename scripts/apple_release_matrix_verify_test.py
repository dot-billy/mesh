#!/usr/bin/env python3
"""Tests for the non-release Apple verification-matrix policy."""

from __future__ import annotations

import copy
import importlib.util
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "apple_release_matrix_verify",
    ROOT / "scripts" / "apple_release_matrix_verify.py",
)
assert SPEC is not None and SPEC.loader is not None
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)


class AppleReleaseMatrixVerifyTest(unittest.TestCase):
    def setUp(self) -> None:
        self.matrix = VERIFY.load_matrix()

    def test_checked_in_matrix_is_complete_and_not_release_eligible(self) -> None:
        VERIFY.verify_matrix(self.matrix)
        self.assertEqual(
            self.matrix["schema"],
            "mesh-apple-release-verification-matrix-v2",
        )
        self.assertFalse(self.matrix["release_eligible"])
        self.assertEqual(
            set(self.matrix["products"]),
            {"macos-admin", "macos-node", "ios-admin", "ios-node"},
        )

    def test_missing_gate_is_rejected(self) -> None:
        changed = copy.deepcopy(self.matrix)
        changed["products"]["ios-node"]["gates"]["physical-device-packet"].remove(
            "revocation-cutoff"
        )
        with self.assertRaisesRegex(VERIFY.MatrixError, "incomplete"):
            VERIFY.verify_matrix(changed)

    def test_support_or_release_claim_is_rejected(self) -> None:
        for field, value in (
            ("release_eligible", True),
            ("support_status", "supported"),
        ):
            with self.subTest(field=field):
                changed = copy.deepcopy(self.matrix)
                if field == "release_eligible":
                    changed[field] = value
                else:
                    changed["products"]["macos-admin"][field] = value
                with self.assertRaises(VERIFY.MatrixError):
                    VERIFY.verify_matrix(changed)

    def test_source_or_simulator_cannot_satisfy_real_world_classes(self) -> None:
        changed = copy.deepcopy(self.matrix)
        changed["source_or_simulator_evidence_cannot_satisfy"].remove(
            "physical-device-packet"
        )
        with self.assertRaisesRegex(VERIFY.MatrixError, "proof classes"):
            VERIFY.verify_matrix(changed)

    def test_ios_node_simulator_group_is_rejected(self) -> None:
        changed = copy.deepcopy(self.matrix)
        changed["products"]["ios-node"]["gates"]["simulator"] = [
            changed["products"]["ios-node"]["gates"]["physical-device"].pop()
        ]
        with self.assertRaises(VERIFY.MatrixError):
            VERIFY.verify_matrix(changed)

    def test_every_product_requires_exact_final_provenance(self) -> None:
        for product_name in self.matrix["products"]:
            with self.subTest(product=product_name):
                changed = copy.deepcopy(self.matrix)
                changed["products"][product_name]["gates"]["provenance"].remove(
                    "independent-verification-without-signing-secrets"
                )
                with self.assertRaises(VERIFY.MatrixError):
                    VERIFY.verify_matrix(changed)

    def test_both_macos_products_require_exact_publication(self) -> None:
        for product_name in ("macos-admin", "macos-node"):
            with self.subTest(product=product_name):
                changed = copy.deepcopy(self.matrix)
                changed["products"][product_name]["gates"]["publication"].remove(
                    "public-redownload-verification"
                )
                with self.assertRaises(VERIFY.MatrixError):
                    VERIFY.verify_matrix(changed)

    def test_macos_node_requires_protected_installer_release(self) -> None:
        changed = copy.deepcopy(self.matrix)
        changed["products"]["macos-node"]["gates"]["protected-release"].remove(
            "installer-signature-verification"
        )
        with self.assertRaises(VERIFY.MatrixError):
            VERIFY.verify_matrix(changed)

    def test_ios_release_policy_cannot_omit_privacy_or_capability_review(self) -> None:
        cases = (
            (
                "ios-admin",
                "privacy-manifest-and-declaration-review",
            ),
            (
                "ios-node",
                "network-extension-capability-approval",
            ),
        )
        for product_name, gate in cases:
            with self.subTest(product=product_name):
                changed = copy.deepcopy(self.matrix)
                changed["products"][product_name]["gates"][
                    "apple-distribution"
                ].remove(gate)
                with self.assertRaises(VERIFY.MatrixError):
                    VERIFY.verify_matrix(changed)


if __name__ == "__main__":
    unittest.main()
