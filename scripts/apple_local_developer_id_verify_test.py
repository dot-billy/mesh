#!/usr/bin/env python3

from __future__ import annotations

import unittest

import apple_local_developer_id_verify as verifier


class LocalDeveloperIDVerifierTests(unittest.TestCase):
    def test_exact_signature_details_are_accepted(self) -> None:
        result = verifier.parse_signature_details(
            "\n".join(
                [
                    "Identifier=io.rw0.mesh.admin",
                    "CDHash=28cd45bce121c3c43c1c234d941f4e8aaf6804d9",
                    (
                        "Authority=Developer ID Application: Bounded Test "
                        "(Y3P5UNNG23)"
                    ),
                    "Timestamp=Jul 24, 2026 at 9:50:18 AM",
                    "TeamIdentifier=Y3P5UNNG23",
                ]
            )
        )
        self.assertEqual(result["TeamIdentifier"], "Y3P5UNNG23")

    def test_wrong_team_or_missing_timestamp_is_rejected(self) -> None:
        base = "\n".join(
            [
                "Identifier=io.rw0.mesh.admin",
                "CDHash=28cd45bce121c3c43c1c234d941f4e8aaf6804d9",
                "Authority=Developer ID Application: Test (Y3P5UNNG23)",
                "TeamIdentifier=Y3P5UNNG23",
            ]
        )
        with self.assertRaisesRegex(verifier.VerificationError, "timestamp"):
            verifier.parse_signature_details(base)
        with self.assertRaisesRegex(verifier.VerificationError, "Team ID"):
            verifier.parse_signature_details(
                base.replace("TeamIdentifier=Y3P5UNNG23", "TeamIdentifier=OTHER")
            )


if __name__ == "__main__":
    unittest.main()
