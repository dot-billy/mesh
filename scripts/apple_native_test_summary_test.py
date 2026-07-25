#!/usr/bin/env python3
"""Tests for the bounded native Apple test-summary sanitizer."""

from __future__ import annotations

import importlib.util
import json
import pathlib
import tempfile
import unittest


MODULE_PATH = pathlib.Path(__file__).with_name("apple_native_test_summary.py")
SPEC = importlib.util.spec_from_file_location("apple_native_test_summary", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
SUMMARY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SUMMARY)


def canonical(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode()


def source_receipt() -> dict[str, object]:
    return {
        "schema": "mesh-apple-source-build-receipt-v1",
        "source": {"commit": "1" * 40, "clean": True},
        "host": {
            "architecture": "arm64",
            "xcode_version": "26.5",
            "xcode_build": "17F42",
        },
        "preflight": {
            "release_credentials_present": False,
            "source_keychain_code_signing_identities": 0,
        },
    }


def raw_summary(platform_name: str = "macOS") -> dict[str, object]:
    return {
        "title": "MUST_NOT_APPEAR",
        "startTime": 1784931000.25,
        "finishTime": 1784931004.75,
        "environmentDescription": "MUST_NOT_APPEAR",
        "topInsights": [
            {"impact": "MUST_NOT_APPEAR", "category": "MUST_NOT_APPEAR", "text": "MUST_NOT_APPEAR"}
        ],
        "result": "Passed",
        "totalTestCount": 11,
        "passedTests": 11,
        "failedTests": 0,
        "skippedTests": 0,
        "expectedFailures": 0,
        "statistics": [{"title": "MUST_NOT_APPEAR", "subtitle": "MUST_NOT_APPEAR"}],
        "devicesAndConfigurations": [
            {
                "device": {
                    "deviceId": "MUST_NOT_APPEAR",
                    "deviceName": "MUST_NOT_APPEAR",
                    "architecture": "arm64",
                    "modelName": "MUST_NOT_APPEAR",
                    "platform": platform_name,
                    "osVersion": "26.5",
                    "osBuildNumber": "25F71",
                },
                "testPlanConfiguration": {
                    "configurationId": "MUST_NOT_APPEAR",
                    "configurationName": "MUST_NOT_APPEAR",
                },
                "passedTests": 11,
                "failedTests": 0,
                "skippedTests": 0,
                "expectedFailures": 0,
            }
        ],
        "testFailures": [],
    }


class NativeTestSummaryTests(unittest.TestCase):
    def test_sanitizes_identifying_and_free_form_fields(self) -> None:
        receipt = source_receipt()
        sanitized = SUMMARY.sanitize(
            raw_summary(),
            receipt,
            "a" * 64,
            "macos",
        )
        encoded = canonical(sanitized)
        self.assertNotIn(b"MUST_NOT_APPEAR", encoded)
        self.assertEqual(sanitized["schema"], "mesh-apple-native-test-summary-v1")
        self.assertEqual(sanitized["tests"]["total"], 11)
        self.assertEqual(sanitized["environment"]["architecture"], "arm64")

    def test_accepts_only_the_named_ios_simulator_platform(self) -> None:
        receipt = source_receipt()
        sanitized = SUMMARY.sanitize(
            raw_summary("iOS Simulator"),
            receipt,
            "b" * 64,
            "ios-simulator",
        )
        self.assertEqual(sanitized["platform"], "ios-simulator")
        with self.assertRaisesRegex(SUMMARY.SummaryError, "test platform"):
            SUMMARY.sanitize(raw_summary(), receipt, "b" * 64, "ios-simulator")

    def test_rejects_failures_skips_and_schema_drift(self) -> None:
        receipt = source_receipt()
        failed = raw_summary()
        failed["result"] = "Failed"
        failed["failedTests"] = 1
        failed["passedTests"] = 10
        failed["testFailures"] = [{"failureText": "MUST_NOT_APPEAR"}]
        with self.assertRaisesRegex(SUMMARY.SummaryError, "did not all pass"):
            SUMMARY.sanitize(failed, receipt, "c" * 64, "macos")
        drifted = raw_summary()
        drifted["newField"] = "unexpected"
        with self.assertRaisesRegex(SUMMARY.SummaryError, "top-level schema"):
            SUMMARY.sanitize(drifted, receipt, "c" * 64, "macos")

    def test_source_receipt_and_output_are_canonical_create_only(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mesh-native-summary-") as root:
            directory = pathlib.Path(root)
            source = directory / "source.json"
            source.write_bytes(canonical(source_receipt()))
            receipt, digest = SUMMARY.load_source_receipt(source)
            sanitized = SUMMARY.sanitize(raw_summary(), receipt, digest, "macos")
            output = directory / "sanitized.json"
            SUMMARY.write_create_only(output, sanitized)
            self.assertEqual(output.read_bytes(), canonical(sanitized))
            with self.assertRaisesRegex(SUMMARY.SummaryError, "new absolute path"):
                SUMMARY.write_create_only(output, sanitized)
            linked = directory / "linked-source.json"
            linked.symlink_to(source)
            with self.assertRaisesRegex(SUMMARY.SummaryError, "physical file"):
                SUMMARY.load_source_receipt(linked)


if __name__ == "__main__":
    unittest.main()
