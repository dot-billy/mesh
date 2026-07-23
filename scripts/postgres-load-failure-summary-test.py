#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import io
import json
import os
import pathlib
import tempfile
import unittest


SCRIPT = pathlib.Path(__file__).with_name("postgres-load-failure-summary.py")
SPEC = importlib.util.spec_from_file_location("postgres_load_failure_summary", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
SUMMARY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SUMMARY)


class FailureSummaryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temporary.name)
        self.report = self.root / "report.json"
        self.stderr = self.root / "driver.stderr"
        self.secret = self.root / "secret.txt"
        self.write(self.stderr, b"fallback failure\n")
        self.write(self.secret, b"super-secret-value-1234567890\n")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def write(path: pathlib.Path, value: bytes) -> None:
        path.write_bytes(value)
        os.chmod(path, 0o600)

    def emit(self) -> tuple[bool, str]:
        output = io.StringIO()
        emitted = SUMMARY.emit_failure_summary(self.report, self.stderr, [self.secret], [], output)
        return emitted, output.getvalue()

    def test_prefers_strict_supported_report_error(self) -> None:
        self.write(
            self.report,
            json.dumps({"schema": SUMMARY.REPORT_SCHEMA, "passed": False, "error": "database snapshot failed"}).encode(),
        )
        self.assertEqual(self.emit(), (True, "LOAD_GATE_ERROR: database snapshot failed\n"))

    def test_duplicate_name_rejects_report_and_uses_stderr(self) -> None:
        self.write(self.report, b'{"schema":"mesh-postgres-load-soak-v1","error":"first","error":"second"}')
        self.assertEqual(self.emit(), (True, "LOAD_GATE_ERROR: fallback failure\n"))

    def test_wrong_schema_and_control_character_use_stderr(self) -> None:
        self.write(self.report, b'{"schema":"wrong","error":"report failure"}')
        self.write(self.stderr, b"earlier safe\nterminal\x1b[31m escape\n")
        self.assertEqual(self.emit(), (True, "LOAD_GATE_ERROR: earlier safe\n"))

    def test_overlong_report_and_secret_stderr_lines_are_not_emitted(self) -> None:
        self.write(
            self.report,
            json.dumps({"schema": SUMMARY.REPORT_SCHEMA, "error": "x" * 513}).encode(),
        )
        self.write(self.stderr, b"last safe\ncontains super-secret-value-1234567890\n")
        self.assertEqual(self.emit(), (True, "LOAD_GATE_ERROR: last safe\n"))

    def test_token_shaped_line_is_not_emitted(self) -> None:
        self.report.unlink(missing_ok=True)
        self.write(self.stderr, b"safe failure\n" + b"A" * 43 + b"\n")
        self.assertEqual(self.emit(), (True, "LOAD_GATE_ERROR: safe failure\n"))

    def test_missing_required_secret_file_fails_closed(self) -> None:
        self.secret.unlink()
        self.assertEqual(self.emit(), (False, ""))

    def test_symlinked_report_is_rejected(self) -> None:
        target = self.root / "target.json"
        self.write(target, b'{"schema":"mesh-postgres-load-soak-v1","error":"unsafe report"}')
        self.report.symlink_to(target)
        self.assertEqual(self.emit(), (True, "LOAD_GATE_ERROR: fallback failure\n"))


if __name__ == "__main__":
    unittest.main()
