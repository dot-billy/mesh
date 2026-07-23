#!/usr/bin/env python3
import copy
import importlib.util
import pathlib
import subprocess
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


def load_script(name: str, path: pathlib.Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


generator = load_script("mesh_public_docs_generator", ROOT / "scripts" / "generate-public-docs.py")
gate = load_script("mesh_public_docs_gate", ROOT / "scripts" / "public-docs-change-gate.py")


class PublicDocumentationTest(unittest.TestCase):
    def test_manifest_generates_complete_public_guide(self):
        manifest = generator.load_manifest(ROOT / "docs" / "public-guide.json")
        rendered = generator.render(manifest)
        self.assertIn("<title>Mesh documentation · Mesh</title>", rendered)
        self.assertIn("Nebula relays", rendered)
        self.assertIn("Firewall rules and groups", rendered)
        self.assertIn("Revoke a node", rendered)
        self.assertIn("Verify revocation", rendered)
        self.assertIn("Revocation cannot be undone", rendered)
        self.assertIn('class="docs-topic docs-topic-wide"', rendered)
        self.assertIn("Retire a network", rendered)
        self.assertNotIn("enrollment_token", rendered)
        self.assertNotIn("recovery_token", rendered)

    def test_rendering_escapes_manifest_text(self):
        manifest = generator.load_manifest(ROOT / "docs" / "public-guide.json")
        changed = copy.deepcopy(manifest)
        changed["title"] = '<script>alert("unsafe")</script>'
        rendered = generator.render(changed)
        self.assertNotIn("<script>", rendered)
        self.assertIn("&lt;script&gt;", rendered)

    def test_checked_in_page_is_current(self):
        result = subprocess.run(
            ["python3", "scripts/generate-public-docs.py", "--check"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_change_gate_requires_canonical_docs_for_product_changes(self):
        passed, affected = gate.evaluate(["internal/control/service.go"])
        self.assertFalse(passed)
        self.assertEqual(affected, ["internal/control/service.go"])
        passed, affected = gate.evaluate([
            "internal/control/service.go",
            "docs/public-guide.json",
            "internal/httpapi/web/docs.html",
        ])
        self.assertTrue(passed)
        self.assertEqual(affected, ["internal/control/service.go"])

    def test_change_gate_ignores_tests_and_docs_automation(self):
        passed, affected = gate.evaluate([
            "internal/control/service_test.go",
            "scripts/generate-public-docs.py",
            "internal/httpapi/web/docs.css",
        ])
        self.assertTrue(passed)
        self.assertEqual(affected, [])


if __name__ == "__main__":
    unittest.main()
