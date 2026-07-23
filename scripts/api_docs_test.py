#!/usr/bin/env python3
import importlib.util
import json
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


generator = load_script("mesh_api_docs_generator", ROOT / "scripts" / "generate-api-docs.py")
gate = load_script("mesh_api_docs_gate", ROOT / "scripts" / "api-docs-change-gate.py")


def assert_example_conforms(
    case: unittest.TestCase,
    value,
    schema,
    document,
    label: str,
):
    if not isinstance(schema, dict):
        case.fail(f"{label}: schema must be an object")
    reference = schema.get("$ref")
    if reference is not None:
        prefix = "#/components/schemas/"
        case.assertTrue(reference.startswith(prefix), f"{label}: unsupported reference {reference}")
        target = reference.removeprefix(prefix)
        assert_example_conforms(
            case,
            value,
            document["components"]["schemas"][target],
            document,
            label,
        )
        return
    expected = schema.get("type")
    if expected is None:
        return
    if expected == "object":
        case.assertIsInstance(value, dict, f"{label}: expected object")
        properties = schema.get("properties", {})
        for field in schema.get("required", []):
            case.assertIn(field, value, f"{label}: missing required field {field}")
        if schema.get("additionalProperties") is False:
            case.assertFalse(set(value) - set(properties), f"{label}: unknown fields")
        for field, item in value.items():
            field_schema = properties.get(field)
            if field_schema is None:
                additional = schema.get("additionalProperties")
                if isinstance(additional, dict):
                    field_schema = additional
            if field_schema is not None:
                assert_example_conforms(
                    case,
                    item,
                    field_schema,
                    document,
                    f"{label}.{field}",
                )
        return
    if expected == "array":
        case.assertIsInstance(value, list, f"{label}: expected array")
        for index, item in enumerate(value):
            assert_example_conforms(
                case,
                item,
                schema.get("items", {}),
                document,
                f"{label}[{index}]",
            )
        return
    if expected == "string":
        case.assertIsInstance(value, str, f"{label}: expected string")
    elif expected == "integer":
        case.assertIsInstance(value, int, f"{label}: expected integer")
        case.assertNotIsInstance(value, bool, f"{label}: boolean is not an integer example")
    elif expected == "number":
        case.assertIsInstance(value, (int, float), f"{label}: expected number")
        case.assertNotIsInstance(value, bool, f"{label}: boolean is not a number example")
    elif expected == "boolean":
        case.assertIsInstance(value, bool, f"{label}: expected boolean")


class APIDocumentationTest(unittest.TestCase):
    def test_checked_in_contract_is_current_and_complete(self):
        result = subprocess.run(
            ["python3", "scripts/generate-api-docs.py", "--check"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        raw = (ROOT / "docs" / "openapi.json").read_bytes()
        document = generator.validate(raw)
        operations = [
            operation
            for path_item in document["paths"].values()
            for method, operation in path_item.items()
            if method in generator.HTTP_METHODS
        ]
        self.assertEqual(len(operations), 67)
        self.assertGreater(
            sum("x-required-permission" in operation for operation in operations),
            40,
        )
        self.assertTrue(all("security" in operation for operation in operations))
        self.assertTrue(all(operation["x-codeSamples"] for operation in operations))

    def test_all_json_examples_conform_to_their_schemas(self):
        document = json.loads((ROOT / "docs" / "openapi.json").read_text(encoding="utf-8"))
        for path, path_item in document["paths"].items():
            for method, operation in path_item.items():
                if method not in generator.HTTP_METHODS:
                    continue
                operation_id = operation["operationId"]
                request = operation.get("requestBody", {}).get("content", {}).get("application/json")
                if request:
                    assert_example_conforms(
                        self,
                        request["example"],
                        request["schema"],
                        document,
                        f"{operation_id} request",
                    )
                for status, response in operation["responses"].items():
                    media = response.get("content", {}).get("application/json")
                    if media:
                        assert_example_conforms(
                            self,
                            media["example"],
                            media["schema"],
                            document,
                            f"{operation_id} response {status}",
                        )

    def test_contract_examples_do_not_publish_credentials(self):
        document = json.loads((ROOT / "docs" / "openapi.json").read_text(encoding="utf-8"))
        serialized = json.dumps(document, separators=(",", ":"))
        for forbidden in (
            '"private_key":"example"',
            '"token":"example"',
            '"code":"example"',
            "BEGIN PRIVATE KEY",
        ):
            self.assertNotIn(forbidden, serialized)

    def test_change_gate_requires_typed_catalog_and_generated_contract(self):
        passed, affected, missing = gate.evaluate(["internal/httpapi/server.go"])
        self.assertFalse(passed)
        self.assertEqual(affected, ["internal/httpapi/server.go"])
        self.assertEqual(missing, ["internal/httpapi/openapi.go", "docs/openapi.json"])
        passed, affected, missing = gate.evaluate([
            "internal/httpapi/server.go",
            "internal/httpapi/openapi.go",
            "docs/openapi.json",
        ])
        self.assertTrue(passed)
        self.assertEqual(affected, ["internal/httpapi/openapi.go", "internal/httpapi/server.go"])
        self.assertEqual(missing, [])

    def test_change_gate_ignores_tests_and_reference_assets(self):
        passed, affected, missing = gate.evaluate([
            "internal/httpapi/server_test.go",
            "internal/httpapi/web/api-docs.js",
            "scripts/generate-api-docs.py",
        ])
        self.assertTrue(passed)
        self.assertEqual(affected, [])
        self.assertEqual(missing, [])


if __name__ == "__main__":
    unittest.main()
