#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "app_store_connect", ROOT / "scripts" / "app_store_connect.py"
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class FakeClient:
    def __init__(self, responses: dict[str, list[dict[str, object]]]) -> None:
        self.responses = responses

    def list_resources(
        self, path: str, *, query: dict[str, str | int] | None = None
    ) -> list[dict[str, object]]:
        del query
        return self.responses.get(path, [])


class AppStoreConnectTest(unittest.TestCase):
    def test_base64url_is_unpadded(self) -> None:
        self.assertEqual(MODULE.base64url(b"\xff\xee"), "_-4")

    def test_der_signature_is_converted_to_fixed_width(self) -> None:
        r = bytes.fromhex("00" + "80" + "11" * 31)
        s = bytes.fromhex("01" * 32)
        sequence = b"\x02" + bytes([len(r)]) + r + b"\x02" + bytes([len(s)]) + s
        der = b"\x30" + bytes([len(sequence)]) + sequence
        raw = MODULE.der_ecdsa_signature_to_raw(der)
        self.assertEqual(len(raw), 64)
        self.assertEqual(raw[:32], bytes.fromhex("80" + "11" * 31))
        self.assertEqual(raw[32:], s)

    def test_der_signature_rejects_trailing_data(self) -> None:
        with self.assertRaises(MODULE.AppStoreConnectError):
            MODULE.der_ecdsa_signature_to_raw(
                b"\x30\x06\x02\x01\x01\x02\x01\x01\x00"
            )

    def test_next_build_uses_remote_and_local_floor(self) -> None:
        client = FakeClient(
            {
                "/v1/builds": [
                    {"attributes": {"version": "7"}},
                    {"attributes": {"version": "3"}},
                    {"attributes": {"version": "not-an-integer"}},
                ]
            }
        )
        self.assertEqual(
            MODULE.next_build_number(client, "app", "0.1.0", 5), 8
        )
        self.assertEqual(
            MODULE.next_build_number(client, "app", "0.1.0", 12), 13
        )

    def test_choose_group_prefers_existing_tester_membership(self) -> None:
        client = FakeClient(
            {
                "/v1/apps/app/betaGroups": [
                    {
                        "id": "one",
                        "attributes": {
                            "name": "First",
                            "isInternalGroup": False,
                        },
                    },
                    {
                        "id": "two",
                        "attributes": {
                            "name": "Second",
                            "isInternalGroup": False,
                        },
                    },
                ],
                "/v1/betaTesters/tester/betaGroups": [{"id": "two"}],
            }
        )
        selected = MODULE.choose_group(
            client,
            app_id="app",
            group_name=None,
            tester={"id": "tester"},
            create_if_missing=False,
        )
        self.assertEqual(selected["id"], "two")

    def test_choose_group_rejects_ambiguous_external_groups(self) -> None:
        client = FakeClient(
            {
                "/v1/apps/app/betaGroups": [
                    {
                        "id": "one",
                        "attributes": {
                            "name": "First",
                            "isInternalGroup": False,
                        },
                    },
                    {
                        "id": "two",
                        "attributes": {
                            "name": "Second",
                            "isInternalGroup": False,
                        },
                    },
                ]
            }
        )
        with self.assertRaises(MODULE.AppStoreConnectError):
            MODULE.choose_group(
                client,
                app_id="app",
                group_name=None,
                tester=None,
                create_if_missing=False,
            )


if __name__ == "__main__":
    unittest.main()
