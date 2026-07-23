#!/usr/bin/env python3

import ipaddress
import os
import pathlib
import tempfile
import unittest

import ui_guided_author


class UIAuthorSecurityTests(unittest.TestCase):
    def test_click_waits_for_an_unobstructed_native_target(self):
        class FakeDriver(ui_guided_author.WebDriver):
            def __init__(self):
                super().__init__("http://127.0.0.1:1")
                self.session = "test-session"
                self.readiness = [False, True, True]
                self.native_clicks = 0

            def execute(self, script, args=None):
                self.assert_click_argument(args)
                return self.readiness.pop(0)

            def request(self, method, path, payload=None):
                self.native_clicks += 1
                if self.native_clicks == 1:
                    raise ui_guided_author.WebDriverCommandError(
                        "intercepted",
                        "element click intercepted",
                    )
                return None

            def assert_click_argument(self, args):
                if args != [{ui_guided_author.ELEMENT_KEY: "button-id"}]:
                    raise AssertionError("click readiness did not use the exact WebDriver element")

        driver = FakeDriver()
        driver.click("button-id")
        self.assertEqual(driver.native_clicks, 2)
        self.assertEqual(driver.readiness, [])

    def test_click_rejects_noncanonical_element_identifier(self):
        driver = ui_guided_author.WebDriver("http://127.0.0.1:1")
        with self.assertRaises(ui_guided_author.ProofError):
            driver.click("../element")

    def test_network_dns_port_is_bounded_and_distinct_from_nebula(self):
        self.assertEqual(ui_guided_author.canonical_dns_proof_port(53, True), 53)
        self.assertEqual(ui_guided_author.canonical_dns_proof_port(5353, True), 5353)
        self.assertEqual(ui_guided_author.canonical_dns_proof_port(53, False), 53)
        for value, enabled in ((0, True), (65536, True), (4242, True), (5353, False), (True, True)):
            with self.subTest(value=value, enabled=enabled), self.assertRaises(ui_guided_author.ProofError):
                ui_guided_author.canonical_dns_proof_port(value, enabled)

    def test_routed_subnet_is_canonical_unicast_and_outside_overlay(self):
        overlay = ipaddress.ip_network("10.88.0.0/24")
        for value in ("172.31.250.0/24", "192.168.50.7/32"):
            with self.subTest(value=value):
                self.assertEqual(ui_guided_author.canonical_routed_subnet(value, overlay), value)
        for value in (
            "172.31.250.1/24",
            "10.88.0.0/25",
            "0.0.0.0/1",
            "127.0.0.0/8",
            "169.254.0.0/16",
            "224.0.0.0/4",
            "2001:db8::/64",
        ):
            with self.subTest(value=value), self.assertRaises(ui_guided_author.ProofError):
                ui_guided_author.canonical_routed_subnet(value, overlay)

    def test_lighthouse_endpoint_accepts_canonical_ipv4_and_dns_only(self):
        for value in ("198.51.100.4:4242", "mesh-proof-lighthouse:4242", "lh.example:65535"):
            with self.subTest(value=value):
                self.assertEqual(ui_guided_author.canonical_lighthouse_endpoint(value), value)
        for value in (
            "LH.example:4242",
            "lh.example.:4242",
            "lh..example:4242",
            "-lh.example:4242",
            "lh.example:04242",
            "lh.example:65536",
            "[2001:db8::1]:4242",
        ):
            with self.subTest(value=value), self.assertRaises(ui_guided_author.ProofError):
                ui_guided_author.canonical_lighthouse_endpoint(value)

    def test_loopback_origin_is_exact(self):
        self.assertEqual(
            ui_guided_author.canonical_loopback_url("http://127.0.0.1:18080"),
            "http://127.0.0.1:18080",
        )
        self.assertEqual(
            ui_guided_author.canonical_loopback_url("https://[::1]:18443/"),
            "https://[::1]:18443",
        )
        for value in (
            "https://mesh.example",
            "http://localhost:18080",
            "http://user@127.0.0.1:18080",
            "http://127.0.0.1:18080/path",
            "http://127.0.0.1:18080?query=1",
            "http://127.0.0.1:99999",
        ):
            with self.subTest(value=value), self.assertRaises(ui_guided_author.ProofError):
                ui_guided_author.canonical_loopback_url(value)

    def test_private_https_requires_explicit_opt_in(self):
        value = "https://172.19.0.10:18081"
        with self.assertRaises(ui_guided_author.ProofError):
            ui_guided_author.canonical_server_url(value)
        self.assertEqual(ui_guided_author.canonical_server_url(value, True), value)
        for rejected in (
            "http://172.19.0.10:18081",
            "https://172.15.0.10:18081",
            "https://192.0.2.10:18081",
            "https://private.example:18081",
        ):
            with self.subTest(value=rejected), self.assertRaises(ui_guided_author.ProofError):
                ui_guided_author.canonical_server_url(rejected, True)

    def test_dns_https_requires_explicit_opt_in_and_canonical_origin(self):
        value = "https://mesh.example.com"
        with self.assertRaises(ui_guided_author.ProofError):
            ui_guided_author.canonical_server_url(value)
        self.assertEqual(
            ui_guided_author.canonical_server_url(value, allow_dns_https=True),
            value,
        )
        self.assertEqual(
            ui_guided_author.canonical_server_url(value + "/", allow_dns_https=True),
            value,
        )
        for rejected in (
            "http://mesh.example.com",
            "https://Mesh.example.com",
            "https://mesh.example.com:443",
            "https://mesh.example.com/path",
            "https://mesh..example.com",
            "https://-mesh.example.com",
            "https://mesh.example.com.",
            "https://user@mesh.example.com",
        ):
            with self.subTest(value=rejected), self.assertRaises(ui_guided_author.ProofError):
                ui_guided_author.canonical_server_url(rejected, allow_dns_https=True)

    def test_private_token_rejects_mode_and_link_ambiguity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            os.chmod(root, 0o700)
            token_path = root / "admin.token"
            token_path.write_text("a" * 43 + "\n", encoding="ascii")
            os.chmod(token_path, 0o600)
            self.assertEqual(ui_guided_author.read_private_token(token_path), "a" * 43)
            os.chmod(token_path, 0o640)
            with self.assertRaises(ui_guided_author.ProofError):
                ui_guided_author.read_private_token(token_path)
            os.chmod(token_path, 0o600)
            link_path = root / "linked.token"
            link_path.symlink_to(token_path)
            with self.assertRaises(ui_guided_author.ProofError):
                ui_guided_author.read_private_token(link_path)
            token_path.write_text(" " + "a" * 43 + "\n", encoding="ascii")
            with self.assertRaises(ui_guided_author.ProofError):
                ui_guided_author.read_private_token(token_path)

    def test_private_oidc_credential_rejects_mode_link_and_delimiter_ambiguity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            os.chmod(root, 0o700)
            credential_path = root / "password"
            credential_path.write_text("correct horse battery staple\n", encoding="utf-8")
            os.chmod(credential_path, 0o600)
            self.assertEqual(
                ui_guided_author.read_private_credential(
                    credential_path,
                    "OIDC password",
                    128,
                ),
                "correct horse battery staple",
            )
            os.chmod(credential_path, 0o640)
            with self.assertRaises(ui_guided_author.ProofError):
                ui_guided_author.read_private_credential(credential_path, "OIDC password", 128)
            os.chmod(credential_path, 0o600)
            link_path = root / "linked-password"
            link_path.symlink_to(credential_path)
            with self.assertRaises(ui_guided_author.ProofError):
                ui_guided_author.read_private_credential(link_path, "OIDC password", 128)
            credential_path.write_bytes(b"line-one\nline-two")
            with self.assertRaises(ui_guided_author.ProofError):
                ui_guided_author.read_private_credential(credential_path, "OIDC password", 128)

    def test_json_publication_is_private_create_only(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            os.chmod(root, 0o700)
            ui_guided_author.require_private_directory(root)
            ui_guided_author.write_new_json(root, "result.json", {"value": 1})
            path = root / "result.json"
            self.assertEqual(path.read_bytes(), b'{"value":1}\n')
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                ui_guided_author.write_new_json(root, "result.json", {"value": 2})


if __name__ == "__main__":
    unittest.main()
