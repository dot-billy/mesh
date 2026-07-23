#!/usr/bin/env python3

"""Author one Mesh network and two nodes through the real browser UI.

The script intentionally uses only the Python standard library and the W3C
WebDriver protocol. Authentication material is read from private files and is
never placed in argv or output. Enrollment credentials are written only to
create-only mode-0600 files in a caller-owned mode-0700 directory.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import pathlib
import re
import shutil
import socket
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


ELEMENT_KEY = "element-6066-11e4-a52e-4f735466cecf"
MAX_WEBDRIVER_RESPONSE = 1 << 20
TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9_-]{43}$")
ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]+$")
NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")
TOPOLOGY_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{0,62}$")
RESULT_SCHEMA = "mesh-ui-guided-author-result-v2"


class ProofError(RuntimeError):
    pass


def canonical_lighthouse_endpoint(value: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 261 or value.count(":") != 1:
        raise ProofError("lighthouse endpoint is not canonical")
    host, port = value.rsplit(":", 1)
    if not port.isascii() or not port.isdigit() or str(int(port)) != port or not 1 <= int(port) <= 65535:
        raise ProofError("lighthouse endpoint is not canonical")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        if len(host) > 253 or host != host.lower() or host.endswith("."):
            raise ProofError("lighthouse endpoint is not canonical")
        labels = host.split(".")
        if any(
            not 1 <= len(label) <= 63
            or label.startswith("-")
            or label.endswith("-")
            or re.fullmatch(r"[a-z0-9-]+", label) is None
            for label in labels
        ):
            raise ProofError("lighthouse endpoint is not canonical")
    else:
        if address.version != 4 or str(address) != host:
            raise ProofError("lighthouse endpoint is not canonical")
    return value


def canonical_routed_subnet(value: str, overlay: ipaddress.IPv4Network) -> str:
    try:
        subnet = ipaddress.ip_network(value, strict=True)
    except ValueError as error:
        raise ProofError("lighthouse routed subnet is not canonical") from error
    if not isinstance(subnet, ipaddress.IPv4Network) or str(subnet) != value or subnet.prefixlen < 1:
        raise ProofError("lighthouse routed subnet is not canonical IPv4")
    if (
        subnet.overlaps(overlay)
        or subnet.network_address.is_unspecified
        or subnet.network_address.is_loopback
        or subnet.network_address.is_link_local
        or subnet.network_address.is_multicast
        or subnet.network_address.is_reserved
    ):
        raise ProofError("lighthouse routed subnet is unsafe or overlaps the overlay")
    return value


def canonical_dns_proof_port(value: int, enabled: bool, nebula_port: int = 4242) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
        raise ProofError("network DNS proof port is invalid")
    if enabled and value == nebula_port:
        raise ProofError("network DNS proof port conflicts with Nebula UDP")
    if not enabled and value != 53:
        raise ProofError("disabled network DNS must retain port 53")
    return value


def canonical_server_url(
    value: str,
    allow_private_https: bool = False,
    allow_dns_https: bool = False,
) -> str:
    if not isinstance(value, str) or not value or len(value) > 256:
        raise ProofError("server URL is missing or oversized")
    try:
        parsed = urllib.parse.urlsplit(value)
    except ValueError as error:
        raise ProofError("server URL is invalid") from error
    if parsed.scheme not in {"http", "https"} or parsed.username is not None or parsed.password is not None:
        raise ProofError("server URL must be HTTP(S) without credentials")
    try:
        port = parsed.port
    except ValueError as error:
        raise ProofError("server URL has an invalid port") from error
    try:
        address = ipaddress.ip_address(parsed.hostname or "")
    except ValueError as error:
        if not allow_dns_https:
            raise ProofError("server URL must use a numeric IP address") from error
        hostname = parsed.hostname or ""
        if (
            parsed.scheme != "https"
            or port is not None
            or hostname != hostname.lower()
            or len(hostname) > 253
            or hostname.endswith(".")
            or any(
                not 1 <= len(label) <= 63
                or label.startswith("-")
                or label.endswith("-")
                or re.fullmatch(r"[a-z0-9-]+", label) is None
                for label in hostname.split(".")
            )
        ):
            raise ProofError("DNS server URL must be a canonical HTTPS origin without an explicit port") from error
        if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
            raise ProofError("server URL must be an origin without path, query, or fragment")
        canonical = f"https://{hostname}"
        if value.rstrip("/") != canonical:
            raise ProofError("server URL is not canonical")
        return canonical
    if port is None:
        raise ProofError("numeric server URL must use an explicit port")
    loopback = address.is_loopback
    private_v4 = isinstance(address, ipaddress.IPv4Address) and any(
        address in network
        for network in (
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
        )
    )
    if not loopback and not (allow_private_https and parsed.scheme == "https" and private_v4):
        raise ProofError("server URL must use loopback HTTP(S) or explicitly allowed private IPv4 HTTPS")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ProofError("server URL must be an origin without path, query, or fragment")
    canonical_host = f"[{address.compressed}]" if isinstance(address, ipaddress.IPv6Address) else address.compressed
    canonical = f"{parsed.scheme}://{canonical_host}:{port}"
    if value.rstrip("/") != canonical:
        raise ProofError("server URL is not canonical")
    return canonical


def canonical_loopback_url(value: str) -> str:
    return canonical_server_url(value)


def require_private_directory(path: pathlib.Path) -> None:
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ProofError("output directory must be a real effective-user-owned mode-0700 directory")


def read_private_token(path: pathlib.Path) -> str:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
        raise ProofError("administrator token file must be an effective-user-owned single-link mode-0600 regular file")
    if info.st_size < 1 or info.st_size > 256:
        raise ProofError("administrator token file has an invalid size")
    with path.open("rb") as source:
        raw = source.read(257)
        after = os.fstat(source.fileno())
    current = path.lstat()
    if len(raw) > 256 or (info.st_dev, info.st_ino, info.st_size) != (after.st_dev, after.st_ino, after.st_size):
        raise ProofError("administrator token changed while reading")
    if (after.st_dev, after.st_ino, after.st_size) != (current.st_dev, current.st_ino, current.st_size):
        raise ProofError("administrator token path changed while reading")
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as error:
        raise ProofError("administrator token is not ASCII") from error
    if text.endswith("\n"):
        text = text[:-1]
    if not text or any(character in text for character in "\r\n\t "):
        raise ProofError("administrator token file is not in exact token-plus-optional-LF form")
    token = text
    if not TOKEN_PATTERN.fullmatch(token):
        raise ProofError("administrator token is not canonical")
    return token


def read_private_credential(path: pathlib.Path, label: str, maximum_bytes: int) -> str:
    if not label or maximum_bytes < 1 or maximum_bytes > 4096:
        raise ProofError("private credential reader configuration is invalid")
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
        raise ProofError(f"{label} file must be an effective-user-owned single-link mode-0600 regular file")
    if info.st_size < 1 or info.st_size > maximum_bytes + 1:
        raise ProofError(f"{label} file has an invalid size")
    with path.open("rb") as source:
        raw = source.read(maximum_bytes + 2)
        after = os.fstat(source.fileno())
    current = path.lstat()
    identity = (info.st_dev, info.st_ino, info.st_size)
    if len(raw) > maximum_bytes + 1 or identity != (after.st_dev, after.st_ino, after.st_size):
        raise ProofError(f"{label} changed while reading")
    if identity != (current.st_dev, current.st_ino, current.st_size):
        raise ProofError(f"{label} path changed while reading")
    if raw.endswith(b"\n"):
        raw = raw[:-1]
    if not raw or len(raw) > maximum_bytes or b"\x00" in raw or b"\r" in raw or b"\n" in raw:
        raise ProofError(f"{label} is empty, oversized, or contains a control delimiter")
    try:
        value = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ProofError(f"{label} is not UTF-8") from error
    if any(not character.isprintable() for character in value):
        raise ProofError(f"{label} contains a non-printable character")
    return value


def write_new_json(directory: pathlib.Path, name: str, value: object) -> None:
    if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,63}\.json", name):
        raise ProofError("output filename is not canonical")
    raw = (json.dumps(value, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8")
    path = directory / name
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
    finally:
        os.close(descriptor)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
        raise ProofError("published UI proof output is not a private regular file")


class WebDriver:
    def __init__(self, endpoint: str):
        self.endpoint = endpoint
        self.session = ""

    def request(self, method: str, path: str, payload: object | None = None) -> object:
        body = None if payload is None else json.dumps(payload, separators=(",", ":")).encode("utf-8")
        request = urllib.request.Request(
            self.endpoint + path,
            data=body,
            method=method,
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                raw = response.read(MAX_WEBDRIVER_RESPONSE + 1)
        except urllib.error.HTTPError as error:
            try:
                raw_error = error.read(MAX_WEBDRIVER_RESPONSE + 1)
                remote = json.loads(raw_error).get("value", {}).get("error", "unknown")
            except Exception:
                remote = "unknown"
            safe_path = re.sub(r"/session/[^/]+", "/session/<id>", path)
            raise ProofError(f"WebDriver {method} {safe_path} failed with HTTP {error.code} ({remote})") from error
        except (urllib.error.URLError, TimeoutError) as error:
            safe_path = re.sub(r"/session/[^/]+", "/session/<id>", path)
            raise ProofError(f"WebDriver {method} {safe_path} did not complete") from error
        if len(raw) > MAX_WEBDRIVER_RESPONSE:
            raise ProofError("WebDriver response exceeded its size bound")
        try:
            document = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ProofError("WebDriver returned invalid JSON") from error
        if not isinstance(document, dict) or set(document) != {"value"}:
            raise ProofError("WebDriver returned an unexpected response shape")
        return document["value"]

    def start(self) -> None:
        value = self.request(
            "POST",
            "/session",
            {
                "capabilities": {
                    "alwaysMatch": {
                        "browserName": "firefox",
                        "acceptInsecureCerts": True,
                        "moz:firefoxOptions": {"args": ["-headless"]},
                    }
                }
            },
        )
        if not isinstance(value, dict) or not ID_PATTERN.fullmatch(str(value.get("sessionId", ""))):
            raise ProofError("WebDriver did not create a canonical session")
        self.session = str(value["sessionId"])

    def close(self) -> None:
        if not self.session:
            return
        try:
            self.request("DELETE", f"/session/{self.session}")
        except ProofError:
            pass
        self.session = ""

    @property
    def prefix(self) -> str:
        if not self.session:
            raise ProofError("WebDriver session is not active")
        return f"/session/{self.session}"

    def navigate(self, url: str) -> None:
        self.request("POST", self.prefix + "/url", {"url": url})

    def find(self, using: str, value: str, root: str = "") -> str:
        path = self.prefix + (f"/element/{root}/element" if root else "/element")
        result = self.request("POST", path, {"using": using, "value": value})
        if not isinstance(result, dict) or not isinstance(result.get(ELEMENT_KEY), str):
            raise ProofError("WebDriver did not return an element")
        return result[ELEMENT_KEY]

    def displayed(self, element: str) -> bool:
        value = self.request("GET", self.prefix + f"/element/{element}/displayed")
        if not isinstance(value, bool):
            raise ProofError("WebDriver returned a non-boolean visibility value")
        return value

    def click(self, element: str) -> None:
        self.request("POST", self.prefix + f"/element/{element}/click", {})

    def clear(self, element: str) -> None:
        self.request("POST", self.prefix + f"/element/{element}/clear", {})

    def type(self, element: str, value: str) -> None:
        self.request("POST", self.prefix + f"/element/{element}/value", {"text": value, "value": list(value)})

    def text(self, element: str) -> str:
        value = self.request("GET", self.prefix + f"/element/{element}/text")
        if not isinstance(value, str) or len(value) > 8192:
            raise ProofError("WebDriver returned invalid element text")
        return value

    def execute_async(self, script: str, args: list | None = None) -> object:
        return self.request("POST", self.prefix + "/execute/async", {"script": script, "args": args or []})

    def execute(self, script: str, args: list | None = None) -> object:
        return self.request("POST", self.prefix + "/execute/sync", {"script": script, "args": args or []})


def wait_until(deadline: float, operation, label: str):
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            result = operation()
            if result:
                return result
        except ProofError as error:
            last_error = error
        time.sleep(0.05)
    raise ProofError(f"timed out waiting for {label}") from last_error


def wait_element(driver: WebDriver, deadline: float, using: str, selector: str, visible: bool = True) -> str:
    def locate():
        element = driver.find(using, selector)
        return element if driver.displayed(element) is visible else ""

    return wait_until(deadline, locate, selector)


def fill(driver: WebDriver, selector: str, value: str, deadline: float) -> None:
    element = wait_element(driver, deadline, "css selector", selector)
    driver.clear(element)
    driver.type(element, value)


def submit_shadow_input(driver: WebDriver, selector: str, value: str) -> None:
    result = driver.execute(
        """
const deepAll = (selector) => {
  const result = [];
  const walk = (root) => {
    result.push(...root.querySelectorAll(selector));
    for (const element of root.querySelectorAll('*')) {
      if (element.shadowRoot) walk(element.shadowRoot);
    }
  };
  walk(document);
  return result;
};
const visible = (element) => {
  const rect = element.getBoundingClientRect();
  const style = getComputedStyle(element);
  return rect.width > 0 && rect.height > 0 && rect.right > 0 && rect.bottom > 0 &&
    rect.left < innerWidth && rect.top < innerHeight && style.display !== 'none' &&
    style.visibility !== 'hidden';
};
const input = deepAll(arguments[0]).find(visible);
if (!input) return 'input-not-found';
const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
input.focus();
setter.call(input, arguments[1]);
input.dispatchEvent(new InputEvent('input', {
  bubbles: true,
  composed: true,
  inputType: 'insertText',
  data: arguments[1],
}));
input.dispatchEvent(new Event('change', {bubbles: true, composed: true}));
const form = input.closest('form');
if (!form) return 'form-not-found';
form.requestSubmit();
return 'submitted';
""",
        [selector, value],
    )
    if result != "submitted":
        raise ProofError(f"OIDC provider form submission failed: {result}")


def oidc_shadow_input_present(driver: WebDriver, selector: str) -> bool:
    return (
        driver.execute(
            """
const selector = arguments[0];
const walk = (root) => {
  for (const element of root.querySelectorAll('*')) {
    if (element.matches(selector)) {
      const rect = element.getBoundingClientRect();
      if (rect.width > 0 && rect.height > 0 && rect.right > 0 && rect.bottom > 0) return true;
    }
    if (element.shadowRoot && walk(element.shadowRoot)) return true;
  }
  return false;
};
return walk(document);
""",
            [selector],
        )
        is True
    )


def sign_in_with_oidc(
    driver: WebDriver,
    server_url: str,
    username: str,
    password: str,
    expected_group: str,
    deadline: float,
) -> None:
    driver.click(wait_element(driver, deadline, "css selector", "#oidc-login"))
    wait_until(
        deadline,
        lambda: driver.execute("return location.origin !== arguments[0];", [server_url]) is True,
        "OIDC provider redirect",
    )
    wait_until(
        deadline,
        lambda: oidc_shadow_input_present(driver, "#ak-identifier-input"),
        "OIDC identifier input",
    )
    submit_shadow_input(driver, "#ak-identifier-input", username)
    username = ""
    wait_until(
        deadline,
        lambda: oidc_shadow_input_present(driver, "input[type=password]"),
        "OIDC password input",
    )
    submit_shadow_input(driver, "input[type=password]", password)
    password = ""
    wait_until(
        deadline,
        lambda: driver.execute(
            "return location.origin === arguments[0] && !document.getElementById('app-view')?.classList.contains('hidden');",
            [server_url],
        )
        is True,
        "OIDC callback and authenticated Mesh workspace",
    )
    session = driver.execute_async(
        """
const done = arguments[arguments.length - 1];
fetch('/api/v1/session', {credentials: 'same-origin'})
  .then(async (response) => done({status: response.status, body: await response.json()}))
  .catch(() => done({status: 0, body: null}));
"""
    )
    if not isinstance(session, dict) or session.get("status") != 200 or not isinstance(session.get("body"), dict):
        raise ProofError("OIDC browser session could not read its authenticated identity")
    body = session["body"]
    principal = body.get("principal")
    expected_permissions = {
        "networks.read",
        "networks.write",
        "networks.security",
        "identity.manage",
        "audit.read",
    }
    if (
        body.get("authenticated") is not True
        or body.get("auth_method") != "oidc"
        or body.get("role") != "admin"
        or set(body.get("permissions", [])) != expected_permissions
        or not isinstance(principal, dict)
        or principal.get("kind") != "oidc_admin"
        or "pwd" not in principal.get("amr", [])
    ):
        raise ProofError("OIDC browser session did not resolve to the required administrator policy")
    if expected_group and expected_group not in principal.get("groups", []):
        raise ProofError("OIDC browser session omitted the expected administrator group")


def reveal_enrollment_token(driver: WebDriver, deadline: float) -> str:
    wait_element(driver, deadline, "css selector", "#enroll-dialog")
    token_element = driver.find("css selector", "#enroll-token")
    if not driver.displayed(token_element):
        driver.click(wait_element(driver, deadline, "css selector", "#enroll-dialog details summary"))
        token_element = wait_element(driver, deadline, "css selector", "#enroll-token")
    token = wait_until(deadline, lambda: driver.text(token_element), "enrollment token text")
    if not TOKEN_PATTERN.fullmatch(token):
        raise ProofError("enrollment token is not canonical")
    return token


def read_install_guidance(
    driver: WebDriver,
    deadline: float,
    allow_offline: bool,
) -> str:
    command = driver.find("css selector", "#install-command")
    if driver.displayed(command):
        value = wait_until(deadline, lambda: driver.text(command), "online install command")
        if "install-online" not in value:
            raise ProofError("online install guidance omitted the supported install command")
        return value
    if not allow_offline:
        raise ProofError("online installation is unavailable; rerun with --allow-offline-install-guide only for a preinstalled proof host")
    unavailable = driver.text(
        wait_element(driver, deadline, "css selector", "#install-unavailable")
    )
    if "Online installation is not configured on this server" not in unavailable:
        raise ProofError("offline install guidance did not explain the missing online origin")
    return ""


def network_workspace_xpath(network_name: str) -> str:
    if not NAME_PATTERN.fullmatch(network_name):
        raise ProofError("network name is not canonical")
    return (
        "//section[contains(concat(' ',normalize-space(@class),' '),' network-workspace ')]"
        f"[.//h2[@id='workspace-network-title' and normalize-space(.)='{network_name}']]"
    )


def wait_network_workspace(driver: WebDriver, deadline: float, network_name: str) -> str:
    workspace_xpath = network_workspace_xpath(network_name)
    return wait_element(driver, deadline, "xpath", workspace_xpath)


def open_network_directory(driver: WebDriver, deadline: float) -> None:
    new_network_visible = driver.execute(
        """
const button = document.getElementById('new-network');
if (!button) return false;
const rect = button.getBoundingClientRect();
return !button.classList.contains('hidden') && rect.width > 0 && rect.height > 0;
"""
    )
    if new_network_visible is True:
        return
    driver.click(
        wait_element(
            driver,
            deadline,
            "css selector",
            ".network-workspace .workspace-back",
        )
    )
    wait_element(driver, deadline, "css selector", "#new-network")


def select_network_workspace(
    driver: WebDriver,
    deadline: float,
    network_name: str,
) -> None:
    if driver.execute(
        "return document.getElementById('workspace-network-title')?.textContent.trim() === arguments[0];",
        [network_name],
    ) is not True:
        driver.click(
            wait_element(
                driver,
                deadline,
                "xpath",
                "//article[contains(concat(' ',normalize-space(@class),' '),' network-directory-row ')]"
                "//button[contains(concat(' ',normalize-space(@class),' '),' network-directory-open ')]"
                f"[.//strong[normalize-space(.)={json.dumps(network_name)}]]",
            )
        )
    wait_network_workspace(driver, deadline, network_name)


def open_workspace_setting(
    driver: WebDriver,
    deadline: float,
    network_name: str,
    label: str,
) -> None:
    wait_network_workspace(driver, deadline, network_name)
    wait_element(
        driver,
        deadline,
        "css selector",
        ".network-workspace .network-settings",
    )
    is_open = driver.execute(
        "return document.querySelector('.network-workspace .network-settings')?.open === true;"
    )
    if is_open is not True:
        driver.click(
            wait_element(
                driver,
                deadline,
                "css selector",
                ".network-workspace .network-settings > summary",
            )
        )
    wait_until(
        deadline,
        lambda: driver.execute(
            "return document.querySelector('.network-workspace .network-settings')?.open === true;"
        )
        is True,
        "open network settings",
    )
    driver.click(
        wait_element(
            driver,
            deadline,
            "xpath",
            network_workspace_xpath(network_name)
            + f"//details[contains(concat(' ',normalize-space(@class),' '),' network-settings ')]"
            + f"//button[normalize-space(.)={json.dumps(label)}]",
        )
    )


def verify_pending_readiness(driver: WebDriver, deadline: float, network_name: str, lighthouse_name: str, endpoint: str, site: str, failure_domain: str, already_open: bool = False, leave_open: bool = False) -> None:
    if not already_open:
        open_workspace_setting(driver, deadline, network_name, "Deployment readiness")
    wait_element(driver, deadline, "css selector", "#readiness-dialog")
    overall = wait_until(
        deadline,
        lambda: driver.text(driver.find("css selector", "#readiness-overall")) == "BLOCKED",
        "blocked pending-network readiness",
    )
    if overall is not True:
        raise ProofError("pending readiness did not render its blocked overall result")
    checks = driver.text(wait_element(driver, deadline, "css selector", "#readiness-check-list"))
    for required in (
        "Managed CIDR collision\nPASS",
        "Client route collision\nNOT OBSERVED",
        "Lighthouse redundancy\nBLOCKED",
        "Site and failure-domain diversity\nNEEDS ATTENTION",
        "Lighthouse DNS\nPASS",
        "Member-side DNS\nNOT OBSERVED",
        "Public UDP reachability\nNOT OBSERVED",
        "A configured endpoint and successful DNS lookup do not prove that public UDP packets reach Nebula.",
        "Allow each public endpoint's UDP port and forward it to Nebula UDP 4242",
    ):
        if required not in checks:
            raise ProofError(f"pending readiness omitted {required.splitlines()[0]}")
    lighthouse_evidence = driver.text(
        wait_element(driver, deadline, "css selector", "#readiness-lighthouse-section")
    )
    endpoint_host = endpoint.rsplit(":", 1)[0]
    try:
        ipaddress.ip_address(endpoint_host)
    except ValueError:
        endpoint_evidence = "DNS resolved to "
    else:
        endpoint_evidence = "IPV4 literal; DNS not required"
    for required in (lighthouse_name, endpoint, endpoint_evidence, "PENDING"):
        if required not in lighthouse_evidence:
            raise ProofError("pending readiness omitted exact lighthouse endpoint evidence")
    declared_site = driver.text(wait_element(driver, deadline, "css selector", "#readiness-site-section"))
    for required in (site, failure_domain, "0/1 active", "0 lighthouses"):
        if required not in declared_site:
            raise ProofError("pending readiness omitted exact declared site grouping")
    add_lighthouse = wait_element(driver, deadline, "css selector", "#readiness-add-lighthouse:not(.hidden)")
    if driver.text(add_lighthouse).strip().lower() != "add second lighthouse":
        raise ProofError("single-lighthouse readiness did not offer the second-lighthouse remediation")
    wait_until(
        deadline,
        lambda: driver.execute("return document.getElementById('readiness-dialog').dataset.autoRefreshScheduled === 'true';") is True,
        "scheduled readiness refresh",
    )
    if not leave_open:
        driver.click(wait_element(driver, deadline, "css selector", "#readiness-dialog .close-dialog"))


def configure_network_dns(
    driver: WebDriver,
    deadline: float,
    network_name: str,
    listen_port: int,
    native_resolver: bool,
    search_domain: str,
) -> None:
    open_workspace_setting(driver, deadline, network_name, "Network DNS")
    wait_element(driver, deadline, "css selector", "#dns-dialog[open]")
    initial = driver.execute(
        "return {enabled: document.getElementById('dns-enabled').checked, port: document.getElementById('dns-listen-port').value, native: document.getElementById('dns-native-resolver').checked, domain: document.getElementById('dns-search-domain').value, firewall: document.getElementById('dns-firewall-state').textContent};"
    )
    if not isinstance(initial, dict) or initial.get("enabled") is not False or initial.get("port") != "53" or initial.get("native") is not False or initial.get("domain") != "" or "Firewall permits UDP 53" not in str(initial.get("firewall", "")):
        raise ProofError("network DNS dialog did not load the safe disabled default")
    driver.click(wait_element(driver, deadline, "css selector", "#dns-enabled"))
    fill(driver, "#dns-listen-port", str(listen_port), deadline)
    if native_resolver:
        driver.click(wait_element(driver, deadline, "css selector", "#dns-native-resolver"))
        fill(driver, "#dns-search-domain", search_domain, deadline)
    driver.click(wait_element(driver, deadline, "css selector", "#save-dns:not(:disabled)"))
    wait_until(
        deadline,
        lambda: driver.execute("return document.getElementById('dns-dialog').open;") is False,
        "network DNS deployment",
    )
    wait_network_workspace(driver, deadline, network_name)
    open_workspace_setting(driver, deadline, network_name, "Network DNS")
    wait_element(driver, deadline, "css selector", "#dns-dialog[open]")
    configured = wait_until(
        deadline,
        lambda: driver.execute(
            "return {enabled: document.getElementById('dns-enabled').checked, port: document.getElementById('dns-listen-port').value, native: document.getElementById('dns-native-resolver').checked, domain: document.getElementById('dns-search-domain').value, firewall: document.getElementById('dns-firewall-state').textContent, resolvers: document.getElementById('dns-resolver-list').textContent};"
        ),
        "network DNS readback",
    )
    if (
        not isinstance(configured, dict)
        or configured.get("enabled") is not True
        or configured.get("port") != str(listen_port)
        or configured.get("native") is not native_resolver
        or configured.get("domain") != (search_domain if native_resolver else "")
        or f"Firewall permits UDP {listen_port}" not in str(configured.get("firewall", ""))
        or "No active lighthouse is available yet" not in str(configured.get("resolvers", ""))
    ):
        raise ProofError("network DNS dialog did not verify the deployed pending-resolver state")
    driver.click(wait_element(driver, deadline, "css selector", "#dns-dialog .close-dialog"))


def configure_network_relays(driver: WebDriver, deadline: float, network_name: str, relay_node_name: str) -> None:
    open_workspace_setting(driver, deadline, network_name, "Network relays")
    wait_element(driver, deadline, "css selector", "#relay-dialog[open]")
    initial = wait_until(
        deadline,
        lambda: driver.execute(
            "return {enabled: document.getElementById('relay-enabled').checked, active: document.getElementById('relay-active-state').textContent, candidates: document.getElementById('relay-candidate-list').textContent};"
        ),
        "network relay safe default",
    )
    if (
        not isinstance(initial, dict)
        or initial.get("enabled") is not False
        or "Managed relays disabled" not in str(initial.get("active", ""))
        or relay_node_name not in str(initial.get("candidates", ""))
    ):
        raise ProofError("network relay dialog did not load the safe disabled default and exact candidate")
    driver.click(wait_element(driver, deadline, "css selector", "#relay-enabled"))
    relay_checkbox = wait_element(
        driver,
        deadline,
        "xpath",
        f"//div[@id='relay-candidate-list']/label[.//strong[normalize-space(.)={json.dumps(relay_node_name)}]]/input[@type='checkbox']",
    )
    driver.click(relay_checkbox)
    if driver.text(wait_element(driver, deadline, "css selector", "#relay-selection-count")).strip() != "1 of 8 selected":
        raise ProofError("network relay selection did not expose its exact bound")
    driver.click(wait_element(driver, deadline, "css selector", "#save-relays:not(:disabled)"))
    wait_until(
        deadline,
        lambda: driver.execute("return document.getElementById('relay-dialog').open;") is False,
        "network relay deployment",
    )
    wait_network_workspace(driver, deadline, network_name)
    open_workspace_setting(driver, deadline, network_name, "Network relays")
    wait_element(driver, deadline, "css selector", "#relay-dialog[open]")
    configured = wait_until(
        deadline,
        lambda: driver.execute(
            "return {enabled: document.getElementById('relay-enabled').checked, active: document.getElementById('relay-active-state').textContent, selected: [...document.querySelectorAll('#relay-candidate-list input:checked')].map((input) => input.closest('label').querySelector('strong').textContent), addresses: document.getElementById('relay-active-list').textContent};"
        ),
        "network relay readback",
    )
    if (
        not isinstance(configured, dict)
        or configured.get("enabled") is not True
        or configured.get("selected") != [relay_node_name]
        or "0 of 1 selected relays active" not in str(configured.get("active", ""))
        or "No selected relay is active yet" not in str(configured.get("addresses", ""))
    ):
        raise ProofError("network relay dialog did not verify the deployed pending-relay state")
    driver.click(wait_element(driver, deadline, "css selector", "#relay-dialog .close-dialog"))


def exercise_redundancy_remediation(driver: WebDriver, deadline: float, args: argparse.Namespace, prior_tokens: tuple[str, str]) -> None:
    driver.click(wait_element(driver, deadline, "css selector", "#readiness-add-lighthouse:not(.hidden)"))
    wait_element(driver, deadline, "css selector", "#node-dialog[open]")
    if driver.execute("return document.getElementById('readiness-dialog').dataset.autoRefreshScheduled || '';") != "":
        raise ProofError("closing readiness did not cancel its scheduled refresh")
    if driver.text(wait_element(driver, deadline, "css selector", "#node-dialog-eyebrow")).strip().lower() != "readiness remediation":
        raise ProofError("second-lighthouse action did not open readiness remediation")
    if driver.text(wait_element(driver, deadline, "css selector", "#node-dialog-title")).strip().lower() != "add a second lighthouse":
        raise ProofError("readiness remediation did not require a second lighthouse")
    if driver.execute("return document.getElementById('node-role').value;") != "lighthouse":
        raise ProofError("readiness remediation did not select the lighthouse role")
    if driver.execute("return document.getElementById('node-role').disabled;") is not True:
        raise ProofError("readiness remediation did not lock the lighthouse role")
    fill(driver, "#node-name", args.backup_lighthouse_name, deadline)
    fill(driver, "#node-site", args.backup_lighthouse_site, deadline)
    fill(driver, "#node-failure-domain", args.backup_lighthouse_failure_domain, deadline)
    fill(driver, "#node-endpoint", args.backup_lighthouse_endpoint, deadline)
    driver.click(wait_element(driver, deadline, "css selector", "#node-form button[type=submit]"))
    backup_token = reveal_enrollment_token(driver, deadline)
    if backup_token in prior_tokens:
        raise ProofError("second-lighthouse enrollment token was reused")
    check_readiness = wait_element(driver, deadline, "css selector", "#enroll-next:not(.hidden)")
    if "check readiness" not in driver.text(check_readiness).strip().lower():
        raise ProofError("second-lighthouse enrollment omitted its readiness return")
    driver.click(check_readiness)
    wait_element(driver, deadline, "css selector", "#readiness-dialog[open]")
    if driver.execute("return ['enroll-node-name','install-command','enroll-command','activate-command','enroll-token'].every((id) => document.getElementById(id).textContent === '');") is not True:
        raise ProofError("second-lighthouse readiness return did not scrub its enrollment disclosure")

    def refreshed_redundancy():
        evidence = driver.text(driver.find("css selector", "#readiness-lighthouse-section"))
        add_button = driver.find("css selector", "#readiness-add-lighthouse")
        return args.backup_lighthouse_name in evidence and args.backup_lighthouse_endpoint in evidence and not driver.displayed(add_button)

    wait_until(deadline, refreshed_redundancy, "refreshed two-lighthouse readiness")
    wait_until(
        deadline,
        lambda: driver.execute("return document.getElementById('readiness-dialog').dataset.autoRefreshScheduled === 'true';") is True,
        "rescheduled readiness refresh",
    )
    checks = driver.text(wait_element(driver, deadline, "css selector", "#readiness-check-list"))
    if "Lighthouse redundancy\nBLOCKED" not in checks:
        raise ProofError("pending second lighthouse fabricated active redundancy")
    sites = driver.text(wait_element(driver, deadline, "css selector", "#readiness-site-section"))
    for required in (args.backup_lighthouse_site, args.backup_lighthouse_failure_domain):
        if required not in sites:
            raise ProofError("second-lighthouse readiness omitted its declared placement")
    driver.click(wait_element(driver, deadline, "css selector", "#readiness-dialog .close-dialog"))
    backup_token = ""


def fetch_inventory(driver: WebDriver) -> dict:
    script = """
const done = arguments[arguments.length - 1];
(async () => {
  const networksResponse = await fetch('/api/v1/networks', {credentials: 'same-origin'});
  if (!networksResponse.ok) throw new Error('networks');
  const networks = await networksResponse.json();
  const nodes = {};
  const dns = {};
  const relays = {};
  for (const network of networks) {
    const response = await fetch(`/api/v1/networks/${network.id}/nodes`, {credentials: 'same-origin'});
    if (!response.ok) throw new Error('nodes');
    nodes[network.id] = await response.json();
    const dnsResponse = await fetch(`/api/v1/networks/${network.id}/dns`, {credentials: 'same-origin'});
    if (!dnsResponse.ok) throw new Error('dns');
    dns[network.id] = await dnsResponse.json();
    const relayResponse = await fetch(`/api/v1/networks/${network.id}/relays`, {credentials: 'same-origin'});
    if (!relayResponse.ok) throw new Error('relays');
    relays[network.id] = await relayResponse.json();
  }
  done({ok: true, networks, nodes, dns, relays});
})().catch(() => done({ok: false}));
"""
    result = driver.execute_async(script)
    if not isinstance(result, dict) or result.get("ok") is not True:
        raise ProofError("browser session could not read back created inventory")
    if not isinstance(result.get("networks"), list) or not isinstance(result.get("nodes"), dict) or not isinstance(result.get("dns"), dict) or not isinstance(result.get("relays"), dict):
        raise ProofError("browser inventory readback has an invalid shape")
    return result


def find_exact(items: list, field: str, expected: str, label: str) -> dict:
    matches = [item for item in items if isinstance(item, dict) and item.get(field) == expected]
    if len(matches) != 1:
        raise ProofError(f"browser inventory does not contain exactly one {label}")
    return matches[0]


def validate_node(node: dict, network_id: str, name: str, role: str, site: str, failure_domain: str, endpoint: str = "", routed_subnets: list[str] | None = None) -> None:
    if not ID_PATTERN.fullmatch(str(node.get("id", ""))) or node.get("network_id") != network_id:
        raise ProofError(f"{role} node identity is invalid")
    if node.get("name") != name or node.get("role") != role:
        raise ProofError(f"{role} node readback differs from the UI input")
    if node.get("site") != site or node.get("failure_domain") != failure_domain:
        raise ProofError(f"{role} topology readback differs from the UI input")
    if endpoint and node.get("public_endpoint") != endpoint:
        raise ProofError("lighthouse endpoint readback differs from the UI input")
    if node.get("routed_subnets", []) != (routed_subnets or []):
        raise ProofError(f"{role} routed-subnet readback differs from the UI input")
    try:
        socket.inet_aton(str(node.get("ip", "")))
    except OSError as error:
        raise ProofError(f"{role} node has an invalid overlay address") from error


def reserve_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--server-url", required=True)
    authentication = parser.add_mutually_exclusive_group(required=True)
    authentication.add_argument("--admin-token-file")
    authentication.add_argument("--oidc-username-file")
    parser.add_argument("--oidc-password-file")
    parser.add_argument("--expected-oidc-group", default="")
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--network-name", required=True)
    parser.add_argument("--cidr", required=True)
    parser.add_argument("--resume-empty-network", action="store_true")
    parser.add_argument("--lighthouse-name", required=True)
    parser.add_argument("--lighthouse-endpoint", required=True)
    parser.add_argument("--lighthouse-routed-subnet", action="append", default=[])
    parser.add_argument("--enable-network-dns", action="store_true")
    parser.add_argument("--dns-listen-port", type=int, default=53)
    parser.add_argument("--enable-native-dns", action="store_true")
    parser.add_argument("--dns-search-domain", default="")
    parser.add_argument("--enable-network-relays", action="store_true")
    parser.add_argument("--relay-node-name", default="")
    parser.add_argument("--member-name", required=True)
    parser.add_argument("--lighthouse-site", default="proof-edge")
    parser.add_argument("--lighthouse-failure-domain", default="proof-edge-a")
    parser.add_argument("--member-site", default="proof-client")
    parser.add_argument("--member-failure-domain", default="proof-client-a")
    parser.add_argument("--exercise-redundancy-remediation", action="store_true")
    parser.add_argument("--backup-lighthouse-name", default="proof-lighthouse-backup")
    parser.add_argument("--backup-lighthouse-endpoint", default="192.0.2.2:4242")
    parser.add_argument("--backup-lighthouse-site", default="proof-backup")
    parser.add_argument("--backup-lighthouse-failure-domain", default="proof-backup-a")
    parser.add_argument("--allow-private-https", action="store_true")
    parser.add_argument("--allow-dns-https", action="store_true")
    parser.add_argument("--allow-offline-install-guide", action="store_true")
    parser.add_argument("--deadline-seconds", type=int, default=120)
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    server_url = canonical_server_url(args.server_url, args.allow_private_https, args.allow_dns_https)
    output_dir = pathlib.Path(args.output_dir)
    require_private_directory(output_dir)
    token = ""
    oidc_username = ""
    oidc_password = ""
    if args.admin_token_file:
        if args.oidc_password_file or args.expected_oidc_group:
            raise ProofError("OIDC password and group options require OIDC username authentication")
        token = read_private_token(pathlib.Path(args.admin_token_file))
    else:
        if not args.oidc_password_file:
            raise ProofError("OIDC username authentication requires a private password file")
        if args.expected_oidc_group and not TOPOLOGY_PATTERN.fullmatch(args.expected_oidc_group):
            raise ProofError("expected OIDC group is not canonical")
        oidc_username = read_private_credential(
            pathlib.Path(args.oidc_username_file),
            "OIDC username",
            256,
        )
        oidc_password = read_private_credential(
            pathlib.Path(args.oidc_password_file),
            "OIDC password",
            1024,
        )
    for label, value in {
        "network": args.network_name,
        "lighthouse": args.lighthouse_name,
        "member": args.member_name,
    }.items():
        if not NAME_PATTERN.fullmatch(value):
            raise ProofError(f"{label} name is not canonical")
    if not re.fullmatch(r"10\.[0-9]{1,3}\.[0-9]{1,3}\.0/(?:1[6-9]|2[0-8])", args.cidr):
        raise ProofError("proof CIDR is not a bounded private IPv4 network")
    overlay = ipaddress.ip_network(args.cidr, strict=True)
    if len(args.lighthouse_routed_subnet) > 8 or len(set(args.lighthouse_routed_subnet)) != len(args.lighthouse_routed_subnet):
        raise ProofError("lighthouse routed subnets are duplicated or exceed the bound")
    for routed_subnet in args.lighthouse_routed_subnet:
        canonical_routed_subnet(routed_subnet, overlay)
    canonical_dns_proof_port(args.dns_listen_port, args.enable_network_dns)
    if args.enable_native_dns:
        if not args.enable_network_dns:
            raise ProofError("native DNS requires managed network DNS")
        if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", args.dns_search_domain) or any(
            not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
            for label in args.dns_search_domain.split(".")
        ) or args.dns_search_domain == "local" or args.dns_search_domain.endswith(".local"):
            raise ProofError("native DNS search domain is not canonical")
    elif args.dns_search_domain:
        raise ProofError("DNS search domain requires native DNS")
    if args.relay_node_name == "":
        args.relay_node_name = args.lighthouse_name
    if not NAME_PATTERN.fullmatch(args.relay_node_name) or args.relay_node_name not in {args.lighthouse_name, args.member_name}:
        raise ProofError("relay node name must select the browser-authored lighthouse or member")
    canonical_lighthouse_endpoint(args.lighthouse_endpoint)
    for label, value in {
        "lighthouse site": args.lighthouse_site,
        "lighthouse failure domain": args.lighthouse_failure_domain,
        "member site": args.member_site,
        "member failure domain": args.member_failure_domain,
    }.items():
        if not TOPOLOGY_PATTERN.fullmatch(value):
            raise ProofError(f"{label} is not canonical")
    if args.exercise_redundancy_remediation:
        if not NAME_PATTERN.fullmatch(args.backup_lighthouse_name) or args.backup_lighthouse_name in {args.lighthouse_name, args.member_name}:
            raise ProofError("backup lighthouse name is invalid or reused")
        canonical_lighthouse_endpoint(args.backup_lighthouse_endpoint)
        for label, value in {
            "backup lighthouse site": args.backup_lighthouse_site,
            "backup lighthouse failure domain": args.backup_lighthouse_failure_domain,
        }.items():
            if not TOPOLOGY_PATTERN.fullmatch(value):
                raise ProofError(f"{label} is not canonical")
        if args.backup_lighthouse_failure_domain == args.lighthouse_failure_domain:
            raise ProofError("backup lighthouse must use a different failure domain")
    if args.deadline_seconds < 10 or args.deadline_seconds > 240:
        raise ProofError("deadline must be between 10 and 240 seconds")
    geckodriver = shutil.which("geckodriver")
    firefox = shutil.which("firefox")
    if geckodriver is None or firefox is None:
        raise ProofError("Firefox and geckodriver are required")

    started = time.monotonic()
    deadline = started + args.deadline_seconds
    port = reserve_port()
    process = subprocess.Popen(
        [geckodriver, "--port", str(port), "--log", "fatal"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    driver = WebDriver(f"http://127.0.0.1:{port}")
    try:
        wait_until(deadline, lambda: driver.request("GET", "/status") or True, "geckodriver readiness")
        driver.start()
        driver.navigate(server_url + "/")
        if token:
            fill(driver, "#admin-token", token, deadline)
            driver.click(wait_element(driver, deadline, "css selector", "#login-form button[type=submit]"))
            wait_element(driver, deadline, "css selector", "#app-view")
            if driver.execute("return document.getElementById('admin-token').value;") != "":
                raise ProofError("successful sign-in left the administrator token in the DOM")
        else:
            sign_in_with_oidc(
                driver,
                server_url,
                oidc_username,
                oidc_password,
                args.expected_oidc_group,
                deadline,
            )
            oidc_username = ""
            oidc_password = ""

        if args.resume_empty_network:
            initial_inventory = fetch_inventory(driver)
            existing_network = find_exact(
                initial_inventory["networks"],
                "name",
                args.network_name,
                "resumable network",
            )
            existing_network_id = str(existing_network.get("id", ""))
            existing_nodes = initial_inventory["nodes"].get(existing_network_id)
            if (
                not ID_PATTERN.fullmatch(existing_network_id)
                or existing_network.get("cidr") != args.cidr
                or existing_nodes != []
            ):
                raise ProofError("resumable network must match the requested CIDR and contain no nodes")
            select_network_workspace(driver, deadline, args.network_name)
            primary_action = wait_element(
                driver,
                deadline,
                "css selector",
                ".network-workspace .workspace-primary-action:not(:disabled)",
            )
            if driver.text(primary_action).strip().lower() != "add lighthouse":
                raise ProofError("empty network workspace did not offer its first-lighthouse action")
            driver.click(primary_action)
        else:
            open_network_directory(driver, deadline)
            driver.click(wait_element(driver, deadline, "css selector", "#new-network"))
            fill(driver, "#network-name", args.network_name, deadline)
            fill(driver, "#network-cidr", args.cidr, deadline)
            driver.click(wait_element(driver, deadline, "css selector", "#network-form button[type=submit]"))
            wait_network_workspace(driver, deadline, args.network_name)
        wait_element(driver, deadline, "css selector", "#node-dialog[open]")
        if driver.text(wait_element(driver, deadline, "css selector", "#node-dialog-eyebrow")).strip().lower() != "step 2 of 3":
            raise ProofError("network creation did not continue into onboarding step 2")
        if driver.text(wait_element(driver, deadline, "css selector", "#node-dialog-title")).strip().lower() != "add your first lighthouse":
            raise ProofError("onboarding step 2 did not require the first lighthouse")
        fill(driver, "#node-name", args.lighthouse_name, deadline)
        fill(driver, "#node-site", args.lighthouse_site, deadline)
        fill(driver, "#node-failure-domain", args.lighthouse_failure_domain, deadline)
        fill(driver, "#node-endpoint", args.lighthouse_endpoint, deadline)
        if args.lighthouse_routed_subnet:
            fill(driver, "#node-routed-subnets", ", ".join(args.lighthouse_routed_subnet), deadline)
        driver.click(wait_element(driver, deadline, "css selector", "#node-form button[type=submit]"))
        lighthouse_token = reveal_enrollment_token(driver, deadline)
        install_command = read_install_guidance(
            driver,
            deadline,
            args.allow_offline_install_guide,
        )
        enroll_command = driver.text(wait_element(driver, deadline, "css selector", "#enroll-command"))
        activate_command = driver.text(wait_element(driver, deadline, "css selector", "#activate-command"))
        next_member = wait_element(driver, deadline, "css selector", "#enroll-next:not(.hidden)")
        if "add first member" not in driver.text(next_member).strip().lower():
            raise ProofError("first-lighthouse enrollment omitted its guided member continuation")
        driver.click(next_member)
        wait_element(driver, deadline, "css selector", "#node-dialog[open]")
        scrubbed = driver.execute(
            "return ['enroll-node-name','install-command','enroll-command','activate-command','enroll-token'].every((id) => document.getElementById(id).textContent === '');"
        )
        if scrubbed is not True:
            raise ProofError("closing the one-time enrollment dialog did not scrub its DOM secrets and commands")
        if driver.execute("return document.getElementById('node-role').value;") != "member":
            raise ProofError("guided first-member continuation did not select the member role")
        if driver.text(wait_element(driver, deadline, "css selector", "#node-dialog-eyebrow")).strip().lower() != "step 3 of 3":
            raise ProofError("guided first-member continuation did not open onboarding step 3")
        if driver.text(wait_element(driver, deadline, "css selector", "#node-dialog-title")).strip().lower() != "add your first member":
            raise ProofError("onboarding step 3 did not require the first member")
        if driver.execute("return document.getElementById('node-role').disabled;") is not True:
            raise ProofError("guided first-member continuation did not lock the required member role")
        fill(driver, "#node-name", args.member_name, deadline)
        fill(driver, "#node-site", args.member_site, deadline)
        fill(driver, "#node-failure-domain", args.member_failure_domain, deadline)
        driver.click(wait_element(driver, deadline, "css selector", "#node-form button[type=submit]"))
        member_token = reveal_enrollment_token(driver, deadline)
        if not TOKEN_PATTERN.fullmatch(member_token) or member_token == lighthouse_token:
            raise ProofError("member enrollment token is invalid or reused")
        check_readiness = wait_element(driver, deadline, "css selector", "#enroll-next:not(.hidden)")
        if "check readiness" not in driver.text(check_readiness).strip().lower():
            raise ProofError("first-member enrollment omitted its guided readiness continuation")
        driver.click(check_readiness)
        wait_element(driver, deadline, "css selector", "#readiness-dialog[open]")
        if driver.execute("return ['enroll-node-name','install-command','enroll-command','activate-command','enroll-token'].every((id) => document.getElementById(id).textContent === '');") is not True:
            raise ProofError("readiness continuation did not scrub the member enrollment disclosure")

        verify_pending_readiness(
            driver,
            deadline,
            args.network_name,
            args.lighthouse_name,
            args.lighthouse_endpoint,
            args.lighthouse_site,
            args.lighthouse_failure_domain,
            already_open=True,
            leave_open=args.exercise_redundancy_remediation,
        )
        if args.lighthouse_routed_subnet:
            node_management = wait_element(
                driver,
                deadline,
                "css selector",
                ".network-workspace .workspace-node-management",
            )
            if driver.execute(
                "return document.querySelector('.network-workspace .workspace-node-management')?.open === true;"
            ) is not True:
                driver.click(
                    wait_element(
                        driver,
                        deadline,
                        "css selector",
                        ".network-workspace .workspace-node-management > summary",
                    )
                )
            card_text = driver.text(node_management)
            for routed_subnet in args.lighthouse_routed_subnet:
                if routed_subnet not in card_text:
                    raise ProofError("dashboard did not render browser-authored routed-subnet ownership")
        if args.exercise_redundancy_remediation:
            exercise_redundancy_remediation(driver, deadline, args, (lighthouse_token, member_token))
        if args.enable_network_dns:
            configure_network_dns(driver, deadline, args.network_name, args.dns_listen_port, args.enable_native_dns, args.dns_search_domain)
        if args.enable_network_relays:
            configure_network_relays(driver, deadline, args.network_name, args.relay_node_name)
        inventory = fetch_inventory(driver)
    finally:
        token = ""
        oidc_username = ""
        oidc_password = ""
        driver.close()
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)

    network = find_exact(inventory["networks"], "name", args.network_name, "network")
    network_id = str(network.get("id", ""))
    if not ID_PATTERN.fullmatch(network_id) or network.get("cidr") != args.cidr:
        raise ProofError("network readback differs from the UI input")
    expected_dns = {
        "enabled": args.enable_network_dns,
        "listen_port": args.dns_listen_port,
    }
    if network.get("dns_settings") != expected_dns:
        raise ProofError("network DNS inventory differs from the UI input")
    dns_document = inventory["dns"].get(network_id)
    if not isinstance(dns_document, dict) or dns_document.get("enabled") is not args.enable_network_dns or dns_document.get("listen_port") != args.dns_listen_port or dns_document.get("native_resolver") is not args.enable_native_dns or dns_document.get("search_domain") != (args.dns_search_domain if args.enable_native_dns else ""):
        raise ProofError("network DNS API readback differs from the UI input")
    if args.enable_network_dns and (dns_document.get("firewall_ready") is not True or dns_document.get("resolvers") != []):
        raise ProofError("pending network DNS readback fabricated resolvers or omitted firewall readiness")
    nodes = inventory["nodes"].get(network_id)
    if not isinstance(nodes, list):
        raise ProofError("browser inventory is missing the created network's nodes")
    lighthouse = find_exact(nodes, "name", args.lighthouse_name, "lighthouse")
    member = find_exact(nodes, "name", args.member_name, "member")
    validate_node(lighthouse, network_id, args.lighthouse_name, "lighthouse", args.lighthouse_site, args.lighthouse_failure_domain, args.lighthouse_endpoint, args.lighthouse_routed_subnet)
    validate_node(member, network_id, args.member_name, "member", args.member_site, args.member_failure_domain)
    if lighthouse["id"] == member["id"] or lighthouse["ip"] == member["ip"]:
        raise ProofError("browser-authored nodes reuse an identity or overlay address")
    relay_document = inventory["relays"].get(network_id)
    selected_relay = lighthouse if args.relay_node_name == args.lighthouse_name else member
    expected_relay_settings = {"enabled": args.enable_network_relays, "relay_node_ids": [selected_relay["id"]] if args.enable_network_relays else []}
    if network.get("relay_settings") != expected_relay_settings:
        raise ProofError("network relay inventory differs from the UI input")
    if (
        not isinstance(relay_document, dict)
        or relay_document.get("enabled") is not args.enable_network_relays
        or relay_document.get("relay_node_ids") != expected_relay_settings["relay_node_ids"]
        or relay_document.get("active_relays") != []
        or relay_document.get("max_relay_nodes") != 8
    ):
        raise ProofError("pending network relay API readback is not exact")
    if args.exercise_redundancy_remediation:
        backup_lighthouse = find_exact(nodes, "name", args.backup_lighthouse_name, "backup lighthouse")
        validate_node(
            backup_lighthouse,
            network_id,
            args.backup_lighthouse_name,
            "lighthouse",
            args.backup_lighthouse_site,
            args.backup_lighthouse_failure_domain,
            args.backup_lighthouse_endpoint,
        )
        if backup_lighthouse["id"] in {lighthouse["id"], member["id"]} or backup_lighthouse["ip"] in {lighthouse["ip"], member["ip"]}:
            raise ProofError("backup lighthouse reused an existing identity or overlay address")
    if install_command and "install-online" not in install_command:
        raise ProofError("UI enrollment guide does not carry the configured online install location")
    if not install_command and not args.allow_offline_install_guide:
        raise ProofError("UI enrollment guide unexpectedly omitted online installation")
    if server_url not in enroll_command:
        raise ProofError("UI enrollment guide does not carry the configured control-plane location")
    if activate_command != "sudo /usr/local/bin/mesh-install activate":
        raise ProofError("UI activation command is not the supported production command")

    write_new_json(output_dir, "networks.json", inventory["networks"])
    write_new_json(output_dir, "lighthouse-created.json", {"node": lighthouse, "enrollment_token": lighthouse_token})
    write_new_json(output_dir, "member-created.json", {"node": member, "enrollment_token": member_token})
    if args.enable_network_dns:
        write_new_json(output_dir, "network-dns.json", dns_document)
    if args.enable_network_relays:
        write_new_json(output_dir, "network-relays.json", relay_document)
    write_new_json(
        output_dir,
        "ui-guide.json",
        {
            "schema": RESULT_SCHEMA,
            "elapsed_milliseconds": int((time.monotonic() - started) * 1000),
            "pending_readiness_verified": True,
            "online_install_available": bool(install_command),
            "install_command": install_command,
            "enroll_command": enroll_command,
            "activate_command": activate_command,
        },
    )
    directory_descriptor = os.open(output_dir, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_descriptor)
    finally:
        os.close(directory_descriptor)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except ProofError as error:
        print(f"ui-guided-author: {error}", file=sys.stderr)
        raise SystemExit(1)
