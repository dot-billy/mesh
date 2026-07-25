#!/usr/bin/env python3
"""Verify the bounded Apple managed-configuration source examples."""

from __future__ import annotations

import argparse
import plistlib
import re
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
SOURCE_DIR = ROOT / "packaging/apple/managed-configuration"
SCHEMA = "mesh-apple-managed-configuration-v1"
APP_DOMAIN = "io.rw0.mesh.admin"
ALLOWED_KEYS = {
    "MeshManagedSchema",
    "ControlPlaneOrigin",
    "AllowOriginChanges",
    "ReleaseChannel",
    "UpdateRing",
    "ShowLocalStatus",
    "NotificationsEnabled",
}
POLICY_NAME = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
FORBIDDEN_KEYS = {
    "EnrollmentToken",
    "RecoveryToken",
    "Session",
    "Cookie",
    "PrivateKey",
    "AccessToken",
}


def _load(path: Path) -> dict[str, object]:
    if not path.is_file() or path.stat().st_size > 16_384:
        raise ValueError(f"{path}: missing or exceeds 16 KiB")
    with path.open("rb") as stream:
        value = plistlib.load(stream)
    if not isinstance(value, dict):
        raise ValueError(f"{path}: top level must be a dictionary")
    return value


def _policy(value: object, label: str) -> None:
    if not isinstance(value, dict) or set(value) != ALLOWED_KEYS:
        raise ValueError(f"{label}: policy keys are not the exact reviewed set")
    if FORBIDDEN_KEYS.intersection(value):
        raise ValueError(f"{label}: secret-bearing key is forbidden")
    if value["MeshManagedSchema"] != SCHEMA:
        raise ValueError(f"{label}: schema mismatch")
    origin = value["ControlPlaneOrigin"]
    if not isinstance(origin, str) or len(origin.encode()) > 2_048:
        raise ValueError(f"{label}: origin must be a bounded string")
    parsed = urlsplit(origin)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in ("", "/")
    ):
        raise ValueError(f"{label}: origin must be an HTTPS origin")
    for key in ("ReleaseChannel", "UpdateRing"):
        item = value[key]
        if not isinstance(item, str) or POLICY_NAME.fullmatch(item) is None:
            raise ValueError(f"{label}: invalid {key}")
    for key in (
        "AllowOriginChanges",
        "ShowLocalStatus",
        "NotificationsEnabled",
    ):
        if type(value[key]) is not bool:
            raise ValueError(f"{label}: {key} must be a Boolean")


def verify(source_dir: Path = SOURCE_DIR) -> None:
    ios = _load(source_dir / "ios-admin-managed-configuration.plist")
    _policy(ios, "iOS managed application configuration")

    profile = _load(source_dir / "macos-admin.mobileconfig")
    if set(profile) != {
        "PayloadContent",
        "PayloadDescription",
        "PayloadDisplayName",
        "PayloadIdentifier",
        "PayloadOrganization",
        "PayloadRemovalDisallowed",
        "PayloadType",
        "PayloadUUID",
        "PayloadVersion",
    }:
        raise ValueError("macOS profile has unexpected top-level fields")
    if profile["PayloadType"] != "Configuration":
        raise ValueError("macOS profile is not a Configuration payload")
    payloads = profile["PayloadContent"]
    if not isinstance(payloads, list) or len(payloads) != 1:
        raise ValueError("macOS profile must contain exactly one payload")
    payload = payloads[0]
    if not isinstance(payload, dict) or payload.get("PayloadType") != (
        "com.apple.ManagedClient.preferences"
    ):
        raise ValueError("macOS profile must use ManagedPreferences")
    domains = payload.get("PayloadContent")
    if not isinstance(domains, dict) or set(domains) != {APP_DOMAIN}:
        raise ValueError("macOS profile must target only the Admin app domain")
    domain = domains[APP_DOMAIN]
    if not isinstance(domain, dict) or set(domain) != {"Forced"}:
        raise ValueError("macOS managed preferences must be forced")
    forced = domain["Forced"]
    if not isinstance(forced, list) or len(forced) != 1:
        raise ValueError("macOS profile must have one forced settings group")
    group = forced[0]
    if not isinstance(group, dict) or set(group) != {"mcx_preference_settings"}:
        raise ValueError("macOS forced group is not canonical")
    _policy(group["mcx_preference_settings"], "macOS managed preferences")

    for key in ("PayloadUUID", "PayloadIdentifier", "PayloadType"):
        if key not in payload:
            raise ValueError(f"macOS inner payload is missing {key}")
    if "PayloadCertificateFileName" in profile or "PayloadSignature" in profile:
        raise ValueError("source example must not pretend to be signed")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-dir", type=Path, default=SOURCE_DIR)
    args = parser.parse_args()
    verify(args.source_dir)
    print("apple managed-configuration source examples verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
