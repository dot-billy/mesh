#!/usr/bin/env python3
"""Minimal App Store Connect client for Mesh TestFlight releases.

The client deliberately has no third-party dependencies. It signs short-lived
ES256 tokens with the local App Store Connect private key, keeps tokens out of
process arguments and output, and exposes only the build/tester operations used
by the Mesh release script.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import pathlib
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterable
from typing import Any


API_BASE = "https://api.appstoreconnect.apple.com"
TERMINAL_PROCESSING_STATES = {"VALID", "FAILED", "INVALID"}
SUCCESSFUL_PROCESSING_STATE = "VALID"


class AppStoreConnectError(RuntimeError):
    pass


def canonical_json(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()


def base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _read_der_length(value: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(value):
        raise AppStoreConnectError("truncated DER signature length")
    first = value[offset]
    offset += 1
    if first < 0x80:
        return first, offset
    count = first & 0x7F
    if count == 0 or count > 4 or offset + count > len(value):
        raise AppStoreConnectError("invalid DER signature length")
    length = int.from_bytes(value[offset : offset + count], "big")
    return length, offset + count


def der_ecdsa_signature_to_raw(value: bytes, component_bytes: int = 32) -> bytes:
    offset = 0
    if not value or value[offset] != 0x30:
        raise AppStoreConnectError("ES256 signature is not one DER sequence")
    sequence_length, offset = _read_der_length(value, offset + 1)
    if offset + sequence_length != len(value):
        raise AppStoreConnectError("ES256 DER sequence length is invalid")
    components: list[bytes] = []
    for _ in range(2):
        if offset >= len(value) or value[offset] != 0x02:
            raise AppStoreConnectError("ES256 DER component is not an integer")
        length, offset = _read_der_length(value, offset + 1)
        if length == 0 or offset + length > len(value):
            raise AppStoreConnectError("ES256 DER integer length is invalid")
        component = value[offset : offset + length]
        offset += length
        if component[0] & 0x80:
            raise AppStoreConnectError("ES256 DER integer is out of range")
        if len(component) > 1 and component[0] == 0:
            component = component[1:]
        if len(component) > component_bytes:
            raise AppStoreConnectError("ES256 DER integer is out of range")
        components.append(component.rjust(component_bytes, b"\0"))
    if offset != len(value):
        raise AppStoreConnectError("ES256 DER signature has trailing bytes")
    return b"".join(components)


def validate_private_key(path: pathlib.Path) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise AppStoreConnectError(
            f"App Store Connect private key is unavailable: {path}"
        ) from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or path.is_symlink()
        or metadata.st_uid != os.getuid()
    ):
        raise AppStoreConnectError(
            "App Store Connect private key must be an owned physical file"
        )
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise AppStoreConnectError(
            "App Store Connect private key must not be group/world accessible"
        )


class TokenProvider:
    def __init__(
        self,
        *,
        key_id: str,
        issuer_id: str,
        private_key: pathlib.Path,
        lifetime_seconds: int = 300,
    ) -> None:
        if not key_id or not issuer_id:
            raise AppStoreConnectError(
                "App Store Connect key ID and issuer ID are required"
            )
        if lifetime_seconds < 60 or lifetime_seconds > 1200:
            raise AppStoreConnectError("JWT lifetime must be between 60 and 1200 seconds")
        validate_private_key(private_key)
        self.key_id = key_id
        self.issuer_id = issuer_id
        self.private_key = private_key
        self.lifetime_seconds = lifetime_seconds
        self._token = ""
        self._refresh_at = 0

    def token(self) -> str:
        now = int(time.time())
        if self._token and now < self._refresh_at:
            return self._token
        header = {"alg": "ES256", "kid": self.key_id, "typ": "JWT"}
        payload = {
            "iss": self.issuer_id,
            "iat": now,
            "exp": now + self.lifetime_seconds,
            "aud": "appstoreconnect-v1",
        }
        signing_input = (
            f"{base64url(canonical_json(header))}."
            f"{base64url(canonical_json(payload))}"
        ).encode("ascii")
        try:
            signed = subprocess.run(
                [
                    "/usr/bin/openssl",
                    "dgst",
                    "-sha256",
                    "-sign",
                    str(self.private_key),
                ],
                input=signing_input,
                check=True,
                capture_output=True,
                timeout=15,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise AppStoreConnectError(
                "failed to sign the App Store Connect token"
            ) from exc
        signature = der_ecdsa_signature_to_raw(signed.stdout)
        self._token = f"{signing_input.decode('ascii')}.{base64url(signature)}"
        self._refresh_at = now + max(30, self.lifetime_seconds - 60)
        return self._token


class AppStoreConnectClient:
    def __init__(
        self,
        token_provider: TokenProvider,
        *,
        api_base: str = API_BASE,
    ) -> None:
        self.token_provider = token_provider
        self.api_base = api_base.rstrip("/")

    def request(
        self,
        method: str,
        path: str,
        *,
        query: dict[str, str | int] | None = None,
        body: object | None = None,
    ) -> dict[str, Any] | None:
        if not path.startswith("/v1/"):
            raise AppStoreConnectError("App Store Connect path is outside /v1")
        url = f"{self.api_base}{path}"
        if query:
            url = f"{url}?{urllib.parse.urlencode(query)}"
        payload = canonical_json(body) if body is not None else None
        request = urllib.request.Request(
            url,
            data=payload,
            method=method,
            headers={
                "Authorization": f"Bearer {self.token_provider.token()}",
                "Accept": "application/json",
                "Content-Type": "application/json",
                "User-Agent": "mesh-testflight-release/1",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                raw = response.read()
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            detail = f"HTTP {exc.code}"
            try:
                decoded = json.loads(raw)
                errors = decoded.get("errors", [])
                messages = [
                    str(item.get("detail") or item.get("title") or "")
                    for item in errors
                    if isinstance(item, dict)
                ]
                messages = [message for message in messages if message]
                if messages:
                    detail = f"{detail}: {'; '.join(messages)}"
            except (UnicodeDecodeError, json.JSONDecodeError, AttributeError):
                pass
            raise AppStoreConnectError(
                f"App Store Connect {method} {path} failed: {detail}"
            ) from exc
        except OSError as exc:
            raise AppStoreConnectError(
                f"App Store Connect {method} {path} failed"
            ) from exc
        if not raw:
            return None
        try:
            decoded = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AppStoreConnectError(
                f"App Store Connect {method} {path} returned invalid JSON"
            ) from exc
        if not isinstance(decoded, dict):
            raise AppStoreConnectError(
                f"App Store Connect {method} {path} returned a non-object"
            )
        return decoded

    def list_resources(
        self,
        path: str,
        *,
        query: dict[str, str | int] | None = None,
    ) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        next_url: str | None = f"{self.api_base}{path}"
        initial_query = query
        pages = 0
        while next_url:
            parsed = urllib.parse.urlsplit(next_url)
            if (
                f"{parsed.scheme}://{parsed.netloc}" != self.api_base
                or not parsed.path.startswith("/v1/")
            ):
                raise AppStoreConnectError("App Store Connect pagination left the API")
            page = self.request(
                "GET",
                parsed.path,
                query=(
                    initial_query
                    if pages == 0
                    else dict(urllib.parse.parse_qsl(parsed.query))
                ),
            )
            if not page or not isinstance(page.get("data"), list):
                raise AppStoreConnectError("App Store Connect list response is invalid")
            for item in page["data"]:
                if not isinstance(item, dict):
                    raise AppStoreConnectError(
                        "App Store Connect resource is invalid"
                    )
                result.append(item)
            links = page.get("links", {})
            next_value = links.get("next") if isinstance(links, dict) else None
            next_url = next_value if isinstance(next_value, str) else None
            initial_query = None
            pages += 1
            if pages > 20:
                raise AppStoreConnectError(
                    "App Store Connect pagination exceeded its bound"
                )
        return result


def one_resource(
    resources: Iterable[dict[str, Any]], description: str
) -> dict[str, Any]:
    selected = list(resources)
    if len(selected) != 1:
        raise AppStoreConnectError(
            f"expected exactly one {description}, found {len(selected)}"
        )
    return selected[0]


def app_for_bundle(
    client: AppStoreConnectClient, bundle_id: str
) -> dict[str, Any]:
    return one_resource(
        client.list_resources(
            "/v1/apps",
            query={"filter[bundleId]": bundle_id, "limit": 2},
        ),
        f"app for bundle {bundle_id}",
    )


def builds_for_version(
    client: AppStoreConnectClient,
    app_id: str,
    version: str,
) -> list[dict[str, Any]]:
    return client.list_resources(
        "/v1/builds",
        query={
            "filter[app]": app_id,
            "filter[preReleaseVersion.version]": version,
            "limit": 200,
            "sort": "-uploadedDate",
        },
    )


def build_for_number(
    client: AppStoreConnectClient,
    app_id: str,
    version: str,
    build_number: str,
) -> dict[str, Any]:
    matches = [
        build
        for build in builds_for_version(client, app_id, version)
        if str(build.get("attributes", {}).get("version", "")) == build_number
    ]
    return one_resource(matches, f"build {version} ({build_number})")


def next_build_number(
    client: AppStoreConnectClient,
    app_id: str,
    version: str,
    local_floor: int,
) -> int:
    observed = [local_floor]
    for build in builds_for_version(client, app_id, version):
        raw = str(build.get("attributes", {}).get("version", ""))
        if raw.isdigit():
            observed.append(int(raw))
    return max(observed) + 1


def external_groups(
    client: AppStoreConnectClient, app_id: str
) -> list[dict[str, Any]]:
    return [
        group
        for group in client.list_resources(
            f"/v1/apps/{app_id}/betaGroups",
            query={"limit": 200},
        )
        if group.get("attributes", {}).get("isInternalGroup") is False
    ]


def tester_for_email(
    client: AppStoreConnectClient, email: str, app_id: str
) -> dict[str, Any] | None:
    resources = client.list_resources(
        "/v1/betaTesters",
        query={"filter[email]": email, "limit": 200},
    )
    matches = [
        tester
        for tester in resources
        if app_id
        in relationship_ids(
            client,
            f"/v1/betaTesters/{tester.get('id', '')}/relationships/apps",
        )
    ]
    if len(matches) > 1:
        raise AppStoreConnectError(
            "App Store Connect returned multiple app-scoped testers for one email"
        )
    return matches[0] if matches else None


def choose_group(
    client: AppStoreConnectClient,
    *,
    app_id: str,
    group_name: str | None,
    tester: dict[str, Any] | None,
    create_if_missing: bool = False,
) -> dict[str, Any]:
    groups = external_groups(client, app_id)
    if group_name:
        named = [
            group
            for group in groups
            if group.get("attributes", {}).get("name") == group_name
        ]
        if named:
            return one_resource(
                named, f"external beta group named {group_name}"
            )
        if create_if_missing:
            result = client.request(
                "POST",
                "/v1/betaGroups",
                body={
                    "data": {
                        "type": "betaGroups",
                        "attributes": {"name": group_name},
                        "relationships": {
                            "app": {
                                "data": {"type": "apps", "id": app_id}
                            }
                        },
                    }
                },
            )
            if not result or not isinstance(result.get("data"), dict):
                raise AppStoreConnectError(
                    "App Store Connect beta-group creation failed"
                )
            created = result["data"]
            if created.get("attributes", {}).get("isInternalGroup") is True:
                raise AppStoreConnectError(
                    "App Store Connect unexpectedly created an internal group"
                )
            return created
        return one_resource(named, f"external beta group named {group_name}")
    if tester is not None:
        tester_id = str(tester.get("id", ""))
        memberships = {
            str(group.get("id", ""))
            for group in client.list_resources(
                f"/v1/betaTesters/{tester_id}/betaGroups",
                query={"limit": 200},
            )
        }
        existing = [group for group in groups if str(group.get("id", "")) in memberships]
        if len(existing) == 1:
            return existing[0]
    return one_resource(groups, "external beta group")


def relationship_ids(
    client: AppStoreConnectClient, path: str
) -> set[str]:
    return {
        str(item.get("id", ""))
        for item in client.list_resources(path, query={"limit": 200})
    }


def create_tester(
    client: AppStoreConnectClient,
    *,
    email: str,
    group_id: str,
    first_name: str | None,
    last_name: str | None,
) -> dict[str, Any]:
    attributes: dict[str, str] = {"email": email}
    if first_name:
        attributes["firstName"] = first_name
    if last_name:
        attributes["lastName"] = last_name
    result = client.request(
        "POST",
        "/v1/betaTesters",
        body={
            "data": {
                "type": "betaTesters",
                "attributes": attributes,
                "relationships": {
                    "betaGroups": {
                        "data": [{"type": "betaGroups", "id": group_id}]
                    }
                },
            }
        },
    )
    if not result or not isinstance(result.get("data"), dict):
        raise AppStoreConnectError("App Store Connect tester creation failed")
    return result["data"]


def add_relationship(
    client: AppStoreConnectClient,
    *,
    path: str,
    resource_type: str,
    resource_id: str,
) -> None:
    client.request(
        "POST",
        path,
        body={"data": [{"type": resource_type, "id": resource_id}]},
    )


def send_invitation(
    client: AppStoreConnectClient,
    *,
    app_id: str,
    tester_id: str,
) -> None:
    client.request(
        "POST",
        "/v1/betaTesterInvitations",
        body={
            "data": {
                "type": "betaTesterInvitations",
                "relationships": {
                    "app": {"data": {"type": "apps", "id": app_id}},
                    "betaTester": {
                        "data": {"type": "betaTesters", "id": tester_id}
                    },
                },
            }
        },
    )


def beta_review_submissions(
    client: AppStoreConnectClient, build_id: str
) -> list[dict[str, Any]]:
    return client.list_resources(
        "/v1/betaAppReviewSubmissions",
        query={"filter[build]": build_id, "limit": 2},
    )


def submit_beta_review(
    client: AppStoreConnectClient, build_id: str
) -> dict[str, Any]:
    existing = beta_review_submissions(client, build_id)
    if len(existing) > 1:
        raise AppStoreConnectError(
            "App Store Connect returned multiple beta-review submissions"
        )
    if existing:
        state = existing[0].get("attributes", {}).get("betaReviewState")
        if state == "REJECTED":
            raise AppStoreConnectError("the beta-review submission was rejected")
        return existing[0]
    result = client.request(
        "POST",
        "/v1/betaAppReviewSubmissions",
        body={
            "data": {
                "type": "betaAppReviewSubmissions",
                "relationships": {
                    "build": {
                        "data": {"type": "builds", "id": build_id}
                    }
                },
            }
        },
    )
    if not result or not isinstance(result.get("data"), dict):
        raise AppStoreConnectError(
            "App Store Connect beta-review submission failed"
        )
    return result["data"]


def build_summary(
    client: AppStoreConnectClient,
    *,
    build: dict[str, Any],
    tester: dict[str, Any] | None = None,
) -> dict[str, Any]:
    build_id = str(build.get("id", ""))
    attributes = build.get("attributes", {})
    detail = client.request("GET", f"/v1/builds/{build_id}/buildBetaDetail")
    detail_attributes = (
        detail.get("data", {}).get("attributes", {})
        if isinstance(detail, dict)
        else {}
    )
    groups = client.list_resources(
        "/v1/betaGroups",
        query={"filter[builds]": build_id, "limit": 200},
    )
    submissions = beta_review_submissions(client, build_id)
    review_state = None
    if len(submissions) == 1:
        review_state = submissions[0].get("attributes", {}).get(
            "betaReviewState"
        )
    elif len(submissions) > 1:
        raise AppStoreConnectError(
            "App Store Connect returned multiple beta-review submissions"
        )
    summary: dict[str, Any] = {
        "build_number": str(attributes.get("version", "")),
        "processing_state": attributes.get("processingState"),
        "uploaded_date": attributes.get("uploadedDate"),
        "expired": attributes.get("expired"),
        "uses_non_exempt_encryption": attributes.get(
            "usesNonExemptEncryption"
        ),
        "internal_beta_state": detail_attributes.get("internalBuildState"),
        "external_beta_state": detail_attributes.get("externalBuildState"),
        "beta_review_state": review_state,
        "beta_groups": sorted(
            str(group.get("attributes", {}).get("name", "")) for group in groups
        ),
    }
    if tester is not None:
        summary["tester_state"] = tester.get("attributes", {}).get("state")
    return summary


def command_status(
    client: AppStoreConnectClient, args: argparse.Namespace
) -> dict[str, Any]:
    app = app_for_bundle(client, args.bundle_id)
    app_id = str(app["id"])
    build = build_for_number(
        client, app_id, args.version, args.build_number
    )
    tester = (
        tester_for_email(client, args.tester_email, app_id)
        if args.tester_email
        else None
    )
    return build_summary(client, build=build, tester=tester)


def command_distribute(
    client: AppStoreConnectClient, args: argparse.Namespace
) -> dict[str, Any]:
    app = app_for_bundle(client, args.bundle_id)
    app_id = str(app["id"])
    build = build_for_number(client, app_id, args.version, args.build_number)
    build_id = str(build["id"])
    processing_state = build.get("attributes", {}).get("processingState")
    if processing_state != SUCCESSFUL_PROCESSING_STATE:
        raise AppStoreConnectError(
            f"build processing state is {processing_state!r}, expected VALID"
        )
    encryption = build.get("attributes", {}).get("usesNonExemptEncryption")
    if encryption is None:
        if not args.uses_only_exempt_encryption:
            raise AppStoreConnectError(
                "build export compliance is unset; confirm the checked-in "
                "declaration with --uses-only-exempt-encryption"
            )
        updated = client.request(
            "PATCH",
            f"/v1/builds/{build_id}",
            body={
                "data": {
                    "type": "builds",
                    "id": build_id,
                    "attributes": {"usesNonExemptEncryption": False},
                }
            },
        )
        if not updated or not isinstance(updated.get("data"), dict):
            raise AppStoreConnectError(
                "App Store Connect export-compliance update failed"
            )
        build = updated["data"]
    elif encryption is True and args.uses_only_exempt_encryption:
        raise AppStoreConnectError(
            "build already declares non-exempt encryption; refusing to replace it"
        )
    tester = tester_for_email(client, args.tester_email, app_id)
    group = choose_group(
        client,
        app_id=app_id,
        group_name=args.beta_group,
        tester=tester,
        create_if_missing=args.create_beta_group,
    )
    group_id = str(group["id"])
    if tester is None:
        tester = create_tester(
            client,
            email=args.tester_email,
            group_id=group_id,
            first_name=args.first_name,
            last_name=args.last_name,
        )
    tester_id = str(tester["id"])

    tester_ids = relationship_ids(
        client, f"/v1/betaGroups/{group_id}/relationships/betaTesters"
    )
    if tester_id not in tester_ids:
        add_relationship(
            client,
            path=f"/v1/betaGroups/{group_id}/relationships/betaTesters",
            resource_type="betaTesters",
            resource_id=tester_id,
        )

    build_ids = relationship_ids(
        client, f"/v1/betaGroups/{group_id}/relationships/builds"
    )
    if build_id not in build_ids:
        add_relationship(
            client,
            path=f"/v1/betaGroups/{group_id}/relationships/builds",
            resource_type="builds",
            resource_id=build_id,
        )

    if args.resend_invitation:
        send_invitation(client, app_id=app_id, tester_id=tester_id)
    summary = build_summary(client, build=build, tester=tester)
    if (
        summary.get("external_beta_state") == "READY_FOR_BETA_SUBMISSION"
        and args.submit_beta_review
    ):
        submission = submit_beta_review(client, build_id)
        summary["beta_review_state"] = submission.get("attributes", {}).get(
            "betaReviewState"
        )
    return {
        **summary,
        "beta_group": group.get("attributes", {}).get("name"),
        "invitation_resent": bool(args.resend_invitation),
    }


def command_wait(
    client: AppStoreConnectClient, args: argparse.Namespace
) -> dict[str, Any]:
    deadline = time.monotonic() + args.timeout
    while True:
        try:
            result = command_status(client, args)
        except AppStoreConnectError as exc:
            if "found 0" not in str(exc) or time.monotonic() >= deadline:
                raise
            result = None
        if result is not None:
            state = result.get("processing_state")
            if state in TERMINAL_PROCESSING_STATES:
                if state != SUCCESSFUL_PROCESSING_STATE:
                    raise AppStoreConnectError(
                        f"build processing ended in {state}"
                    )
                return result
        if time.monotonic() >= deadline:
            raise AppStoreConnectError("timed out waiting for build processing")
        time.sleep(args.poll_interval)


def required_value(value: str | None, description: str) -> str:
    if value:
        return value
    raise AppStoreConnectError(f"{description} is required")


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser()
    value.add_argument(
        "--key-id",
        default=os.environ.get("APP_STORE_CONNECT_API_KEY_ID"),
    )
    value.add_argument(
        "--issuer-id",
        default=os.environ.get("APP_STORE_CONNECT_ISSUER_ID"),
    )
    value.add_argument(
        "--private-key",
        type=pathlib.Path,
        default=(
            pathlib.Path(os.environ["APP_STORE_CONNECT_API_KEY_PATH"])
            if os.environ.get("APP_STORE_CONNECT_API_KEY_PATH")
            else None
        ),
    )
    subparsers = value.add_subparsers(dest="command", required=True)

    def add_build_arguments(command: argparse.ArgumentParser) -> None:
        command.add_argument("--bundle-id", required=True)
        command.add_argument("--version", required=True)
        command.add_argument("--build-number", required=True)

    next_build = subparsers.add_parser("next-build")
    next_build.add_argument("--bundle-id", required=True)
    next_build.add_argument("--version", required=True)
    next_build.add_argument("--local-floor", type=int, default=0)

    status = subparsers.add_parser("status")
    add_build_arguments(status)
    status.add_argument("--tester-email")

    wait = subparsers.add_parser("wait")
    add_build_arguments(wait)
    wait.add_argument("--tester-email")
    wait.add_argument("--timeout", type=int, default=1800)
    wait.add_argument("--poll-interval", type=int, default=30)

    distribute = subparsers.add_parser("distribute")
    add_build_arguments(distribute)
    distribute.add_argument("--tester-email", required=True)
    distribute.add_argument("--beta-group")
    distribute.add_argument(
        "--create-beta-group",
        action="store_true",
        help="create the named external beta group when it does not exist",
    )
    distribute.add_argument("--first-name")
    distribute.add_argument("--last-name")
    distribute.add_argument("--resend-invitation", action="store_true")
    distribute.add_argument("--submit-beta-review", action="store_true")
    distribute.add_argument(
        "--uses-only-exempt-encryption",
        action="store_true",
        help=(
            "confirm the app uses no encryption or only exempt encryption, "
            "matching ITSAppUsesNonExemptEncryption=false"
        ),
    )
    return value


def main() -> int:
    args = parser().parse_args()
    key_id = required_value(args.key_id, "App Store Connect key ID")
    issuer_id = required_value(args.issuer_id, "App Store Connect issuer ID")
    private_key = args.private_key
    if private_key is None:
        private_key = pathlib.Path.home() / "private_keys" / f"AuthKey_{key_id}.p8"
    client = AppStoreConnectClient(
        TokenProvider(
            key_id=key_id,
            issuer_id=issuer_id,
            private_key=private_key,
        )
    )
    if args.command == "next-build":
        app = app_for_bundle(client, args.bundle_id)
        print(
            next_build_number(
                client,
                str(app["id"]),
                args.version,
                args.local_floor,
            )
        )
        return 0
    if args.command == "status":
        result = command_status(client, args)
    elif args.command == "wait":
        result = command_wait(client, args)
    elif args.command == "distribute":
        result = command_distribute(client, args)
    else:
        raise AppStoreConnectError("unsupported command")
    print(json.dumps(result, sort_keys=True, indent=2, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AppStoreConnectError as exc:
        print(f"App Store Connect: {exc}", file=sys.stderr)
        raise SystemExit(1)
