#!/usr/bin/env python3
"""Focused tests for the iOS mobile framework normalization and receipt gates."""

from __future__ import annotations

import importlib.util
import json
import pathlib
import plistlib
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]


def load_module(name: str, path: pathlib.Path):
    specification = importlib.util.spec_from_file_location(name, path)
    assert specification and specification.loader
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


NORMALIZE = load_module(
    "apple_mobile_framework_normalize",
    ROOT / "scripts" / "apple_mobile_framework_normalize.py",
)
RECEIPT = load_module(
    "apple_mobile_framework_receipt",
    ROOT / "scripts" / "apple_mobile_framework_receipt.py",
)


def write_framework(root: pathlib.Path) -> None:
    libraries = []
    for identifier in reversed(sorted(RECEIPT.EXPECTED_SLICES)):
        expected = RECEIPT.EXPECTED_SLICES[identifier]
        library = {
            "BinaryPath": "MeshMobile.framework/MeshMobile",
            "LibraryIdentifier": identifier,
            "LibraryPath": "MeshMobile.framework",
            "SupportedArchitectures": expected["architectures"],
            "SupportedPlatform": "ios",
        }
        if expected["variant"] is not None:
            library["SupportedPlatformVariant"] = expected["variant"]
        libraries.append(library)
        framework = root / identifier / "MeshMobile.framework"
        headers = framework / "Headers"
        modules = framework / "Modules"
        headers.mkdir(parents=True)
        modules.mkdir()
        (framework / "MeshMobile").write_bytes(b"normalized static archive")
        (framework / "Info.plist").write_bytes(
            plistlib.dumps(
                {
                    "CFBundleExecutable": "MeshMobile",
                    "CFBundleIdentifier": "MeshMobile",
                    "CFBundlePackageType": "FMWK",
                    "CFBundleShortVersionString": "timestamp",
                    "CFBundleVersion": "timestamp",
                    "MinimumOSVersion": "100.0",
                }
            )
        )
        (headers / "Iosmobile.objc.h").write_text(
            "@interface IosmobileEngineSession : NSObject\n"
            "- (NSString*)frameworkIdentity;\n"
            "- (BOOL)prepare:(NSString*)configurationJSON error:(NSError**)error;\n"
            "- (BOOL)rebind:(NSError**)error;\n"
            "- (NSData*)receive:(NSError**)error;\n"
            "- (BOOL)send:(NSData*)packet error:(NSError**)error;\n"
            "- (BOOL)start:(NSError**)error;\n"
            "- (void)stop;\n"
            "@end\n"
            "@interface IosmobileEnrollmentSession : NSObject\n"
            "- (NSString*)enroll:(NSString*)serverURL "
            "enrollmentToken:(NSString*)enrollmentToken "
            "monotonicCounter:(long long)monotonicCounter "
            "error:(NSError**)error;\n"
            "- (NSString*)recover:(NSString*)serverURL "
            "monotonicCounter:(long long)monotonicCounter "
            "error:(NSError**)error;\n"
            "@end\n"
            "@interface IosmobileLifecycleSession : NSObject\n"
            "- (NSString*)refresh:(NSString*)serverURL "
            "currentConfigurationJSON:(NSString*)currentConfigurationJSON "
            "monotonicCounter:(long long)monotonicCounter "
            "error:(NSError**)error;\n"
            "- (NSString*)reportRuntime:(NSString*)serverURL "
            "currentConfigurationJSON:(NSString*)currentConfigurationJSON "
            "instanceGeneration:(long long)instanceGeneration "
            "sequence:(long long)sequence state:(NSString*)state "
            "runtimeUptimeMS:(long long)runtimeUptimeMS "
            "packetsRead:(long long)packetsRead "
            "packetsWritten:(long long)packetsWritten "
            "hasPacketCounters:(BOOL)hasPacketCounters "
            "errorCode:(NSString*)errorCode error:(NSError**)error;\n"
            "@end\n"
            "@interface IosmobileIdentityRemovalSession : NSObject\n"
            "- (BOOL)remove:(NSError**)error;\n"
            "@end\n"
            "FOUNDATION_EXPORT NSString* IosmobileEnsureIdentity("
            "NSString*, NSString*, NSError**);\n"
            "FOUNDATION_EXPORT NSString* IosmobileFrameworkIdentity(void);\n"
            "FOUNDATION_EXPORT NSString* "
            "IosmobileFrameworkIdentitySHA256(void);\n"
            "FOUNDATION_EXPORT IosmobileEngineSession* "
            "IosmobileNewEngineSession(NSString*, NSString*, NSError**);\n"
            "FOUNDATION_EXPORT IosmobileEnrollmentSession* "
            "IosmobileNewEnrollmentSession(NSString*, NSString*, NSError**);\n"
            "FOUNDATION_EXPORT IosmobileIdentityRemovalSession* "
            "IosmobileNewIdentityRemovalSession("
            "NSString*, NSString*, NSError**);\n"
            "FOUNDATION_EXPORT IosmobileLifecycleSession* "
            "IosmobileNewLifecycleSession(NSString*, NSString*, NSError**);\n"
        )
        for name in ("MeshMobile.h", "Universe.objc.h", "ref.h"):
            (headers / name).write_text(f"/* {name} */\n")
        (modules / "module.modulemap").write_text('framework module "MeshMobile" {}\n')
    (root / "Info.plist").write_bytes(
        plistlib.dumps(
            {
                "AvailableLibraries": libraries,
                "CFBundlePackageType": "XFWK",
                "XCFrameworkFormatVersion": "1.0",
            }
        )
    )


def fake_tool(*arguments: str, **_kwargs: object) -> str:
    if arguments[0] == "lipo" and arguments[1] == "-archs":
        return (
            "x86_64 arm64\n"
            if "ios-arm64_x86_64-simulator" in arguments[-1]
            else "arm64\n"
        )
    if arguments[0] == "lipo" and arguments[1] == "-thin":
        pathlib.Path(arguments[-1]).write_bytes(b"thin archive")
        return ""
    if arguments[:2] == ("ar", "-t"):
        return "go.o\n000000.o\n"
    if arguments[:2] == ("ar", "-x"):
        return ""
    if arguments[0] == "vtool":
        platform_name = (
            "IOSSIMULATOR"
            if "ios-arm64_x86_64-simulator" in str(arguments[-1])
            else "IOS"
        )
        # The temporary object path has no slice name, so infer simulator from
        # the currently requested binary through a test-level replacement.
        return f"platform {platform_name}\nminos 17.0\nsdk 26.5\n"
    if arguments[0] == "strings":
        return (
            "github.com/slackhq/nebula\nv1.10.3\n"
            "mesh-ios-mobile-framework-v5\n"
            "extension-enrollment-lifecycle-renewal-credential-rotation-"
            "mobile-evidence-identity-removal-signed-config-packet-session\n"
            "mesh-ios-tunnel-configuration-v4\n"
            "mesh-ios-lifecycle-refresh-v1\n"
            "mesh-ios-nebula-engine-configuration-v1\n"
            "/private/var/tmp/mesh-apple-ios-mobile-source-v5\n"
        )
    raise AssertionError(arguments)


class AppleMobileFrameworkReceiptTest(unittest.TestCase):
    def test_normalizer_canonicalizes_slice_order_and_versions(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mesh-mobile-normalize-test-") as raw:
            framework = pathlib.Path(raw) / "MeshMobile.xcframework"
            framework.mkdir()
            write_framework(framework)
            with mock.patch.object(NORMALIZE, "normalize_archive"):
                NORMALIZE.normalize(framework)
            outer = plistlib.loads((framework / "Info.plist").read_bytes())
            self.assertEqual(
                [
                    item["LibraryIdentifier"]
                    for item in outer["AvailableLibraries"]
                ],
                ["ios-arm64", "ios-arm64_x86_64-simulator"],
            )
            for identifier in RECEIPT.EXPECTED_SLICES:
                inner = plistlib.loads(
                    (
                        framework
                        / identifier
                        / "MeshMobile.framework"
                        / "Info.plist"
                    ).read_bytes()
                )
                self.assertEqual(inner["CFBundleShortVersionString"], "0.1.0")
                self.assertEqual(inner["CFBundleVersion"], "1")

    def test_source_receipt_rejects_credentials_and_wrong_input_digest(self) -> None:
        inputs, digest = RECEIPT.load_inputs()
        self.assertEqual(inputs["go_version"], "1.26.5")
        value = {
            "schema": "mesh-apple-source-build-receipt-v1",
            "source": {"commit": "a" * 40, "clean": False},
            "host": {
                "go_version": "1.26.5",
                "xcode_version": "26.5",
                "xcode_build": "17F42",
            },
            "inputs": {"apple_build_sha256": digest},
            "preflight": {
                "release_credentials_present": False,
                "source_keychain_code_signing_identities": 0,
            },
        }
        with tempfile.TemporaryDirectory(prefix="mesh-mobile-input-test-") as raw:
            path = pathlib.Path(raw) / "receipt.json"
            path.write_bytes(RECEIPT.canonical_json(value))
            loaded, _ = RECEIPT.load_source_receipt(path, digest)
            self.assertEqual(loaded, value)

            value["preflight"]["release_credentials_present"] = True
            path.write_bytes(RECEIPT.canonical_json(value))
            with self.assertRaisesRegex(RECEIPT.ReceiptError, "credential state"):
                RECEIPT.load_source_receipt(path, digest)

            value["preflight"]["release_credentials_present"] = False
            value["inputs"]["apple_build_sha256"] = "b" * 64
            path.write_bytes(RECEIPT.canonical_json(value))
            with self.assertRaisesRegex(RECEIPT.ReceiptError, "credential state"):
                RECEIPT.load_source_receipt(path, digest)

    def test_framework_inventory_and_exports_are_exact(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mesh-mobile-framework-test-") as raw:
            framework = pathlib.Path(raw) / "MeshMobile.xcframework"
            framework.mkdir()
            write_framework(framework)
            NORMALIZE.normalize = NORMALIZE.normalize
            with (
                mock.patch.object(RECEIPT, "run", side_effect=fake_tool),
                mock.patch.object(
                    RECEIPT,
                    "inspect_object_version",
                    side_effect=lambda _binary, _architecture, platform_name: {
                        "platform": platform_name,
                        "minos": "17.0",
                        "sdk": "26.5",
                    },
                ),
            ):
                # Normalize only metadata; the fake archive is intentionally tiny.
                with mock.patch.object(NORMALIZE, "normalize_archive"):
                    NORMALIZE.normalize(framework)
                result = RECEIPT.inspect_framework(
                    framework,
                    "/private/var/tmp/mesh-apple-ios-mobile-source-v5",
                )
                self.assertEqual(result["exports"], RECEIPT.EXPECTED_EXPORTS)
                self.assertEqual(result["regular_files"], 15)

                header = (
                    framework
                    / "ios-arm64"
                    / "MeshMobile.framework"
                    / "Headers"
                    / "Iosmobile.objc.h"
                )
                header.write_text(
                    header.read_text()
                    + "FOUNDATION_EXPORT NSData* IosmobilePrivateKey(void);\n"
                )
                with self.assertRaisesRegex(RECEIPT.ReceiptError, "exports"):
                    RECEIPT.inspect_framework(
                        framework,
                        "/private/var/tmp/mesh-apple-ios-mobile-source-v5",
                    )

    def test_collection_requires_matching_independent_trees(self) -> None:
        common = {
            "tree_sha256": "a" * 64,
            "regular_files": 15,
            "regular_file_bytes": 1,
        }
        source = {
            "source": {"commit": "a" * 40, "clean": False},
            "host": {},
            "inputs": {},
        }
        arguments = type(
            "Arguments",
            (),
            {
                "framework": "/absolute/first",
                "rebuild": "/absolute/second",
                "input_receipt": "/absolute/input",
            },
        )()
        with (
            mock.patch.object(
                RECEIPT,
                "load_inputs",
                return_value=(
                    {
                        "ios_tunnel": {
                            "framework_build": {
                                "canonical_source_root": (
                                    "/private/var/tmp/"
                                    "mesh-apple-ios-mobile-source-v5"
                                )
                            }
                        }
                    },
                    "a" * 64,
                ),
            ),
            mock.patch.object(
                RECEIPT,
                "load_source_receipt",
                return_value=(source, "b" * 64),
            ),
            mock.patch.object(
                RECEIPT,
                "inspect_framework",
                side_effect=[common, {**common, "tree_sha256": "c" * 64}],
            ),
        ):
            with self.assertRaisesRegex(RECEIPT.ReceiptError, "differ"):
                RECEIPT.collect(arguments)


if __name__ == "__main__":
    unittest.main()
