#!/usr/bin/env python3
"""Normalize gomobile XCFramework archives for byte reproducibility."""

from __future__ import annotations

import argparse
import os
import pathlib
import plistlib
import re
import shutil
import subprocess
import sys
import tempfile


class NormalizeError(RuntimeError):
    pass


def run(*arguments: str, cwd: pathlib.Path | None = None) -> str:
    try:
        result = subprocess.run(
            arguments,
            check=True,
            capture_output=True,
            text=True,
            timeout=60,
            env={"PATH": os.environ.get("PATH", ""), "LANG": "C"},
            cwd=cwd,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise NormalizeError(f"framework normalization failed: {arguments[0]}") from exc
    return result.stdout


def normalize_archive(binary: pathlib.Path, architectures: list[str]) -> None:
    with tempfile.TemporaryDirectory(prefix="mesh-mobile-normalize-") as root:
        temporary = pathlib.Path(root)
        normalized: list[pathlib.Path] = []
        lipo_info = run("lipo", "-info", str(binary))
        for architecture in architectures:
            thin = temporary / f"{architecture}.a"
            if lipo_info.startswith("Non-fat file:"):
                if len(architectures) != 1:
                    raise NormalizeError(
                        "non-fat gomobile archive declares multiple architectures"
                    )
                shutil.copyfile(binary, thin)
            else:
                run("lipo", "-thin", architecture, str(binary), "-output", str(thin))
            members = [
                line.strip()
                for line in run("ar", "-t", str(thin)).splitlines()
                if line.strip() and not line.startswith("__.SYMDEF")
            ]
            if (
                not members
                or len(members) > 4096
                or len(set(members)) != len(members)
                or any(
                    re.fullmatch(r"(?:go|[0-9]{6})\.o", member) is None
                    for member in members
                )
            ):
                raise NormalizeError("gomobile archive member inventory is invalid")
            objects = temporary / f"{architecture}-objects"
            objects.mkdir()
            run("ar", "-x", str(thin), cwd=objects)
            output = temporary / f"{architecture}-normalized.a"
            run(
                "libtool",
                "-static",
                "-D",
                "-o",
                str(output),
                *(str(objects / member) for member in members),
            )
            normalized.append(output)

        replacement = temporary / "normalized"
        if len(normalized) == 1:
            shutil.copyfile(normalized[0], replacement)
        else:
            run(
                "lipo",
                "-create",
                *(str(path) for path in normalized),
                "-output",
                str(replacement),
            )
        os.chmod(replacement, 0o755)
        os.replace(replacement, binary)


def normalize(root: pathlib.Path) -> None:
    info_path = root / "Info.plist"
    try:
        info = plistlib.loads(info_path.read_bytes())
    except (OSError, plistlib.InvalidFileException) as exc:
        raise NormalizeError("XCFramework Info.plist is invalid") from exc
    libraries = info.get("AvailableLibraries")
    if not isinstance(libraries, list) or len(libraries) != 2:
        raise NormalizeError("XCFramework library inventory is not exact")
    seen: set[str] = set()
    for library in libraries:
        if not isinstance(library, dict):
            raise NormalizeError("XCFramework library metadata is invalid")
        identifier = library.get("LibraryIdentifier")
        architectures = library.get("SupportedArchitectures")
        if (
            not isinstance(identifier, str)
            or identifier in seen
            or not isinstance(architectures, list)
            or not architectures
            or any(architecture not in {"arm64", "x86_64"} for architecture in architectures)
        ):
            raise NormalizeError("XCFramework library metadata is invalid")
        seen.add(identifier)
        framework = root / identifier / "MeshMobile.framework"
        binary = framework / "MeshMobile"
        inner_info_path = framework / "Info.plist"
        try:
            inner_info = plistlib.loads(inner_info_path.read_bytes())
        except (OSError, plistlib.InvalidFileException) as exc:
            raise NormalizeError("framework Info.plist is invalid") from exc
        if (
            inner_info.get("CFBundleExecutable") != "MeshMobile"
            or inner_info.get("CFBundleIdentifier") != "MeshMobile"
            or inner_info.get("CFBundlePackageType") != "FMWK"
            or inner_info.get("MinimumOSVersion") != "100.0"
        ):
            raise NormalizeError("gomobile framework metadata is unexpected")
        inner_info["CFBundleShortVersionString"] = "0.1.0"
        inner_info["CFBundleVersion"] = "1"
        inner_info_path.write_bytes(
            plistlib.dumps(inner_info, fmt=plistlib.FMT_XML, sort_keys=True)
        )
        normalize_archive(binary, architectures)
    if seen != {"ios-arm64", "ios-arm64_x86_64-simulator"}:
        raise NormalizeError("XCFramework platform slices are not exact")
    libraries.sort(key=lambda library: library["LibraryIdentifier"])
    info_path.write_bytes(plistlib.dumps(info, fmt=plistlib.FMT_XML, sort_keys=True))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("framework")
    args = parser.parse_args()
    root = pathlib.Path(args.framework)
    if not root.is_absolute() or not root.is_dir() or root.is_symlink():
        raise NormalizeError("framework must be one absolute physical directory")
    normalize(root)
    print(f"normalized gomobile XCFramework: {root}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except NormalizeError as exc:
        print(f"Apple mobile framework normalization: {exc}", file=sys.stderr)
        raise SystemExit(1)
