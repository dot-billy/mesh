#!/usr/bin/env python3
"""Build the static GitHub Pages artifact for Mesh."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import shutil
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = ROOT / "site"
DEFAULT_OUTPUT = ROOT / ".pages-dist"
OUTPUT_MARKER = ".mesh-pages-output"

STATIC_FILES = ("index.html", "styles.css", "site.js")
SCREENSHOTS = {
    "control-plane.png": SOURCE / "assets" / "control-plane.png",
    "fleet-overview.png": SOURCE / "assets" / "fleet-overview.png",
    "fleet-mobile.png": SOURCE / "assets" / "fleet-mobile.png",
}


def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def require_sources() -> None:
    required = [
        *(SOURCE / name for name in STATIC_FILES),
        *SCREENSHOTS.values(),
        ROOT / "docs" / "public-guide.json",
        ROOT / "docs" / "openapi.json",
        ROOT / "internal" / "httpapi" / "web" / "docs.html",
        ROOT / "internal" / "httpapi" / "web" / "docs.css",
        ROOT / "internal" / "httpapi" / "web" / "font-awesome",
    ]
    missing = [path.relative_to(ROOT).as_posix() for path in required if not path.exists()]
    if missing:
        raise RuntimeError(f"missing Pages source: {', '.join(missing)}")


def pages_guide_html() -> str:
    source = (ROOT / "internal" / "httpapi" / "web" / "docs.html").read_text()
    replacements = {
        'href="/font-awesome/css/font-awesome.min.css"': (
            'href="../font-awesome/css/font-awesome.min.css"'
        ),
        'href="/docs.css"': 'href="../docs.css"',
        'href="/api-docs.html"': 'href="../openapi.json"',
        'href="/"': 'href="../"',
        ">API reference<": ">OpenAPI 3.1<",
        ">Open control plane<": ">Mesh overview<",
    }
    for old, new in replacements.items():
        source = source.replace(old, new)
    return source


def write_build(target: pathlib.Path) -> None:
    target.mkdir(parents=True, exist_ok=True)
    assets = target / "assets"
    assets.mkdir()

    for name in STATIC_FILES:
        shutil.copy2(SOURCE / name, target / name)
    for name, source in SCREENSHOTS.items():
        shutil.copy2(source, assets / name)

    guide = target / "guide"
    guide.mkdir()
    (guide / "index.html").write_text(pages_guide_html())
    shutil.copy2(ROOT / "internal" / "httpapi" / "web" / "docs.css", target / "docs.css")
    shutil.copytree(
        ROOT / "internal" / "httpapi" / "web" / "font-awesome",
        target / "font-awesome",
    )

    shutil.copy2(ROOT / "docs" / "public-guide.json", target / "public-guide.json")
    shutil.copy2(ROOT / "docs" / "openapi.json", target / "openapi.json")
    (target / ".nojekyll").write_text("")
    (target / OUTPUT_MARKER).write_text("Mesh GitHub Pages build output.\n")

    guide_manifest = json.loads((ROOT / "docs" / "public-guide.json").read_text())
    build_manifest = {
        "schema": "mesh-pages-build-v1",
        "guide_reviewed_at": guide_manifest["reviewed_at"],
        "sources": {
            "docs/public-guide.json": sha256(ROOT / "docs" / "public-guide.json"),
            "docs/openapi.json": sha256(ROOT / "docs" / "openapi.json"),
            **{
                f"site/assets/{source.name}": sha256(source)
                for source in SCREENSHOTS.values()
            },
        },
    }
    (target / "site-build.json").write_text(
        json.dumps(build_manifest, indent=2, sort_keys=True) + "\n"
    )


def replace_output(staged: pathlib.Path, output: pathlib.Path) -> None:
    if output.exists():
        if output == DEFAULT_OUTPUT:
            shutil.rmtree(output)
        elif (output / OUTPUT_MARKER).is_file():
            shutil.rmtree(output)
        else:
            raise RuntimeError(
                f"refusing to replace unrecognized output directory: {output}"
            )
    staged.replace(output)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=pathlib.Path,
        default=DEFAULT_OUTPUT,
        help="destination for the complete static Pages artifact",
    )
    args = parser.parse_args()

    output = args.output
    if not output.is_absolute():
        output = (ROOT / output).resolve()
    if output == ROOT or output == pathlib.Path("/"):
        parser.error("output must be a dedicated build directory")

    require_sources()
    output.parent.mkdir(parents=True, exist_ok=True)
    staged = pathlib.Path(
        tempfile.mkdtemp(prefix=f".{output.name}-", dir=output.parent)
    )
    try:
        write_build(staged)
        replace_output(staged, output)
    finally:
        if staged.exists():
            shutil.rmtree(staged)

    print(f"built GitHub Pages artifact: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
