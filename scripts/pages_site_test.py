#!/usr/bin/env python3
"""Regression checks for the Mesh GitHub Pages artifact."""

from __future__ import annotations

import hashlib
from html.parser import HTMLParser
import json
import pathlib
import re
import subprocess
import sys
import tempfile
from urllib.parse import urlparse


ROOT = pathlib.Path(__file__).resolve().parents[1]
BUILD_SCRIPT = ROOT / "scripts" / "build-pages-site.py"
WORKFLOW = ROOT / ".github" / "workflows" / "pages.yml"


class AssetParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.references: list[str] = []
        self.meta: list[dict[str, str]] = []

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        values = {name: value or "" for name, value in attrs}
        if tag in {"a", "link"} and values.get("href"):
            self.references.append(values["href"])
        if tag in {"img", "script"} and values.get("src"):
            self.references.append(values["src"])
        if tag == "meta":
            self.meta.append(values)


def tree_digest(root: pathlib.Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for path in sorted(candidate for candidate in root.rglob("*") if candidate.is_file()):
        result[path.relative_to(root).as_posix()] = hashlib.sha256(
            path.read_bytes()
        ).hexdigest()
    return result


def assert_local_references(page: pathlib.Path, output: pathlib.Path) -> None:
    parser = AssetParser()
    parser.feed(page.read_text())
    for reference in parser.references:
        parsed = urlparse(reference)
        if parsed.scheme or parsed.netloc or reference.startswith("#"):
            continue
        path = reference.split("#", 1)[0].split("?", 1)[0]
        if not path:
            continue
        assert not path.startswith("/"), f"root-absolute Pages reference: {reference}"
        target = (page.parent / path).resolve()
        if path.endswith("/"):
            target /= "index.html"
        assert output in target.parents or target == output, (
            f"reference escapes Pages output: {reference}"
        )
        assert target.exists(), f"missing Pages reference: {reference} from {page}"


def main() -> int:
    assert WORKFLOW.is_file(), "GitHub Pages workflow is missing"
    workflow = WORKFLOW.read_text()
    for required in (
        'branches: ["main"]',
        "pages: write",
        "id-token: write",
        "actions/checkout@v6",
        "actions/setup-python@v6",
        "actions/configure-pages@v5",
        "actions/upload-pages-artifact@v4",
        "actions/deploy-pages@v4",
        "python3 scripts/pages_site_test.py",
    ):
        assert required in workflow, f"Pages workflow is missing {required!r}"

    with tempfile.TemporaryDirectory(prefix="mesh-pages-test-") as temporary:
        base = pathlib.Path(temporary)
        first = base / "first"
        second = base / "second"
        for output in (first, second):
            subprocess.run(
                [sys.executable, str(BUILD_SCRIPT), "--output", str(output)],
                cwd=ROOT,
                check=True,
                text=True,
                capture_output=True,
            )

        assert tree_digest(first) == tree_digest(second), "Pages build is not deterministic"
        for required in (
            "index.html",
            "styles.css",
            "site.js",
            "assets/control-plane.png",
            "assets/fleet-overview.png",
            "assets/fleet-mobile.png",
            "guide/index.html",
            "docs.css",
            "font-awesome/css/font-awesome.min.css",
            "public-guide.json",
            "openapi.json",
            "site-build.json",
            ".nojekyll",
        ):
            assert (first / required).is_file(), f"Pages output is missing {required}"

        landing = first / "index.html"
        guide = first / "guide" / "index.html"
        assert_local_references(landing, first)
        assert_local_references(guide, first)

        landing_text = landing.read_text()
        parser = AssetParser()
        parser.feed(landing_text)
        csp = [
            item.get("content", "")
            for item in parser.meta
            if item.get("http-equiv", "").lower() == "content-security-policy"
        ]
        assert csp and "default-src 'self'" in csp[0], "landing page needs a CSP"
        for required in (
            "Build private networks you can actually operate.",
            "Read the operator guide",
            'aria-controls="site-navigation"',
        ):
            assert required in landing_text, f"landing page is missing {required!r}"
        assert (
            "review the documented boundaries before production use"
            in landing_text.lower()
        )

        combined_text = "\n".join(
            path.read_text(errors="ignore")
            for path in first.rglob("*")
            if path.is_file() and path.suffix in {".html", ".css", ".js", ".json"}
        )
        for forbidden in (
            r"localhost",
            r"127\.0\.0\.1",
            r"10\.46\.0\.34",
            r"Bearer\s+eyJ[A-Za-z0-9._-]+",
            r"Bearer\s+[A-Fa-f0-9]{32,}",
        ):
            assert not re.search(forbidden, combined_text, re.IGNORECASE), (
                f"Pages output contains forbidden private content matching {forbidden!r}"
            )

        guide_text = guide.read_text()
        assert 'href="../docs.css"' in guide_text
        assert 'href="../openapi.json"' in guide_text
        assert 'href="/docs.css"' not in guide_text
        assert 'href="/api-docs.html"' not in guide_text

        public_guide = json.loads((first / "public-guide.json").read_text())
        assert public_guide["schema"] == "mesh-public-guide-v1"
        openapi = json.loads((first / "openapi.json").read_text())
        assert openapi["openapi"].startswith("3.1")

    print("GitHub Pages site checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
