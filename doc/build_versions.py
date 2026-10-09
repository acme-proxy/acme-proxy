#!/usr/bin/env python3
"""Build the published book: every minor release line, `main`, and an index.

The site this writes is what `.github/workflows/mdbook.yml` deploys:

- `<X.Y>/` for each minor line, built from its highest `X.Y.Z` tag — a patch
  does not change what the book describes, so one copy per line is enough;
- `dev/` from the working tree, which in CI is `main`;
- the latest release a second time at the root, so the links the README and
  crates.io have always carried land on the version an operator runs;
- `versions.json`, which `doc/versions.js` reads for its selector and banner.

Each tag's book is built from that tag's own `doc/`, with `doc/versions.js`
from the working tree added to it through mdBook's environment overrides, so a
committed `book.toml` is never edited. A tag whose book does not build fails
the whole run: a version silently missing from the site is worse.

Needs the release tags in the clone (`fetch-depth: 0` in CI), and `mdbook` and
`mdbook-mermaid` on the path. Run from anywhere in the repository:
`python3 doc/build_versions.py [OUT_DIR]` (default `doc/site`).
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib
from pathlib import Path

DOC = Path(__file__).resolve().parent
REPO = DOC.parent
RELEASE_TAG = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")


def git(*args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(REPO), *args], check=True, capture_output=True, text=True
    ).stdout


def release_lines() -> list[tuple[str, str]]:
    """`(X.Y, highest X.Y.Z tag)` for every minor line, newest first."""
    latest: dict[tuple[int, int], tuple[int, str]] = {}
    for tag in git("tag", "--list").split():
        match = RELEASE_TAG.match(tag)
        if not match:
            continue
        major, minor, patch = map(int, match.groups())
        if (major, minor) not in latest or patch > latest[(major, minor)][0]:
            latest[(major, minor)] = (patch, tag)
    return [
        (f"{major}.{minor}", latest[(major, minor)][1])
        for major, minor in sorted(latest, reverse=True)
    ]


def build(doc: Path, version: str, dest: Path) -> None:
    """Build the book rooted at `doc` into `dest`, with the selector injected."""
    script = doc / "versions.js"
    script.write_text(
        f'window.ACME_PROXY_DOC_VERSION = "{version}";\n'
        + (DOC / "versions.js").read_text()
    )
    with open(doc / "book.toml", "rb") as f:
        html = tomllib.load(f).get("output", {}).get("html", {})
    scripts = [s for s in html.get("additional-js", []) if s != "versions.js"]
    env = dict(os.environ)
    env["MDBOOK_OUTPUT__HTML__ADDITIONAL_JS"] = json.dumps([*scripts, "versions.js"])
    print(f"building {version} into {dest}", file=sys.stderr)
    subprocess.run(["mdbook", "build", str(doc), "-d", str(dest)], check=True, env=env)


def main() -> None:
    out = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else DOC / "site"
    lines = release_lines()
    if not lines:
        sys.exit("no X.Y.Z tag in this clone; fetch them (`git fetch --tags`)")

    shutil.rmtree(out, ignore_errors=True)
    out.mkdir(parents=True)
    with tempfile.TemporaryDirectory() as work:
        for version, tag in lines:
            tree = Path(work) / tag
            tree.mkdir()
            archive = tree / "doc.tar"
            git("archive", "--output", str(archive), tag, "doc")
            with tarfile.open(archive) as tar:
                tar.extractall(tree, filter="data")
            build(tree / "doc", version, out / version)

        # The working tree, not HEAD, so an uncommitted edit can be previewed.
        dev = Path(work) / "dev"
        shutil.copytree(
            DOC, dev, ignore=shutil.ignore_patterns("book", "site", "__pycache__")
        )
        build(dev, "dev", out / "dev")

    latest_version, latest_tag = lines[0]
    shutil.copytree(out / latest_version, out, dirs_exist_ok=True)

    versions = [
        {
            "version": version,
            "tag": tag,
            "path": "" if version == latest_version else f"{version}/",
            "latest": version == latest_version,
        }
        for version, tag in lines
    ]
    versions.append({"version": "dev", "tag": None, "path": "dev/", "latest": False})
    (out / "versions.json").write_text(json.dumps(versions, indent=2) + "\n")
    print(f"site written to {out}, latest {latest_tag}", file=sys.stderr)


if __name__ == "__main__":
    main()
