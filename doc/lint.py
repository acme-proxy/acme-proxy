#!/usr/bin/env python3
"""Style gate for the mdBook under `doc/`.

Checks the mechanical half of the conventions the book is written to. Everything
here is a rule a reviewer would otherwise have to apply by eye, on a book with
50-odd pages:

- prose wraps at 80 columns (tables, fenced code, headings and link-only lines
  are exempt — none of them is a sentence);
- no numbered headings, because an ordered list is what an ordered thing wants;
- no trailing whitespace, which the `### Reference` entries used to depend on;
- every fenced block declares a language;
- every relative link resolves, including its `#anchor`;
- no configuration key is documented in two files at once.

Run from the repository root: `python3 doc/lint.py`.
"""

from __future__ import annotations

import os
import re
import sys
from collections import defaultdict

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "src")
MAX_WIDTH = 80

problems: list[str] = []


def report(path: str, line: int, message: str) -> None:
    problems.append(f"{os.path.relpath(path)}:{line}: {message}")


def slug(heading: str) -> str:
    """mdBook's heading-to-anchor transformation, close enough for link checks."""
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", heading.strip())
    text = re.sub(r"[`*]", "", text)
    text = re.sub(r"[^\w\s-]", "", text.lower())
    return re.sub(r"\s", "-", text)


def markdown_files() -> list[str]:
    found = []
    for directory, _, names in os.walk(ROOT):
        found.extend(
            os.path.join(directory, name) for name in names if name.endswith(".md")
        )
    return sorted(found)


files = markdown_files()
anchors: dict[str, set[str]] = {}
key_locations: dict[str, set[str]] = defaultdict(set)

for path in files:
    lines = open(path, encoding="utf-8").read().split("\n")
    anchors[os.path.normpath(path)] = {
        slug(m.group(2))
        for m in (re.match(r"^(#+)\s+(.*)$", line) for line in lines)
        if m
    }

    in_fence = False
    for number, line in enumerate(lines, start=1):
        fence = re.match(r"^\s*```(\S*)", line)
        if fence:
            if not in_fence and not fence.group(1):
                report(path, number, "fenced block declares no language")
            in_fence = not in_fence
            continue

        if line != line.rstrip():
            report(path, number, "trailing whitespace")

        if in_fence:
            continue

        if re.match(r"^#+ \d+\.", line):
            report(path, number, "numbered heading — use an ordered list instead")

        # A key is documented where its own environment variable is named on the
        # entry line; the leaf name alone collides legitimately (filter.allowed_ip
        # .allow and filter.identifiers.allow are different keys).
        if line.startswith("**`"):
            for env in re.findall(r"`(ACME_PROXY_[A-Z0-9_<>]+)`", line):
                key_locations[env].add(os.path.normpath(path))

        exempt = (
            line.lstrip().startswith(("|", "http"))
            or line.startswith("#")
            # A `### Reference` entry is one logical line: term, type, default
            # and environment variable belong together and must not be wrapped.
            or line.startswith("**`")
            or re.match(r"^\s*[-*]?\s*\[[^\]]+\]\([^)]+\)[.,]?\s*$", line)
            or re.match(r"^\s{4,}\S", line)  # indented code
        )
        if len(line) > MAX_WIDTH and not exempt:
            report(path, number, f"line is {len(line)} columns, over {MAX_WIDTH}")

for path in files:
    directory = os.path.dirname(path)
    for number, line in enumerate(
        open(path, encoding="utf-8").read().split("\n"), start=1
    ):
        for target in re.findall(r"\]\(([^)]+)\)", line):
            if target.startswith(("http", "mailto:")):
                continue
            relative, _, fragment = target.partition("#")
            resolved = (
                os.path.normpath(os.path.join(directory, relative))
                if relative
                else os.path.normpath(path)
            )
            if not os.path.exists(resolved):
                report(path, number, f"link target does not exist: {target}")
            elif fragment and fragment not in anchors.get(resolved, set()):
                report(path, number, f"link anchor does not exist: {target}")

for key, where in sorted(key_locations.items()):
    if len(where) > 1:
        listed = ", ".join(sorted(os.path.relpath(p) for p in where))
        problems.append(f"{key} is documented in more than one file: {listed}")

if problems:
    print(f"{len(problems)} problem(s):", file=sys.stderr)
    for problem in problems:
        print(f"  {problem}", file=sys.stderr)
    sys.exit(1)

print(f"doc/lint.py: {len(files)} pages, no problems")
