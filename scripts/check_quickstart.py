#!/usr/bin/env python3
"""Check that the CI `quickstart` job runs exactly the README quick start.

Reads the first ```yaml block under "## Quick start" in README.md and the `quickstart` job in
.github/workflows/ci.yml, and compares the action steps: same actions, same order, same `with:` values,
same job permissions. The README's `uses: basitalisandhu/security-actions/<name>@v0` becomes
`uses: ./vendor/security-actions/<name>` in CI (the copy under test), and the README's checkout step is
replaced in CI by scripts/make_quickstart_project.py, so those two differences are expected.

Exit 1 and print the differences if the two drift apart. Needs PyYAML.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
PUBLISHED = re.compile(r"^basitalisandhu/security-actions/([a-z0-9-]+)@v\d+$")
LOCAL_PREFIX = "./vendor/security-actions/"


def readme_workflow(text: str) -> dict:
    section = text.split("## Quick start", 1)[1]
    block = re.search(r"```yaml\n(.*?)```", section, re.S)
    if not block:
        raise SystemExit("README.md: no ```yaml block under ## Quick start")
    return yaml.safe_load(block.group(1))


def main() -> int:
    readme = readme_workflow((ROOT / "README.md").read_text(encoding="utf-8"))
    ci = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))
    problems: list[str] = []
    job = (ci.get("jobs") or {}).get("quickstart")
    if not job:
        print("ci.yml: no quickstart job")
        return 1
    readme_job = next(iter(readme["jobs"].values()))
    expected = []
    for step in readme_job["steps"]:
        uses = step.get("uses", "")
        if uses.startswith("actions/checkout@"):
            continue
        m = PUBLISHED.match(uses)
        if not m:
            problems.append(f"README quick start step {uses!r} is not a basitalisandhu/security-actions/<name>@v0 step")
            continue
        expected.append((LOCAL_PREFIX + m.group(1), step.get("with") or {}))
    actual = [(s["uses"], s.get("with") or {}) for s in job["steps"] if str(s.get("uses", "")).startswith(LOCAL_PREFIX)]
    if expected != actual:
        problems.append(f"steps differ:\n  README: {expected}\n  CI:     {actual}")
    if readme.get("permissions") != job.get("permissions"):
        problems.append(f"permissions differ: README {readme.get('permissions')} vs CI {job.get('permissions')}")
    for p in problems:
        print(f"quickstart: {p}")
    if not problems:
        print(f"quickstart: CI runs the README quick start ({len(actual)} action steps)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
