#!/usr/bin/env python3
"""Create a small, clean consumer project for the README quick-start test.

The CI job `quickstart` runs the README's quick-start steps against this directory instead of a real
repository: Claude Code settings and instruction files from the agent-config-audit clean fixture, a
prompt from the prompt-secrets-scan clean fixture, and a package-lock.json whose packages are all MIT.
Every gate in the quick start should pass on it. Standard library only.

Usage: python3 scripts/make_quickstart_project.py DIRECTORY
"""
from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def build(target: Path) -> None:
    target.mkdir(parents=True, exist_ok=True)
    shutil.copytree(ROOT / "agent-config-audit/tests/fixtures/clean", target, dirs_exist_ok=True)
    shutil.copytree(ROOT / "prompt-secrets-scan/tests/fixtures/clean", target, dirs_exist_ok=True)
    packages = {"": {"name": "quickstart-demo", "version": "1.0.0"}}
    for name, version in [("left-pad", "1.3.0"), ("ms", "2.1.3")]:
        packages[f"node_modules/{name}"] = {"version": version, "license": "MIT"}
    lock = {"name": "quickstart-demo", "version": "1.0.0", "lockfileVersion": 3, "requires": True, "packages": packages}
    (target / "package-lock.json").write_text(json.dumps(lock, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__.strip().splitlines()[-1], file=sys.stderr)
        sys.exit(2)
    build(Path(sys.argv[1]))
    print(f"quickstart project written to {sys.argv[1]}")
