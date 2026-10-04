#!/usr/bin/env python3
"""Validate every action.yml and workflow file in this repository.

Checks that each action parses, is a composite action, declares name, description, author and branding,
gives every input a description and a default (or required: true), gives every output a description and
a value that points at an existing step id, uses `shell` on every run step, only references declared
inputs, and pins external actions to one of the known major tags listed in ALLOWED_USES. Workflows must
parse, declare permissions, and use only those same external actions (plus local `./<name>` ones).

With --remote, `git ls-remote --tags` confirms that each referenced tag exists upstream.
Exit 1 and print the problems if any check fails. Needs PyYAML.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover
    print("PyYAML is required: python -m pip install pyyaml")
    sys.exit(2)

ROOT = Path(__file__).resolve().parents[1]
ALLOWED_USES = {
    "actions/checkout": {"v4"},
    "actions/setup-python": {"v5"},
    "actions/setup-node": {"v4"},
    "github/codeql-action/upload-sarif": {"v3"},
}
INPUT_REF_RE = re.compile(r"inputs\.([A-Za-z0-9_-]+)")
STEP_REF_RE = re.compile(r"steps\.([A-Za-z0-9_-]+)\.outputs")


def load(path: Path):
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def check_uses(ref: str, where: str, problems: list[str], uses: set[tuple[str, str]]) -> None:
    if ref.startswith("./"):
        if not (ROOT / ref[2:] / "action.yml").is_file():
            problems.append(f"{where}: local action {ref} has no action.yml")
        return
    if "@" not in ref:
        problems.append(f"{where}: uses {ref} is not pinned to a tag")
        return
    name, tag = ref.rsplit("@", 1)
    if name not in ALLOWED_USES:
        problems.append(f"{where}: uses {name} is not in the allowed list ({', '.join(sorted(ALLOWED_USES))})")
    elif tag not in ALLOWED_USES[name]:
        problems.append(f"{where}: uses {ref} should be one of {', '.join(sorted(ALLOWED_USES[name]))}")
    uses.add((name, tag))


def check_action(path: Path, problems: list[str], uses: set[tuple[str, str]]) -> None:
    where = path.relative_to(ROOT).as_posix()
    try:
        doc = load(path)
    except yaml.YAMLError as exc:
        problems.append(f"{where}: does not parse: {exc}")
        return
    for key in ("name", "description", "author"):
        if not isinstance(doc.get(key), str) or not doc[key].strip():
            problems.append(f"{where}: missing {key}")
    branding = doc.get("branding") or {}
    if not isinstance(branding, dict) or not branding.get("icon") or not branding.get("color"):
        problems.append(f"{where}: branding needs icon and color")
    inputs = doc.get("inputs") or {}
    for name, spec in inputs.items():
        if not isinstance(spec, dict) or not spec.get("description"):
            problems.append(f"{where}: input {name} needs a description")
            continue
        if "default" not in spec and spec.get("required") is not True:
            problems.append(f"{where}: input {name} needs a default or required: true")
    runs = doc.get("runs") or {}
    if runs.get("using") != "composite":
        problems.append(f"{where}: runs.using must be composite")
    step_ids: set[str] = set()
    text = path.read_text(encoding="utf-8")
    for i, step in enumerate(runs.get("steps") or []):
        sid = step.get("id")
        if sid:
            step_ids.add(sid)
        if "run" in step and not step.get("shell"):
            problems.append(f"{where}: step {i} ({step.get('name', sid)}) runs a script without shell")
        if "uses" in step:
            check_uses(step["uses"], f"{where} step {i}", problems, uses)
    for ref in set(INPUT_REF_RE.findall(text)):
        if ref not in inputs:
            problems.append(f"{where}: references undeclared input {ref}")
    for name, spec in (doc.get("outputs") or {}).items():
        if not isinstance(spec, dict) or not spec.get("description") or "value" not in spec:
            problems.append(f"{where}: output {name} needs a description and a value")
            continue
        for sid in STEP_REF_RE.findall(str(spec["value"])):
            if sid not in step_ids:
                problems.append(f"{where}: output {name} references unknown step id {sid}")
    readme = path.parent / "README.md"
    if not readme.is_file():
        problems.append(f"{where}: no README.md next to it")
    else:
        rd = readme.read_text(encoding="utf-8")
        for name in inputs:
            if f"`{name}`" not in rd:
                problems.append(f"{where}: README does not document input {name}")
    if not (path.parent / "src").is_dir() or not (path.parent / "tests").is_dir():
        problems.append(f"{where}: needs src/ and tests/ directories")


def check_workflow(path: Path, problems: list[str], uses: set[tuple[str, str]]) -> None:
    where = path.relative_to(ROOT).as_posix()
    try:
        doc = load(path)
    except yaml.YAMLError as exc:
        problems.append(f"{where}: does not parse: {exc}")
        return
    # PyYAML reads the bare key `on` as boolean True.
    if "on" not in doc and True not in doc:
        problems.append(f"{where}: missing on")
    if "permissions" not in doc:
        problems.append(f"{where}: top-level permissions missing")
    jobs = doc.get("jobs") or {}
    if not jobs:
        problems.append(f"{where}: no jobs")
    for jname, job in jobs.items():
        if "runs-on" not in job:
            problems.append(f"{where}: job {jname} has no runs-on")
        for i, step in enumerate(job.get("steps") or []):
            if "uses" in step:
                check_uses(step["uses"], f"{where} job {jname} step {i}", problems, uses)


def remote_tags_exist(uses: set[tuple[str, str]]) -> list[str]:
    problems = []
    for name, tag in sorted(uses):
        repo = "/".join(name.split("/")[:2])
        try:
            out = subprocess.run(["git", "ls-remote", "--tags", f"https://github.com/{repo}", f"refs/tags/{tag}"],
                                 capture_output=True, text=True, timeout=60, check=False).stdout
        except (OSError, subprocess.TimeoutExpired) as exc:
            problems.append(f"{repo}@{tag}: could not query tags ({exc})")
            continue
        if f"refs/tags/{tag}" not in out:
            problems.append(f"{repo}@{tag}: tag not found upstream")
        else:
            print(f"{repo}@{tag}: {out.split()[0]}")
    return problems


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    problems: list[str] = []
    uses: set[tuple[str, str]] = set()
    actions = sorted(ROOT.glob("*/action.yml"))
    workflows = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
    if not actions:
        problems.append("no */action.yml found")
    for a in actions:
        check_action(a, problems, uses)
    for w in workflows:
        check_workflow(w, problems, uses)
    if "--remote" in args:
        problems += remote_tags_exist(uses)
    if problems:
        print("\n".join(problems))
        return 1
    print(f"ok: {len(actions)} action(s), {len(workflows)} workflow(s), external actions: " + ", ".join(f"{n}@{t}" for n, t in sorted(uses)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
