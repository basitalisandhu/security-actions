#!/usr/bin/env python3
"""Structural check for SARIF 2.1.0 files produced by the actions in this repository.

This is not a full JSON Schema validation. It checks the parts that GitHub code
scanning rejects when they are wrong: version, runs, tool.driver, unique rule ids,
results that point at a known rule, valid levels, non-empty messages, relative
artifact URIs and 1-based line numbers.

Usage: check_sarif.py FILE [FILE ...]        exit 1 and print the problems if any file fails
Import: from check_sarif import problems      returns a list of problem strings (empty means ok)
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

LEVELS = {"none", "note", "warning", "error"}


def problems(doc: object) -> list[str]:
    out: list[str] = []
    if not isinstance(doc, dict):
        return ["top level is not an object"]
    if doc.get("version") != "2.1.0":
        out.append(f"version must be '2.1.0', got {doc.get('version')!r}")
    schema = doc.get("$schema")
    if not isinstance(schema, str) or "sarif-2.1.0" not in schema:
        out.append("$schema must reference sarif-2.1.0")
    runs = doc.get("runs")
    if not isinstance(runs, list) or not runs:
        return out + ["runs must be a non-empty list"]
    for ri, run in enumerate(runs):
        prefix = f"runs[{ri}]"
        if not isinstance(run, dict):
            out.append(f"{prefix} is not an object")
            continue
        driver = (run.get("tool") or {}).get("driver") if isinstance(run.get("tool"), dict) else None
        if not isinstance(driver, dict) or not isinstance(driver.get("name"), str) or not driver["name"]:
            out.append(f"{prefix}.tool.driver.name is missing")
            driver = {}
        rules = driver.get("rules", [])
        if not isinstance(rules, list):
            out.append(f"{prefix}.tool.driver.rules must be a list")
            rules = []
        rule_ids: list[str] = []
        for i, rule in enumerate(rules):
            if not isinstance(rule, dict) or not isinstance(rule.get("id"), str) or not rule["id"]:
                out.append(f"{prefix}.tool.driver.rules[{i}] has no string id")
                continue
            if rule["id"] in rule_ids:
                out.append(f"{prefix}.tool.driver.rules[{i}] duplicates id {rule['id']}")
            rule_ids.append(rule["id"])
            short = rule.get("shortDescription")
            if short is not None and (not isinstance(short, dict) or not isinstance(short.get("text"), str)):
                out.append(f"{prefix}.tool.driver.rules[{i}].shortDescription.text must be a string")
            cfg = rule.get("defaultConfiguration")
            if cfg is not None and cfg.get("level") not in LEVELS:
                out.append(f"{prefix}.tool.driver.rules[{i}].defaultConfiguration.level is invalid")
        results = run.get("results")
        if not isinstance(results, list):
            out.append(f"{prefix}.results must be a list (use [] for a clean run)")
            results = []
        for i, res in enumerate(results):
            rp = f"{prefix}.results[{i}]"
            if not isinstance(res, dict):
                out.append(f"{rp} is not an object")
                continue
            rid = res.get("ruleId")
            if not isinstance(rid, str) or not rid:
                out.append(f"{rp}.ruleId is missing")
            elif rule_ids and rid not in rule_ids:
                out.append(f"{rp}.ruleId {rid} is not declared in tool.driver.rules")
            if "ruleIndex" in res:
                idx = res["ruleIndex"]
                if not isinstance(idx, int) or idx < 0 or idx >= len(rule_ids) or rule_ids[idx] != rid:
                    out.append(f"{rp}.ruleIndex does not match ruleId")
            if "level" in res and res["level"] not in LEVELS:
                out.append(f"{rp}.level is invalid: {res['level']!r}")
            msg = res.get("message")
            if not isinstance(msg, dict) or not isinstance(msg.get("text"), str) or not msg["text"].strip():
                out.append(f"{rp}.message.text is missing or empty")
            locs = res.get("locations", [])
            if not isinstance(locs, list):
                out.append(f"{rp}.locations must be a list")
                locs = []
            for li, loc in enumerate(locs):
                lp = f"{rp}.locations[{li}]"
                phys = loc.get("physicalLocation") if isinstance(loc, dict) else None
                if not isinstance(phys, dict):
                    out.append(f"{lp}.physicalLocation is missing")
                    continue
                art = phys.get("artifactLocation")
                uri = art.get("uri") if isinstance(art, dict) else None
                if not isinstance(uri, str) or not uri:
                    out.append(f"{lp}.physicalLocation.artifactLocation.uri is missing")
                elif uri.startswith(("/", "file:")) or "\\" in uri:
                    out.append(f"{lp} uri must be a relative, forward-slash path: {uri!r}")
                region = phys.get("region")
                if region is not None:
                    line = region.get("startLine") if isinstance(region, dict) else None
                    if not isinstance(line, int) or isinstance(line, bool) or line < 1:
                        out.append(f"{lp}.region.startLine must be an integer >= 1")
                    end = region.get("endLine") if isinstance(region, dict) else None
                    if end is not None and (not isinstance(end, int) or end < line):
                        out.append(f"{lp}.region.endLine must be >= startLine")
            fps = res.get("partialFingerprints")
            if fps is not None and (not isinstance(fps, dict) or not all(isinstance(v, str) for v in fps.values())):
                out.append(f"{rp}.partialFingerprints must map strings to strings")
    return out


def check_file(path: Path) -> list[str]:
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"{path}: cannot parse: {exc}"]
    return [f"{path}: {p}" for p in problems(doc)]


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if not args:
        print(__doc__)
        return 2
    bad = 0
    for arg in args:
        found = check_file(Path(arg))
        if found:
            bad += 1
            print("\n".join(found))
        else:
            doc = json.loads(Path(arg).read_text(encoding="utf-8"))
            n = sum(len(r.get("results", [])) for r in doc["runs"])
            print(f"{arg}: ok ({n} result(s))")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
