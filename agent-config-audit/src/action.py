#!/usr/bin/env python3
"""GitHub Actions entry point for agent-config-audit.

Runs audit_agent_config.Auditor on a directory, then writes:
  - a SARIF 2.1.0 report (--sarif) for GitHub code scanning,
  - a JSON report (--json) with the raw findings,
  - a Markdown job summary appended to $GITHUB_STEP_SUMMARY (or --summary FILE),
  - outputs to $GITHUB_OUTPUT: finding-count, highest-severity, sarif-file, gate.

Exit codes: 0 clean or below the --fail-on threshold, 1 a finding at or above the
threshold exists, 2 usage error. Standard library only, no network.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import audit_agent_config as audit  # noqa: E402

TOOL_NAME = "agent-config-audit"
TOOL_URI = "https://github.com/basitalisandhu/security-actions/tree/main/agent-config-audit"
VERSION = "1.0.0"
SEVERITIES = audit.SEVERITIES  # critical, high, medium, low, info
SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "0.0"}

# Short descriptions for the rule ids that audit_agent_config emits. A finding whose id is
# not listed here still gets a rule entry, built from the finding's own title.
RULE_DESCRIPTIONS = {
    "PERM-001": "Any shell command is pre-approved in permissions.allow",
    "PERM-002": "Risky program pre-approved in permissions.allow",
    "PERM-003": "Permission mode that removes prompts (bypassPermissions, dontAsk, auto, or a Codex approval policy)",
    "PERM-004": "File writes pre-approved for every path",
    "PERM-005": "Web fetch or search pre-approved for every domain",
    "PERM-006": "Every tool of an MCP server pre-approved",
    "PERM-007": "All project MCP servers auto-approved",
    "PERM-008": "All hooks disabled",
    "PERM-009": "Pre-approved command carries a permission-bypass flag",
    "PERM-010": "additionalDirectories grants the whole home or root directory",
    "PERM-011": "Broad allow rules with no deny rules",
    "HOOK-001": "Hook references a script that does not exist",
    "HOOK-002": "Hook can reach the network",
    "HOOK-003": "Hook command contains a credential",
    "HOOK-004": "Hook pipes remote content into a shell",
    "HOOK-005": "Shell-form hook leaves a path variable unquoted",
    "HOOK-006": "Hook script is world-writable",
    "MCP-001": "MCP server or HTTP hook uses plain HTTP",
    "MCP-002": "Literal credential in MCP server configuration",
    "MCP-003": "MCP server runs an unpinned package, image or URL",
    "MCP-004": "MCP server runs from a temporary or download directory",
    "MCP-005": "MCP server started with a safety-bypass flag or through a shell string",
    "MCP-006": "MCP server uses the deprecated SSE transport",
    "MCP-007": "Filesystem MCP server exposes the whole home or root directory",
    "MCP-008": "MCP server addressed by raw IP",
    "SEC-001": "Secret found in agent configuration",
    "INJ-001": "Instruction-override phrase in instruction file",
    "INJ-002": "Instruction to hide actions from the user",
    "INJ-003": "Instruction to send data or secrets to an external endpoint",
    "INJ-004": "Instruction to run remote code or auto-run commands",
    "INJ-005": "Invisible or bidirectional Unicode in instruction file",
    "INJ-006": "HTML comment containing instructions",
    "INJ-007": "Long base64-looking blob in instruction file",
    "INJ-008": "Instruction to weaken safety controls or run destructive commands",
    "INJ-009": "Instruction to read credential files",
    "FILE-001": "Agent configuration file is world-writable",
    "CFG-001": "Configuration file does not parse",
    "PLUGIN-001": "Plugin ships a bin/ directory that goes on PATH",
    "SKILL-001": "Skill or command pre-approves broad tool access",
    "SKILL-002": "SKILL.md metadata is incomplete",
}


def to_sarif(report: dict) -> dict:
    """Convert an audit report (Auditor.report()) to a SARIF 2.1.0 document."""
    rules: list[dict] = []
    index: dict[str, int] = {}
    results: list[dict] = []
    for f in report["findings"]:
        rid = f["id"]
        if rid not in index:
            index[rid] = len(rules)
            worst = min((x["severity"] for x in report["findings"] if x["id"] == rid), key=SEVERITIES.index)
            rules.append({
                "id": rid,
                "name": rid.replace("-", ""),
                "shortDescription": {"text": RULE_DESCRIPTIONS.get(rid, f["title"])},
                "fullDescription": {"text": RULE_DESCRIPTIONS.get(rid, f["title"]) + "."},
                "help": {"text": f["recommendation"], "markdown": f["recommendation"]},
                "helpUri": TOOL_URI + "#rules",
                "defaultConfiguration": {"level": SARIF_LEVEL[worst]},
                "properties": {"security-severity": SECURITY_SEVERITY[worst], "tags": ["security", f["category"]], "precision": "medium"},
            })
        uri = f["file"].replace(os.sep, "/").lstrip("./")
        if not uri or uri.startswith("/"):
            uri = uri.lstrip("/") or "."
        line = f["line"] if isinstance(f["line"], int) and f["line"] >= 1 else 1
        fingerprint = hashlib.sha256(f"{rid}|{uri}|{f['evidence']}".encode("utf-8")).hexdigest()
        results.append({
            "ruleId": rid,
            "ruleIndex": index[rid],
            "level": SARIF_LEVEL[f["severity"]],
            "message": {"text": f"{f['title']}. {f['recommendation']}"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri, "uriBaseId": "%SRCROOT%"},
                                                "region": {"startLine": line}}}],
            "partialFingerprints": {"primaryLocationLineHash": fingerprint},
            "properties": {"severity": f["severity"], "category": f["category"], "evidence": f["evidence"]},
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": TOOL_NAME, "version": VERSION, "informationUri": TOOL_URI, "rules": rules}},
            "results": results,
            "columnKind": "utf16CodeUnits",
        }],
    }


def to_summary(report: dict, max_rows: int = 100) -> str:
    s = report["summary"]
    lines = ["## Agent configuration audit", "",
             f"Scanned {len(report['scanned_files'])} file(s). Findings: **{s['total']}** "
             f"(critical {s['critical']}, high {s['high']}, medium {s['medium']}, low {s['low']}, info {s['info']}).", ""]
    if report["findings"]:
        lines += ["| Severity | Rule | Title | File | Line |", "|---|---|---|---|---|"]
        for f in report["findings"][:max_rows]:
            title = f["title"].replace("|", "\\|")
            lines.append(f"| {f['severity']} | `{f['id']}` | {title} | `{f['file']}` | {f['line'] or ''} |")
        if len(report["findings"]) > max_rows:
            lines.append(f"| ... | | {len(report['findings']) - max_rows} more finding(s) in the SARIF report | | |")
        lines += ["", "Evidence is redacted in all outputs. Open the SARIF report or the Security tab for recommendations."]
    else:
        lines.append("No findings. Permissions, hooks, MCP servers and instruction files passed every check this action runs.")
    if report["errors"]:
        lines += ["", "<details><summary>Scan notes</summary>", ""] + [f"- {e}" for e in report["errors"]] + ["", "</details>"]
    return "\n".join(lines) + "\n"


def append_file(env_name: str, text: str, override: str | None = None) -> None:
    target = override or os.environ.get(env_name)
    if target:
        with open(target, "a", encoding="utf-8") as fh:
            fh.write(text)


def set_outputs(values: dict[str, str], override: str | None = None) -> None:
    append_file("GITHUB_OUTPUT", "".join(f"{k}={v}\n" for k, v in values.items()), override)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", default=".", help="directory to audit")
    ap.add_argument("--extra", action="append", default=[], help="additional file to audit (repeatable)")
    ap.add_argument("--sarif", default="agent-config-audit.sarif", help="SARIF output path")
    ap.add_argument("--json", dest="json_out", default="", help="optional JSON report path")
    ap.add_argument("--summary", default="", help="write the Markdown summary here instead of $GITHUB_STEP_SUMMARY")
    ap.add_argument("--fail-on", default="high", choices=SEVERITIES + ["none"], help="lowest severity that fails (default high)")
    args = ap.parse_args(argv)

    root = Path(args.root)
    if not root.is_dir():
        print(f"::error::agent-config-audit: {root} is not a directory", file=sys.stderr)
        return 2
    extra = [Path(e) for e in args.extra if e.strip()]
    auditor = audit.Auditor(root, include_home=False, extra=extra)
    auditor.run()
    report = auditor.report()

    sarif = to_sarif(report)
    Path(args.sarif).write_text(json.dumps(sarif, indent=1), encoding="utf-8")
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(report, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    append_file("GITHUB_STEP_SUMMARY", to_summary(report), args.summary or None)

    findings = report["findings"]
    highest = min((f["severity"] for f in findings), key=SEVERITIES.index) if findings else "none"
    gate = "pass"
    if args.fail_on != "none" and findings:
        threshold = SEVERITIES.index(args.fail_on)
        if any(SEVERITIES.index(f["severity"]) <= threshold for f in findings):
            gate = "fail"
    set_outputs({"finding-count": str(len(findings)), "highest-severity": highest, "sarif-file": args.sarif, "gate": gate})

    for f in findings:
        cmd = "error" if f["severity"] in {"critical", "high"} else "warning" if f["severity"] == "medium" else "notice"
        loc = f"file={f['file']}" + (f",line={f['line']}" if f["line"] else "")
        print(f"::{cmd} {loc},title={f['id']}::{f['title']}")
    print(f"{TOOL_NAME}: {len(findings)} finding(s), highest severity {highest}, gate {gate} (fail-on {args.fail_on})")
    return 1 if gate == "fail" else 0


if __name__ == "__main__":
    sys.exit(main())
