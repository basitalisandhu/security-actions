#!/usr/bin/env python3
"""Find secrets and credentials inside prompt files, system prompts, notebooks and agent instruction files.

Scans the files matched by --paths (globs relative to --root; the defaults cover Markdown, text,
prompt templates, Jupyter notebooks and the usual agent instruction files) for provider API keys,
private keys, bearer tokens, JSON Web Tokens, webhook URLs, database connection strings with
embedded passwords and generic "api_key = ..." assignments.

Outputs: a SARIF 2.1.0 report (--sarif), an optional JSON report (--json), a Markdown job summary
appended to $GITHUB_STEP_SUMMARY (or --summary FILE), workflow annotations on stdout, and outputs
in $GITHUB_OUTPUT (finding-count, files-scanned, sarif-file, gate).

Matched values are never printed in full: evidence keeps the first four and last two characters.

Allowlist file (--allowlist, default .prompt-secrets-allowlist when it exists), one entry per line:
  # comment
  sha256:<hex>        sha256 of the exact matched value (keeps the secret out of the allowlist)
  re:<regex>          regular expression matched against the value
  path:<glob>         skip files matching this glob (fnmatch against the relative path)
  rule:<RULE-ID>      disable a rule everywhere
  <literal>           any other line is a literal value to allow
A line containing "secrets-scan: ignore" or "pragma: allowlist secret" is skipped as well.

Exit codes: 0 clean or below --fail-on, 1 a finding at or above --fail-on exists, 2 usage error.
Standard library only. Read-only. No network.
"""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import math
import os
import re
import sys
from pathlib import Path

TOOL_NAME = "prompt-secrets-scan"
TOOL_URI = "https://github.com/basitalisandhu/security-actions/tree/main/prompt-secrets-scan"
VERSION = "1.0.0"
SEVERITIES = ["critical", "high", "medium", "low"]
SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0"}
MAX_FILE_BYTES = 5 * 1024 * 1024

DEFAULT_PATHS = [
    "**/*.md", "**/*.mdx", "**/*.txt", "**/*.prompt", "**/*.prompty", "**/*.ipynb",
    "**/*.jinja", "**/*.jinja2", "**/*.j2", "**/*.tmpl", "**/*.hbs",
    "**/prompts/**/*", "**/prompt/**/*", "**/system_prompt*", "**/system-prompt*",
    ".cursorrules", ".clinerules", ".windsurfrules", ".cursor/rules/**/*", ".claude/**/*.md",
    ".claude/settings.json", ".claude/settings.local.json", ".mcp.json", ".github/copilot-instructions.md",
]
EXCLUDED_DIRS = {".git", "node_modules", "vendor", "dist", "build", ".venv", "venv", "site-packages", "__pycache__", ".tox", ".mypy_cache"}
INLINE_IGNORE_RE = re.compile(r"(?i)secrets-scan:\s*ignore|pragma:\s*allowlist\s+secret")
PLACEHOLDER_RE = re.compile(r"(?i)(xxxx|your[_-]|example|placeholder|redacted|changeme|change-me|<[^>]+>|\.\.\.|\*\*\*|dummy|sample|insert|replace|todo|tbd|\$\{|\{\{|%\(|__[a-z]+__)")
ENV_REF_RE = re.compile(r"^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?$")

# (rule id, name, regex, severity, group holding the secret or 0). Order matters: a match that overlaps an
# earlier accepted match on the same line is dropped, so specific prefixes come before broad patterns.
RULES: list[tuple[str, str, re.Pattern[str], str, int]] = [
    ("PSS-ANTHROPIC", "Anthropic API key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{32,}\b"), "critical", 0),
    ("PSS-OPENROUTER", "OpenRouter API key", re.compile(r"\bsk-or-v1-[0-9a-f]{64}\b"), "critical", 0),
    ("PSS-OPENAI", "OpenAI API key", re.compile(r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{32,}\b"), "critical", 0),
    ("PSS-STRIPE", "Stripe secret key", re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}\b"), "critical", 0),
    ("PSS-GOOGLE-API", "Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), "critical", 0),
    ("PSS-GOOGLE-OAUTH", "Google OAuth client secret", re.compile(r"\bGOCSPX-[A-Za-z0-9_-]{28}\b"), "critical", 0),
    ("PSS-AWS-KEY-ID", "AWS access key id", re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b"), "critical", 0),
    ("PSS-AWS-SECRET", "AWS secret access key", re.compile(r"(?i)aws_?secret_?access_?key\b[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])"), "critical", 1),
    ("PSS-GITHUB", "GitHub token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{22,}\b"), "critical", 0),
    ("PSS-GITLAB", "GitLab personal access token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b"), "critical", 0),
    ("PSS-SLACK-TOKEN", "Slack token", re.compile(r"\bxox[abprse]-[A-Za-z0-9-]{10,}\b"), "critical", 0),
    ("PSS-SLACK-WEBHOOK", "Slack incoming webhook", re.compile(r"https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+"), "high", 0),
    ("PSS-DISCORD-WEBHOOK", "Discord webhook", re.compile(r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+"), "high", 0),
    ("PSS-NPM", "npm access token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"), "critical", 0),
    ("PSS-PYPI", "PyPI API token", re.compile(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}"), "critical", 0),
    ("PSS-HUGGINGFACE", "Hugging Face token", re.compile(r"\bhf_[A-Za-z0-9]{30,}\b"), "critical", 0),
    ("PSS-GROQ", "Groq API key", re.compile(r"\bgsk_[A-Za-z0-9]{40,}\b"), "critical", 0),
    ("PSS-REPLICATE", "Replicate API token", re.compile(r"\br8_[A-Za-z0-9]{36,}\b"), "critical", 0),
    ("PSS-PERPLEXITY", "Perplexity API key", re.compile(r"\bpplx-[A-Za-z0-9]{40,}\b"), "critical", 0),
    ("PSS-XAI", "xAI API key", re.compile(r"\bxai-[A-Za-z0-9]{60,}\b"), "critical", 0),
    ("PSS-SENDGRID", "SendGrid API key", re.compile(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b"), "critical", 0),
    ("PSS-MAILGUN", "Mailgun API key", re.compile(r"\bkey-[0-9a-f]{32}\b"), "high", 0),
    ("PSS-TWILIO", "Twilio API key", re.compile(r"\bSK[0-9a-f]{32}\b"), "high", 0),
    ("PSS-TELEGRAM", "Telegram bot token", re.compile(r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b"), "critical", 0),
    ("PSS-DIGITALOCEAN", "DigitalOcean token", re.compile(r"\bdo[pr]_v1_[0-9a-f]{64}\b"), "critical", 0),
    ("PSS-DATABRICKS", "Databricks token", re.compile(r"\bdapi[0-9a-f]{32}\b"), "critical", 0),
    ("PSS-LINEAR", "Linear API key", re.compile(r"\blin_api_[A-Za-z0-9]{40}\b"), "high", 0),
    ("PSS-NOTION", "Notion integration token", re.compile(r"\b(?:secret|ntn)_[A-Za-z0-9]{43}\b"), "high", 0),
    ("PSS-SHOPIFY", "Shopify access token", re.compile(r"\bshp(?:at|ca|pa|ss)_[0-9a-fA-F]{32}\b"), "critical", 0),
    ("PSS-AGE", "age secret key", re.compile(r"\bAGE-SECRET-KEY-1[0-9A-Z]{58}\b"), "critical", 0),
    ("PSS-AZURE-STORAGE", "Azure storage account key", re.compile(r"(?i)AccountKey=([A-Za-z0-9+/]{86}==)"), "critical", 1),
    ("PSS-PRIVATE-KEY", "Private key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"), "critical", 0),
    ("PSS-CONNECTION-STRING", "Connection string with embedded password",
     re.compile(r"(?i)\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqp|amqps|mssql|jdbc:[a-z]+):\/\/[^\s:/@\"']+:([^\s@/\"']{4,})@[^\s\"']+"), "critical", 1),
    ("PSS-JWT", "JSON Web Token", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), "medium", 0),
    ("PSS-BEARER", "Bearer token", re.compile(r"(?i)\bbearer\s+([A-Za-z0-9_\-.=+/]{20,})"), "high", 1),
    ("PSS-GENERIC", "Generic secret assignment",
     re.compile(r"(?i)\b(?:api[_-]?key|secret[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|api[_-]?token|refresh[_-]?token|password|passwd|secret)\b[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9_\-./+=]{16,})[\"']?"), "high", 1),
]
RULE_INDEX = {r[0]: i for i, r in enumerate(RULES)}
RULE_HELP = {
    "PSS-PRIVATE-KEY": "Remove the key material from the file, rotate the key and purge it from history.",
    "PSS-CONNECTION-STRING": "Reference the credential through an environment variable or a secret store; rotate the password.",
    "PSS-BEARER": "Replace the literal token with a placeholder such as ${TOKEN}; rotate it if it was ever valid.",
    "PSS-JWT": "Remove the token; even expired tokens reveal claims and signing conventions.",
    "PSS-GENERIC": "Load the value from the environment or a secret store and reference it as ${VAR}.",
}
DEFAULT_HELP = "Rotate the credential now, move it to a secret store or environment variable, and purge it from git history."


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def redact(value: str) -> str:
    if value.startswith("-----BEGIN"):
        return value
    if len(value) <= 8:
        return "****"
    return value[:4] + "****" + value[-2:]


class Allowlist:
    def __init__(self, text: str = ""):
        self.literals: set[str] = set()
        self.hashes: set[str] = set()
        self.regexes: list[re.Pattern[str]] = []
        self.paths: list[str] = []
        self.rules: set[str] = set()
        self.errors: list[str] = []
        for n, raw in enumerate(text.splitlines(), 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            kind, _, rest = line.partition(":")
            if kind == "sha256" and re.fullmatch(r"[0-9a-fA-F]{64}", rest.strip()):
                self.hashes.add(rest.strip().lower())
            elif kind == "re":
                try:
                    self.regexes.append(re.compile(rest))
                except re.error as exc:
                    self.errors.append(f"allowlist line {n}: bad regex ({exc})")
            elif kind == "path":
                self.paths.append(rest.strip().replace("\\", "/"))
            elif kind == "rule":
                self.rules.add(rest.strip())
            else:
                self.literals.add(line)

    def path_allowed(self, rel: str) -> bool:
        rel = rel.replace("\\", "/")
        return any(fnmatch.fnmatch(rel, p) or fnmatch.fnmatch(rel, p.rstrip("/") + "/*") for p in self.paths)

    def value_allowed(self, rule_id: str, value: str) -> bool:
        if rule_id in self.rules or value in self.literals:
            return True
        if hashlib.sha256(value.encode("utf-8")).hexdigest() in self.hashes:
            return True
        return any(r.search(value) for r in self.regexes)


class Finding:
    __slots__ = ("rule_id", "name", "severity", "file", "line", "value", "context")

    def __init__(self, rule_id: str, name: str, severity: str, file: str, line: int, value: str, context: str):
        self.rule_id, self.name, self.severity, self.file, self.line, self.value, self.context = rule_id, name, severity, file, line, value, context

    def fingerprint(self) -> str:
        return hashlib.sha256(f"{self.rule_id}|{self.file}|{self.value}".encode("utf-8")).hexdigest()

    def as_dict(self) -> dict:
        return {"rule": self.rule_id, "name": self.name, "severity": self.severity, "file": self.file, "line": self.line,
                "evidence": redact(self.value), "context": self.context, "fingerprint": self.fingerprint()}


def scan_text(text: str, file: str, allow: Allowlist, context: str = "") -> list[Finding]:
    """Scan one text body line by line. Overlapping matches on a line keep the first rule in RULES order."""
    out: list[Finding] = []
    for lineno, line in enumerate(text.splitlines(), 1):
        if INLINE_IGNORE_RE.search(line):
            continue
        taken: list[tuple[int, int]] = []
        for rule_id, name, pattern, severity, group in RULES:
            for m in pattern.finditer(line):
                value = m.group(group) if group else m.group(0)
                if not value or any(a < m.end() and m.start() < b for a, b in taken):
                    continue
                if rule_id != "PSS-PRIVATE-KEY" and (PLACEHOLDER_RE.search(value) or ENV_REF_RE.match(value)):
                    continue
                if rule_id in {"PSS-GENERIC", "PSS-BEARER"} and (shannon_entropy(value) < 3.0 or len(set(value)) < 8 or value.lower().startswith(("http", "bearer", "basic"))):
                    continue
                if rule_id == "PSS-CONNECTION-STRING" and (value.lower() in {"password", "pass", "secret"} or shannon_entropy(value) < 2.0):
                    continue
                if allow.value_allowed(rule_id, value):
                    continue
                taken.append((m.start(), m.end()))
                out.append(Finding(rule_id, name, severity, file, lineno, value, context))
    return out


def scan_notebook(raw: str, file: str, allow: Allowlist) -> list[Finding]:
    """Scan cell sources and text outputs of a Jupyter notebook. Lines point into the raw .ipynb file."""
    try:
        nb = json.loads(raw)
    except json.JSONDecodeError:
        return scan_text(raw, file, allow)
    out: list[Finding] = []
    for i, cell in enumerate(nb.get("cells") or []):
        if not isinstance(cell, dict):
            continue
        bodies: list[tuple[str, str]] = []
        src = cell.get("source")
        bodies.append(("".join(src) if isinstance(src, list) else str(src or ""), f"cell {i} source"))
        for o in cell.get("outputs") or []:
            if not isinstance(o, dict):
                continue
            if isinstance(o.get("text"), (list, str)):
                bodies.append(("".join(o["text"]) if isinstance(o["text"], list) else o["text"], f"cell {i} output"))
            data = o.get("data") or {}
            for mime, val in data.items():
                if mime.startswith("text/") and isinstance(val, (list, str)):
                    bodies.append(("".join(val) if isinstance(val, list) else val, f"cell {i} output ({mime})"))
        for body, where in bodies:
            for f in scan_text(body, file, allow, context=where):
                idx = raw.find(f.value if not f.value.startswith("-----BEGIN") else f.value[:20])
                f.line = raw.count("\n", 0, idx) + 1 if idx >= 0 else 1
                out.append(f)
    return out


def discover(root: Path, patterns: list[str], excludes: list[str]) -> list[Path]:
    found: dict[Path, None] = {}
    for pattern in patterns:
        pattern = pattern.strip()
        if not pattern:
            continue
        try:
            matches = sorted(root.glob(pattern))
        except (ValueError, NotImplementedError):
            continue
        for p in matches:
            if not p.is_file():
                continue
            rel = p.relative_to(root).as_posix()
            parts = p.relative_to(root).parts
            if any(part in EXCLUDED_DIRS for part in parts[:-1]):
                continue
            if any(fnmatch.fnmatch(rel, e) for e in excludes):
                continue
            found[p] = None
    return list(found)


def is_binary(data: bytes) -> bool:
    return b"\x00" in data[:8192]


def scan(root: Path, patterns: list[str], excludes: list[str], allow: Allowlist) -> tuple[list[Finding], list[str], list[str]]:
    findings: list[Finding] = []
    scanned: list[str] = []
    notes: list[str] = list(allow.errors)
    for p in discover(root, patterns, excludes):
        rel = p.relative_to(root).as_posix()
        if allow.path_allowed(rel):
            continue
        try:
            if p.stat().st_size > MAX_FILE_BYTES:
                notes.append(f"skipped {rel}: larger than {MAX_FILE_BYTES} bytes")
                continue
            data = p.read_bytes()
        except OSError as exc:
            notes.append(f"could not read {rel}: {exc}")
            continue
        if is_binary(data):
            continue
        text = data.decode("utf-8", errors="replace")
        scanned.append(rel)
        if p.suffix == ".ipynb":
            findings.extend(scan_notebook(text, rel, allow))
        else:
            findings.extend(scan_text(text, rel, allow))
    findings.sort(key=lambda f: (SEVERITIES.index(f.severity), f.file, f.line, f.rule_id))
    return findings, scanned, notes


def to_sarif(findings: list[Finding]) -> dict:
    rules = []
    for rule_id, name, _pattern, severity, _g in RULES:
        rules.append({
            "id": rule_id, "name": rule_id.replace("-", ""),
            "shortDescription": {"text": name},
            "fullDescription": {"text": f"{name} found in a prompt, notebook or agent instruction file."},
            "help": {"text": RULE_HELP.get(rule_id, DEFAULT_HELP), "markdown": RULE_HELP.get(rule_id, DEFAULT_HELP)},
            "helpUri": TOOL_URI + "#rules",
            "defaultConfiguration": {"level": SARIF_LEVEL[severity]},
            "properties": {"security-severity": SECURITY_SEVERITY[severity], "tags": ["security", "secret", "CWE-798"], "precision": "high" if rule_id not in {"PSS-GENERIC", "PSS-BEARER", "PSS-JWT"} else "medium"},
        })
    results = []
    for f in findings:
        where = f" ({f.context})" if f.context else ""
        results.append({
            "ruleId": f.rule_id, "ruleIndex": RULE_INDEX[f.rule_id], "level": SARIF_LEVEL[f.severity],
            "message": {"text": f"{f.name} in {f.file}{where}: {redact(f.value)}. {RULE_HELP.get(f.rule_id, DEFAULT_HELP)}"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.file, "uriBaseId": "%SRCROOT%"}, "region": {"startLine": max(1, f.line)}}}],
            "partialFingerprints": {"primaryLocationLineHash": f.fingerprint()},
            "properties": {"severity": f.severity, "evidence": redact(f.value)},
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": TOOL_NAME, "version": VERSION, "informationUri": TOOL_URI, "rules": rules}},
                  "results": results, "columnKind": "utf16CodeUnits"}],
    }


def to_summary(findings: list[Finding], scanned: list[str], notes: list[str], max_rows: int = 100) -> str:
    counts = {s: sum(1 for f in findings if f.severity == s) for s in SEVERITIES}
    lines = ["## Prompt secrets scan", "",
             f"Scanned {len(scanned)} file(s). Findings: **{len(findings)}** "
             f"(critical {counts['critical']}, high {counts['high']}, medium {counts['medium']}, low {counts['low']}).", ""]
    if findings:
        lines += ["| Severity | Rule | Type | File | Line | Evidence |", "|---|---|---|---|---|---|"]
        for f in findings[:max_rows]:
            lines.append(f"| {f.severity} | `{f.rule_id}` | {f.name} | `{f.file}` | {f.line} | `{redact(f.value)}` |")
        if len(findings) > max_rows:
            lines.append(f"| ... | | {len(findings) - max_rows} more in the SARIF report | | | |")
        lines += ["", "Rotate anything real, move it to a secret store, and add `sha256:<hash>` lines to the allowlist for sample values that must stay."]
    else:
        lines.append("No secrets found in the scanned prompt, notebook and instruction files.")
    if notes:
        lines += ["", "<details><summary>Scan notes</summary>", ""] + [f"- {n}" for n in notes] + ["", "</details>"]
    return "\n".join(lines) + "\n"


def append_file(env_name: str, text: str, override: str | None = None) -> None:
    target = override or os.environ.get(env_name)
    if target:
        with open(target, "a", encoding="utf-8") as fh:
            fh.write(text)


def split_list(raw: str) -> list[str]:
    return [x.strip() for x in re.split(r"[\n,]", raw or "") if x.strip()]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", default=".", help="directory to scan")
    ap.add_argument("--paths", default="", help="globs to scan, comma or newline separated (default: prompt, notebook and instruction files)")
    ap.add_argument("--exclude", default="", help="globs to skip, comma or newline separated (matched against the relative path)")
    ap.add_argument("--allowlist", default="", help="allowlist file (default: .prompt-secrets-allowlist if present)")
    ap.add_argument("--sarif", default="prompt-secrets-scan.sarif")
    ap.add_argument("--json", dest="json_out", default="")
    ap.add_argument("--summary", default="", help="write the Markdown summary here instead of $GITHUB_STEP_SUMMARY")
    ap.add_argument("--fail-on", default="high", choices=SEVERITIES + ["none"])
    args = ap.parse_args(argv)

    root = Path(args.root)
    if not root.is_dir():
        print(f"::error::{TOOL_NAME}: {root} is not a directory", file=sys.stderr)
        return 2
    allow_path = Path(args.allowlist) if args.allowlist else root / ".prompt-secrets-allowlist"
    if args.allowlist and not allow_path.is_file():
        print(f"::error::{TOOL_NAME}: allowlist {allow_path} not found", file=sys.stderr)
        return 2
    allow = Allowlist(allow_path.read_text(encoding="utf-8") if allow_path.is_file() else "")
    patterns = split_list(args.paths) or DEFAULT_PATHS
    findings, scanned, notes = scan(root, patterns, split_list(args.exclude), allow)

    Path(args.sarif).write_text(json.dumps(to_sarif(findings), indent=1), encoding="utf-8")
    if args.json_out:
        Path(args.json_out).write_text(json.dumps({"tool": TOOL_NAME, "version": VERSION, "files_scanned": scanned, "notes": notes,
                                                    "findings": [f.as_dict() for f in findings]}, indent=1) + "\n", encoding="utf-8")
    append_file("GITHUB_STEP_SUMMARY", to_summary(findings, scanned, notes), args.summary or None)

    gate = "pass"
    if args.fail_on != "none" and any(SEVERITIES.index(f.severity) <= SEVERITIES.index(args.fail_on) for f in findings):
        gate = "fail"
    append_file("GITHUB_OUTPUT", f"finding-count={len(findings)}\nfiles-scanned={len(scanned)}\nsarif-file={args.sarif}\ngate={gate}\n")
    for f in findings:
        cmd = "error" if f.severity in {"critical", "high"} else "warning" if f.severity == "medium" else "notice"
        print(f"::{cmd} file={f.file},line={f.line},title={f.rule_id}::{f.name}: {redact(f.value)}")
    print(f"{TOOL_NAME}: {len(findings)} finding(s) in {len(scanned)} file(s), gate {gate} (fail-on {args.fail_on})")
    return 1 if gate == "fail" else 0


if __name__ == "__main__":
    sys.exit(main())
