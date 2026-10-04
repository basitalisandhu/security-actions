#!/usr/bin/env python3
# Copied from agent-security-skills (plugins/agent-security/skills/agent-config-audit/scripts/audit_agent_config.py),
# Copyright (c) 2026 Muhammad Basit Ali, MIT licence: https://github.com/basitalisandhu/agent-security-skills
# Keep this file in sync with the upstream copy; the GitHub Actions glue (SARIF, job summary, outputs) lives in action.py.
"""Audit AI-agent configuration for risky permissions, secrets, unpinned servers and prompt injection.

Scans, relative to --root (default: current directory):
  Claude Code     CLAUDE.md, .claude/CLAUDE.md, .claude/settings*.json, .claude/{commands,skills,agents,hooks}/**, .mcp.json
  Plugins         .claude-plugin/*.json, hooks/hooks.json, skills/*/SKILL.md, agents/*.md, commands/*.md, plugins/*/...
  Cursor          .cursorrules, .cursor/rules/**/*.mdc, .cursor/mcp.json
  Others          AGENTS.md, .github/copilot-instructions.md, .github/instructions/**, .windsurfrules, .clinerules,
                  .vscode/mcp.json, .gemini/settings.json, GEMINI.md, .codex/config.toml
  --include-home  ~/.claude/settings.json, ~/.claude/CLAUDE.md, ~/.cursor/mcp.json, claude_desktop_config.json, ...
  --extra FILE    any additional file (for example a claude_desktop_config.json somewhere else)

Output: JSON (default) or Markdown with findings {id, severity, title, file, line, evidence, recommendation}.
Evidence is redacted: a matched secret is never printed in full.
Exit code: 0, or 1 when --fail-on SEVERITY is given and a finding of that severity or higher exists.

Standard library only. Read-only. No network.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import math
import os
import re
import shlex
import stat
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

VERSION = "0.1.0"
SEVERITIES = ["critical", "high", "medium", "low", "info"]
MAX_FILE_BYTES = 2 * 1024 * 1024

PROJECT_GLOBS = [
    "CLAUDE.md", "CLAUDE.local.md", ".claude/CLAUDE.md", ".claude/settings.json", ".claude/settings.local.json",
    ".claude/commands/**/*.md", ".claude/skills/**/SKILL.md", ".claude/agents/**/*.md", ".claude/hooks/**/*", ".mcp.json",
    ".claude-plugin/plugin.json", ".claude-plugin/marketplace.json", "hooks/hooks.json", "skills/*/SKILL.md",
    "agents/**/*.md", "commands/**/*.md", "plugins/*/.claude-plugin/plugin.json", "plugins/*/hooks/hooks.json",
    "plugins/*/.mcp.json", "plugins/*/skills/*/SKILL.md", "plugins/*/agents/**/*.md", "plugins/*/commands/**/*.md",
    ".cursorrules", ".cursor/rules/**/*.mdc", ".cursor/rules/**/*.md", ".cursor/mcp.json", "AGENTS.md",
    ".github/copilot-instructions.md", ".github/instructions/**/*.md", ".windsurfrules", ".windsurf/rules/**/*",
    ".clinerules", ".clinerules/**/*", ".vscode/mcp.json", ".gemini/settings.json", "GEMINI.md", ".codex/config.toml",
    ".roo/rules/**/*", ".aider.conf.yml", ".continue/config.json", ".continue/config.yaml",
]
HOME_FILES = [
    "~/.claude/settings.json", "~/.claude/CLAUDE.md", "~/.cursor/mcp.json", "~/.codex/config.toml",
    "~/.gemini/settings.json", "~/Library/Application Support/Claude/claude_desktop_config.json",
    "~/.config/Claude/claude_desktop_config.json", "~/AppData/Roaming/Claude/claude_desktop_config.json",
    "~/.continue/config.json", "~/.continue/config.yaml",
]
INSTRUCTION_SUFFIXES = {".md", ".mdc", ".txt"}
INSTRUCTION_NAMES = {".cursorrules", ".windsurfrules", ".clinerules"}

HIGH_RISK_PROGRAMS = {"rm", "sudo", "su", "curl", "wget", "nc", "ncat", "netcat", "bash", "sh", "zsh", "eval", "dd", "mkfs",
                      "shred", "chmod", "chown", "base64", "xxd", "env", "printenv", "python", "python3", "node", "perl",
                      "ruby", "ssh", "scp", "sftp", "rsync", "telnet", "socat", "openssl", "gpg", "crontab", "systemctl",
                      "launchctl", "osascript", "powershell", "pwsh", "cmd"}
MEDIUM_RISK_PROGRAMS = {"git", "npm", "npx", "pnpm", "yarn", "bun", "pip", "pip3", "uv", "uvx", "pipx", "docker", "podman",
                        "kubectl", "helm", "aws", "gcloud", "az", "terraform", "pulumi", "gh", "glab", "vercel", "fly",
                        "flyctl", "heroku", "railway", "make", "cargo", "go", "mvn", "gradle", "dotnet", "brew", "apt",
                        "apt-get", "yum", "dnf", "pacman", "snap", "find", "xargs"}
DANGEROUS_FLAGS = {"--dangerously-skip-permissions", "--allow-all", "--yolo", "--no-sandbox", "--unsafe", "--trust-all",
                   "--allow-all-tools", "--disable-sandbox", "--full-auto", "--approval-mode=yolo", "--permission-mode=bypassPermissions",
                   "-y", "--yes", "--dangerously-allow-browser"}
SECRET_KEY_RE = re.compile(r"(?i)(api[_-]?key|secret|token|passw(or)?d|passwd|credential|private[_-]?key|auth|bearer|cookie|session)")
ENV_REF_RE = re.compile(r"^\$\{?[A-Za-z_][A-Za-z0-9_]*(:-[^}]*)?\}?$|^\$\{user_config\.[A-Za-z0-9_]+\}$")
PLACEHOLDER_RE = re.compile(r"(?i)(xxxx|your[_-]|example|placeholder|redacted|changeme|change-me|<[^>]+>|\.\.\.|\*\*\*|dummy|sample|test-?key|fake|insert|replace|todo|tbd|\$\{)")

SECRET_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    ("OpenAI API key", re.compile(r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{32,}\b"), "critical"),
    ("Anthropic API key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{32,}\b"), "critical"),
    ("GitHub token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{22,}\b"), "critical"),
    ("GitLab token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b"), "critical"),
    ("AWS access key id", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"), "critical"),
    ("Slack token", re.compile(r"\bxox[abprse]-[A-Za-z0-9-]{10,}\b"), "critical"),
    ("Slack webhook", re.compile(r"https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+"), "high"),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), "critical"),
    ("Stripe key", re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}\b"), "critical"),
    ("npm token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"), "critical"),
    ("Hugging Face token", re.compile(r"\bhf_[A-Za-z0-9]{30,}\b"), "critical"),
    ("Masoon agent key", re.compile(r"\bhsk\.ag-[0-9a-f]{12}\.[A-Za-z0-9_-]{32}\b"), "critical"),
    ("Masoon operator token", re.compile(r"\bhop\.op-[0-9a-f]{12}\.[A-Za-z0-9_-]{32}\b"), "critical"),
    ("Private key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY(?: BLOCK)?-----"), "critical"),
    ("JSON Web Token", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), "high"),
    ("Generic secret assignment", re.compile(r"(?i)\b(api[_-]?key|secret[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|api[_-]?token|password|passwd|secret)\b[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9_\-./+=]{16,})[\"']?"), "high"),
]

# (id, severity, pattern, title, recommendation, negatable). A negatable pattern is skipped when the words just
# before it negate it ("never print a secret", "do not paste tokens"), so security guidance is not flagged as an attack.
INJECTION_PATTERNS: list[tuple[str, str, re.Pattern[str], str, str, bool]] = [
    ("INJ-001", "high", re.compile(r"(?i)\b(ignore|disregard|forget|override)\s+(all\s+|any\s+|the\s+|your\s+)?(previous|prior|above|earlier|preceding|system|other)\s+(instructions?|rules?|prompts?|guidance|constraints?)"), "Instruction-override phrase", "Remove it. Instruction files should add guidance, never cancel the host's or user's rules.", False),
    ("INJ-001", "high", re.compile(r"(?i)\b(you are now (?:a|an|in|the)\b|new instructions?:|system override|(?:enter|enable|activate|switch to) developer mode)"), "Role or instruction override phrase", "Remove it. This is the signature of a prompt-injection payload.", False),
    ("INJ-002", "high", re.compile(r"(?i)\b(do not|don't|never|without)\s+(tell|inform|mention|show|notify|ask|alert|warn|reveal (?:this )?to)\s+(the\s+)?(user|human|operator|developer)"), "Instruction to hide actions from the user", "Remove it. Agents must not be told to act without the user's knowledge.", False),
    ("INJ-002", "high", re.compile(r"(?i)\b(silently|secretly|covertly|quietly)\s+(run|execute|send|upload|install|delete|modify|change|post|fetch|download|exfiltrate)"), "Covert action instruction", "Remove it.", True),
    ("INJ-003", "high", re.compile(r"(?i)\b(send|post|upload|transmit|forward|exfiltrate|copy|submit)\s+(?:the\s+|all\s+|every\s+|my\s+|your\s+|our\s+|this\s+|these\s+|it\s+|them\s+)?(?:full\s+|entire\s+|whole\s+|raw\s+)?(?:contents?\s+of\s+(?:the\s+)?)?(data|files?|inbox|emails?|messages?|repository|repo|code|source|logs?|results?|output|history|transcript|conversation|everything|secrets?|keys?|tokens?|credentials?|passwords?|\.env|[\w.-]+)\b[^.\n]{0,40}?\b(to|at)\s+(https?://|www\.|[\w.+-]+@[\w-]+\.[a-z]{2,}|[a-z0-9-]+(?:\.[a-z0-9-]+)+\.(?:com|net|io|dev|ai|org|xyz|site|me|app)\b|a\s+webhook|my\s+server|this\s+url|the\s+url\s+below)"), "Instruction to send data to an external endpoint", "Remove it unless the destination is a documented, approved integration; agents should never be instructed to ship data outward from an instruction file.", True),
    ("INJ-003", "high", re.compile(r"(?i)\b(send|post|upload|include|paste|print|echo|output|share|read|cat|copy|forward|email|reveal|dump|expose)\s+(?:the\s+|all\s+|any\s+|every\s+|my\s+|your\s+|our\s+|its\s+|their\s+|a\s+|an\s+)?(?:contents?\s+of\s+(?:the\s+)?)?(api[_ ]?keys?|tokens?|credentials?|secrets?|passwords?|\.env\b|ssh keys?|private keys?|\.aws/credentials|environment variables?)"), "Instruction that touches secrets", "Remove it. No instruction file should direct an agent to read or emit credentials.", True),
    ("INJ-004", "critical", re.compile(r"(?i)(curl|wget)\b[^\n|]{0,120}\|\s*(sudo\s+)?(sh|bash|zsh|python3?|node|perl)\b"), "Remote code piped into a shell", "Download to a file, review it, pin a hash, then run it. Never pipe remote content into a shell from an instruction file.", True),
    ("INJ-004", "high", re.compile(r"(?i)\b(always|automatically|on (every|each) (start|session|run)|before (anything|every))\b[^.\n]{0,60}\b(run|execute|install|npx|pip install|curl|wget|source)\b"), "Instruction to auto-run commands", "Instruction files that make the agent run commands on every session are a persistence mechanism; move the behaviour into a reviewed hook or remove it.", True),
    ("INJ-008", "high", re.compile(r"(?i)\b(use|set|enable|run|pass|add|start|launch|with|using)\s+(?:the\s+)?(?:flag\s+)?(--dangerously-skip-permissions|bypassPermissions|--yolo|--allow-all)|\b(disable|turn off|skip|bypass|remove)\s+(?:all\s+|the\s+|every\s+|any\s+)?(hooks?|permissions?(?:\s+prompts?| checks?)?|guardrails|sandbox(?:ing)?|safety(?:\s+checks?)?|security(?:\s+checks?)?|approvals?|confirmations?)\b|\bauto-?approve\s+(all|everything|every)\b|\bapprove\s+(all|everything)\s+(?:automatically|without)"), "Instruction to weaken safety controls", "Remove it. Permission and hook settings belong in reviewed settings files, not in prose the model reads.", True),
    ("INJ-008", "high", re.compile(r"(?i)\b(rm\s+-rf\s+[/~.*]|chmod\s+(-R\s+)?777|git\s+push\s+(-f|--force)\b[^\n]*\b(main|master)\b|mkfs\.|:\(\)\s*\{\s*:\|:&\s*\};:)"), "Destructive command in instruction file", "Remove it or make it an explicit, user-triggered step with confirmation.", True),
    ("INJ-009", "high", re.compile(r"(?i)\b(cat|read|open|print|echo|source|dump|copy|upload)\b[^.\n]{0,40}(~/\.ssh/|\.aws/credentials|/etc/shadow|~/\.netrc|id_rsa|id_ed25519|\.git-credentials|~/\.npmrc|~/\.config/gh)"), "Instruction to read credential files", "Remove it.", True),
]
NEGATION_RE = re.compile(r"(?i)\b(never|not|don't|do not|must not|should not|shouldn't|won't|cannot|can't|no|without|avoid|refuse|forbid|forbidden|prohibited|instead of|rather than|unless)\b[^.\n]{0,25}$")
HTML_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.S)
IMPERATIVE_RE = re.compile(r"(?i)\b(always|never|must|run|execute|send|ignore|do not|don't|install|curl|wget|delete|upload|post)\b")
ZERO_WIDTH_RE = re.compile("[\u200b\u200c\u200d\u200e\u200f\u2060\u2061\u2062\u2063\u2064\ufeff\u00ad\u180e]")
BIDI_RE = re.compile("[\u202a-\u202e\u2066-\u2069]")
TAG_CHARS_RE = re.compile("[\U000e0000-\U000e007f]")
BASE64_BLOB_RE = re.compile(r"(?<![A-Za-z0-9+/=])(?:[A-Za-z0-9+/]{4}){20,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?(?![A-Za-z0-9+/=])")
NETWORK_TOOL_RE = re.compile(r"(?i)\b(curl|wget|nc|ncat|netcat|socat|telnet|ssh|scp|sftp|rsync|Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\b|https?://")
PIPE_TO_SHELL_RE = re.compile(r"(?i)(curl|wget)\b[^|\n]*\|\s*(sudo\s+)?(sh|bash|zsh|python3?|node|perl)\b")


@dataclass
class Finding:
    id: str
    severity: str
    category: str
    title: str
    file: str
    line: int | None
    evidence: str
    recommendation: str

    def key(self):
        return (self.id, self.file, self.line, self.evidence)


class Auditor:
    def __init__(self, root: Path, include_home: bool = False, extra: list[Path] | None = None):
        self.root = root.resolve()
        self.include_home = include_home
        self.extra = [p.resolve() for p in (extra or [])]
        self.findings: list[Finding] = []
        self.scanned: list[str] = []
        self.errors: list[str] = []
        self._seen = set()

    # ------------------------------------------------------------------ helpers
    def rel(self, path: Path) -> str:
        try:
            return str(path.resolve().relative_to(self.root))
        except ValueError:
            return str(path)

    def add(self, fid: str, severity: str, category: str, title: str, path: Path, line: int | None, evidence: str, recommendation: str) -> None:
        f = Finding(fid, severity, category, title, self.rel(path), line, redact(evidence)[:300], recommendation)
        if f.key() in self._seen:
            return
        self._seen.add(f.key())
        self.findings.append(f)

    @staticmethod
    def line_of(text: str, needle: str) -> int | None:
        if not needle:
            return None
        idx = text.find(needle)
        if idx < 0:
            idx = text.find(needle.split("\n")[0][:40])
        if idx < 0:
            return None
        return text.count("\n", 0, idx) + 1

    def read(self, path: Path) -> str | None:
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                self.errors.append(f"skipped {path}: larger than {MAX_FILE_BYTES} bytes")
                return None
            return path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            self.errors.append(f"could not read {path}: {exc}")
            return None

    # ------------------------------------------------------------------ discovery
    def targets(self) -> list[Path]:
        found: list[Path] = []
        for pattern in PROJECT_GLOBS:
            for p in sorted(self.root.glob(pattern)):
                if p.is_file() and "node_modules" not in p.parts and ".git" not in p.parts:
                    found.append(p)
        if self.include_home:
            for h in HOME_FILES:
                p = Path(os.path.expanduser(h))
                if p.is_file():
                    found.append(p)
        found.extend(p for p in self.extra if p.is_file())
        uniq: list[Path] = []
        seen = set()
        for p in found:
            r = p.resolve()
            if r not in seen:
                seen.add(r)
                uniq.append(p)
        return uniq

    # ------------------------------------------------------------------ dispatch
    def run(self) -> None:
        for path in self.targets():
            self.scanned.append(self.rel(path))
            self.check_mode(path)
            text = self.read(path)
            if text is None:
                continue
            self.scan_secrets(path, text)
            name = path.name
            if name.endswith(".json"):
                self.scan_json(path, text)
            elif name.endswith(".toml"):
                self.scan_toml(path, text)
            elif path.suffix in INSTRUCTION_SUFFIXES or name in INSTRUCTION_NAMES or "rules" in path.parts or "instructions" in path.parts:
                self.scan_instructions(path, text)
                if name == "SKILL.md" or "commands" in path.parts or "agents" in path.parts:
                    self.scan_frontmatter(path, text)
            elif "hooks" in path.parts:
                self.scan_hook_script(path, text)
        for plugin_root in self.plugin_roots():
            if (plugin_root / "bin").is_dir():
                self.add("PLUGIN-001", "low", "plugin", "Plugin ships a bin/ directory that goes on the Bash PATH",
                         plugin_root / "bin", None, "bin/", "Review every executable in bin/; while the plugin is enabled Claude can run them as bare commands.")

    def plugin_roots(self) -> list[Path]:
        roots = []
        for manifest in list(self.root.glob(".claude-plugin/plugin.json")) + list(self.root.glob("plugins/*/.claude-plugin/plugin.json")):
            roots.append(manifest.parent.parent)
        return roots

    # ------------------------------------------------------------------ checks
    def check_mode(self, path: Path) -> None:
        if os.name != "posix":
            return
        try:
            mode = path.stat().st_mode
        except OSError:
            return
        if mode & stat.S_IWOTH:
            self.add("FILE-001", "medium", "file", "Agent configuration file is world-writable", path, None, oct(mode & 0o777),
                     "chmod o-w the file. Anyone on the machine could add hooks, permissions or instructions.")

    def scan_secrets(self, path: Path, text: str) -> None:
        for title, pattern, sev in SECRET_PATTERNS:
            for m in pattern.finditer(text):
                value = m.group(m.lastindex) if m.lastindex else m.group(0)
                if title == "Generic secret assignment":
                    value = m.group(2)
                    if ENV_REF_RE.match(value) or value.startswith("$") or PLACEHOLDER_RE.search(value) or value.lower().startswith(("http", "bearer", "basic")):
                        continue
                    if shannon_entropy(value) < 3.0 or len(set(value)) < 8:
                        continue
                    # skip Markdown prose like "password: the user's password"
                    if " " in value:
                        continue
                elif PLACEHOLDER_RE.search(value) or (len(set(value)) < 8 and "PRIVATE KEY" not in value):
                    continue
                line = text.count("\n", 0, m.start()) + 1
                self.add("SEC-001", sev, "secret", f"{title} found in agent configuration", path, line, m.group(0),
                         "Move the value to an environment variable or a secret store, reference it as ${VAR}, rotate it now, and purge it from history.")

    def scan_json(self, path: Path, text: str) -> None:
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            self.add("CFG-001", "low", "config", "JSON file does not parse", path, exc.lineno, str(exc)[:120],
                     "Fix the syntax; a config that fails to parse is silently ignored by most hosts, so its protections (deny rules, hooks) are not applied.")
            return
        if not isinstance(data, dict):
            return
        if "permissions" in data or "hooks" in data or "enableAllProjectMcpServers" in data or "disableAllHooks" in data:
            self.scan_settings(path, text, data)
        if "hooks" in data and isinstance(data["hooks"], dict):
            self.scan_hooks(path, text, data["hooks"], plugin_root=self.plugin_root_for(path))
        servers = self.extract_mcp_servers(data)
        if servers:
            self.scan_mcp(path, text, servers)
        if path.name == "plugin.json" and isinstance(data.get("hooks"), dict):
            self.scan_hooks(path, text, data["hooks"], plugin_root=self.plugin_root_for(path))

    def plugin_root_for(self, path: Path) -> Path | None:
        for parent in [path.parent] + list(path.parents):
            if (parent / ".claude-plugin" / "plugin.json").exists():
                return parent
        return None

    @staticmethod
    def extract_mcp_servers(data: dict) -> dict:
        for key in ("mcpServers", "servers"):
            if isinstance(data.get(key), dict):
                return {k: v for k, v in data[key].items() if isinstance(v, dict)}
        if data and all(isinstance(v, dict) and ("command" in v or "url" in v) for v in data.values()):
            return dict(data)
        return {}

    # settings.json ------------------------------------------------------------
    def scan_settings(self, path: Path, text: str, data: dict) -> None:
        perms = data.get("permissions") or {}
        mode = perms.get("defaultMode") or data.get("defaultMode")
        if mode == "bypassPermissions":
            self.add("PERM-003", "critical", "permissions", "defaultMode is bypassPermissions", path, self.line_of(text, "bypassPermissions"),
                     '"defaultMode": "bypassPermissions"', "Use default or acceptEdits, and allowlist specific commands instead. Bypass mode removes every prompt, including for destructive commands.")
        elif mode in {"dontAsk", "auto"}:
            self.add("PERM-003", "medium", "permissions", f"defaultMode is {mode}", path, self.line_of(text, mode), f'"defaultMode": "{mode}"',
                     "Confirm this is intended; commands outside the allow list run without a prompt in this mode.")
        if data.get("skipDangerousModePermissionPrompt") is True:
            self.add("PERM-003", "high", "permissions", "Dangerous-mode prompt is skipped", path, self.line_of(text, "skipDangerousModePermissionPrompt"),
                     "skipDangerousModePermissionPrompt: true", "Remove it.")
        if data.get("enableAllProjectMcpServers") is True:
            self.add("PERM-007", "medium", "permissions", "All project MCP servers are auto-approved", path, self.line_of(text, "enableAllProjectMcpServers"),
                     '"enableAllProjectMcpServers": true', "Approve project MCP servers one by one. A malicious .mcp.json in a cloned repo would otherwise start automatically.")
        if data.get("disableAllHooks") is True:
            self.add("PERM-008", "medium", "permissions", "All hooks are disabled", path, self.line_of(text, "disableAllHooks"), '"disableAllHooks": true',
                     "Re-enable hooks; guard hooks such as secret-exposure blocking do not run while this is set.")
        for rule in perms.get("allow") or []:
            if not isinstance(rule, str):
                continue
            self.scan_allow_rule(path, text, rule)
        for d in perms.get("additionalDirectories") or []:
            if isinstance(d, str) and (d.rstrip("/") or "/") in {"/", "~", "$HOME", os.path.expanduser("~"), "/home", "/Users", "C:\\", "C:"}:
                self.add("PERM-010", "medium", "permissions", "additionalDirectories grants the whole home or root directory", path, self.line_of(text, d), d,
                         "Grant the specific project directories you need.")
        allow = [r for r in perms.get("allow") or [] if isinstance(r, str)]
        deny = perms.get("deny") or []
        if any(r.split("(")[0] in {"Bash", "Write", "Edit", "MultiEdit"} and ("(" not in r or r.endswith("(*)")) for r in allow) and not deny:
            self.add("PERM-011", "low", "permissions", "Broad allow rules with no deny rules", path, None, "permissions.deny is empty",
                     "Add deny rules for the commands and paths that must never run (for example Bash(rm -rf *), Read(./.env), Bash(curl *)).")

    def scan_allow_rule(self, path: Path, text: str, rule: str) -> None:
        tool, _, spec = rule.partition("(")
        spec = spec[:-1] if spec.endswith(")") else spec
        line = self.line_of(text, rule)
        tool_l = tool.strip()
        if tool_l == "Bash":
            words = spec.split()
            if not spec.strip() or spec.strip() in {"*", "**", ":*"}:
                self.add("PERM-001", "critical", "permissions", "Any shell command is pre-approved", path, line, rule,
                         "Replace with specific rules such as Bash(npm test), Bash(git status *), Bash(pytest *).")
                return
            prog = os.path.basename(words[0]) if words else ""
            wildcard_next = len(words) == 1 or (len(words) > 1 and words[1] in {"*", "**"})
            if prog in HIGH_RISK_PROGRAMS and wildcard_next:
                self.add("PERM-002", "high", "permissions", f"Dangerous program pre-approved with a wildcard: {prog}", path, line, rule,
                         f"Narrow the rule to the exact invocations you need (for example Bash({prog} --version)), or remove it.")
            elif prog in HIGH_RISK_PROGRAMS:
                self.add("PERM-002", "low", "permissions", f"Risky program pre-approved with a narrow pattern: {prog}", path, line, rule,
                         "Confirm the pattern cannot be widened with shell tricks (quotes, variables, command substitution).")
            elif prog in MEDIUM_RISK_PROGRAMS and wildcard_next:
                self.add("PERM-002", "medium", "permissions", f"Broad pre-approval for {prog}", path, line, rule,
                         f"Prefer subcommand-level rules (for example Bash({prog} status *)) so that publish, push --force or install of arbitrary packages still prompt.")
            if any(flag in spec for flag in DANGEROUS_FLAGS if flag not in {"-y", "--yes"}):
                self.add("PERM-009", "high", "permissions", "Pre-approved command carries a permission-bypass flag", path, line, rule, "Remove the flag from the rule.")
        elif tool_l in {"Write", "Edit", "MultiEdit", "NotebookEdit"} and (not spec.strip() or spec.strip() in {"*", "**", "**/*"}):
            self.add("PERM-004", "medium", "permissions", f"{tool_l} is pre-approved for every path", path, line, rule,
                     "Scope it to the project (for example Write(./src/**)) and deny .claude/, .git/ and dotfiles.")
        elif tool_l in {"WebFetch", "WebSearch"} and (not spec.strip() or spec.strip() in {"*", "domain:*"}):
            self.add("PERM-005", "medium", "permissions", f"{tool_l} is pre-approved for every domain", path, line, rule,
                     "Allow specific domains (WebFetch(domain:docs.example.com)). Unrestricted fetch is a data-exfiltration channel under prompt injection.")
        elif tool_l.startswith("mcp__") and (tool_l.endswith("*") or tool_l.count("__") == 1) and not spec:
            self.add("PERM-006", "medium", "permissions", "Every tool of an MCP server is pre-approved", path, line, rule,
                     "Allow the individual read-only tools you need; keep write and delete tools behind a prompt.")

    # hooks ----------------------------------------------------------------------
    def scan_hooks(self, path: Path, text: str, hooks: dict, plugin_root: Path | None) -> None:
        for event, matchers in hooks.items():
            if not isinstance(matchers, list):
                continue
            for matcher in matchers:
                if not isinstance(matcher, dict):
                    continue
                for h in matcher.get("hooks") or []:
                    if not isinstance(h, dict):
                        continue
                    self.scan_hook(path, text, event, h, plugin_root)

    def scan_hook(self, path: Path, text: str, event: str, h: dict, plugin_root: Path | None) -> None:
        htype = h.get("type", "command")
        command = h.get("command") or ""
        args = [a for a in (h.get("args") or []) if isinstance(a, str)]
        full = " ".join([command] + args)
        line = self.line_of(text, command or h.get("url") or "")
        if htype == "http":
            url = h.get("url") or ""
            host = re.sub(r"^[a-z]+://", "", url).split("/")[0].split(":")[0].lower()
            if host and host not in {"localhost", "127.0.0.1", "::1", "[::1]"} and not host.endswith(".localhost"):
                self.add("HOOK-002", "high", "hooks", f"{event} hook posts tool data to a remote endpoint", path, line, url,
                         "Hook payloads include commands, file paths and sometimes file contents. Keep HTTP hooks on loopback or make sure the endpoint is yours and uses HTTPS.")
            if url.startswith("http://") and host not in {"localhost", "127.0.0.1"}:
                self.add("MCP-001", "high", "hooks", "HTTP hook uses plain HTTP", path, line, url, "Use https://.")
            return
        if htype != "command":
            return
        if PIPE_TO_SHELL_RE.search(full):
            self.add("HOOK-004", "critical", "hooks", f"{event} hook pipes remote content into a shell", path, line, full,
                     "Bundle the script with the repository or plugin and call it by path.")
        elif NETWORK_TOOL_RE.search(full) and not re.search(r"(?i)localhost|127\.0\.0\.1", full):
            self.add("HOOK-002", "high", "hooks", f"{event} hook can reach the network", path, line, full,
                     "Hooks receive the tool input (commands, paths, prompts). A hook that calls curl, ssh or an external URL can exfiltrate them. Keep hooks local or document exactly what is sent where.")
        for title, pattern, sev in SECRET_PATTERNS[:-1]:
            if pattern.search(full):
                self.add("HOOK-003", "critical", "hooks", f"{event} hook command contains a {title}", path, line, full,
                         "Read the secret from the environment inside the script instead.")
        if "${CLAUDE_PLUGIN_ROOT}" in command and not args and not re.search(r"\"\$\{CLAUDE_PLUGIN_ROOT\}[^\"]*\"", command):
            self.add("HOOK-005", "low", "hooks", "Shell-form hook leaves ${CLAUDE_PLUGIN_ROOT} unquoted", path, line, command,
                     'Quote it ("${CLAUDE_PLUGIN_ROOT}"/script.sh) or use exec form with args so a path with spaces stays one argument.')
        script = self.hook_script_path(command, args, plugin_root)
        if script is not None and not script.exists():
            self.add("HOOK-001", "medium", "hooks", f"{event} hook references a script that does not exist", path, line, str(script),
                     "Fix the path. A missing hook fails open (the tool runs) or fails loudly, depending on the host; either way the control it was meant to add is absent.")
        elif script is not None and script.exists() and os.name == "posix" and (script.stat().st_mode & stat.S_IWOTH):
            self.add("HOOK-006", "high", "hooks", "Hook script is world-writable", path, line, str(script),
                     "chmod o-w the script. Anyone on the machine could change what runs on every tool call.")

    def hook_script_path(self, command: str, args: list[str], plugin_root: Path | None) -> Path | None:
        candidates = args[:1] if args else []
        if not candidates:
            try:
                words = shlex.split(command)
            except ValueError:
                return None
            candidates = [w for w in words if "/" in w or w.endswith((".sh", ".py", ".js", ".mjs", ".ts", ".rb"))][:1]
        if not candidates:
            return None
        raw = candidates[0]
        if "${CLAUDE_PLUGIN_ROOT}" in raw:
            if plugin_root is None:
                return None
            raw = raw.replace("${CLAUDE_PLUGIN_ROOT}", str(plugin_root))
        raw = raw.replace("${CLAUDE_PROJECT_DIR}", str(self.root)).replace("$CLAUDE_PROJECT_DIR", str(self.root))
        if "${" in raw or "$" in raw or raw.startswith(("-", "|")):
            return None
        p = Path(os.path.expanduser(raw))
        if not p.is_absolute():
            p = self.root / p
        return p

    def scan_hook_script(self, path: Path, text: str) -> None:
        if PIPE_TO_SHELL_RE.search(text):
            self.add("HOOK-004", "critical", "hooks", "Hook script pipes remote content into a shell", path, self.line_of(text, "curl") or self.line_of(text, "wget"),
                     PIPE_TO_SHELL_RE.search(text).group(0), "Vendor the script instead.")
        elif NETWORK_TOOL_RE.search(text) and not re.search(r"(?i)localhost|127\.0\.0\.1", text):
            m = NETWORK_TOOL_RE.search(text)
            self.add("HOOK-002", "medium", "hooks", "Hook script can reach the network", path, text.count("\n", 0, m.start()) + 1, m.group(0),
                     "Confirm what the script sends and where; hook input contains commands, paths and prompts.")

    # MCP ------------------------------------------------------------------------
    def scan_mcp(self, path: Path, text: str, servers: dict) -> None:
        for name, cfg in servers.items():
            url = cfg.get("url") or ""
            stype = cfg.get("type") or ("http" if url else "stdio")
            line = self.line_of(text, f'"{name}"')
            if url:
                host = re.sub(r"^[a-z]+://", "", url).split("/")[0].split("@")[-1]
                hostname = host.rsplit(":", 1)[0].strip("[]") if not host.startswith("[") else host.split("]")[0].strip("[")
                loop = hostname in {"localhost", "127.0.0.1", "::1", "0.0.0.0"} or hostname.endswith(".localhost")
                if url.startswith(("http://", "ws://")) and not loop:
                    self.add("MCP-001", "high", "mcp", f"MCP server {name} uses plain {url.split(':')[0].upper()}", path, line, url,
                             "Use https:// or wss://. Tokens in headers and every tool result travel in clear text otherwise.")
                if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname) and not loop:
                    self.add("MCP-008", "medium", "mcp", f"MCP server {name} is addressed by raw IP", path, line, url,
                             "Use a DNS name with a valid certificate so the server identity can be verified and pinned.")
                if stype == "sse":
                    self.add("MCP-006", "low", "mcp", f"MCP server {name} uses the deprecated SSE transport", path, line, '"type": "sse"', "Switch to type http (streamable HTTP).")
            for hname, hval in (cfg.get("headers") or {}).items():
                if isinstance(hval, str):
                    self.literal_credential(path, line, name, f"headers.{hname}", hval)
            for ename, eval_ in (cfg.get("env") or {}).items():
                if isinstance(eval_, str):
                    self.literal_credential(path, line, name, f"env.{ename}", eval_)
            command = cfg.get("command") or ""
            args = [a for a in (cfg.get("args") or []) if isinstance(a, str)]
            self.pinning(path, line, name, command, args)
            joined = " ".join([command] + args)
            for flag in DANGEROUS_FLAGS:
                if flag in {"-y", "--yes"}:
                    continue
                if flag in args or f" {flag}" in joined:
                    self.add("MCP-005", "medium", "mcp", f"MCP server {name} is started with {flag}", path, line, joined, "Remove the flag; run the server with its default safety checks.")
            if re.search(r"(^|/)(tmp|temp|Downloads|Desktop)/", command) or any(re.search(r"(^|/)(tmp|temp|Downloads)/", a) for a in args):
                self.add("MCP-004", "medium", "mcp", f"MCP server {name} runs from a temporary or download directory", path, line, joined,
                         "Install the server to a stable, version-controlled location.")
            if "server-filesystem" in joined or "mcp-server-filesystem" in joined or "filesystem" in name.lower():
                roots = [a for a in args if a.startswith(("/", "~", "$HOME", "C:")) and not a.startswith("/dev")]
                broad = [r for r in roots if (r.rstrip("/") or "/") in {"/", "~", "$HOME", "/home", "/Users", "C:", "C:\\"} or r.rstrip("/") == os.path.expanduser("~")]
                if broad:
                    self.add("MCP-007", "high", "mcp", f"Filesystem MCP server {name} exposes the whole home or root directory", path, line, " ".join(broad),
                             "Point it at the specific project directories the agent needs.")
            if command in {"sh", "bash", "zsh", "cmd", "powershell", "pwsh"} and any(a in {"-c", "/c"} for a in args):
                self.add("MCP-005", "low", "mcp", f"MCP server {name} is launched through a shell string", path, line, joined,
                         "Launch the binary directly with args so the command line cannot be re-interpreted.")

    def literal_credential(self, path: Path, line: int | None, server: str, where: str, value: str) -> None:
        v = value.strip()
        if not v or ENV_REF_RE.match(v) or "${" in v or v.startswith("$"):
            return
        secretish_key = bool(SECRET_KEY_RE.search(where))
        known = next((t for t, p, _ in SECRET_PATTERNS[:-1] if p.search(v)), None)
        bearer = re.match(r"(?i)^(bearer|basic|token)\s+(\S{12,})$", v)
        if known:
            self.add("MCP-002", "critical", "mcp", f"Literal {known} in {where} of MCP server {server}", path, line, f"{where}: {v}",
                     "Reference it as ${VAR} and set the variable in your shell or secret store; rotate the exposed value.")
        elif bearer and not PLACEHOLDER_RE.search(bearer.group(2)):
            self.add("MCP-002", "high", "mcp", f"Literal credential in {where} of MCP server {server}", path, line, f"{where}: {v}",
                     "Use ${VAR} substitution instead of a literal token.")
        elif secretish_key and len(v) >= 8 and not PLACEHOLDER_RE.search(v) and shannon_entropy(v) >= 3.0:
            self.add("MCP-002", "high", "mcp", f"Literal credential in {where} of MCP server {server}", path, line, f"{where}: {v}",
                     "Use ${VAR} substitution instead of a literal value.")

    def pinning(self, path: Path, line: int | None, server: str, command: str, args: list[str]) -> None:
        base = os.path.basename(command)
        if base in {"npx", "pnpx", "bunx", "pnpm", "yarn"}:
            pkgs = [a for a in args if not a.startswith("-") and a not in {"dlx", "exec", "run"}]
            if base in {"pnpm", "yarn"} and "dlx" not in args and "exec" not in args:
                return
            pkg = pkgs[0] if pkgs else ""
            if pkg and not re.search(r".@[~^]?\d|.@latest$|.@[0-9a-f]{7,}$", pkg) and not pkg.startswith((".", "/")):
                self.add("MCP-003", "medium", "mcp", f"MCP server {server} runs an unpinned npm package", path, line, " ".join([command] + args),
                         f"Pin a version ({pkg}@x.y.z) or install the package and point command at the installed binary; `{base} -y` fetches whatever is latest on every start.")
            elif pkg.endswith("@latest"):
                self.add("MCP-003", "medium", "mcp", f"MCP server {server} tracks @latest", path, line, " ".join([command] + args), "Pin an exact version.")
        elif base in {"uvx", "pipx"} or (base == "uv" and args[:2] == ["tool", "run"]):
            spec = next((a for a in args if not a.startswith("-") and a not in {"run", "tool"}), "")
            idx = args.index("--from") + 1 if "--from" in args and args.index("--from") + 1 < len(args) else None
            if idx is not None:
                spec = args[idx]
            if spec and not re.search(r"==|@|\.git#|\.whl$", spec):
                self.add("MCP-003", "medium", "mcp", f"MCP server {server} runs an unpinned Python package", path, line, " ".join([command] + args),
                         f"Pin it ({spec}==x.y.z or --from {spec}==x.y.z).")
        elif base in {"docker", "podman"} and "run" in args:
            image = next((a for a in args[args.index("run") + 1:] if not a.startswith("-") and ":" not in a[:2] and "=" not in a and "/" in a or re.match(r"^[a-z0-9][a-z0-9._-]*(:[A-Za-z0-9._-]+)?(@sha256:[0-9a-f]{64})?$", a)), "")
            if image and "@sha256:" not in image and (":" not in image.split("/")[-1] or image.endswith(":latest")):
                self.add("MCP-003", "medium", "mcp", f"MCP server {server} runs an unpinned container image", path, line, image, "Pin an image digest (@sha256:...) or at least a version tag.")
        elif base in {"deno"} and any(a.startswith("http") for a in args):
            self.add("MCP-003", "medium", "mcp", f"MCP server {server} runs code straight from a URL", path, line, " ".join([command] + args), "Vendor the module and pin its integrity hash.")
        elif re.match(r"^https?://", command):
            self.add("MCP-003", "medium", "mcp", f"MCP server {server} command is a URL", path, line, command, "Install it locally.")

    # TOML (codex) ---------------------------------------------------------------
    def scan_toml(self, path: Path, text: str) -> None:
        for m in re.finditer(r"(?im)^\s*(approval_policy|sandbox_mode|sandbox)\s*=\s*\"?(never|danger-full-access|full-access|yolo)\"?", text):
            self.add("PERM-003", "high", "permissions", f"{m.group(1)} set to {m.group(2)}", path, text.count("\n", 0, m.start()) + 1, m.group(0).strip(),
                     "Use an approval policy that prompts for unsafe commands and keep the sandbox on.")
        for m in re.finditer(r"(?im)^\s*(url|command)\s*=\s*\"(http://[^\"]+)\"", text):
            self.add("MCP-001", "high", "mcp", "MCP server configured over plain HTTP", path, text.count("\n", 0, m.start()) + 1, m.group(2), "Use https://.")

    # instruction files ----------------------------------------------------------
    def scan_instructions(self, path: Path, text: str) -> None:
        for fid, sev, pattern, title, rec, negatable in INJECTION_PATTERNS:
            for m in pattern.finditer(text):
                if negatable and NEGATION_RE.search(text[max(0, m.start() - 40): m.start()]):
                    continue
                line = text.count("\n", 0, m.start()) + 1
                self.add(fid, sev, "injection", title, path, line, m.group(0), rec)
        for m in ZERO_WIDTH_RE.finditer(text):
            self.add("INJ-005", "high", "injection", "Invisible (zero-width) character in instruction file", path, text.count("\n", 0, m.start()) + 1,
                     f"U+{ord(m.group(0)):04X}", "Remove it. Invisible characters hide text from reviewers while the model still reads it.")
            break
        for m in BIDI_RE.finditer(text):
            self.add("INJ-005", "high", "injection", "Bidirectional control character in instruction file", path, text.count("\n", 0, m.start()) + 1,
                     f"U+{ord(m.group(0)):04X}", "Remove it. Bidi overrides make displayed text differ from what the model reads.")
            break
        for m in TAG_CHARS_RE.finditer(text):
            self.add("INJ-005", "critical", "injection", "Unicode tag characters (hidden ASCII) in instruction file", path, text.count("\n", 0, m.start()) + 1,
                     f"U+{ord(m.group(0)):05X}", "Remove them. Tag characters encode invisible instructions that some models decode.")
            break
        for m in HTML_COMMENT_RE.finditer(text):
            body = m.group(1).strip()
            if len(body) > 20 and IMPERATIVE_RE.search(body):
                self.add("INJ-006", "medium", "injection", "HTML comment containing instructions", path, text.count("\n", 0, m.start()) + 1, body[:120],
                         "Rendered Markdown hides comments from readers but not from the model. Move the text into the open or delete it.")
        for m in BASE64_BLOB_RE.finditer(text):
            blob = m.group(0)
            if shannon_entropy(blob) > 4.0:
                self.add("INJ-007", "medium", "injection", "Long base64-looking blob in instruction file", path, text.count("\n", 0, m.start()) + 1, blob[:60] + "...",
                         "Decode and review it, or remove it. Encoded payloads are a common way to smuggle instructions past review.")
                break

    def scan_frontmatter(self, path: Path, text: str) -> None:
        if not text.startswith("---"):
            if path.name == "SKILL.md":
                self.add("SKILL-002", "info", "skill", "SKILL.md has no frontmatter", path, 1, text[:40], "Add name and description so the skill loads with metadata.")
            return
        end = text.find("\n---", 3)
        fm = text[3:end] if end > 0 else ""
        m = re.search(r"(?im)^(allowed-tools|allowedTools)\s*:\s*(.+)$", fm)
        if m:
            tools = m.group(2)
            if re.search(r"\bBash(\((\*|\s*)\))?(\s|,|$)", tools) or "Bash(*)" in tools:
                self.add("SKILL-001", "medium", "skill", "Skill or command pre-approves unrestricted Bash", path, text[:text.find(m.group(0))].count("\n") + 1, m.group(0).strip(),
                         "Grant specific commands, for example Bash(python3 scripts/*), and keep the grant short-lived.")
            if re.search(r"\b(Write|Edit)(\((\*|\*\*)?\))?(\s|,|$)", tools):
                self.add("SKILL-001", "low", "skill", "Skill or command pre-approves writes everywhere", path, None, m.group(0).strip(), "Scope the write grant to the paths the skill needs.")
        if path.name == "SKILL.md" and not re.search(r"(?m)^name\s*:", fm):
            self.add("SKILL-002", "info", "skill", "SKILL.md frontmatter has no name", path, 1, fm[:40], "Add name: matching the directory.")
        if path.name == "SKILL.md" and not re.search(r"(?m)^description\s*:", fm):
            self.add("SKILL-002", "info", "skill", "SKILL.md frontmatter has no description", path, 1, fm[:40], "Add a description; it is what makes the skill trigger.")
        pm = re.search(r"(?im)^permissionMode\s*:\s*(bypassPermissions|dontAsk)", fm)
        if pm:
            self.add("PERM-003", "high", "permissions", f"Agent file sets permissionMode {pm.group(1)}", path, None, pm.group(0), "Remove it; let the user's settings decide.")

    # ------------------------------------------------------------------ report
    def report(self) -> dict:
        order = {s: i for i, s in enumerate(SEVERITIES)}
        findings = sorted(self.findings, key=lambda f: (order[f.severity], f.file, f.line or 0, f.id))
        summary = {s: sum(1 for f in findings if f.severity == s) for s in SEVERITIES}
        summary["total"] = len(findings)
        return {
            "tool": "audit_agent_config", "version": VERSION, "root": str(self.root),
            "generated_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "scanned_files": self.scanned, "errors": self.errors, "summary": summary,
            "findings": [asdict(f) for f in findings],
        }


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def redact(evidence: str) -> str:
    """Mask anything that looks like a credential so the report can be shared."""
    out = evidence
    for title, pattern, _ in SECRET_PATTERNS[:-1]:
        if title == "Private key block":
            continue
        out = pattern.sub(lambda m: m.group(0)[:6] + "****" + m.group(0)[-2:] if len(m.group(0)) > 10 else "****", out)
    out = re.sub(r"(?i)((?:bearer|basic|token)\s+)(\S{12,})", lambda m: m.group(1) + m.group(2)[:4] + "****", out)
    out = re.sub(r"(?i)((?:api[_-]?key|secret[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|api[_-]?token|password|passwd|secret)\b[\"']?\s*[:=]\s*[\"']?)([A-Za-z0-9_\-./+=]{8,})",
                 lambda m: m.group(1) + m.group(2)[:4] + "****", out)
    return out


def to_markdown(rep: dict) -> str:
    s = rep["summary"]
    lines = [f"# Agent configuration audit", "", f"Root: `{rep['root']}`  ", f"Generated: {rep['generated_at']}  ",
             f"Files scanned: {len(rep['scanned_files'])}  ", "",
             "| Severity | Count |", "|---|---|"] + [f"| {sev} | {s[sev]} |" for sev in SEVERITIES] + ["", f"Total findings: {s['total']}", ""]
    if rep["findings"]:
        lines += ["| ID | Severity | Title | File | Line | Evidence |", "|---|---|---|---|---|---|"]
        for f in rep["findings"]:
            ev = f["evidence"].replace("|", "\\|").replace("\n", " ")
            lines.append(f"| {f['id']} | {f['severity']} | {f['title']} | `{f['file']}` | {f['line'] or ''} | `{ev[:80]}` |")
        lines += ["", "## Recommendations", ""]
        seen = set()
        for f in rep["findings"]:
            if f["id"] in seen:
                continue
            seen.add(f["id"])
            lines.append(f"- **{f['id']}** ({f['severity']}): {f['recommendation']}")
    else:
        lines.append("No findings. The scanned configuration has no risky permissions, secrets, unpinned servers or injection patterns that this tool detects.")
    if rep["errors"]:
        lines += ["", "## Scan errors", ""] + [f"- {e}" for e in rep["errors"]]
    lines += ["", "## Files scanned", ""] + [f"- `{p}`" for p in rep["scanned_files"]]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", default=".", help="project directory to audit (default: current directory)")
    ap.add_argument("--extra", action="append", default=[], help="additional file to audit (repeatable)")
    ap.add_argument("--include-home", action="store_true", help="also audit the user-level config files in the home directory")
    ap.add_argument("--format", choices=["json", "markdown"], default="json")
    ap.add_argument("--output", help="write the report to this file instead of stdout")
    ap.add_argument("--fail-on", choices=SEVERITIES, help="exit 1 when a finding of this severity or higher exists")
    args = ap.parse_args(argv)
    auditor = Auditor(Path(args.root), include_home=args.include_home, extra=[Path(e) for e in args.extra])
    auditor.run()
    rep = auditor.report()
    text = to_markdown(rep) if args.format == "markdown" else json.dumps(rep, indent=1, ensure_ascii=False) + "\n"
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
        print(f"wrote {args.output} ({rep['summary']['total']} findings)", file=sys.stderr)
    else:
        sys.stdout.write(text)
    if args.fail_on:
        threshold = SEVERITIES.index(args.fail_on)
        if any(SEVERITIES.index(f["severity"]) <= threshold for f in rep["findings"]):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
