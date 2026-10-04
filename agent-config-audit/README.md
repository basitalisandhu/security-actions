# agent-config-audit

Audits the AI agent configuration checked into a repository and reports risky permissions, hooks that reach the network or pipe remote code into a shell, MCP servers over plain HTTP or with literal credentials or unpinned packages, secrets in agent config files, and prompt-injection patterns in instruction files. Results go to a SARIF 2.1.0 report (uploaded to code scanning by default), the job summary and workflow annotations.

Files it looks at, relative to `path`: `CLAUDE.md`, `.claude/settings*.json`, `.claude/{commands,skills,agents,hooks}/**`, `.mcp.json`, `.claude-plugin/*.json`, `hooks/hooks.json`, `.cursorrules`, `.cursor/rules/**`, `.cursor/mcp.json`, `AGENTS.md`, `.github/copilot-instructions.md`, `.github/instructions/**`, `.windsurfrules`, `.clinerules`, `.vscode/mcp.json`, `.gemini/settings.json`, `GEMINI.md`, `.codex/config.toml`, `.roo/rules/**`, `.aider.conf.yml` and `.continue/config.*`. Home-directory files are never read.

The scanner (`src/audit_agent_config.py`) is a copy of the one in [agent-security-skills](https://github.com/basitalisandhu/agent-security-skills); this directory adds the GitHub integration.

## Usage

```yaml
name: agent-config-audit
on:
  push:
    branches: [main]
  pull_request:
permissions:
  contents: read
  security-events: write   # only needed while upload-sarif is "true"
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: basitalisandhu/security-actions/agent-config-audit@v1
        with:
          fail-on: high
```

Without code scanning (for example on a private repository without GitHub Advanced Security), set `upload-sarif: "false"` and drop `security-events: write`; the summary and annotations still appear.

## Inputs

| Input | Default | Description |
|---|---|---|
| `path` | `.` | Directory to audit, relative to the workspace. |
| `extra-files` | `""` | Additional files to audit, one per line. |
| `fail-on` | `high` | Lowest severity that fails the job: `critical`, `high`, `medium`, `low`, `info` or `none`. |
| `sarif-file` | `agent-config-audit.sarif` | Where to write the SARIF report. |
| `upload-sarif` | `"true"` | Upload the SARIF report to code scanning. |
| `category` | `agent-config-audit` | Code scanning category. |
| `python-version` | `""` | Set up this Python version first; empty uses the runner's `python3` (3.10 or later). |

## Outputs

| Output | Description |
|---|---|
| `finding-count` | Total findings at every severity. |
| `highest-severity` | `critical`, `high`, `medium`, `low`, `info` or `none`. |
| `sarif-file` | Path of the SARIF report. |
| `gate` | `pass` or `fail` according to `fail-on`. |

## Permissions

`contents: read` to read the repository. `security-events: write` only when `upload-sarif` is `"true"`. No token is used by the script itself and it makes no network requests.

## Rules

| Id | Severity | What it reports |
|---|---|---|
| PERM-001 | critical | `Bash(*)` or an equivalent rule that pre-approves every shell command |
| PERM-002 | high, medium, low | Risky program (curl, rm, python, docker, git, ...) pre-approved with a wildcard |
| PERM-003 | critical, high, medium | `bypassPermissions`, `dontAsk`, `auto`, skipped dangerous-mode prompt, Codex `approval_policy = never` |
| PERM-004 to PERM-006 | medium | Write, WebFetch or a whole MCP server pre-approved without a scope |
| PERM-007, PERM-008 | medium | All project MCP servers auto-approved; all hooks disabled |
| PERM-009 | high | Pre-approved command carries `--dangerously-skip-permissions` or a similar flag |
| PERM-010, PERM-011 | medium, low | `additionalDirectories` grants `/` or `~`; broad allow rules with no deny rules |
| HOOK-001 to HOOK-006 | critical to low | Missing hook script, hook that reaches the network, credential in a hook command, `curl ... \| sh` in a hook, unquoted plugin root, world-writable hook script |
| MCP-001 to MCP-008 | critical to low | Plain HTTP, literal credential, unpinned package or image, temp-directory server, bypass flag, SSE transport, filesystem server on `/`, raw IP |
| SEC-001 | critical, high | Provider API key, token, private key or generic secret in an agent config file |
| INJ-001 to INJ-009 | critical to medium | Instruction override, hidden actions, exfiltration, remote code, invisible Unicode, instruction-bearing HTML comments, base64 blobs, safety-control weakening, credential-file reads |
| FILE-001, CFG-001 | medium, low | World-writable config file; JSON that does not parse |
| PLUGIN-001, SKILL-001, SKILL-002 | low, medium, info | Plugin `bin/` on PATH; skill pre-approves unrestricted Bash or writes; missing skill metadata |

Evidence in the report is redacted: a matched secret is never printed in full.

## Local use

```sh
python3 agent-config-audit/src/action.py --root . --sarif out.sarif --summary summary.md --fail-on high
python3 agent-config-audit/src/audit_agent_config.py --root . --format markdown   # the scanner on its own
python3 -m pytest agent-config-audit/tests
```
