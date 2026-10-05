# security-actions

GitHub Actions for AI agent and supply chain security checks. Six small composite actions, each in its own directory with a dependency-free Python or Node script and a test suite, that teams drop into CI with one `uses:` line. The agent-side actions find risky agent configuration and leaked credentials in prompt files; the supply-chain actions diff SBOMs, audit licences, keep `llms.txt` valid and tell search engines about changed pages.

```yaml
- uses: basitalisandhu/security-actions/agent-config-audit@v0
```

## Actions

| Action | What it does | Output | Runtime |
|---|---|---|---|
| [agent-config-audit](agent-config-audit/) | Audits `.claude/settings.json` permissions and hooks, `.mcp.json` servers (plain HTTP, literal credentials, unpinned packages), Cursor rules, and `CLAUDE.md`/`AGENTS.md` instruction files for prompt-injection patterns and secrets. | SARIF, job summary, annotations, `fail-on` gate | Python |
| [prompt-secrets-scan](prompt-secrets-scan/) | Finds provider API keys, private keys, bearer tokens, JWTs, webhooks and connection strings inside prompt files, system prompts, notebooks and agent instruction files, with an allowlist file. | SARIF, job summary, annotations | Python |
| [llms-txt-check](llms-txt-check/) | Validates that a site directory or URL serves an `llms.txt` that follows the convention (H1, blockquote summary, H2 link sections, resolvable links), or generates one from a docs directory. | Job summary, annotations, outputs | Python |
| [indexnow-ping](indexnow-ping/) | Submits changed URLs (from a sitemap with a `changed-since` filter, or an explicit list) to IndexNow after a Pages deploy. | Job summary, outputs | Node |
| [sbom-diff-comment](sbom-diff-comment/) | Diffs two CycloneDX or SPDX SBOMs and posts or updates one pull request comment with added, removed and changed components and licence changes. | PR comment, job summary, Markdown file | Node |
| [license-audit](license-audit/) | Reads `package-lock.json`, `requirements.txt` (with installed metadata) or an SBOM and flags licences outside an allowlist, evaluating SPDX expressions. | SARIF, job summary, annotations | Python |

Every action's README has the full inputs and outputs table and the permissions it needs. None of the scripts has a dependency outside the Python standard library or Node's built-in modules, and none phones home: the only network calls are the ones the action exists to make (IndexNow endpoint, GitHub comments API, optional link checks).

## Quick start

A workflow that runs the three SARIF-producing checks on every push and pull request:

```yaml
name: security-actions
on:
  push:
    branches: [main]
  pull_request:
permissions:
  contents: read
  security-events: write
jobs:
  checks:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: basitalisandhu/security-actions/agent-config-audit@v0
      - uses: basitalisandhu/security-actions/prompt-secrets-scan@v0
      - uses: basitalisandhu/security-actions/license-audit@v0
        with:
          fail-on: unknown
```

Set `upload-sarif: "false"` on any of them to skip code scanning (and drop `security-events: write`); the job summary and annotations still appear.

## Versioning

- `v0` is a moving tag that always points at the latest `v0.x.y` release. `uses: ...@v0` gets fixes and new inputs without breaking changes.
- Each release also has an immutable tag (`v0.1.0`). Pin to it, or to a commit SHA, when you need reproducible runs.
- A breaking change (an input removed or its default changed in a way that alters results, an output renamed, a different exit code) moves to the next major with a new moving tag. The old major keeps receiving security fixes for six months after the next major ships.
- Inputs are only added with defaults, so an existing workflow keeps working after an update.

The release workflow (`.github/workflows/release.yml`) runs the test suites, creates the GitHub release from `CHANGELOG.md` and moves the major tag.

## Permissions

| Action | `contents` | `security-events` | `pull-requests` | Token used |
|---|---|---|---|---|
| agent-config-audit | read | write (only with `upload-sarif`) | | none |
| prompt-secrets-scan | read | write (only with `upload-sarif`) | | none |
| llms-txt-check | read (directory source) | | | none |
| indexnow-ping | | | | none |
| sbom-diff-comment | read | | write | `GITHUB_TOKEN` or `token` |
| license-audit | read | write (only with `upload-sarif`) | | none |

## Development

```sh
make test        # pytest for the Python actions, node --test for the Node actions
make check       # validate every action.yml and workflow file
make selftest    # run each action's script on its fixtures and check the SARIF it writes
```

Requirements: Python 3.10 or later with `pytest` and `pyyaml` (`pip install pytest pyyaml`), Node 18 or later. The tests run offline; the Node tests use loopback HTTP servers for the IndexNow endpoint and the GitHub API. SARIF output is checked for structure by `scripts/check_sarif.py` in every suite and in CI.

Layout of each action:

```text
<name>/
  action.yml       composite action; inputs become environment variables for the script
  README.md        usage, inputs, outputs, permissions, rules
  src/             one script, standard library or Node built-ins only
  tests/           pytest or node:test, with fixtures/
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the checklist, [docs/good-first-issues.md](docs/good-first-issues.md) for ready-to-file tasks, and [SECURITY.md](SECURITY.md) for reporting.

## Sibling projects

More tools by the same author: https://github.com/basitalisandhu

- [agentic-semgrep-rules](https://github.com/basitalisandhu/agentic-semgrep-rules): Semgrep rules for AI agent code, with its own composite action.
- [agent-security-skills](https://github.com/basitalisandhu/agent-security-skills): the agent configuration audit script in this repository is copied from the `agent-config-audit` skill there.
- [.github](https://github.com/basitalisandhu/.github): reusable security baseline workflow (CodeQL, gitleaks, dependency review, Scorecard).

## Licence

MIT, see [LICENSE](LICENSE).
