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
      - uses: actions/checkout@v7
      - uses: basitalisandhu/security-actions/agent-config-audit@v0
      - uses: basitalisandhu/security-actions/prompt-secrets-scan@v0
      - uses: basitalisandhu/security-actions/license-audit@v0
        with:
          fail-on: unknown
```

Set `upload-sarif: "false"` on any of them to skip code scanning (and drop `security-events: write`); the job summary and annotations still appear.

CI runs this quick start as written on every push and same-repository pull request: the `quickstart` job in `.github/workflows/ci.yml` creates a fresh project with `scripts/make_quickstart_project.py`, runs the three steps above against the copy of the actions under test, and checks that every gate passes. `scripts/check_quickstart.py` fails the build if the job and this README drift apart.

## Versioning

Consumers can pin any of three ways:

| Pin | Example | What you get |
|---|---|---|
| Major tag | `uses: basitalisandhu/security-actions/agent-config-audit@v0` | Every 0.x.y release as it ships. `v0` **moves**: each release re-points it at the new release commit. |
| Release tag | `uses: basitalisandhu/security-actions/agent-config-audit@v0.2.0` | Exactly that release. Release tags are never moved. |
| Commit SHA | `uses: basitalisandhu/security-actions/agent-config-audit@<40-character SHA> # v0.2.0` | Exactly that commit, even if a tag were changed. Dependabot and Renovate update the SHA and the comment. |

- `v0` is a moving tag that always points at the latest `v0.x.y` release. `uses: ...@v0` gets fixes and new inputs without breaking changes.
- Each release also has an immutable tag (`v0.2.0`). Pin to it, or to a commit SHA, when you need reproducible runs. `git ls-remote --tags https://github.com/basitalisandhu/security-actions` lists each tag and its commit.
- A breaking change (an input removed or its default changed in a way that alters results, an output renamed, a different exit code) moves to the next major with a new moving tag. The old major keeps receiving security fixes for six months after the next major ships.
- Inputs are only added with defaults, so an existing workflow keeps working after an update.

The release workflow (`.github/workflows/release.yml`) runs the test suites, creates the GitHub release from `CHANGELOG.md` and moves the major tag.

## Troubleshooting

Every action ends a run in one of three ways: exit 0 (gate passed), exit 1 (the gate failed on findings, or a comment or ping was rejected) or exit 2 with a single `::error::<action>: ...` line that says what was wrong with the input. If a log shows a Python or Node traceback, or a line containing `internal error`, that is a bug: please [open an issue](https://github.com/basitalisandhu/security-actions/issues) with the line and, if you can, the file that caused it.

| Symptom | Cause and fix |
|---|---|
| `Resource not accessible by integration` in the "Upload SARIF" step | The job lacks `security-events: write`, or it runs for a pull request from a fork, where the token is read-only. Add the permission, or set `upload-sarif: "false"` on fork pull requests; the summary and annotations still appear. |
| `license-audit: no package-lock.json, requirements.txt or SBOM found` | The action looks in `path` (default the workspace root). Set `path` to the project directory or list the files in `inputs`. |
| `license-audit: <file>: not valid JSON (...)`, `expected a JSON object at the top level` or `not UTF-8 text` | The lockfile or SBOM is truncated, is a different format, or was written with another encoding. Regenerate it; the message gives the line and column of the first JSON error. |
| `license-audit` reports many packages as `unknown` for `requirements.txt` | Licences come from installed metadata. Install the requirements in the job before the step (`pip install -r requirements.txt`), or point `site-packages` at the environment that has them. |
| `agent-config-audit` reports `CFG-001` | A JSON configuration file does not parse (or is nested too deeply to read). Claude Code and other hosts ignore such a file, so its deny rules and hooks are not applied; fix the syntax. |
| A scan note says `skipped <file>: larger than ... bytes` | agent-config-audit reads files up to 2 MB and prompt-secrets-scan up to 5 MB, to keep runs fast. Large generated files are rarely instruction files; exclude them, or split them. |
| `cannot read or write <path>` | An output path such as `sarif-file`, `markdown-file` or `output` points into a directory that does not exist. Create the directory first or use a path in the workspace. |
| `sbom-diff-comment` posts no comment | Outside a pull request it skips the comment by design. Inside one it needs `pull-requests: write`; fork pull requests get a read-only token, so run it from `workflow_run` with `pr-number`, or set `comment: "false"`. |
| `indexnow-ping` answers 403 | The key file is not reachable at `https://<host>/<key>.txt` (or at `key-location`). Deploy the key file before the ping step. |
| `timeout must be a number of seconds greater than 0` | The `timeout` input is empty after expression substitution, or not a number. Use a whole number such as `30`. |
| An action fails to start on a self-hosted runner | The actions set up Node 24 through `actions/setup-node@v7` and `actions/setup-python@v7`; the runner must be recent enough to run Node 24 actions. GitHub-hosted runners need no change. |

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
