# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/). The `v0` tag always points at the latest 0.x.y release.

## [Unreleased]

Nothing yet.

## [0.3.1] - 2026-10-29

### Fixed

- `agent-config-audit`, `license-audit` and `prompt-secrets-scan`: deeply nested JSON (settings and MCP files, lockfiles, SBOMs, `package.json`, notebooks) is reported the same way on every supported Python (`CFG-001`, or one `::error::` line naming the file). Python 3.14 no longer raises `RecursionError` from `json.loads` at the old depth, so JSON is now checked for nesting first (limit 200 levels) instead of relying on it.
- CI runs the Python suites on 3.10, 3.12, 3.13 and 3.14.

## [0.3.0] - 2026-10-28

### Added

- `sbom-diff-comment`: a section with more than 10 rows is folded into a `<details>` block whose summary shows the section and its row count (for example `Added (123)`); the 50-row cap still applies (#6).
- README: a Troubleshooting section, and a `quickstart` CI job that runs the README quick start as written against a fresh project (`scripts/make_quickstart_project.py`), kept in step with the README by `scripts/check_quickstart.py`.
- Property tests with seeded random input for every reader (settings and MCP files, notebooks, allowlists, lockfiles, SBOMs, `llms.txt`, sitemaps) and scaling tests that compare a run on ten times the input.

### Fixed

- Every Python action now ends bad input with one `::error::` line and exit code 2 instead of a traceback: an output path in a missing directory, a lockfile or SBOM that is a JSON array, not UTF-8 or nested too deeply, and an unexpected error (which now asks to be reported).
- `agent-config-audit`: settings, hooks and MCP entries whose fields have the wrong JSON type (for example `"permissions": true` or `"env": [..]`) are skipped instead of crashing the scan; deeply nested JSON is reported as `CFG-001`.
- `license-audit`: names, versions and licences that are numbers, nulls or objects in a lockfile or SBOM no longer crash the run.
- `prompt-secrets-scan`: notebooks whose `cells`, `outputs` or `data` have the wrong type are scanned (as text when they are not notebooks) instead of crashing; an allowlist with bytes that are not UTF-8 still loads.
- `llms-txt-check`: a malformed URL as `source` or as a link no longer crashes the check; `--timeout` must be 1 or more.
- `indexnow-ping`: sitemap entries without `<lastmod>` were treated as explicit URLs whenever `urls` or `urls-file` was also set, so they skipped `changed-since`; a missing `urls-file` and a `timeout` or `max-urls` that is not a number are now clear errors.
- `sbom-diff-comment`: fields of the wrong JSON type in an SBOM are treated as absent, and a missing, unreadable or invalid SBOM names the file; a `timeout` that is not a number is a clear error.

### Changed

- The `agent-config-audit` scanner here now differs from the copy in agent-security-skills by the fixes above.

### Performance

- `license-audit` finds each package's line number from an index built in one pass; reading lockfiles and SBOMs was quadratic in their size (20,000 packages took several seconds per file).
- `agent-config-audit` and `prompt-secrets-scan` (notebooks) look up line numbers by binary search instead of counting newlines from the start of the file for every match.
- `indexnow-ping` parses sitemaps in one linear pass; a truncated sitemap with many unclosed `<url>` tags was quadratic. Splitting explicit and sitemap URLs no longer compares every entry against every other.
- `sbom-diff-comment` checks SPDX `documentDescribes` with a set instead of a list scan per package.

## [0.2.0] - 2026-10-16

### Added

- `llms-txt-check`: added `--sorted` flag and `LLMS-015` rule (note) to report sections and link entries not in the generator's deterministic order (#9, thanks @AK-Lmn).

### Changed

- Removed the umbrella branding; this project stands alone and links its sibling repositories directly.
- The composite actions now run `actions/setup-python@v7` (agent-config-audit, prompt-secrets-scan, llms-txt-check, license-audit) and `actions/setup-node@v7` (indexnow-ping, sbom-diff-comment) instead of v5 and v4. GitHub-hosted runners need no change; a self-hosted runner must be recent enough to run Node 24 actions (#19 to #24).
- CI and release workflows use `actions/checkout@v7`, `actions/setup-python@v7` and `actions/setup-node@v7`; `scripts/check_actions.py` allows the previous major alongside the new one while Dependabot moves files across, and Dependabot now watches every action folder (#13 to #16).
- The README documents the three ways to pin (`@v0`, `@v0.2.0`, a commit SHA) and that `v0` moves on each release; examples use `actions/checkout@v7`.

## [0.1.0] - 2026-10-03

### Added

- `agent-config-audit`: audits Claude Code settings and hooks, `.mcp.json` servers, Cursor rules, `CLAUDE.md` and `AGENTS.md` instruction files and other agent configuration for risky permissions, secrets, unpinned servers and prompt-injection patterns. SARIF 2.1.0 output, job summary, annotations, `fail-on` gate. The scanner is a copy of the one in agent-security-skills.
- `prompt-secrets-scan`: finds provider API keys, private keys, bearer tokens, JSON Web Tokens, Slack and Discord webhooks, connection strings with embedded passwords and generic secret assignments inside prompt files, system prompts, Jupyter notebooks (cell sources and text outputs) and agent instruction files. Allowlist file with `sha256:`, `re:`, `path:`, `rule:` and literal entries, inline ignore comments, placeholder and entropy filters. SARIF, summary, annotations.
- `llms-txt-check`: validates an `llms.txt` from a site directory or URL against the convention (H1, blockquote summary, H2 link sections, headings depth, relative link resolution, optional remote link checks) and generates one from a docs directory with deterministic output.
- `indexnow-ping`: submits URLs from a sitemap (index files followed, gzip handled, `changed-since` filter on `lastmod`) or an explicit list to IndexNow, batched at 10,000 per request, one retry on 429, dry-run mode.
- `sbom-diff-comment`: diffs CycloneDX and SPDX JSON SBOMs by versionless package URL, reports added, removed, version and licence changes, and creates or updates one marked pull request comment through the REST API with bounded requests and body truncation.
- `license-audit`: reads `package-lock.json` (v1 to v3, with `node_modules` fallback), `requirements.txt` (installed metadata, `-r` includes) and CycloneDX or SPDX SBOMs, normalises licence strings to SPDX ids, evaluates `AND`, `OR` and `WITH` expressions against an allowlist and denylist, and writes SARIF, a summary with the licence distribution and annotations.
- `scripts/check_sarif.py` structural validator for SARIF 2.1.0, used by every Python suite and by the CI self-test.
- `scripts/check_actions.py` validator for `action.yml` files and workflows, including the pinned external action list.
- CI workflow (validation, Python 3.10 and 3.12 suites, Node 18 and 22 suites, self-test of every action on its fixtures) and release workflow (tests, GitHub release from this file, moving major tag).
