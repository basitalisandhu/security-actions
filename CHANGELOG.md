# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/). The `v1` tag always points at the latest 1.x.y release.

## [Unreleased]

## [1.0.0] - 2026-10-03

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
