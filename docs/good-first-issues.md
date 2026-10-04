# Good first issues

Issues the maintainer intends to open under the `good first issue` label, written out so they can be filed in one sitting. Each one is self-contained, touches one action, and has acceptance criteria that `make test` and `make check` can verify. Read [CONTRIBUTING.md](../CONTRIBUTING.md) first: no dependencies, inputs only grow, secrets never reach the output, CHANGELOG entry under Unreleased.

## 1. prompt-secrets-scan: scan `.env.example`-style files only when asked

**Context.** `prompt-secrets-scan/src/prompt_secrets_scan.py` keeps `DEFAULT_PATHS` to prompt, notebook and instruction files on purpose. Teams that also keep `.env.example`, `docker-compose.yml` or Helm values next to their prompts asked for a one-line way to include them without listing every glob.

**Acceptance criteria.**

- A new input `extra-paths` (default empty) whose globs are appended to the default list instead of replacing it, as `paths` does.
- `action.yml`, the README inputs table and the script's `--help` document it.
- A test in `tests/test_prompt_secrets_scan.py` shows that `--extra-paths "*.env.example"` finds a secret in such a file while the default file set is still scanned.

## 2. license-audit: read `pnpm-lock.yaml` and `yarn.lock`

**Context.** `license-audit/src/license_audit.py` reads `package-lock.json` only. pnpm and Yarn users have to generate an SBOM first. Neither lockfile carries licence fields, so this is the same `node_modules/<name>/package.json` fallback the v1 lockfile path already uses; only the package list and the manifest line numbers differ.

**Acceptance criteria.**

- `read_any` recognises `pnpm-lock.yaml` (`packages:` keys such as `/name@version` or `name@version`) and `yarn.lock` (`"name@^1.0.0":` headers followed by `version "1.0.0"`), without PyYAML: a line-based parser is enough for the names and versions.
- `autodetect` includes both files.
- Fixtures under `tests/fixtures/pnpm/` and `tests/fixtures/yarn/` with a small `node_modules` tree, and tests that assert statuses and line numbers.
- README input description for `inputs` lists the new file names.

## 3. llms-txt-check: report sections that are not sorted when `--sorted` is given

**Context.** Some teams generate `llms.txt` and want pull requests to fail when someone hand-edits the file out of order. The generator in `llms-txt-check/src/llms_txt_check.py` already emits sections and entries in a deterministic order (`Docs` first, then alphabetical; `README`/`index` first within a section).

**Acceptance criteria.**

- A new rule `LLMS-015` (note) reports a section whose link entries are not in the generator's order, and a section list that is not in the generator's order. It only runs with the new `--sorted` flag and `sorted` input (default `"false"`).
- `check_text` gains the parameter; `parse` is unchanged.
- Tests cover a sorted file (no finding), an unsorted file with the flag (finding) and an unsorted file without the flag (no finding).
- README rules table updated.

## 4. sbom-diff-comment: collapse long tables inside `<details>`

**Context.** `renderMarkdown` in `sbom-diff-comment/src/sbom_diff.mjs` caps every table at `MAX_ROWS` (50) and adds an "and N more" row. A pull request that bumps 200 transitive dependencies still produces a long comment. GitHub renders `<details><summary>` blocks in comments.

**Acceptance criteria.**

- When a section has more than 10 rows, the table is wrapped in `<details><summary>Added (123)</summary>` ... `</details>`; sections with 10 rows or fewer are unchanged.
- `MAX_ROWS` stays as the hard cap.
- Tests in `tests/sbom_diff.test.mjs` cover both branches and confirm the marker line is still the first line of the body.

## 5. indexnow-ping: read URLs from a changed-files list produced by `git diff`

**Context.** The README suggests passing explicit URLs. A common source is `git diff --name-only` between two deploys, which yields file paths such as `content/blog/post.md`, not URLs. A small mapping step inside the action would remove a custom shell step from every workflow.

**Acceptance criteria.**

- New inputs `paths-file` (file with one repository path per line) and `path-to-url` (a template such as `https://www.example.org/{path}` where `{path}` is the path with its extension removed and `index` stripped; `README.md` and `index.md` map to the directory URL).
- A pure function `pathToUrl(path, template)` exported from `src/indexnow.mjs` with tests for `content/blog/post.md`, `docs/index.md`, `README.md` and a nested `a/b/c.html`.
- URLs from `paths-file` are treated like `urls` (always submitted, host-filtered).
- README inputs table and an example updated.

## 6. agent-config-audit: `baseline-file` input to suppress known findings

**Context.** Repositories that adopt the audit with existing findings want to fail only on new ones. The SARIF results already carry a stable `partialFingerprints.primaryLocationLineHash` (sha256 of rule, file and redacted evidence) in `agent-config-audit/src/action.py`.

**Acceptance criteria.**

- New input `baseline-file` (default empty): a JSON file with a list of fingerprints, or a previous SARIF file from this action; findings whose fingerprint is listed are kept in the SARIF with `"baselineState": "unchanged"` and excluded from the gate and the summary table.
- `--baseline` flag on `src/action.py`, and a `--write-baseline FILE` flag that writes the current fingerprints so a team can create the file in one run.
- Tests: a baseline created from the risky fixture makes a second run pass with `fail-on: critical`; a new finding not in the baseline still fails; the SARIF still passes `scripts/check_sarif.py`.
- README inputs table and a short "Adopting on an existing repository" paragraph.
