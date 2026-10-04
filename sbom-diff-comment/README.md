# sbom-diff-comment

Diffs two SBOM files and keeps one pull request comment up to date with what changed: components added, removed, version changes and licence changes. Reads CycloneDX JSON (`bomFormat`) and SPDX JSON (`spdxVersion`), in any combination. Components are matched by package URL without the version (or `type/group/name` when there is no purl), so a bump appears as one "version change" rather than a removal plus an addition. Nested CycloneDX components are included; the SPDX root package described by the document is skipped.

The comment carries a hidden marker (`<!-- sbom-diff-comment:<marker> -->`), so a re-run updates the earlier comment instead of adding a new one. The script uses only `fetch` against the GitHub REST API with a timeout, reads at most 500 existing comments when looking for the marker, and truncates the body to GitHub's comment size limit. No dependencies; Node 18 or later.

## Usage

```yaml
name: sbom-diff
on:
  pull_request:
permissions:
  contents: read
  pull-requests: write
jobs:
  sbom:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      # Produce head.cdx.json for the pull request and base.cdx.json for the base branch with the SBOM tool
      # you already use (for example cdxgen, syft or npm sbom), or download the base SBOM from the latest release.
      - run: npm sbom --sbom-format cyclonedx > head.cdx.json
      - run: |
          git fetch origin "${{ github.base_ref }}" --depth 1
          git worktree add ../base "origin/${{ github.base_ref }}"
          (cd ../base && npm ci --ignore-scripts && npm sbom --sbom-format cyclonedx) > base.cdx.json
      - uses: basitalisandhu/security-actions/sbom-diff-comment@v1
        with:
          base: base.cdx.json
          head: head.cdx.json
          fail-on: license-change
```

To keep separate comments for several ecosystems, run the action once per pair with a different `marker`.

## Inputs

| Input | Default | Description |
|---|---|---|
| `base` | required | Base SBOM path (CycloneDX JSON or SPDX JSON). |
| `head` | required | Head SBOM path. |
| `comment` | `"true"` | Post or update the comment. `false` only writes the file, summary and outputs. |
| `token` | `${{ github.token }}` | Token with `pull-requests: write`. |
| `pr-number` | `""` | Pull request number; empty reads it from the event payload. |
| `title` | `SBOM diff` | Comment heading. |
| `marker` | `default` | Marker suffix that identifies the comment to update. |
| `fail-on` | `none` | `none`, `any-change` or `license-change`. |
| `markdown-file` | `sbom-diff.md` | Where the comment body is written. |
| `timeout` | `30` | Seconds per API request. |
| `node-version` | `""` | Set up this Node version first; empty uses the runner's `node`. |

## Outputs

| Output | Description |
|---|---|
| `added-count` | Components only in head. |
| `removed-count` | Components only in base. |
| `changed-count` | Components whose version changed. |
| `license-change-count` | Components whose licence set changed. |
| `comment-url` | URL of the created or updated comment; empty when none was posted. |
| `markdown-file` | Path of the Markdown body. |

## Permissions

`pull-requests: write` for the comment (the default `GITHUB_TOKEN` is enough), `contents: read` to read the SBOM files. Outside a pull request, or when `comment` is `false`, no API call is made. On `pull_request` events from forks the default token is read-only; run the action from a `workflow_run` workflow with `pr-number` set, or set `comment: "false"` and rely on the job summary.

## Local use

```sh
INPUT_BASE=base.cdx.json INPUT_HEAD=head.cdx.json INPUT_COMMENT=false node sbom-diff-comment/src/sbom_diff.mjs && cat sbom-diff.md
node --test "sbom-diff-comment/tests/*.test.mjs"
```
