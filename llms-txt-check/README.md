# llms-txt-check

Checks that a built site directory or a live URL serves an `llms.txt` that follows the [llms.txt convention](https://llmstxt.org/): an H1 with the site name, a blockquote summary, optional free-form Markdown, then H2 sections made of `- [name](url): notes` link entries, with an `## Optional` section for pages that can be skipped. Relative links are resolved against the site directory; remote links can be checked with bounded HEAD requests. In `generate` mode it writes an `llms.txt` from a docs directory and then checks the result.

## Usage

Check the file after a static site build:

```yaml
jobs:
  llms-txt:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v4
      - run: npm run build          # produces _site/llms.txt
      - uses: basitalisandhu/security-actions/llms-txt-check@v1
        with:
          source: _site
          fail-on: warning
```

Check a deployed site (no checkout needed):

```yaml
      - uses: basitalisandhu/security-actions/llms-txt-check@v1
        with:
          source: https://docs.example.com
          check-links: "true"
```

Generate one from `docs/` and commit it (or publish it with the site):

```yaml
      - uses: basitalisandhu/security-actions/llms-txt-check@v1
        with:
          mode: generate
          docs-dir: docs
          output: public/llms.txt
          site-name: Acme Docs
          site-url: https://docs.example.com
          summary: Acme is a command-line tool for doing the thing.
          link-format: html
```

The generator groups files by their top-level subdirectory (root files go under `## Docs`), takes the title from frontmatter `title:`, the first H1 or the file name, and uses the first paragraph (code blocks, images and headings skipped, Markdown stripped, 160 characters at most) as the note. Output is deterministic, so a diff on the generated file shows real documentation changes.

## Inputs

| Input | Default | Description |
|---|---|---|
| `mode` | `check` | `check` or `generate`. |
| `source` | `.` | check: site directory, path to an `llms.txt`, or site URL. |
| `check-links` | `"false"` | check: HEAD-request remote links (at most 50). |
| `sorted` | `"false"` | check: report sections and link entries not in the generator's order (LLMS-015 note). |
| `docs-dir` | `docs` | generate: Markdown source directory. |
| `output` | `llms.txt` | generate: output path. |
| `site-name` | `""` | generate: H1 text; empty uses the repository name. |
| `site-url` | `""` | generate: base URL for links; empty writes root-relative links. |
| `summary` | `""` | generate: blockquote text. |
| `link-format` | `md` | generate: `md`, `html` or `none`. |
| `fail-on` | `error` | `error`, `warning` or `none`. |
| `timeout` | `10` | Seconds per HTTP request. |
| `python-version` | `""` | Set up this Python first; empty uses the runner's `python3` (3.10 or later). |

## Outputs

| Output | Description |
|---|---|
| `status` | `pass` or `fail`. |
| `error-count` | Number of errors. |
| `warning-count` | Number of warnings. |
| `llms-txt-path` | Path or URL of the file checked or written. |

## Permissions

`contents: read` when checking files in the workspace; none when checking a URL. Network access is used only for a URL `source` and for `check-links`.

## Rules

| Id | Level | Meaning |
|---|---|---|
| LLMS-001 | error | `llms.txt` not found at the source |
| LLMS-002 | error | First content line is not an H1 |
| LLMS-008 | error | More than one H1 |
| LLMS-013 | error | File is empty |
| LLMS-003 | warning | No blockquote summary after the H1 |
| LLMS-004 | warning | No H2 link sections |
| LLMS-005 | warning | A section has no link entries |
| LLMS-006 | warning | A section line is not a `- [name](url): notes` entry |
| LLMS-007 | warning | Heading deeper than H2 |
| LLMS-009 | warning | Relative link (or site-url link) does not resolve under the site directory |
| LLMS-010 | warning | Remote link did not answer 2xx or 3xx (`check-links` only) |
| LLMS-011 | warning | Empty link target |
| LLMS-012 | note | Duplicate link target |
| LLMS-014 | note | No `llms-full.txt` next to the file |
| LLMS-015 | note | Sections or link entries are not sorted in the generator's order (`--sorted` only) |

## Local use

```sh
python3 llms-txt-check/src/llms_txt_check.py --source _site --fail-on warning
python3 llms-txt-check/src/llms_txt_check.py --mode generate --docs-dir docs --site-name "Acme Docs" --site-url https://docs.example.com
python3 -m pytest llms-txt-check/tests
```
