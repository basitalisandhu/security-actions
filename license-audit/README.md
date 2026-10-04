# license-audit

Flags dependency licences that are not in an allowlist. Reads `package-lock.json` (lockfile v2/v3 `license` fields, falling back to the installed `node_modules/<name>/package.json`; v1 lockfiles use the fallback only), `requirements.txt` (names resolved against installed distribution metadata: `License-Expression`, `License`, or the `License ::` classifiers; `-r` includes followed), CycloneDX JSON and SPDX JSON SBOMs. Licence strings are normalised to SPDX ids where the mapping is unambiguous ("Apache 2.0", "GPLv3", "BSD License", deprecated `GPL-3.0` and `GPL-3.0+` forms) and SPDX expressions are evaluated: an `OR` passes when any alternative is allowed, an `AND` needs every part allowed. Writes SARIF 2.1.0, a job summary with a licence distribution table, and annotations on the manifest line of each flagged package.

The built-in allowlist is a common permissive set, offered as a starting point rather than legal advice; set `allowlist` to your own policy.

## Usage

```yaml
name: licences
on: [push, pull_request]
permissions:
  contents: read
  security-events: write   # only needed while upload-sarif is "true"
jobs:
  licences:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: basitalisandhu/security-actions/license-audit@v1
        with:
          allowlist: |
            MIT
            Apache-2.0
            BSD-2-Clause
            BSD-3-Clause
            ISC
          denylist: SSPL-1.0, BUSL-1.1
          fail-on: unknown
```

For `requirements.txt` the packages must be installed first so their metadata is visible to the `python3` that runs the action:

```yaml
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install -r requirements.txt
      - uses: basitalisandhu/security-actions/license-audit@v1
        with:
          inputs: requirements.txt
```

For the most accurate npm data run `npm ci --ignore-scripts` first, so a lockfile entry without a `license` field can be read from the installed package.

## Inputs

| Input | Default | Description |
|---|---|---|
| `path` | `.` | Project directory. |
| `inputs` | `""` | Files to read, one per line; empty auto-detects `package-lock.json`, `requirements.txt`, `*.cdx.json`, `bom.json`, `sbom.json`, `*.spdx.json`. |
| `allowlist` | `""` | SPDX ids that are acceptable; empty uses the built-in list. |
| `denylist` | `""` | SPDX ids that always fail, even inside an `OR`. |
| `ignore-packages` | `""` | Package names to skip. |
| `include-dev` | `"true"` | Include npm dev dependencies. |
| `site-packages` | `""` | Directory with installed Python metadata; empty uses the running interpreter's environment. |
| `fail-on` | `disallowed` | `disallowed`, `unknown` or `none`. |
| `sarif-file` | `license-audit.sarif` | SARIF output path. |
| `upload-sarif` | `"true"` | Upload to code scanning. |
| `category` | `license-audit` | Code scanning category. |
| `python-version` | `""` | Set up this Python first; empty uses the runner's `python3` (3.10 or later). |

## Outputs

| Output | Description |
|---|---|
| `package-count` | Packages read. |
| `disallowed-count` | Disallowed or denied packages. |
| `unknown-count` | Packages with no or unrecognised licence information. |
| `sarif-file` | Path of the SARIF report. |
| `gate` | `pass` or `fail`. |

## Permissions

`contents: read`, plus `security-events: write` when `upload-sarif` is `"true"`. No network requests.

## Rules

| Id | Level | Status |
|---|---|---|
| LIC-001 | warning | `disallowed`: a recognised licence that is not in the allowlist |
| LIC-002 | error | `denied`: a licence in the denylist |
| LIC-003 | note | `unknown`: no licence declared, package not installed, or an id that is neither recognised nor listed |

Classifier-based detection is approximate: the PyPI classifier "BSD License" is mapped to `BSD-3-Clause`, and "Apache Software License" to `Apache-2.0`. Packages that declare `License-Expression` (PEP 639) are read exactly.

## Local use

```sh
python3 license-audit/src/license_audit.py --root . --fail-on unknown --sarif out.sarif --summary summary.md
python3 -m pytest license-audit/tests
```
