# prompt-secrets-scan

Finds credentials that ended up inside prompt files, system prompts, Jupyter notebooks and agent instruction files: the places general secret scanners are often configured to skip, and the places that get pasted into chat windows. Detects API keys of common providers (Anthropic, OpenAI, OpenRouter, Google, AWS, GitHub, GitLab, Slack, Stripe, npm, PyPI, Hugging Face, Groq, Replicate, Perplexity, xAI, SendGrid, Mailgun, Twilio, Telegram, DigitalOcean, Databricks, Linear, Notion, Shopify, age, Azure storage), private key blocks, bearer tokens, JSON Web Tokens, Slack and Discord webhooks, connection strings with embedded passwords, and generic `api_key = "..."` assignments with an entropy check. Writes SARIF 2.1.0, a job summary and annotations. Matched values are never printed in full.

Default file set, relative to `path`: `**/*.md`, `**/*.mdx`, `**/*.txt`, `**/*.prompt`, `**/*.prompty`, `**/*.ipynb` (cell sources and text outputs), `**/*.jinja`, `**/*.jinja2`, `**/*.j2`, `**/*.tmpl`, `**/*.hbs`, anything under a `prompts/` or `prompt/` directory, `system_prompt*`, `.cursorrules`, `.clinerules`, `.windsurfrules`, `.cursor/rules/**`, `.claude/**/*.md`, `.claude/settings*.json`, `.mcp.json` and `.github/copilot-instructions.md`. `node_modules`, `vendor`, `dist`, `build`, virtualenvs and `.git` are skipped, as are binary files and files over 5 MiB.

## Usage

```yaml
name: prompt-secrets
on: [push, pull_request]
permissions:
  contents: read
  security-events: write   # only needed while upload-sarif is "true"
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: basitalisandhu/security-actions/prompt-secrets-scan@v1
        with:
          fail-on: high
```

## Allowlist

Create `.prompt-secrets-allowlist` at the scanned root (or point `allowlist-file` elsewhere). One entry per line:

```text
# sample values documented on purpose: store the hash, not the value
sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
# regular expression on the matched value
re:^sk-test-
# skip files
path:docs/samples/*
# disable a rule everywhere
rule:PSS-JWT
# a literal value (fine for values that are public anyway)
https://hooks.slack.com/services/T000/B000/public-sample
```

A line that contains `secrets-scan: ignore` or `pragma: allowlist secret` is skipped. Values that look like placeholders (`xxxx`, `your_`, `example`, `<...>`, `${VAR}`, `{{ var }}`) are skipped automatically.

## Inputs

| Input | Default | Description |
|---|---|---|
| `path` | `.` | Directory to scan. |
| `paths` | `""` | Globs to scan, comma or newline separated; empty uses the built-in list. |
| `exclude` | `""` | Globs to skip, matched against the relative path. |
| `allowlist-file` | `""` | Allowlist file; empty uses `.prompt-secrets-allowlist` when present. |
| `fail-on` | `high` | Lowest severity that fails the job: `critical`, `high`, `medium`, `low`, `none`. |
| `sarif-file` | `prompt-secrets-scan.sarif` | SARIF output path. |
| `upload-sarif` | `"true"` | Upload to code scanning. |
| `category` | `prompt-secrets-scan` | Code scanning category. |
| `python-version` | `""` | Set up this Python first; empty uses the runner's `python3` (3.10 or later). |

## Outputs

| Output | Description |
|---|---|
| `finding-count` | Findings at every severity. |
| `files-scanned` | Number of files scanned. |
| `sarif-file` | Path of the SARIF report. |
| `gate` | `pass` or `fail` according to `fail-on`. |

## Permissions

`contents: read`, plus `security-events: write` when `upload-sarif` is `"true"`. The script makes no network requests.

## Rules

| Id | Severity | Pattern |
|---|---|---|
| PSS-ANTHROPIC, PSS-OPENAI, PSS-OPENROUTER, PSS-GOOGLE-API, PSS-GOOGLE-OAUTH, PSS-AWS-KEY-ID, PSS-AWS-SECRET, PSS-GITHUB, PSS-GITLAB, PSS-SLACK-TOKEN, PSS-STRIPE, PSS-NPM, PSS-PYPI, PSS-HUGGINGFACE, PSS-GROQ, PSS-REPLICATE, PSS-PERPLEXITY, PSS-XAI, PSS-SENDGRID, PSS-TELEGRAM, PSS-DIGITALOCEAN, PSS-DATABRICKS, PSS-SHOPIFY, PSS-AGE, PSS-AZURE-STORAGE | critical | Provider-specific key formats |
| PSS-PRIVATE-KEY | critical | `-----BEGIN ... PRIVATE KEY-----` |
| PSS-CONNECTION-STRING | critical | `postgres://`, `mysql://`, `mongodb://`, `redis://`, `amqp://`, `mssql://`, `jdbc:` URLs with a password |
| PSS-SLACK-WEBHOOK, PSS-DISCORD-WEBHOOK, PSS-MAILGUN, PSS-TWILIO, PSS-LINEAR, PSS-NOTION | high | Webhook URLs and provider keys with less distinctive formats |
| PSS-BEARER | high | `Bearer <token>` with 20 or more characters and enough entropy |
| PSS-GENERIC | high | `api_key`, `secret`, `password`, `*_token` assigned a 16+ character high-entropy value |
| PSS-JWT | medium | `eyJ...` three-part tokens |

## Local use

```sh
python3 prompt-secrets-scan/src/prompt_secrets_scan.py --root . --sarif out.sarif --summary summary.md
python3 -m pytest prompt-secrets-scan/tests
```

The credential-filled tree that the tests and the CI self-test scan is not committed. `tests/leaky_fixture.py` assembles every value from parts and writes the tree to a directory outside the repository (`python3 prompt-secrets-scan/tests/leaky_fixture.py /tmp/leaky`), so no file in this repository holds a credential-shaped string.
