#!/usr/bin/env python3
"""Write the "leaky" fixture tree that the prompt-secrets-scan tests and the CI self-test scan.

The tree is generated instead of committed: its whole point is to hold strings shaped like real
credentials, and secret scanners (GitHub push protection included) rightly refuse files that do.
Every value is assembled from parts, so no line of this module, or of the tests that import it,
looks like a credential on its own. The file layout and line numbers are what the tests assert on.

    python3 prompt-secrets-scan/tests/leaky_fixture.py DEST      writes the tree into DEST

DEST must lie outside this repository. The tests get the same tree from the `leaky` fixture in conftest.py.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

# Mixed-case alphanumerics with enough entropy to pass the scanner's generic checks. Sliced from a
# rotating offset to make every value; on its own it carries no prefix a scanner recognises.
_CHARS = "Q7mX2vL9pR4nB8kJ3wH6yT1cF5sD0aG2eZ8uV4iO7lM1"


def fake(prefix: str, length: int, shift: int = 0) -> str:
    """A credential-shaped value: prefix plus `length` characters of _CHARS starting at `shift`."""
    return prefix + (_CHARS * (length // len(_CHARS) + 2))[shift:shift + length]


ANTHROPIC = fake("sk-ant-api03-", 44)
OPENAI_ALLOWED = fake("sk-proj-", 42, shift=5)  # listed in the allowlist, so never reported
GITHUB = fake("ghp_", 36)
GITHUB_IGNORED = fake("ghp_", 36, shift=3)  # sits on a line marked "secrets-scan: ignore"
GOOGLE = fake("AIza", 35)
AWS_KEY_ID = fake("AKIA", 16).upper()
SLACK_BOT = "xoxb-" + "123456789012" + "-" + fake("", 24)
SLACK_WEBHOOK = "https://hooks.slack.com/services/" + "T0A1B2C3D/B4E5F6G7H/" + fake("", 24)
HUGGINGFACE = fake("hf_", 34)
NPM = fake("npm_", 36)
BEARER = fake("", 32, shift=9)
GENERIC = fake("", 31, shift=17)
DB_PASSWORD = "Tr0ub4dor" + "-and-3"
PLACEHOLDER = "sk-example-" + "x" * 40  # skipped by the placeholder filter

# The armour lines come from a template so this module never holds a complete BEGIN ... END block.
# The body is the public openssh-key-v1 preamble, not key material.
_ARMOUR = "-----{} OPENSSH PRIVATE KEY-----"
PRIVATE_KEY = "\n".join([
    _ARMOUR.format("BEGIN"),
    "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW",
    _ARMOUR.format("END"),
]) + "\n"


def _notebook() -> dict:
    return {
        "cells": [
            {"cell_type": "markdown", "metadata": {}, "source": ["# Notebook\n", "No secrets in this cell.\n"]},
            {
                "cell_type": "code", "metadata": {}, "execution_count": 1,
                "outputs": [{"output_type": "stream", "name": "stdout", "text": [f"token: {SLACK_BOT}\n"]}],
                "source": ["import os\n", f'client = Client(api_key="{HUGGINGFACE}")\n'],
            },
        ],
        "metadata": {}, "nbformat": 4, "nbformat_minor": 5,
    }


def build(dest: Path | str) -> Path:
    """Write the tree into dest (created if needed) and return it. Refuses a dest inside the repository."""
    dest = Path(dest)
    resolved = dest.resolve()
    if resolved == REPO or REPO in resolved.parents:
        raise ValueError(f"refusing to write credential-shaped fixtures inside the repository ({REPO}); choose a directory outside it")
    files = {
        "prompts/system.md": "\n".join([
            "# Support assistant",
            "",
            f"You are a support assistant. Use the API with the key {ANTHROPIC} to look up tickets.",
            "",
            f"When calling the billing service use Authorization: Bearer {BEARER} and report the result.",
            "",
            f"Database: postgres://support:{DB_PASSWORD}@db.internal.invalid:5432/tickets",
            "",
            f"The GitHub token is {GITHUB}",
            f"Slack: {SLACK_WEBHOOK}",
        ]) + "\n",
        "AGENTS.md": "\n".join([
            "# Agents",
            "",
            f'api_key = "{GENERIC}"',
            "password: hunter2",
            f'EXAMPLE_KEY = "{PLACEHOLDER}"',
            f"AWS_ACCESS_KEY_ID={AWS_KEY_ID}",
            f"Google: {GOOGLE}",
            f"Allowed sample: {OPENAI_ALLOWED}",
            f"Ignored on purpose: {GITHUB_IGNORED}  # secrets-scan: ignore",
        ]) + "\n",
        "keys.txt": PRIVATE_KEY,
        "explore.ipynb": json.dumps(_notebook(), indent=1) + "\n",
        "node_modules/pkg/README.md": f"{GITHUB} in a vendored file must be skipped\n",
        ".prompt-secrets-allowlist": "\n".join(["# sample values that are allowed to stay", OPENAI_ALLOWED, "path:docs/samples/*"]) + "\n",
    }
    for rel, text in files.items():
        path = dest / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return dest


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("usage: leaky_fixture.py DEST", file=sys.stderr)
        return 2
    try:
        dest = build(args[0])
    except ValueError as exc:
        print(f"leaky_fixture: {exc}", file=sys.stderr)
        return 2
    print(f"leaky fixture written to {dest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
