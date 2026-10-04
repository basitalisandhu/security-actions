# Contributing

Thank you for helping teams run these checks. This document is the layout standard and the pull request checklist. `make test` and `make check` enforce most of it and CI runs both on every pull request.

## Ground rules

- No dependencies. Python scripts use the standard library only; Node scripts use built-in modules only. An action that needs a package manager step is slower, needs network at run time and widens the supply chain of everyone who uses it.
- Precision over coverage. A check that is noisy on real repositories gets narrowed or removed. If a pattern cannot be made precise, give it a lower severity and say so in the README.
- Secrets never reach the output. Any value a scanner matches is redacted (first four and last two characters) in SARIF, summaries, JSON and logs. Tests assert this.
- Inputs only grow. Add inputs with defaults; never remove or rename one inside a major version. See the versioning policy in the README.
- Every action is self-contained. `uses: basitalisandhu/security-actions/<name>@v1` must work with nothing but that directory, so no shared runtime code between actions (the shared `scripts/check_sarif.py` is used by tests and CI only).

## Layout

```text
<name>/
  action.yml        composite action; inputs are passed to the script as environment variables
  README.md         usage snippet, inputs and outputs tables, permissions, rules
  src/<script>      one script, with a module-level docstring or comment that explains the CLI
  tests/            pytest (test_<name>.py) or node:test (<name>.test.mjs), plus fixtures/
```

`action.yml` conventions:

- `name`, `description`, `author: "Muhammad Basit Ali (@basitalisandhu)"` and `branding`.
- Every input has a `description` and a `default` (or `required: true`).
- The run step reads inputs from `env:` variables, never by interpolating `${{ inputs.x }}` into the script text.
- Scripts exit 0 on success, 1 when a gate fails, 2 on usage errors. For SARIF-producing actions the run step turns exit 1 into a `gate=fail` output so the upload step still runs, and a final step fails the job.
- Set-up steps for Python or Node are conditional on a `python-version` or `node-version` input and skipped by default.
- External actions are limited to the list in `scripts/check_actions.py` (`actions/checkout@v4`, `actions/setup-python@v5`, `actions/setup-node@v4`, `github/codeql-action/upload-sarif@v3`). Adding one needs a reason in the pull request.

## Tests

- Python: `python3 -m pytest` from the repository root (each suite also runs on its own with `python3 -m pytest <name>/tests`).
- Node: `node --test "<name>/tests/*.test.mjs"`.
- Tests must pass offline. Network behaviour is tested against loopback `http.createServer` instances (Node) or injected fetch functions (Python).
- Every SARIF-producing action validates its output with `scripts/check_sarif.py` in at least one test.
- Fixtures that contain credentials must be synthetic values that match the detection patterns but belong to no real account. Avoid words the placeholder filter skips (`example`, `sample`, `dummy`, `xxxx`) unless the test is about the filter.
- Do not commit such fixtures. Build them at test time from parts, as `prompt-secrets-scan/tests/leaky_fixture.py` does, so that push protection and secret scanners never see a credential-shaped line in this repository.

## Pull request checklist

- [ ] `make test` and `make check` pass locally.
- [ ] New input documented in the action's README table with its default, and added with a default in `action.yml`.
- [ ] New rule id documented in the action's README rules table.
- [ ] Fixture added or extended for the new behaviour; a negative case too when it is a detector.
- [ ] `CHANGELOG.md` updated under Unreleased.
- [ ] No em-dashes, no model names or product identifiers in prose. Provider names that a pattern detects are fine.
- [ ] No new third-party action or package.

## Reporting false positives

Open an issue with the action name, the rule id, the matching text (redacted where needed) and why it is safe. Narrowing a pattern, adding an allowlist mechanism or adding a negative fixture are all welcome pull requests.

## Licence

By contributing you agree that your contribution is licensed under the MIT licence of this repository.
