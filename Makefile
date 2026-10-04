.PHONY: test test-python test-node check selftest

test: test-python test-node

test-python:
	python3 -m pytest -q

test-node:
	node --test indexnow-ping/tests/*.test.mjs
	node --test sbom-diff-comment/tests/*.test.mjs

check:
	python3 scripts/check_actions.py

# Run each action's script on its fixtures the way the CI self-test does, without the composite wrapper.
selftest:
	python3 agent-config-audit/src/action.py --root agent-config-audit/tests/fixtures/risky --sarif /tmp/aca.sarif --summary /dev/null --fail-on none
	python3 prompt-secrets-scan/tests/leaky_fixture.py /tmp/pss-leaky
	python3 prompt-secrets-scan/src/prompt_secrets_scan.py --root /tmp/pss-leaky --sarif /tmp/pss.sarif --summary /dev/null --fail-on none
	python3 llms-txt-check/src/llms_txt_check.py --source llms-txt-check/tests/fixtures/site-valid --summary /dev/null --fail-on warning
	INPUT_HOST=www.example.org INPUT_DRY_RUN=true INPUT_URLS=https://www.example.org/ node indexnow-ping/src/indexnow.mjs
	INPUT_BASE=sbom-diff-comment/tests/fixtures/base.cdx.json INPUT_HEAD=sbom-diff-comment/tests/fixtures/head.cdx.json INPUT_COMMENT=false INPUT_MARKDOWN_FILE=/tmp/sbom-diff.md node sbom-diff-comment/src/sbom_diff.mjs
	python3 license-audit/src/license_audit.py --root license-audit/tests/fixtures/npm --sarif /tmp/la.sarif --summary /dev/null --fail-on none
	python3 scripts/check_sarif.py /tmp/aca.sarif /tmp/pss.sarif /tmp/la.sarif
