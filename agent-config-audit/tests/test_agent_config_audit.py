"""Tests for the agent-config-audit action script (SARIF, summary, outputs, exit codes)."""
from __future__ import annotations

import io
import json
import sys
from contextlib import redirect_stdout
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
ACTION_DIR = HERE.parent
REPO = ACTION_DIR.parent
sys.path.insert(0, str(ACTION_DIR / "src"))
sys.path.insert(0, str(REPO / "scripts"))

import action  # noqa: E402
import check_sarif  # noqa: E402

RISKY = HERE / "fixtures" / "risky"
CLEAN = HERE / "fixtures" / "clean"


def run(tmp_path: Path, root: Path, *extra: str, env: dict | None = None, monkeypatch=None):
    sarif = tmp_path / "out.sarif"
    summary = tmp_path / "summary.md"
    argv = ["--root", str(root), "--sarif", str(sarif), "--summary", str(summary), *extra]
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = action.main(argv)
    doc = json.loads(sarif.read_text(encoding="utf-8"))
    return rc, doc, summary.read_text(encoding="utf-8"), buf.getvalue()


def rule_ids(doc: dict) -> set[str]:
    return {r["ruleId"] for r in doc["runs"][0]["results"]}


def test_risky_fixture_reports_expected_rules(tmp_path):
    rc, doc, summary, out = run(tmp_path, RISKY, "--fail-on", "none")
    assert rc == 0
    found = rule_ids(doc)
    for rid in ["PERM-001", "PERM-003", "PERM-007", "HOOK-004", "HOOK-001", "MCP-001", "MCP-002", "MCP-003", "MCP-007",
                "INJ-001", "INJ-002", "INJ-004", "INJ-006", "INJ-008", "INJ-009"]:
        assert rid in found, rid
    assert "| critical |" in summary or "critical" in summary
    assert "::error file=.claude/settings.json" in out


def test_risky_sarif_is_structurally_valid(tmp_path):
    _, doc, _, _ = run(tmp_path, RISKY, "--fail-on", "none")
    assert check_sarif.problems(doc) == []
    assert doc["version"] == "2.1.0"
    driver = doc["runs"][0]["tool"]["driver"]
    assert driver["name"] == "agent-config-audit"
    ids = [r["id"] for r in driver["rules"]]
    assert len(ids) == len(set(ids))
    for res in doc["runs"][0]["results"]:
        assert ids[res["ruleIndex"]] == res["ruleId"]
        assert res["level"] in {"error", "warning", "note"}
        loc = res["locations"][0]["physicalLocation"]
        assert loc["region"]["startLine"] >= 1
        assert not loc["artifactLocation"]["uri"].startswith("/")
        assert res["partialFingerprints"]["primaryLocationLineHash"]


def test_rules_carry_security_severity(tmp_path):
    _, doc, _, _ = run(tmp_path, RISKY, "--fail-on", "none")
    for rule in doc["runs"][0]["tool"]["driver"]["rules"]:
        assert rule["defaultConfiguration"]["level"] in {"error", "warning", "note"}
        float(rule["properties"]["security-severity"])
        assert rule["shortDescription"]["text"]
        assert rule["help"]["text"]


def test_clean_fixture_has_no_findings(tmp_path):
    rc, doc, summary, _ = run(tmp_path, CLEAN)
    assert rc == 0
    assert doc["runs"][0]["results"] == []
    assert check_sarif.problems(doc) == []
    assert "No findings" in summary


def test_fail_on_threshold(tmp_path):
    assert run(tmp_path, RISKY, "--fail-on", "critical")[0] == 1
    assert run(tmp_path, RISKY, "--fail-on", "high")[0] == 1
    assert run(tmp_path, RISKY, "--fail-on", "none")[0] == 0
    assert run(tmp_path, CLEAN, "--fail-on", "info")[0] == 0


def test_fail_on_respects_severity_order(tmp_path):
    project = tmp_path / "medium-only"
    (project / ".mcp.json").parent.mkdir(parents=True)
    (project / ".mcp.json").write_text(json.dumps({"mcpServers": {"s": {"command": "npx", "args": ["-y", "@scope/server"]}}}))
    rc, doc, _, _ = run(tmp_path, project, "--fail-on", "high")
    assert rule_ids(doc) == {"MCP-003"}
    assert rc == 0
    assert run(tmp_path, project, "--fail-on", "medium")[0] == 1


def test_outputs_and_step_summary_env(tmp_path, monkeypatch):
    out_file = tmp_path / "github_output"
    step_summary = tmp_path / "step_summary"
    monkeypatch.setenv("GITHUB_OUTPUT", str(out_file))
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(step_summary))
    sarif = tmp_path / "x.sarif"
    with redirect_stdout(io.StringIO()):
        rc = action.main(["--root", str(RISKY), "--sarif", str(sarif), "--fail-on", "high"])
    assert rc == 1
    outputs = dict(line.split("=", 1) for line in out_file.read_text().splitlines())
    assert int(outputs["finding-count"]) > 10
    assert outputs["highest-severity"] == "critical"
    assert outputs["gate"] == "fail"
    assert outputs["sarif-file"] == str(sarif)
    assert "## Agent configuration audit" in step_summary.read_text()


def test_secrets_are_redacted_in_every_output(tmp_path):
    # Assembled from parts so this file does not itself look like it holds a credential.
    token = "v9Qm2xL7" + "pR4nB8kJ3wH6yT1cF5sD0aG2eZ8uV4iO7lM1"
    assert token in (RISKY / ".mcp.json").read_text()
    sarif = tmp_path / "out.sarif"
    summary = tmp_path / "summary.md"
    js = tmp_path / "report.json"
    with redirect_stdout(io.StringIO()):
        action.main(["--root", str(RISKY), "--sarif", str(sarif), "--summary", str(summary), "--json", str(js), "--fail-on", "none"])
    for p in (sarif, summary, js):
        assert token not in p.read_text(encoding="utf-8"), p.name


def test_extra_file_is_audited(tmp_path):
    extra = tmp_path / "elsewhere.json"
    extra.write_text(json.dumps({"mcpServers": {"x": {"url": "http://198.51.100.7/mcp"}}}))
    _, doc, _, _ = run(tmp_path, CLEAN, "--extra", str(extra), "--fail-on", "none")
    assert {"MCP-001", "MCP-008"} <= rule_ids(doc)


def test_missing_root_is_a_usage_error(tmp_path, capsys):
    rc = action.main(["--root", str(tmp_path / "nope"), "--sarif", str(tmp_path / "o.sarif")])
    assert rc == 2
    assert "::error" in capsys.readouterr().err


def test_every_known_rule_has_a_description():
    for rid in action.RULE_DESCRIPTIONS:
        assert rid.split("-")[0] in {"PERM", "HOOK", "MCP", "SEC", "INJ", "FILE", "CFG", "PLUGIN", "SKILL"}
    with pytest.raises(KeyError):
        action.SARIF_LEVEL["unknown"]
