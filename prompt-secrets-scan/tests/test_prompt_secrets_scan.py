"""Tests for prompt-secrets-scan: detection, allowlist, notebooks, redaction, SARIF, exit codes."""
from __future__ import annotations

import hashlib
import io
import json
import sys
from contextlib import redirect_stdout
from pathlib import Path

HERE = Path(__file__).resolve().parent
ACTION_DIR = HERE.parent
sys.path.insert(0, str(ACTION_DIR / "src"))
sys.path.insert(0, str(ACTION_DIR.parent / "scripts"))

import check_sarif  # noqa: E402
import prompt_secrets_scan as pss  # noqa: E402
from leaky_fixture import ANTHROPIC, BEARER, DB_PASSWORD, GENERIC, GITHUB, GOOGLE, HUGGINGFACE, NPM, SLACK_BOT, fake  # noqa: E402

# The leaky tree is generated outside the repository by the session-scoped `leaky` fixture in conftest.py.
CLEAN = HERE / "fixtures" / "clean"


def run(tmp_path: Path, root: Path, *extra: str):
    sarif = tmp_path / "out.sarif"
    summary = tmp_path / "summary.md"
    js = tmp_path / "report.json"
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = pss.main(["--root", str(root), "--sarif", str(sarif), "--summary", str(summary), "--json", str(js), *extra])
    return rc, json.loads(sarif.read_text()), summary.read_text(), json.loads(js.read_text()), buf.getvalue()


def rules_by_file(doc: dict) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for r in doc["runs"][0]["results"]:
        out.setdefault(r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], set()).add(r["ruleId"])
    return out


def test_leaky_fixture_detects_each_credential_type(tmp_path, leaky):
    rc, doc, summary, report, out = run(tmp_path, leaky, "--fail-on", "none")
    assert rc == 0
    by_file = rules_by_file(doc)
    assert {"PSS-ANTHROPIC", "PSS-BEARER", "PSS-CONNECTION-STRING", "PSS-GITHUB", "PSS-SLACK-WEBHOOK"} <= by_file["prompts/system.md"]
    assert {"PSS-GENERIC", "PSS-AWS-KEY-ID", "PSS-GOOGLE-API"} <= by_file["AGENTS.md"]
    assert by_file["keys.txt"] == {"PSS-PRIVATE-KEY"}
    assert {"PSS-SLACK-TOKEN", "PSS-HUGGINGFACE"} <= by_file["explore.ipynb"]
    assert "node_modules/pkg/README.md" not in by_file
    assert "node_modules/pkg/README.md" not in report["files_scanned"]
    assert "::error file=prompts/system.md,line=3,title=PSS-ANTHROPIC" in out
    assert "| critical |" in summary


def test_placeholders_inline_ignore_and_allowlist_are_respected(tmp_path, leaky):
    _, doc, _, _, _ = run(tmp_path, leaky, "--fail-on", "none")
    agents = [r for r in doc["runs"][0]["results"] if r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "AGENTS.md"]
    lines = {r["locations"][0]["physicalLocation"]["region"]["startLine"] for r in agents}
    assert 5 not in lines, "sk-example-xxxx placeholder must not be reported"
    assert 8 not in lines, "allowlisted literal must not be reported"
    assert 9 not in lines, "inline secrets-scan: ignore must be honoured"
    assert 4 not in lines, "short password value is below the generic length floor"


def test_clean_fixture_passes(tmp_path):
    rc, doc, summary, _, _ = run(tmp_path, CLEAN)
    assert rc == 0
    assert doc["runs"][0]["results"] == []
    assert "No secrets found" in summary
    assert check_sarif.problems(doc) == []


def test_sarif_is_valid_and_declares_every_rule(tmp_path, leaky):
    _, doc, _, _, _ = run(tmp_path, leaky, "--fail-on", "none")
    assert check_sarif.problems(doc) == []
    driver = doc["runs"][0]["tool"]["driver"]
    assert [r["id"] for r in driver["rules"]] == [r[0] for r in pss.RULES]
    for res in doc["runs"][0]["results"]:
        assert driver["rules"][res["ruleIndex"]]["id"] == res["ruleId"]
        assert res["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1
        assert res["partialFingerprints"]["primaryLocationLineHash"]


def test_no_raw_secret_in_any_output(tmp_path, leaky):
    secrets = [ANTHROPIC, BEARER, DB_PASSWORD, GITHUB, GENERIC, HUGGINGFACE, SLACK_BOT]
    sarif = tmp_path / "o.sarif"
    summary = tmp_path / "s.md"
    js = tmp_path / "r.json"
    buf = io.StringIO()
    with redirect_stdout(buf):
        pss.main(["--root", str(leaky), "--sarif", str(sarif), "--summary", str(summary), "--json", str(js), "--fail-on", "none"])
    for text in (sarif.read_text(), summary.read_text(), js.read_text(), buf.getvalue()):
        for s in secrets:
            assert s not in text


def test_fail_on_levels(tmp_path, leaky):
    assert run(tmp_path, leaky, "--fail-on", "critical")[0] == 1
    assert run(tmp_path, leaky, "--fail-on", "high")[0] == 1
    assert run(tmp_path, leaky, "--fail-on", "none")[0] == 0
    assert run(tmp_path, CLEAN, "--fail-on", "low")[0] == 0


def test_outputs_file(tmp_path, monkeypatch, leaky):
    out_file = tmp_path / "gh_out"
    monkeypatch.setenv("GITHUB_OUTPUT", str(out_file))
    with redirect_stdout(io.StringIO()):
        rc = pss.main(["--root", str(leaky), "--sarif", str(tmp_path / "x.sarif"), "--summary", str(tmp_path / "s.md")])
    assert rc == 1
    outputs = dict(l.split("=", 1) for l in out_file.read_text().splitlines())
    assert outputs["gate"] == "fail"
    assert int(outputs["finding-count"]) >= 11
    assert int(outputs["files-scanned"]) == 4


def test_sha256_regex_rule_and_path_allowlist_entries(tmp_path):
    root = tmp_path / "proj"
    (root / "docs").mkdir(parents=True)
    key = fake("sk-ant-api03-", 44, shift=21)
    (root / "a.md").write_text(f"key {key}\n")
    (root / "b.md").write_text(f"token {GITHUB}\n")
    (root / "c.md").write_text(f"{GOOGLE}\n")
    (root / "docs" / "d.md").write_text(f"{NPM}\n")
    allow = tmp_path / "allow.txt"
    allow.write_text("\n".join([
        "# comment", f"sha256:{hashlib.sha256(key.encode()).hexdigest()}", f"re:^{GITHUB[:6]}", "rule:PSS-GOOGLE-API", "path:docs/*",
    ]) + "\n")
    rc, doc, _, report, _ = run(tmp_path, root, "--allowlist", str(allow))
    assert rc == 0
    assert doc["runs"][0]["results"] == []
    assert "docs/d.md" not in report["files_scanned"]


def test_custom_paths_and_exclude(tmp_path):
    root = tmp_path / "proj"
    (root / "cfg").mkdir(parents=True)
    (root / "cfg" / "app.yaml").write_text(f"api_key: {GENERIC}\n")
    (root / "cfg" / "skip.yaml").write_text(f"api_key: {GENERIC}\n")
    rc, doc, _, report, _ = run(tmp_path, root, "--paths", "cfg/*.yaml", "--exclude", "cfg/skip.*", "--fail-on", "none")
    assert report["files_scanned"] == ["cfg/app.yaml"]
    assert {r["ruleId"] for r in doc["runs"][0]["results"]} == {"PSS-GENERIC"}


def test_overlapping_patterns_keep_the_specific_rule():
    found = pss.scan_text(ANTHROPIC, "x.md", pss.Allowlist())
    assert [f.rule_id for f in found] == ["PSS-ANTHROPIC"]
    jwt = ".".join(["eyJhbGciOiJIUzI1NiJ9", "eyJzdWIiOiIxMjM0NTY3ODkwIn0", fake("", 24)])
    found = pss.scan_text("Authorization: Bearer " + jwt, "x.md", pss.Allowlist())
    assert [f.rule_id for f in found] == ["PSS-JWT"]


def test_connection_string_with_placeholder_password_is_skipped():
    assert pss.scan_text("postgres://user:password@localhost/db", "x.md", pss.Allowlist()) == []
    assert pss.scan_text("postgres://user:${DB_PASS}@localhost/db", "x.md", pss.Allowlist()) == []
    found = pss.scan_text(f"mongodb+srv://app:{DB_PASSWORD}@cluster0.invalid/db", "x.md", pss.Allowlist())
    assert [f.rule_id for f in found] == ["PSS-CONNECTION-STRING"]


def test_notebook_lines_point_into_the_raw_file(leaky):
    raw = (leaky / "explore.ipynb").read_text()
    found = pss.scan_notebook(raw, "explore.ipynb", pss.Allowlist())
    for f in found:
        assert f.value in raw.splitlines()[f.line - 1]
        assert f.context.startswith("cell ")


def test_binary_and_oversized_files_are_skipped(tmp_path):
    root = tmp_path / "proj"
    root.mkdir()
    (root / "bin.md").write_bytes(b"\x00\x01" + GITHUB.encode())
    (root / "big.txt").write_text("x" * (pss.MAX_FILE_BYTES + 1))
    rc, doc, summary, report, _ = run(tmp_path, root)
    assert rc == 0 and doc["runs"][0]["results"] == []
    assert report["files_scanned"] == []
    assert "larger than" in summary


def test_usage_errors(tmp_path, capsys):
    assert pss.main(["--root", str(tmp_path / "missing"), "--sarif", str(tmp_path / "o.sarif")]) == 2
    assert pss.main(["--root", str(CLEAN), "--allowlist", str(tmp_path / "no-such-allowlist"), "--sarif", str(tmp_path / "o.sarif")]) == 2
    assert "::error" in capsys.readouterr().err


def test_redact_keeps_only_edges():
    assert pss.redact("abcdefghijklmnop") == "abcd****op"
    assert pss.redact("short") == "****"
    assert pss.redact("-----BEGIN PRIVATE KEY-----").startswith("-----BEGIN")
