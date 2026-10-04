"""Tests for license-audit: readers, normalisation, expression evaluation, policy, SARIF, outputs."""
from __future__ import annotations

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
import license_audit as la  # noqa: E402

FX = HERE / "fixtures"


def run(tmp_path: Path, *args: str):
    sarif = tmp_path / "out.sarif"
    summary = tmp_path / "summary.md"
    js = tmp_path / "report.json"
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = la.main([*args, "--sarif", str(sarif), "--summary", str(summary), "--json", str(js)])
    report = json.loads(js.read_text()) if js.exists() else {}
    doc = json.loads(sarif.read_text()) if sarif.exists() else {}
    return rc, doc, summary.read_text() if summary.exists() else "", report, buf.getvalue()


def status_map(report: dict) -> dict[str, str]:
    return {p["name"]: p["status"] for p in report["packages"]}


def test_canonical_aliases_and_deprecated_ids():
    cases = {
        "MIT": "MIT", "mit": "MIT", "MIT License": "MIT", "Apache 2.0": "Apache-2.0", "Apache License, Version 2.0": "Apache-2.0",
        "Apache Software License": "Apache-2.0", "BSD License": "BSD-3-Clause", "Simplified BSD": "BSD-2-Clause", "GPLv3": "GPL-3.0-only",
        "GPL-3.0": "GPL-3.0-only", "GPL-3.0+": "GPL-3.0-or-later", "LGPL-2.1": "LGPL-2.1-only", "AGPL-3.0": "AGPL-3.0-only",
        "License :: OSI Approved :: MIT License": "MIT", "License :: OSI Approved :: GNU General Public License v3 (GPLv3)": "GPL-3.0-only",
        "Python Software Foundation License": "PSF-2.0", "The Unlicense (Unlicense)": "Unlicense", "Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0",
        "zlib/libpng": "Zlib", "Proprietary": "LicenseRef-Proprietary", "Some Custom Thing": "Some Custom Thing",
    }
    for raw, want in cases.items():
        assert la.canonical(raw) == want, raw
    for raw in ["", "UNKNOWN", "SEE LICENSE IN LICENSE", "NOASSERTION", "UNLICENSED"]:
        assert la.canonical(raw) is None, raw


def test_policy_leaf_and_expressions():
    pol = la.Policy(["MIT", "Apache-2.0", "BSD-3-Clause"], ["SSPL-1.0", "BUSL-1.1"])
    assert pol.evaluate("MIT") == "allowed"
    assert pol.evaluate("GPL-3.0-only") == "disallowed"
    assert pol.evaluate("SSPL-1.0") == "denied"
    assert pol.evaluate("Totally Made Up") == "unknown"
    assert pol.evaluate("") == "unknown"
    assert pol.evaluate("(MIT OR GPL-2.0-only)") == "allowed"
    assert pol.evaluate("MIT AND GPL-2.0-only") == "disallowed"
    assert pol.evaluate("MIT AND (Apache-2.0 OR SSPL-1.0)") == "allowed"
    assert pol.evaluate("MIT AND SSPL-1.0") == "denied"
    assert pol.evaluate("SSPL-1.0 OR GPL-3.0-only") == "disallowed"
    assert pol.evaluate("MIT/Apache-2.0") == "allowed"
    assert pol.evaluate("GPL-2.0-only WITH Classpath-exception-2.0") == "disallowed"
    assert la.Policy(["GPL-2.0-only WITH Classpath-exception-2.0"]).evaluate("GPL-2.0-only WITH Classpath-exception-2.0") == "allowed"
    assert pol.evaluate("apache 2.0") == "allowed", "aliases are normalised before matching"
    assert la.Policy(["mit"]).evaluate("MIT") == "allowed", "allowlist matching is case-insensitive"
    assert pol.evaluate("((MIT)") == "allowed", "unbalanced parentheses do not crash"


def test_package_lock_v3(tmp_path):
    rc, doc, summary, report, out = run(tmp_path, "--root", str(FX / "npm"), "--fail-on", "unknown")
    assert rc == 1
    s = status_map(report)
    assert s["lodash"] == "allowed" and s["@scope/widget"] == "allowed"
    assert s["copyleft-lib"] == "disallowed" and s["old-style"] == "disallowed" and s["both-lib"] == "disallowed"
    assert s["dual-lib"] == "allowed", "an OR with an allowed alternative passes"
    assert s["nolicense-field"] == "allowed", "licence read from node_modules/<name>/package.json"
    assert s["mystery"] == "unknown"
    assert s["dev-only"] == "disallowed"
    assert next(p for p in report["packages"] if p["name"] == "dev-only")["dev"] is True
    assert "::warning file=package-lock.json,line=10,title=LIC-001::copyleft-lib" in out
    assert "| disallowed | copyleft-lib |" in summary
    assert check_sarif.problems(doc) == []


def test_no_dev_and_ignore_packages(tmp_path):
    _, _, _, report, _ = run(tmp_path, "--root", str(FX / "npm"), "--no-dev", "--ignore-packages", "mystery, old-style", "--fail-on", "none")
    names = set(status_map(report))
    assert "dev-only" not in names and "mystery" not in names and "old-style" not in names
    assert "lodash" in names


def test_package_lock_v1_falls_back_to_node_modules(tmp_path):
    rc, _, _, report, _ = run(tmp_path, "--root", str(FX / "npm-v1"))
    assert rc == 0
    s = status_map(report)
    assert s["legacy-lib"] == "allowed"
    assert next(p for p in report["packages"] if p["name"] == "legacy-lib")["expression"] == "MIT OR Apache-2.0"
    assert s["unseen"] == "unknown"


def test_requirements_with_installed_metadata(tmp_path):
    rc, doc, _, report, _ = run(tmp_path, "--root", str(FX / "python"), "--site-packages", str(FX / "python" / "site-packages"))
    assert rc == 1
    s = status_map(report)
    assert s == {"copyleft-tool": "disallowed", "not-installed-pkg": "unknown", "classifier-only": "allowed", "six": "allowed", "pydantic": "allowed", "requests": "allowed"}
    by_name = {p["name"]: p for p in report["packages"]}
    assert by_name["pydantic"]["licenses"] == ["MIT"], "License-Expression wins"
    assert by_name["classifier-only"]["licenses"] == ["BSD-3-Clause"], "classifier used when License is UNKNOWN"
    assert by_name["six"]["source"] == "base.txt" and by_name["six"]["line"] == 1, "-r includes are followed"
    assert by_name["copyleft-tool"]["source"] == "requirements.txt" and by_name["copyleft-tool"]["line"] == 5
    assert check_sarif.problems(doc) == []


def test_parse_requirements_skips_options_urls_and_paths():
    names = [n for n, _, _ in la.parse_requirements(FX / "python" / "requirements.txt")]
    assert names == ["six", "classifier-only", "requests", "pydantic", "copyleft-tool", "not-installed-pkg"]


def test_sbom_inputs(tmp_path):
    rc, doc, _, report, _ = run(tmp_path, "--root", str(FX / "sbom"))
    assert rc == 1
    pk = {(p["source"], p["name"]): p["status"] for p in report["packages"]}
    assert pk[("app.cdx.json", "lodash")] == "allowed"
    assert pk[("app.cdx.json", "copyleft-lib")] == "disallowed"
    assert pk[("app.cdx.json", "named-lic")] == "allowed", "licence name 'Apache License 2.0' normalised"
    assert pk[("app.cdx.json", "expr-lib")] == "allowed"
    assert pk[("app.cdx.json", "nolic")] == "unknown"
    assert pk[("app.cdx.json", "nested-ssl")] == "disallowed", "nested components are read"
    assert pk[("app.spdx.json", "gpl-thing")] == "disallowed"
    assert pk[("app.spdx.json", "nolic")] == "unknown"
    assert ("app.spdx.json", "app") not in pk, "the described root package is skipped"
    assert check_sarif.problems(doc) == []


def test_denylist_and_custom_allowlist(tmp_path):
    rc, doc, _, report, out = run(tmp_path, "--root", str(FX / "sbom"), "--input", "app.cdx.json",
                                 "--allowlist", "MIT, Apache-2.0, GPL-3.0-only, ISC", "--denylist", "SSPL-1.0", "--fail-on", "disallowed")
    assert rc == 1
    s = status_map(report)
    assert s["copyleft-lib"] == "allowed" and s["nested-ssl"] == "denied"
    assert "::error file=app.cdx.json" in out
    denied = [r for r in doc["runs"][0]["results"] if r["ruleId"] == "LIC-002"]
    assert len(denied) == 1 and denied[0]["level"] == "error"


def test_fail_on_levels(tmp_path):
    assert run(tmp_path, "--root", str(FX / "npm-v1"), "--fail-on", "disallowed")[0] == 0
    assert run(tmp_path, "--root", str(FX / "npm-v1"), "--fail-on", "unknown")[0] == 1
    assert run(tmp_path, "--root", str(FX / "npm"), "--fail-on", "none")[0] == 0


def test_sarif_structure(tmp_path):
    _, doc, _, _, _ = run(tmp_path, "--root", str(FX / "npm"), "--fail-on", "none")
    assert check_sarif.problems(doc) == []
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    assert [r["id"] for r in rules] == ["LIC-001", "LIC-002", "LIC-003"]
    for res in doc["runs"][0]["results"]:
        assert rules[res["ruleIndex"]]["id"] == res["ruleId"]
        assert res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "package-lock.json"
        assert res["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1
        assert res["properties"]["status"] in {"disallowed", "denied", "unknown"}


def test_outputs_file(tmp_path, monkeypatch):
    gh_out = tmp_path / "gh_out"
    monkeypatch.setenv("GITHUB_OUTPUT", str(gh_out))
    with redirect_stdout(io.StringIO()):
        rc = la.main(["--root", str(FX / "npm"), "--sarif", str(tmp_path / "o.sarif"), "--summary", str(tmp_path / "s.md")])
    assert rc == 1
    outputs = dict(l.split("=", 1) for l in gh_out.read_text().splitlines())
    assert outputs == {"package-count": "9", "disallowed-count": "4", "unknown-count": "1", "sarif-file": str(tmp_path / "o.sarif"), "gate": "fail"}


def test_usage_errors(tmp_path, capsys):
    assert la.main(["--root", str(tmp_path / "missing"), "--sarif", str(tmp_path / "o.sarif")]) == 2
    empty = tmp_path / "empty"
    empty.mkdir()
    assert la.main(["--root", str(empty), "--sarif", str(tmp_path / "o.sarif")]) == 2
    (empty / "weird.json").write_text("{}")
    assert la.main(["--root", str(empty), "--input", "weird.json", "--sarif", str(tmp_path / "o.sarif")]) == 2
    assert la.main(["--root", str(empty), "--input", "nope.json", "--sarif", str(tmp_path / "o.sarif")]) == 2
    assert capsys.readouterr().err.count("::error") == 4


def test_summary_lists_distribution(tmp_path):
    _, _, summary, _, _ = run(tmp_path, "--root", str(FX / "npm"), "--fail-on", "none")
    assert "Licence distribution" in summary and "| `MIT` | 1 |" in summary
    _, _, clean, _, _ = run(tmp_path, "--root", str(FX / "npm"), "--allowlist", "MIT,Apache-2.0,GPL-3.0-only,GPL-3.0-or-later,LGPL-2.1-only,AGPL-3.0-only,BSD-3-Clause",
                            "--ignore-packages", "mystery", "--fail-on", "none")
    assert "Every package licence is in the allowlist." in clean
