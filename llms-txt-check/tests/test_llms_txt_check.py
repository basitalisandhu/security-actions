"""Tests for llms-txt-check: parsing, rules, directory and URL sources, generation, outputs."""
from __future__ import annotations

import io
import json
import sys
from contextlib import redirect_stdout
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "src"))

import llms_txt_check as ltc  # noqa: E402

VALID = HERE / "fixtures" / "site-valid"
BROKEN = HERE / "fixtures" / "site-broken"
DOCS = HERE / "fixtures" / "docs-src"


def rules(problems):
    return [p.rule for p in problems]


def run(tmp_path: Path, *args: str):
    js = tmp_path / "report.json"
    summary = tmp_path / "summary.md"
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = ltc.main([*args, "--json", str(js), "--summary", str(summary)])
    return rc, json.loads(js.read_text()), summary.read_text(), buf.getvalue()


def test_valid_site_passes(tmp_path):
    rc, report, summary, out = run(tmp_path, "--source", str(VALID))
    assert rc == 0
    assert report["status"] == "pass" and report["problems"] == []
    assert "follows the llms.txt convention" in summary
    assert "llms-txt-check: pass" in out


def test_broken_site_reports_each_rule(tmp_path):
    rc, report, summary, out = run(tmp_path, "--source", str(BROKEN))
    assert rc == 1
    found = {p["rule"] for p in report["problems"]}
    assert {"LLMS-002", "LLMS-008", "LLMS-003", "LLMS-005", "LLMS-006", "LLMS-007", "LLMS-009", "LLMS-014"} <= found
    assert "LLMS-001" not in found
    assert "::error file=" in out and "line=1,title=LLMS-002" in out
    assert "| error |" in summary


def test_parse_extracts_structure():
    doc = ltc.parse((VALID / "llms.txt").read_text())
    assert doc["title"] == "Acme Docs" and doc["title_line"] == 1
    assert doc["summary"].startswith("Acme is a tool")
    assert [s["name"] for s in doc["sections"]] == ["Docs", "Optional"]
    assert doc["sections"][0]["links"][0] == {"line": 9, "name": "Getting started", "url": "/docs/getting-started.md", "notes": "Install Acme and run the first command"}
    assert doc["sections"][1]["links"][0]["notes"] == ""


def test_code_blocks_are_ignored_when_parsing():
    text = "# T\n\n> s\n\n## Docs\n\n- [A](/a.md)\n\n```\n# not a heading\n- not a link\n```\n"
    assert rules(ltc.check_text(text)) == []


def test_missing_file_is_an_error(tmp_path):
    rc, report, _, _ = run(tmp_path, "--source", str(tmp_path))
    assert rc == 1
    assert rules([ltc.Problem(**{k: v for k, v in p.items()}) for p in report["problems"]]) == ["LLMS-001"]


def test_empty_file(tmp_path):
    (tmp_path / "llms.txt").write_text("\n\n")
    rc, report, _, _ = run(tmp_path, "--source", str(tmp_path))
    assert rc == 1 and [p["rule"] for p in report["problems"]] == ["LLMS-013"]


def test_duplicate_and_empty_links():
    text = "# T\n\n> s\n\n## Docs\n\n- [A](https://x.invalid/a)\n- [B](https://x.invalid/a)\n- [C]()\n"
    found = rules(ltc.check_text(text))
    assert "LLMS-012" in found and "LLMS-011" in found


def test_fail_on_levels(tmp_path):
    text = "# T\n\n## Docs\n\n- [A](https://x.invalid/a)\n"
    (tmp_path / "llms.txt").write_text(text)
    assert run(tmp_path, "--source", str(tmp_path), "--fail-on", "error")[0] == 0
    assert run(tmp_path, "--source", str(tmp_path), "--fail-on", "warning")[0] == 1
    assert run(tmp_path, "--source", str(BROKEN), "--fail-on", "none")[0] == 0


def test_url_source_uses_fetcher_and_link_checker():
    fetched = []
    text = "# Remote\n\n> s\n\n## Docs\n\n- [ok](https://remote.invalid/ok)\n- [bad](https://remote.invalid/bad)\n"
    got, where, site_dir, has_full = ltc.load_source("https://remote.invalid", fetcher=lambda u: fetched.append(u) or text)
    assert fetched == ["https://remote.invalid/llms.txt"]
    assert got == text and site_dir is None and has_full is None
    problems = ltc.check_text(got, check_links=True, link_checker=lambda u: u.endswith("/ok"))
    assert rules(problems) == ["LLMS-010"]
    assert problems[0].line == 8
    # without --check-links no remote request is made
    assert ltc.check_text(got, check_links=False, link_checker=lambda u: (_ for _ in ()).throw(AssertionError("called"))) == []


def test_url_source_missing_file(tmp_path, monkeypatch):
    monkeypatch.setattr(ltc, "fetch_text", lambda u, timeout=10: None)
    rc, report, _, _ = run(tmp_path, "--source", "https://remote.invalid/")
    assert rc == 1 and report["problems"][0]["rule"] == "LLMS-001"


def test_relative_link_resolution(tmp_path):
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "a.md").write_text("# a\n")
    (tmp_path / "docs" / "b.html").write_text("<p>b</p>")
    (tmp_path / "docs" / "c").mkdir()
    (tmp_path / "docs" / "c" / "index.html").write_text("<p>c</p>")
    for url in ["/docs/a.md", "/docs/a", "docs/b.html", "/docs/b", "/docs/c/", "/docs/c", "/docs/a.md#section", "/"]:
        assert ltc.resolve_relative(tmp_path, url), url
    assert not ltc.resolve_relative(tmp_path, "/docs/missing")


def test_generate_builds_sections_from_docs_dir(tmp_path):
    out = tmp_path / "llms.txt"
    rc, report, _, _ = run(tmp_path, "--mode", "generate", "--docs-dir", str(DOCS), "--output", str(out),
                           "--site-name", "Acme", "--summary-text", "Acme docs.", "--site-url", "https://acme.example")
    assert rc == 0 and report["status"] == "pass"
    text = out.read_text()
    assert text.startswith("# Acme\n\n> Acme docs.\n\n## Docs\n")
    assert "## Guides" in text and "## Reference" in text
    assert "- [Acme Overview](https://acme.example/README.md): Acme is a tool that does a thing with links removed from the excerpt." in text
    assert "- [Installing Acme](https://acme.example/guides/install.md): Install Acme with pip or from source." in text
    assert "- [Usage Tips](https://acme.example/guides/usage-tips.md)" in text
    assert "pip install acme" not in text, "code blocks must not become the excerpt"
    assert ltc.check_text(text) == []


def test_generate_link_formats(tmp_path):
    html = ltc.generate(DOCS, "Acme", "s", link_format="html")
    assert "(/index.html)" in html and "(/guides/install.html)" in html
    none = ltc.generate(DOCS, "Acme", "s", link_format="none")
    assert "(/)" in none and "(/guides/install)" in none
    md = ltc.generate(DOCS, "Acme", "s")
    assert "(/README.md)" in md and "(/reference/cli.md)" in md


def test_generate_is_deterministic_and_checks_relative_links(tmp_path):
    assert ltc.generate(DOCS, "Acme", "s") == ltc.generate(DOCS, "Acme", "s")
    out = tmp_path / "llms.txt"
    rc, report, _, _ = run(tmp_path, "--mode", "generate", "--docs-dir", str(DOCS), "--output", str(out), "--site-name", "Acme")
    assert rc == 0 and report["problems"] == []


def test_generate_default_name_from_repository(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_REPOSITORY", "someone/acme-docs")
    out = tmp_path / "llms.txt"
    run(tmp_path, "--mode", "generate", "--docs-dir", str(DOCS), "--output", str(out))
    assert out.read_text().startswith("# acme-docs\n\n> Documentation for acme-docs.\n")


def test_generate_missing_docs_dir_is_usage_error(tmp_path, capsys):
    assert ltc.main(["--mode", "generate", "--docs-dir", str(tmp_path / "nope"), "--output", str(tmp_path / "o")]) == 2
    assert "::error" in capsys.readouterr().err


def test_outputs_file(tmp_path, monkeypatch):
    gh_out = tmp_path / "gh_out"
    monkeypatch.setenv("GITHUB_OUTPUT", str(gh_out))
    with redirect_stdout(io.StringIO()):
        rc = ltc.main(["--source", str(BROKEN), "--summary", str(tmp_path / "s.md")])
    assert rc == 1
    outputs = dict(l.split("=", 1) for l in gh_out.read_text().splitlines())
    assert outputs["status"] == "fail" and outputs["error-count"] == "2" and int(outputs["warning-count"]) >= 5
    assert outputs["llms-txt-path"].endswith("llms.txt")


def test_strip_md_and_title_extraction():
    assert ltc.strip_md("A **bold** `code` [link](http://x) <b>tag</b>") == "A bold code link tag"
    title, excerpt = ltc.title_and_excerpt("---\ntitle: \"Quoted\"\n---\n\n![img](x.png)\n\nFirst para.\n", "fallback")
    assert (title, excerpt) == ("Quoted", "First para.")
    title, excerpt = ltc.title_and_excerpt("no heading\n", "Fallback Name")
    assert (title, excerpt) == ("Fallback Name", "no heading")
    long = "x" * 200
    assert ltc.title_and_excerpt(f"# T\n\n{long}\n", "f")[1].endswith("...")


def test_sorted_flag_reports_out_of_order_sections_and_links(tmp_path):
    sorted_text = "# Acme\n\n> Summary.\n\n## Docs\n\n- [Overview](/README.md)\n- [Architecture](/architecture.md)\n- [Guide](/guide.md)\n\n## Reference\n\n- [API](/api.md)\n- [CLI](/cli.md)\n"
    unsorted_sections = "# Acme\n\n> Summary.\n\n## Reference\n\n- [API](/api.md)\n\n## Docs\n\n- [Overview](/README.md)\n"
    unsorted_links = "# Acme\n\n> Summary.\n\n## Docs\n\n- [Guide](/guide.md)\n- [Architecture](/architecture.md)\n"
    unsorted_readme_last = "# Acme\n\n> Summary.\n\n## Docs\n\n- [Architecture](/architecture.md)\n- [Overview](/README.md)\n"

    # Sorted file produces no findings with or without --sorted
    assert "LLMS-015" not in rules(ltc.check_text(sorted_text, sorted=False))
    assert "LLMS-015" not in rules(ltc.check_text(sorted_text, sorted=True))

    # Unsorted files produce no finding without the flag
    assert "LLMS-015" not in rules(ltc.check_text(unsorted_sections, sorted=False))
    assert "LLMS-015" not in rules(ltc.check_text(unsorted_links, sorted=False))
    assert "LLMS-015" not in rules(ltc.check_text(unsorted_readme_last, sorted=False))

    # Unsorted files produce LLMS-015 finding with the flag
    p_sec = ltc.check_text(unsorted_sections, sorted=True)
    assert "LLMS-015" in rules(p_sec)
    assert any("Section list" in p.message for p in p_sec if p.rule == "LLMS-015")

    p_links = ltc.check_text(unsorted_links, sorted=True)
    assert "LLMS-015" in rules(p_links)
    assert any("link entries" in p.message for p in p_links if p.rule == "LLMS-015")

    p_readme = ltc.check_text(unsorted_readme_last, sorted=True)
    assert "LLMS-015" in rules(p_readme)

    # CLI runs with --sorted flag
    (tmp_path / "llms.txt").write_text(unsorted_sections)
    rc_without, report_without, _, _ = run(tmp_path, "--source", str(tmp_path), "--fail-on", "none")
    assert "LLMS-015" not in [p["rule"] for p in report_without["problems"]]

    rc_with, report_with, _, _ = run(tmp_path, "--source", str(tmp_path), "--sorted", "--fail-on", "none")
    assert "LLMS-015" in [p["rule"] for p in report_with["problems"]]

