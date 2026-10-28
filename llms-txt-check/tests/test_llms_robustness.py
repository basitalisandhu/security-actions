"""Property and regression tests for llms-txt-check: malformed files, URLs and options end in a clear result."""
from __future__ import annotations

import io
import random
import sys
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "src"))

import llms_txt_check as ltc  # noqa: E402

PIECES = ["# Title", "## Docs", "### Deep", "> summary", "- [a](docs/a.md): note", "- [b](http://[::1)", "- [](%zz)",
          "- [c](https://example.invalid/x)", "```", "plain text", "", "- not a link", "* [d](/)", "#", "##"]


def run_main(args: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        try:
            rc = ltc.main(args)
        except SystemExit as exc:  # argparse usage errors
            rc = exc.code
    return rc, out.getvalue(), err.getvalue()


def test_random_llms_txt_files_always_give_a_result(tmp_path):
    r = random.Random(20261028)
    for i in range(500):
        text = "\n".join(r.choice(PIECES) for _ in range(r.randrange(1, 25)))
        problems = ltc.check_text(text, site_dir=tmp_path, sorted=r.random() < 0.5, check_links=True, link_checker=lambda u: False)
        assert all(p.level in ltc.LEVEL_ORDER for p in problems), i


@pytest.mark.parametrize("url", ["http://[::1", "http://[zz]/llms.txt"])
def test_malformed_urls_are_not_a_traceback(url):
    assert ltc.fetch_text(url, timeout=1) is None
    assert ltc.head_ok(url, timeout=1) is False


def test_malformed_source_url_reports_not_found(tmp_path):
    rc, out, err = run_main(["--source", "http://[::1", "--summary", str(tmp_path / "s.md")])
    assert rc == 1
    assert "LLMS-001" in out and "Traceback" not in err


@pytest.mark.parametrize("value", ["-5", "0", "soon"])
def test_timeout_must_be_a_positive_whole_number(tmp_path, value):
    rc, _out, err = run_main(["--source", str(tmp_path), "--timeout", value])
    assert rc == 2
    assert "argument --timeout" in err


def test_unwritable_output_is_one_error_line(tmp_path):
    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "a.md").write_bytes(b"---\ntitle: \n---\n\xff\n")
    rc, _out, err = run_main(["--mode", "generate", "--docs-dir", str(docs), "--output", str(tmp_path / "missing" / "llms.txt"),
                              "--summary", str(tmp_path / "s.md")])
    assert rc == 2
    assert err.startswith("::error::llms-txt-check: cannot read or write ") and "Traceback" not in err
