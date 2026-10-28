"""Property, regression and scaling tests for prompt-secrets-scan: odd notebooks, allowlists and paths never crash it."""
from __future__ import annotations

import io
import json
import random
import sys
import time
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "src"))

import prompt_secrets_scan as pss  # noqa: E402
from leaky_fixture import GITHUB  # noqa: E402

KEYS = ["cells", "source", "outputs", "text", "data", "text/plain", "text/html", "cell_type", "metadata"]


def value(r: random.Random, depth: int = 0):
    c = r.randrange(9 if depth < 4 else 5)
    if c == 0:
        return r.choice([None, True, False])
    if c == 1:
        return r.randint(-5, 5)
    if c == 2:
        return r.choice(["", "x = 1\n", GITHUB, ["a", 3, None]])
    if c == 3:
        return 1.5
    if c == 4:
        return "s"
    if c in (5, 6):
        return [value(r, depth + 1) for _ in range(r.randrange(4))]
    return {r.choice(KEYS): value(r, depth + 1) for _ in range(r.randrange(5))}


def run_main(args: list[str]) -> tuple[int, str]:
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        rc = pss.main(args)
    return rc, err.getvalue()


def test_random_notebooks_never_crash_the_scan():
    r = random.Random(20261028)
    allow = pss.Allowlist("")
    for _ in range(1000):
        pss.scan_notebook(json.dumps(value(r)), "nb.ipynb", allow)  # must not raise


def test_notebook_shaped_but_wrong_json_is_scanned_as_text():
    allow = pss.Allowlist("")
    for raw in ('{"cells": 5, "k": "%s"}' % GITHUB, '["%s"]' % GITHUB, "[" * 100000):
        found = pss.scan_notebook(raw, "nb.ipynb", allow)
        if GITHUB in raw:
            assert [f.rule_id for f in found] == ["PSS-GITHUB"]


def test_notebook_fields_of_the_wrong_type_are_skipped():
    nb = {"cells": [{"source": 5, "outputs": [{"text": 7, "data": "x"}, 3]}, 3, {"source": ["a\n", 4, GITHUB]}]}
    found = pss.scan_notebook(json.dumps(nb, indent=1), "nb.ipynb", pss.Allowlist(""))
    assert [(f.rule_id, f.context) for f in found] == [("PSS-GITHUB", "cell 2 source")]


def test_allowlist_that_is_not_utf8_still_loads(tmp_path):
    (tmp_path / ".prompt-secrets-allowlist").write_bytes(b"\xff\xfe# odd bytes\nrule:PSS-GITHUB\n")
    (tmp_path / "AGENTS.md").write_text(f"token {GITHUB}\n")
    rc, err = run_main(["--root", str(tmp_path), "--sarif", str(tmp_path / "o.sarif"), "--summary", str(tmp_path / "s.md")])
    assert rc == 0, err


def test_unwritable_sarif_path_is_one_error_line(tmp_path):
    rc, err = run_main(["--root", str(tmp_path), "--sarif", str(tmp_path / "missing" / "o.sarif"), "--summary", str(tmp_path / "s.md")])
    assert rc == 2
    assert err.startswith("::error::prompt-secrets-scan: cannot read or write ") and "Traceback" not in err


def test_symlink_loops_and_directories_named_like_files_are_ignored(tmp_path):
    (tmp_path / "loop").symlink_to(tmp_path)
    (tmp_path / "AGENTS.md").symlink_to(tmp_path / "missing.md")
    (tmp_path / "CLAUDE.md").mkdir()
    rc, err = run_main(["--root", str(tmp_path), "--sarif", str(tmp_path / "o.sarif"), "--summary", str(tmp_path / "s.md")])
    assert rc == 0, err


def _seconds(fn) -> float:
    best = float("inf")
    for _ in range(2):
        start = time.perf_counter()
        fn()
        best = min(best, time.perf_counter() - start)
    return max(best, 0.005)


def test_notebook_scan_scales_linearly():
    # Each finding's line was found by counting newlines from the start of the raw notebook.
    def make(n: int) -> str:
        cells = [{"cell_type": "code", "source": [f"key_{i} = '{GITHUB[:-6]}{i:06d}'\n"], "outputs": []} for i in range(n)]
        return json.dumps({"cells": cells}, indent=1)
    allow = pss.Allowlist("")
    small_nb, large_nb = make(500), make(5000)
    small = _seconds(lambda: pss.scan_notebook(small_nb, "nb.ipynb", allow))
    large = _seconds(lambda: pss.scan_notebook(large_nb, "nb.ipynb", allow))
    assert large / small < 30, f"500 cells: {small:.3f}s, 5,000 cells: {large:.3f}s"
