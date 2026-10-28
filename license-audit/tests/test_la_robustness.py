"""Property, regression and scaling tests for license-audit: malformed lockfiles and SBOMs give one clear error line."""
from __future__ import annotations

import io
import json
import random
import sys
import time
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "src"))

import license_audit as la  # noqa: E402

KEYS = ["packages", "dependencies", "name", "version", "license", "licenses", "type", "dev", "bomFormat", "components",
        "group", "purl", "expression", "id", "spdxVersion", "SPDXID", "documentDescribes", "licenseConcluded", "externalRefs",
        "referenceType", "referenceLocator", "node_modules/a", "node_modules/b"]


def value(r: random.Random, depth: int = 0):
    c = r.randrange(9 if depth < 4 else 5)
    if c == 0:
        return r.choice([None, True, False])
    if c == 1:
        return r.randint(-5, 5)
    if c == 2:
        return r.choice(["", "MIT", "GPL-3.0-only", "MIT OR (Apache-2.0", "pkg:npm/a@1", "CycloneDX", "SPDX-2.3", "purl"])
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
        rc = la.main(args)
    return rc, err.getvalue()


def test_random_lockfiles_and_sboms_exit_cleanly(tmp_path):
    r = random.Random(20261028)
    names = ["package-lock.json", "a.cdx.json", "a.spdx.json"]
    for i in range(300):
        d = tmp_path / str(i)
        d.mkdir()
        name = names[i % 3]
        doc = value(r)
        if isinstance(doc, dict) and name != "package-lock.json":
            doc["bomFormat" if name == "a.cdx.json" else "spdxVersion"] = "CycloneDX" if name == "a.cdx.json" else "SPDX-2.3"
        (d / name).write_text(json.dumps(doc))
        rc, err = run_main(["--root", str(d), "--input", name, "--sarif", str(d / "o.sarif"), "--summary", str(d / "s.md"), "--fail-on", "none"])
        assert rc in (0, 2), (i, err)
        assert "internal error" not in err and "Traceback" not in err, (i, err)


@pytest.mark.parametrize("name, content, message", [
    ("package-lock.json", b"[]", "expected a JSON object at the top level, found list"),
    ("package-lock.json", b"\xff\xfe{", "not UTF-8 text"),
    ("package-lock.json", b"{\"packages\": ", "not valid JSON"),
    ("package-lock.json", b"[" * 100000, "nested too deeply"),
    ("bom.cdx.json", b"\"just a string\"", "expected a JSON object"),
])
def test_bad_input_files_are_one_error_line(tmp_path, name, content, message):
    (tmp_path / name).write_bytes(content)
    rc, err = run_main(["--root", str(tmp_path), "--input", name, "--sarif", str(tmp_path / "o.sarif"), "--summary", str(tmp_path / "s.md")])
    assert rc == 2
    assert err.startswith("::error::license-audit: ") and message in err, err
    assert err.count("\n") == 1


def test_wrong_types_inside_entries_are_tolerated(tmp_path):
    (tmp_path / "x.spdx.json").write_text(json.dumps({"spdxVersion": "SPDX-2.3", "documentDescribes": [{}],
                                                        "packages": [{"name": 1, "licenseConcluded": ["x"], "externalRefs": [None]}]}))
    (tmp_path / "x.cdx.json").write_text(json.dumps({"bomFormat": "CycloneDX", "components": [{"name": "a", "group": 3, "purl": 4,
                                                       "licenses": [{"expression": 5}, {"license": {"id": None, "name": "MIT"}}]}]}))
    (tmp_path / "package-lock.json").write_text(json.dumps({"packages": {"node_modules/x": {"name": 2, "version": None, "license": {"a": 1}}}}))
    for name in ("x.spdx.json", "x.cdx.json", "package-lock.json"):
        rc, err = run_main(["--root", str(tmp_path), "--input", name, "--sarif", str(tmp_path / "o.sarif"), "--summary", str(tmp_path / "s.md"), "--fail-on", "none"])
        assert rc == 0, (name, err)


def test_line_index_agrees_with_find(tmp_path):
    text = json.dumps({"packages": {"": {}, "node_modules/a": {"license": "MIT"}, "node_modules/b": {"name": "b"}},
                       "components": [{"purl": "pkg:npm/a@1"}]}, indent=2)
    index = la.LineIndex(text)
    for needle in ['"node_modules/a"', '"node_modules/b"', '"purl": "pkg:npm/a@1"', '"name": "b"', '"MIT"', '"absent"']:
        assert index.line_of(needle) == la.line_of(text, needle), needle


def _seconds(fn) -> float:
    best = float("inf")
    for _ in range(2):
        start = time.perf_counter()
        fn()
        best = min(best, time.perf_counter() - start)
    return max(best, 0.005)


@pytest.mark.parametrize("kind", ["npm", "cyclonedx", "spdx"])
def test_readers_scale_linearly(tmp_path, kind):
    # Each package's line number used text.find() and text.count() over the whole file, so 20,000
    # packages took several seconds per reader. The LineIndex makes it one pass.
    def make(n: int) -> Path:
        d = tmp_path / f"{kind}{n}"
        d.mkdir()
        if kind == "npm":
            doc = {"lockfileVersion": 3, "packages": {"": {}, **{f"node_modules/p{i}": {"version": "1.0.0", "license": "MIT"} for i in range(n)}}}
            path = d / "package-lock.json"
        elif kind == "cyclonedx":
            doc = {"bomFormat": "CycloneDX", "components": [{"name": f"c{i}", "version": "1", "purl": f"pkg:npm/c{i}@1",
                                                             "licenses": [{"license": {"id": "MIT"}}]} for i in range(n)]}
            path = d / "a.cdx.json"
        else:
            doc = {"spdxVersion": "SPDX-2.3", "packages": [{"name": f"c{i}", "SPDXID": f"SPDXRef-{i}", "licenseConcluded": "MIT"} for i in range(n)]}
            path = d / "a.spdx.json"
        path.write_text(json.dumps(doc, indent=2))
        return path
    small_path, large_path = make(1000), make(10000)
    small = _seconds(lambda: la.read_any(small_path, small_path.parent, True, None))
    large = _seconds(lambda: la.read_any(large_path, large_path.parent, True, None))
    assert large / small < 30, f"{kind}: 1,000 packages {small:.3f}s, 10,000 packages {large:.3f}s"
