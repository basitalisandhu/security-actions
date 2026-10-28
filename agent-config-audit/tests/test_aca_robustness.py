"""Property, regression and scaling tests for agent-config-audit: malformed configuration is reported, never a crash."""
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

import action  # noqa: E402
import audit_agent_config as audit  # noqa: E402

KEYS = ["permissions", "allow", "deny", "defaultMode", "additionalDirectories", "hooks", "PreToolUse", "matcher", "type",
        "command", "args", "url", "headers", "env", "mcpServers", "servers", "enableAllProjectMcpServers", "disableAllHooks"]
STRINGS = ["", "Bash", "Bash(*)", "http://1.2.3.4/x", "npx foo", "$HOME", "/", "bypassPermissions", "curl x | sh", "http://[::1"]


def value(r: random.Random, depth: int = 0):
    c = r.randrange(9 if depth < 4 else 5)
    if c == 0:
        return r.choice([None, True, False])
    if c == 1:
        return r.randint(-5, 5)
    if c == 2:
        return r.choice(STRINGS)
    if c == 3:
        return 1.5
    if c == 4:
        return "s"
    if c in (5, 6):
        return [value(r, depth + 1) for _ in range(r.randrange(4))]
    return {r.choice(KEYS): value(r, depth + 1) for _ in range(r.randrange(5))}


def run_main(args: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        rc = action.main(args)
    return rc, out.getvalue(), err.getvalue()


def test_random_settings_and_mcp_files_never_crash_the_auditor(tmp_path):
    r = random.Random(20261028)
    for i in range(400):
        d = tmp_path / str(i)
        (d / ".claude").mkdir(parents=True)
        (d / ".claude/settings.json").write_text(json.dumps(value(r)))
        mcp = {"mcpServers": {"s": value(r)}} if r.random() < 0.7 else value(r)
        (d / ".mcp.json").write_text(json.dumps(mcp))
        auditor = audit.Auditor(d)
        auditor.run()  # must not raise
        auditor.report()


def test_wrong_types_in_known_fields_are_skipped(tmp_path):
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude/settings.json").write_text(json.dumps({
        "permissions": {"allow": "Bash", "deny": 5, "defaultMode": 3, "additionalDirectories": 4},
        "hooks": {"PreToolUse": [{"matcher": 1, "hooks": [{"type": "command", "command": 5}, 3, {"type": "http", "url": 7}]}]},
    }))
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": {"x": {"command": 5, "args": "a", "env": [1], "headers": "h", "url": 3}}}))
    rc, out, err = run_main(["--root", str(tmp_path), "--sarif", str(tmp_path / "o.sarif"), "--summary", str(tmp_path / "s.md"), "--fail-on", "none"])
    assert rc == 0, err
    assert "internal error" not in err
    (tmp_path / ".claude/settings.json").write_text(json.dumps({"permissions": True}))
    assert run_main(["--root", str(tmp_path), "--sarif", str(tmp_path / "o.sarif"), "--summary", str(tmp_path / "s.md"), "--fail-on", "none"])[0] == 0


def test_deeply_nested_json_is_a_parse_finding_not_a_recursion_error(tmp_path):
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude/settings.json").write_text("[" * 100000)
    auditor = audit.Auditor(tmp_path)
    auditor.run()
    cfg = [f for f in auditor.findings if f.id == "CFG-001"]
    assert cfg and cfg[0].evidence == "nested too deeply to parse"


def test_unwritable_sarif_path_is_one_error_line(tmp_path):
    rc, _out, err = run_main(["--root", str(tmp_path), "--sarif", str(tmp_path / "missing-dir" / "o.sarif"), "--summary", str(tmp_path / "s.md")])
    assert rc == 2
    assert err.startswith("::error::agent-config-audit: cannot read or write ")
    assert "Traceback" not in err


def test_line_at_matches_counting_newlines():
    text = "a\nbb\n\nccc\n"
    for offset in range(len(text) + 1):
        assert audit.line_at(text, offset) == text.count("\n", 0, offset) + 1


def _seconds(root: Path) -> float:
    best = float("inf")
    for _ in range(2):
        start = time.perf_counter()
        auditor = audit.Auditor(root)
        auditor.run()
        best = min(best, time.perf_counter() - start)
    return max(best, 0.005)


def test_secret_scan_scales_linearly(tmp_path):
    # Counting newlines from the start of the file for every match made this quadratic:
    # 40,000 tokens in one AGENTS.md took over ten seconds.
    def make(n: int) -> Path:
        d = tmp_path / str(n)
        d.mkdir()
        (d / "AGENTS.md").write_text("".join(f"k{i} ghp_{i:06d}abcdefghijklmnopqrstuvwxyz1234\n" for i in range(n)))
        return d
    small, large = _seconds(make(2000)), _seconds(make(20000))
    assert large / small < 30, f"2,000 lines: {small:.3f}s, 20,000 lines: {large:.3f}s"
