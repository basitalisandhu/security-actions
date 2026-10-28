"""The explicit JSON depth limit behaves the same on every Python version."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import license_audit as mod  # noqa: E402

DEEP = ["[" * 100000, "[" * 100000 + "]" * 100000, '{"a":' * 5000 + "1" + "}" * 5000]


@pytest.mark.parametrize("text", DEEP)
def test_deep_input_is_refused_before_parsing(text):
    with pytest.raises(mod.JSONTooDeepError, match="nested"):
        mod.json_loads(text)
    assert issubclass(mod.JSONTooDeepError, RecursionError)


def test_input_at_the_limit_parses():
    text = "[" * mod.MAX_JSON_DEPTH + "]" * mod.MAX_JSON_DEPTH
    assert mod.json_depth(text) == mod.MAX_JSON_DEPTH
    assert isinstance(mod.json_loads(text), list)


def test_brackets_inside_strings_do_not_count():
    text = '{"a": "' + "[" * 10000 + '\\"{{{", "b": [1, {"c": "]]]"}]}'
    assert mod.json_depth(text) == 3
    assert mod.json_loads(text)["b"][1]["c"] == "]]]"
