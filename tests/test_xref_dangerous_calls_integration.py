"""End-to-end integration test for the active runtime path of the
``is_dangerous_api`` fix.

The real consumer of ``constants.is_dangerous_api`` is
``xref_analysis.check_for_dangerous_calls`` (called by
``pe_context_extractor`` to populate each function's ``dangerous_calls`` JSON
column). ``xref_analysis`` is IDA-bound at import time, but
``check_for_dangerous_calls`` is a pure function whose only free names are the
``typing`` hints, ``json``, ``debug_print`` and ``constants``. We AST-extract
the *real* function source and run it against the real ``is_dangerous_api`` so
the test exercises the actual shipped code path (not a re-implementation).

This is the test that proves the bug fix changes runtime output: before the
fix, mixed-case dangerous API names shipped in ``dangerous_apis.json`` (e.g.
``CreateMutex``) were NOT flagged by ``check_for_dangerous_calls`` because
``is_dangerous_api`` lowercased the query while the stored set kept the raw
mixed-case keys. After the fix (lowercase the set at load time), those names
ARE flagged.
"""
import ast
import json
import pathlib
from typing import Any, Dict, List, Optional, Set, Tuple

import pytest

from deep_extract import constants

_XREF = pathlib.Path(constants.__file__).resolve().parent / "xref_analysis.py"


def _make_check_for_dangerous_calls() -> "types.FunctionType":
    """AST-extract ``check_for_dangerous_calls`` from xref_analysis.py and bind
    it to stubbed globals (real constants, real json, noop debug_print)."""
    src = _XREF.read_text(encoding="utf-8")
    tree = ast.parse(src)
    fn_node = next(
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.FunctionDef) and n.name == "check_for_dangerous_calls"
    )
    code = compile(
        ast.fix_missing_locations(ast.Module(body=[fn_node], type_ignores=[])),
        "<extracted>",
        "exec",
    )
    import sys, types
    _DEEP = pathlib.Path(constants.__file__).resolve().parent
    if "deep_extract" not in sys.modules:
        pkg = types.ModuleType("deep_extract")
        pkg.__path__ = [str(_DEEP)]
        sys.modules["deep_extract"] = pkg
    # constants is already the isolated copy from conftest.
    ns = {
        "List": List, "Dict": Dict, "Any": Any, "Optional": Optional,
        "Set": Set, "Tuple": Tuple,
        "json": json, "constants": constants,
        "debug_print": lambda *a, **k: None,
    }
    exec(code, ns)
    return ns["check_for_dangerous_calls"]


@pytest.fixture
def check():
    return _make_check_for_dangerous_calls()


def _xrefs(*names):
    return [{"function_name": n} for n in names]


# ---------------------------------------------------------------------------
# Post-fix behavior: mixed-case dangerous calls are flagged
# ---------------------------------------------------------------------------

def test_mixed_case_dangerous_calls_are_flagged(check):
    """Mixed-case entries shipped in dangerous_apis.json are now flagged by the
    active runtime path (they were unreachable before the fix)."""
    out = json.loads(check(_xrefs("CreateMutex", "__imp_CryptEncrypt", "createremotethreadex")))
    assert set(out) == {"CreateMutex", "__imp_CryptEncrypt", "createremotethreadex"}


def test_original_case_preserved_in_output(check):
    """check_for_dangerous_calls appends the original function_name (not
    lowercased) to the result, so callers see the name as it appeared in the
    binary."""
    out = json.loads(check(_xrefs("CreateMutex", "createremotethreadex")))
    assert "CreateMutex" in out  # original mixed case preserved
    assert "createremotethreadex" in out


def test_benign_and_empty_skipped(check):
    out = json.loads(check(_xrefs("somebenignhelper", "", "CreateMutex")))
    assert out == ["CreateMutex"]


def test_duplicates_deduplicated(check):
    out = json.loads(check(_xrefs("CreateMutex", "CreateMutex", "CreateMutex")))
    assert out == ["CreateMutex"]


def test_wpp_prefix_flagged(check):
    out = json.loads(check(_xrefs("WPP_Init_Tracing", "somebenignhelper")))
    assert out == ["WPP_Init_Tracing"]


def test_none_input_returns_empty_list(check):
    """None (non-iterable) raises TypeError inside the loop, which the function
    catches, returning an empty JSON list."""
    assert json.loads(check(None)) == []


def test_empty_input_returns_empty_list(check):
    assert json.loads(check([])) == []


# ---------------------------------------------------------------------------
# Pre-fix vs post-fix: the fix changes runtime output
# ---------------------------------------------------------------------------

def test_pre_fix_would_miss_mixed_case_entries(check, monkeypatch):
    """Simulate the pre-fix set (raw mixed-case, no lowercasing) and confirm the
    mixed-case dangerous calls are NOT flagged -- i.e. the new tests would fail
    without the constants.py fix. Then restore the fixed set and confirm they
    ARE flagged, proving the fix changes runtime output."""
    raw = constants._load_json_data("dangerous_apis.json", default=[])
    pre_fix_set = set(raw)  # raw mixed-case (pre-fix behavior)
    fixed_set = {str(e).strip().lower() for e in raw if str(e).strip()}

    # PRE-FIX: mixed-case entries unreachable.
    monkeypatch.setattr(constants, "DANGEROUS_API_CALLS", pre_fix_set)
    pre = json.loads(check(_xrefs("CreateMutex", "__imp_CryptEncrypt", "createremotethreadex")))
    assert "CreateMutex" not in pre
    assert "__imp_CryptEncrypt" not in pre
    assert "createremotethreadex" in pre  # lowercase entry still matched pre-fix

    # POST-FIX: mixed-case entries now reachable.
    monkeypatch.setattr(constants, "DANGEROUS_API_CALLS", fixed_set)
    post = json.loads(check(_xrefs("CreateMutex", "__imp_CryptEncrypt", "createremotethreadex")))
    assert set(post) == {"CreateMutex", "__imp_CryptEncrypt", "createremotethreadex"}
