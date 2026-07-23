"""Isolation tests for ``deep_extract.extractor_core.load_dangerous_api_calls``.

``extractor_core`` is IDA-bound at import time (it re-exports from
``pe_metadata``/``loop_analysis``/etc. which import the ``ida_*`` API), so it
cannot be imported outside IDA. ``load_dangerous_api_calls`` itself is pure
Python with a small set of free names (``get_script_dir``, ``debug_print``,
``constants``, ``os``, ``json``, ``_DANGEROUS_API_CACHE``, and the ``List``
type hint). We AST-extract the *real* function source from ``extractor_core.py``,
compile it, and exec it into a namespace with stubs for those free names. This
exercises the actual shipped code (not a re-implementation) in isolation.

The function was changed to lowercase+strip its output in all three branches
(JSON, text, fallback) so that it stays consistent with the now-lowercase
``constants.DANGEROUS_API_CALLS`` set and with the lowercased query used by
``is_dangerous_api``. These tests pin that normalization on every branch.
"""
import ast
import json
import pathlib
from typing import List

import pytest

from deep_extract import constants

_EXTRACTOR_CORE = (
    pathlib.Path(constants.__file__).resolve().parent / "extractor_core.py"
)


def _make_func(script_dir: pathlib.Path, cache: dict):
    src = _EXTRACTOR_CORE.read_text(encoding="utf-8")
    tree = ast.parse(src)
    fn_node = next(
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.FunctionDef) and n.name == "load_dangerous_api_calls"
    )
    mod = ast.Module(body=[fn_node], type_ignores=[])
    code = compile(ast.fix_missing_locations(mod), "<extracted>", "exec")

    ns: dict = {
        "List": List,
        "get_script_dir": lambda: str(script_dir),
        "debug_print": lambda *a, **k: None,
        "constants": constants,
        "__os_module": __import__("os"),
        "__json_module": __import__("json"),
    }
    ns["os"] = ns["__os_module"]
    ns["json"] = ns["__json_module"]
    ns["_DANGEROUS_API_CACHE"] = cache
    exec(code, ns)
    return ns["load_dangerous_api_calls"]


@pytest.fixture
def make_func(tmp_path):
    """Factory: build an isolated load_dangerous_api_calls bound to tmp_path as
    its script dir, with a fresh cache each call."""
    def _factory(script_dir=None, cache=None):
        return _make_func(script_dir or tmp_path, cache if cache is not None else {})
    return _factory


# ---------------------------------------------------------------------------
# JSON branch (.json file, list payload)
# ---------------------------------------------------------------------------

def test_json_branch_lowercases_and_strips(make_func, tmp_path):
    (tmp_path / "apis.json").write_text(
        json.dumps(["CreateMutex", "  CryptEncrypt  ", "initiatesystemshutdowna"]),
        encoding="utf-8",
    )
    func = make_func()
    out = func("apis.json")
    assert out == ["createmutex", "cryptencrypt", "initiatesystemshutdowna"]
    assert all(s == s.strip().lower() for s in out)


def test_json_branch_filters_empty_and_whitespace_only(make_func, tmp_path):
    (tmp_path / "apis.json").write_text(
        json.dumps(["CreateMutex", "   ", "", "cryptencrypt"]),
        encoding="utf-8",
    )
    func = make_func()
    out = func("apis.json")
    assert out == ["createmutex", "cryptencrypt"]


def test_json_branch_coerces_non_string_entries(make_func, tmp_path):
    (tmp_path / "apis.json").write_text(json.dumps([123, True, "CreateMutex"]), encoding="utf-8")
    func = make_func()
    out = func("apis.json")
    # 123 -> "123", True -> "true", "CreateMutex" -> "createmutex"
    assert out == ["123", "true", "createmutex"]


# ---------------------------------------------------------------------------
# Text branch (non-.json file)
# ---------------------------------------------------------------------------

def test_text_branch_lowercases_and_strips(make_func, tmp_path):
    (tmp_path / "apis.txt").write_text(
        "CreateMutex\n  CryptEncrypt  \ninitiatesystemshutdowna\n\n",
        encoding="utf-8",
    )
    func = make_func()
    out = func("apis.txt")
    assert out == ["createmutex", "cryptencrypt", "initiatesystemshutdowna"]


def test_text_branch_filters_blank_lines(make_func, tmp_path):
    (tmp_path / "apis.lst").write_text("CreateMutex\n\n   \ncryptencrypt\n", encoding="utf-8")
    func = make_func()
    out = func("apis.lst")
    assert out == ["createmutex", "cryptencrypt"]


# ---------------------------------------------------------------------------
# Fallback paths (file missing / invalid JSON / non-list JSON)
# ---------------------------------------------------------------------------

def test_missing_file_falls_back_to_sorted_lowercase_set(make_func):
    func = make_func()
    out = func("does-not-exist.json")
    assert out == sorted(constants.DANGEROUS_API_CALLS)
    assert all(s == s.lower() for s in out)


def test_invalid_json_falls_back_to_sorted_set(make_func, tmp_path):
    (tmp_path / "broken.json").write_text("{not valid json", encoding="utf-8")
    func = make_func()
    out = func("broken.json")
    assert out == sorted(constants.DANGEROUS_API_CALLS)


def test_non_list_json_falls_back_to_sorted_set(make_func, tmp_path):
    # A JSON object (not a list) must NOT be accepted; falls back.
    (tmp_path / "obj.json").write_text(json.dumps({"CreateMutex": 1}), encoding="utf-8")
    func = make_func()
    out = func("obj.json")
    assert out == sorted(constants.DANGEROUS_API_CALLS)


def test_empty_json_list_returns_empty(make_func, tmp_path):
    (tmp_path / "empty.json").write_text("[]", encoding="utf-8")
    func = make_func()
    out = func("empty.json")
    assert out == []


# ---------------------------------------------------------------------------
# Caching
# ---------------------------------------------------------------------------

def test_caching_returns_equal_list_and_populates_cache(make_func, tmp_path):
    (tmp_path / "apis.json").write_text(json.dumps(["CreateMutex", "cryptencrypt"]), encoding="utf-8")
    cache = {}
    func = make_func(cache=cache)
    first = func("apis.json")
    second = func("apis.json")
    assert first == second == ["createmutex", "cryptencrypt"]
    assert "apis.json" in cache


def test_cache_hit_does_not_reread_file(make_func, tmp_path):
    """Once cached, a second call must return the cached list even if the file
    on disk changes (the cache short-circuits before opening the file)."""
    p = tmp_path / "apis.json"
    p.write_text(json.dumps(["CreateMutex"]), encoding="utf-8")
    cache = {}
    func = make_func(cache=cache)
    first = func("apis.json")
    # Mutate the file after caching.
    p.write_text(json.dumps(["SomethingElse"]), encoding="utf-8")
    second = func("apis.json")
    assert first == second == ["createmutex"]


# ---------------------------------------------------------------------------
# Consistency with the canonical set (real shipped data file)
# ---------------------------------------------------------------------------

def test_real_dangerous_apis_json_matches_constants_set():
    """Loading the shipped deep_extract/dangerous_apis.json through the real
    function yields exactly the canonical lowercase set."""
    deep_dir = pathlib.Path(constants.__file__).resolve().parent
    func = _make_func(deep_dir, {})
    out = func("dangerous_apis.json")
    assert set(out) == constants.DANGEROUS_API_CALLS
    assert all(s == s.strip().lower() for s in out)
    # 486 raw entries -> 484 unique after lowercasing (2 case-collision pairs).
    assert len(out) == 484


def test_fallback_equals_sorted_constants_set_lowercase():
    """The fallback branch returns sorted(constants.DANGEROUS_API_CALLS), which is
    now all-lowercase; this keeps the legacy wrapper consistent with the set."""
    deep_dir = pathlib.Path(constants.__file__).resolve().parent
    func = _make_func(deep_dir, {})
    out = func("nonexistent-file-xyz.json")
    assert out == sorted(constants.DANGEROUS_API_CALLS)
    assert all(s == s.lower() for s in out)
