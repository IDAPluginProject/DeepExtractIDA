"""Unit tests for ``deep_extract.asm_generator.AsmGenerator`` formatting helpers.

The sibling ``test_asm_generator_address_smoke.py`` covers the bonus address/ID
fix in the header & index builders. This file covers the *other* pure logic in
``asm_generator`` that is otherwise only reached through the full pipeline:

- ``_categorize_functions``: library-first split, ``::`` class-method regex,
  and skipping functions with no assembly.
- ``_format_xrefs`` / ``_format_strings`` / ``_format_dangerous_apis``: JSON-or-
  list parsing, module/id/name formatting, length truncation + ``... (+N more)``
  suffixes, and graceful handling of garbage input.
- ``_estimate_lines``: fixed header budget + newline count + trailing line.
- ``_split_into_groups``: line-budget grouping that splits when the cumulative
  estimate exceeds ``ASM_GROUP_TARGET_LINES``.
"""
import json
import pathlib

import pytest

from deep_extract.asm_generator import AsmGenerator


@pytest.fixture
def gen(tmp_path):
    return AsmGenerator(tmp_path, "mod.dll")


# ---------------------------------------------------------------------------
# _categorize_functions
# ---------------------------------------------------------------------------

def test_categorize_library_detected_first(gen):
    """A name matching a library pattern goes to library even if it has '::'."""
    funcs = [{"function_name": "std::vector::push", "mangled_name": "std::vec",
              "assembly_code": "nop", "function_id": 1}]
    cm, st, lib = gen._categorize_functions(funcs)
    assert cm == {} and st == []
    assert len(lib) == 1
    assert lib[0]["_library_tag"] == "STL"


def test_categorize_class_method_regex(gen):
    funcs = [{"function_name": "Foo::Bar", "mangled_name": "?Bar",
              "assembly_code": "nop", "function_id": 2}]
    cm, st, lib = gen._categorize_functions(funcs)
    assert list(cm.keys()) == ["Foo"]
    assert st == [] and lib == []


def test_categorize_standalone(gen):
    funcs = [{"function_name": "Plain", "mangled_name": "Plain",
              "assembly_code": "nop", "function_id": 3}]
    cm, st, lib = gen._categorize_functions(funcs)
    assert cm == {} and lib == []
    assert [f["function_name"] for f in st] == ["Plain"]


def test_categorize_skips_functions_without_assembly(gen):
    funcs = [
        {"function_name": "NoAsm", "mangled_name": "NoAsm", "assembly_code": None, "function_id": 4},
        {"function_name": "EmptyAsm", "mangled_name": "EmptyAsm", "assembly_code": "", "function_id": 5},
        {"function_name": "HasAsm", "mangled_name": "HasAsm", "assembly_code": "nop", "function_id": 6},
    ]
    cm, st, lib = gen._categorize_functions(funcs)
    assert [f["function_name"] for f in st] == ["HasAsm"]
    assert cm == {} and lib == []


# ---------------------------------------------------------------------------
# _format_xrefs
# ---------------------------------------------------------------------------

def test_format_xrefs_empty():
    assert AsmGenerator._format_xrefs(None) == ""
    assert AsmGenerator._format_xrefs("") == ""
    assert AsmGenerator._format_xrefs("[]") == ""


def test_format_xrefs_module_present():
    out = AsmGenerator._format_xrefs([{"function_name": "a", "module_name": "kernel32.dll"}])
    assert out == "a [kernel32.dll]"


def test_format_xrefs_internal_module_uses_id():
    out = AsmGenerator._format_xrefs([{"function_name": "a", "module_name": "internal", "function_id": 5}])
    assert out == "a (id:5)"


def test_format_xrefs_plain_name():
    assert AsmGenerator._format_xrefs([{"function_name": "a"}]) == "a"


def test_format_xrefs_accepts_json_string():
    out = AsmGenerator._format_xrefs(json.dumps([{"function_name": "a"}]))
    assert out == "a"


def test_format_xrefs_bad_json_returns_empty():
    assert AsmGenerator._format_xrefs("{bad") == ""


def test_format_xrefs_non_list_returns_empty():
    assert AsmGenerator._format_xrefs({"not": "a list"}) == ""


def test_format_xrefs_truncates_at_twenty_with_suffix():
    out = AsmGenerator._format_xrefs([{"function_name": f"f{i}"} for i in range(25)])
    assert out.endswith(" ... (+5 more)")
    assert out.count(", ") == 19  # 20 items joined by 19 commas


# ---------------------------------------------------------------------------
# _format_strings
# ---------------------------------------------------------------------------

def test_format_strings_empty():
    assert AsmGenerator._format_strings(None) == ""


def test_format_strings_dict_value():
    assert AsmGenerator._format_strings([{"value": "hello"}]) == '"hello"'


def test_format_strings_plain_string():
    assert AsmGenerator._format_strings(["hi"]) == '"hi"'


def test_format_strings_truncates_long_value_at_sixty():
    out = AsmGenerator._format_strings([{"value": "x" * 70}])
    assert out == '"' + "x" * 60 + '..."'


def test_format_strings_truncates_at_ten_with_suffix():
    out = AsmGenerator._format_strings([{"value": str(i)} for i in range(12)])
    assert out.endswith(" ... (+2 more)")
    assert out.count(", ") == 9  # 10 items joined by 9 commas


# ---------------------------------------------------------------------------
# _format_dangerous_apis
# ---------------------------------------------------------------------------

def test_format_dangerous_apis_empty():
    assert AsmGenerator._format_dangerous_apis(None) == ""
    assert AsmGenerator._format_dangerous_apis("") == ""


def test_format_dangerous_apis_dict_entries():
    assert AsmGenerator._format_dangerous_apis([{"name": "CreateMutex"}]) == "CreateMutex"


def test_format_dangerous_apis_plain_strings():
    assert AsmGenerator._format_dangerous_apis(["CreateMutex"]) == "CreateMutex"


def test_format_dangerous_apis_truncates_at_fifteen():
    out = AsmGenerator._format_dangerous_apis([str(i) for i in range(20)])
    assert out == ", ".join(str(i) for i in range(15))


def test_format_dangerous_apis_non_list_returns_empty():
    assert AsmGenerator._format_dangerous_apis({"a": 1}) == ""


# ---------------------------------------------------------------------------
# _estimate_lines
# ---------------------------------------------------------------------------

def test_estimate_lines_empty_assembly():
    assert AsmGenerator._estimate_lines({"assembly_code": None}) == 13  # 12 header + 0 + 1


def test_estimate_lines_counts_newlines():
    # "a\nb\nc" has 2 newlines -> 12 + 2 + 1 = 15
    assert AsmGenerator._estimate_lines({"assembly_code": "a\nb\nc"}) == 15


# ---------------------------------------------------------------------------
# _split_into_groups
# ---------------------------------------------------------------------------

def test_split_into_groups_single_group_under_budget(gen):
    funcs = [{"assembly_code": "x"} for _ in range(3)]
    groups = gen._split_into_groups(funcs)
    assert len(groups) == 1
    assert len(groups[0]) == 3


def test_split_into_groups_splits_when_over_budget(gen):
    # Each tiny func estimates to 13 lines; 200 funcs ~ 2600 lines > 2500 budget.
    funcs = [{"assembly_code": "x"} for _ in range(200)]
    groups = gen._split_into_groups(funcs)
    assert len(groups) >= 2
    # All functions are preserved across groups
    assert sum(len(g) for g in groups) == 200
    # No group exceeds the target budget (in line estimates)
    for g in groups:
        est = sum(AsmGenerator._estimate_lines(f) for f in g)
        assert est <= gen.ASM_GROUP_TARGET_LINES or len(g) == 1


def test_split_into_groups_huge_single_function_stays_one_group(gen):
    # A single function larger than the budget cannot be split further.
    big = [{"assembly_code": "x\n" * 3000}]
    groups = gen._split_into_groups(big)
    assert len(groups) == 1
