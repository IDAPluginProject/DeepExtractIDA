"""Exhaustive edge-case smoke tests for imports_globals_helpers.py (P3, P4).

Goes beyond the core fail-without-fix tests: covers empty/None containers,
missing fields, non-string access types, placeholder-name backfill ordering,
duplicate-EA dedup, invalid hex, and multi-module flattening. All inputs are
synthetic JSON shapes mirroring pe_metadata.py / xref_analysis.py output.
"""
from deep_extract.imports_globals_helpers import flatten_imports_rows, merge_global_access


# ----------------------- flatten_imports_rows -----------------------

def test_flatten_module_with_empty_functions():
    rows = flatten_imports_rows([{"module_name": "a.dll", "functions": []}])
    assert rows == []


def test_flatten_module_with_functions_none():
    rows = flatten_imports_rows([{"module_name": "a.dll", "functions": None}])
    assert rows == []


def test_flatten_skips_non_dict_function_entries():
    data = [{"module_name": "a.dll", "functions": ["notadict", 42, None, {"address": "0x1", "mangled_name": "ok"}]}]
    rows = flatten_imports_rows(data)
    assert len(rows) == 1
    assert rows[0][5] == "ok"  # mangled_name


def test_flatten_import_missing_address_key():
    """An import entry with no 'address' key at all -> iat_ea None."""
    rows = flatten_imports_rows([{"module_name": "a.dll", "functions": [
        {"mangled_name": "NoAddr", "is_delay_loaded": False}]}])
    assert len(rows) == 1
    assert rows[0][7] is None  # iat_ea


def test_flatten_import_empty_string_address():
    rows = flatten_imports_rows([{"module_name": "a.dll", "functions": [
        {"address": "", "mangled_name": "EmptyAddr"}]}])
    assert rows[0][7] is None


def test_flatten_import_non_string_address():
    """A numeric address (not a hex string) is guarded to None, not crashed."""
    rows = flatten_imports_rows([{"module_name": "a.dll", "functions": [
        {"address": 12345, "mangled_name": "IntAddr"}]}])
    assert rows[0][7] is None


def test_flatten_import_missing_function_and_mangled_name():
    rows = flatten_imports_rows([{"module_name": "a.dll", "functions": [
        {"address": "0x10", "is_delay_loaded": False}]}])
    assert rows[0][4] is None  # function_name
    assert rows[0][5] is None  # mangled_name


def test_flatten_duplicate_module_mangled_both_returned():
    """Flatten returns both; dedup is the DB's job (UNIQUE + INSERT OR IGNORE)."""
    data = [{"module_name": "a.dll", "functions": [
        {"address": "0x10", "mangled_name": "Dup", "ordinal": None},
        {"address": "0x14", "mangled_name": "Dup", "ordinal": 2}]}]
    rows = flatten_imports_rows(data)
    assert len(rows) == 2


def test_flatten_multi_module_same_function_name():
    data = [
        {"module_name": "a.dll", "functions": [{"address": "0x10", "mangled_name": "Shared"}]},
        {"module_name": "b.dll", "functions": [{"address": "0x20", "mangled_name": "Shared"}]},
    ]
    rows = flatten_imports_rows(data)
    assert len(rows) == 2
    assert {r[0] for r in rows} == {"a.dll", "b.dll"}


def test_flatten_ordinal_and_api_set_and_sig():
    data = [{"module_name": "api-ms-win-core.dll", "raw_module_name": "api-ms-win-core.dll",
             "is_api_set": True, "functions": [
        {"address": "0x10", "mangled_name": "Api", "ordinal": 7,
         "is_delay_loaded": False, "function_signature_extended": "void Api(void)"}]}]
    rows = flatten_imports_rows(data)
    r = rows[0]
    assert r[0] == "api-ms-win-core.dll" and r[2] is True  # is_api_set
    assert r[6] == 7  # ordinal
    assert r[8] == "void Api(void)"  # signature


def test_flatten_empty_list():
    assert flatten_imports_rows([]) == []


# ----------------------- merge_global_access -----------------------

def test_merge_entry_missing_access_type():
    acc = {}
    merge_global_access(acc, [{"address": "0x1000", "name": "g_a"}])
    assert acc[0x1000]["access_types"] == set()


def test_merge_entry_non_string_access_type():
    acc = {}
    merge_global_access(acc, [{"address": "0x1000", "name": "g_a", "access_type": 1}])
    assert acc[0x1000]["access_types"] == set()


def test_merge_entry_empty_string_access_type():
    acc = {}
    merge_global_access(acc, [{"address": "0x1000", "name": "g_a", "access_type": ""}])
    assert acc[0x1000]["access_types"] == set()


def test_merge_entry_missing_name_falls_back_to_addr():
    acc = {}
    merge_global_access(acc, [{"address": "0x1000", "access_type": "Read"}])
    assert acc[0x1000]["name"] == "0x1000"


def test_merge_entry_none_name_falls_back_to_addr():
    acc = {}
    merge_global_access(acc, [{"address": "0x1000", "name": None, "access_type": "Read"}])
    assert acc[0x1000]["name"] == "0x1000"


def test_merge_same_ea_same_access_type_dedups():
    acc = {}
    merge_global_access(acc, [
        {"address": "0x2000", "name": "g_b", "access_type": "Read"},
        {"address": "0x2000", "name": "g_b", "access_type": "Read"},
    ])
    assert acc[0x2000]["access_types"] == {"Read"}


def test_merge_real_name_retained_against_later_placeholder():
    """A real name seen first must NOT be overwritten by a later hex placeholder."""
    acc = {}
    merge_global_access(acc, [{"address": "0x3000", "name": "g_real", "access_type": "Write"}])
    merge_global_access(acc, [{"address": "0x3000", "name": "0x3000", "access_type": "Read"}])
    assert acc[0x3000]["name"] == "g_real"


def test_merge_placeholder_then_real_backfills():
    acc = {}
    merge_global_access(acc, [{"address": "0x4000", "name": "0x4000", "access_type": "Write"}])
    merge_global_access(acc, [{"address": "0x4000", "name": "g_backfilled", "access_type": "Read"}])
    assert acc[0x4000]["name"] == "g_backfilled"


def test_merge_entry_missing_address_skipped():
    acc = {}
    merge_global_access(acc, [{"name": "g_noaddr", "access_type": "Read"}])
    assert acc == {}


def test_merge_entry_int_address_skipped():
    acc = {}
    merge_global_access(acc, [{"address": 4096, "name": "g_int", "access_type": "Read"}])
    assert acc == {}


def test_merge_entry_invalid_hex_skipped():
    acc = {}
    merge_global_access(acc, [{"address": "0xZZZZ", "name": "g_bad", "access_type": "Read"}])
    assert acc == {}


def test_merge_non_dict_entries_skipped():
    acc = {}
    merge_global_access(acc, ["str", 42, None, {"address": "0x5000", "name": "g_ok", "access_type": "Read"}])
    assert set(acc.keys()) == {0x5000}


def test_merge_accumulates_across_calls():
    acc = {}
    merge_global_access(acc, [{"address": "0x6000", "name": "g_c", "access_type": "Read"}])
    merge_global_access(acc, [{"address": "0x6000", "name": "g_c", "access_type": "Write"}])
    merge_global_access(acc, [{"address": "0x7000", "name": "g_d", "access_type": "Read"}])
    assert acc[0x6000]["access_types"] == {"Read", "Write"}
    assert acc[0x7000]["access_types"] == {"Read"}
