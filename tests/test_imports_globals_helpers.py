"""Unit tests for the structured imports/globals helpers (P3, P4).

``flatten_imports_rows`` guards delay-load imports (``address: None``) and
json_safety truncation markers (trailing ``_truncated`` dict). Without the
iat_ea guard, ``int(None, 16)`` raises TypeError on every delay-load import;
without the _truncated skip, the flatten loop raises KeyError on the missing
``functions`` key. ``merge_global_access`` deduplicates by EA and produces
deterministic sorted access_types.
"""
from deep_extract.imports_globals_helpers import flatten_imports_rows, merge_global_access


def test_flatten_normal_imports():
    data = [{
        "module_name": "kernel32.dll",
        "raw_module_name": "kernel32.dll",
        "is_api_set": False,
        "functions": [
            {"address": "0x140010000", "mangled_name": "CreateFileW",
             "function_name": "CreateFileW", "ordinal": None,
             "is_delay_loaded": False, "function_signature_extended": "..."},
        ],
    }]
    rows = flatten_imports_rows(data)
    assert len(rows) == 1
    (mod, raw_mod, is_api, is_delay, fn, mangled, ord_, iat, sig) = rows[0]
    assert mod == "kernel32.dll" and raw_mod == "kernel32.dll"
    assert is_api is False and is_delay is False
    assert fn == "CreateFileW" and mangled == "CreateFileW"
    assert iat == 0x140010000
    assert ord_ is None


def test_flatten_delay_load_imports_have_null_iat_ea():
    """Guard for delay-load ``address: None`` (pe_metadata.py:1609).

    Without the guard this raises TypeError; with it, iat_ea is NULL.
    """
    data = [{
        "module_name": "d3d11.dll", "raw_module_name": "d3d11.dll",
        "is_api_set": False,
        "functions": [
            {"address": None, "mangled_name": "D3D11CreateDevice",
             "function_name": "D3D11CreateDevice", "ordinal": 5,
             "is_delay_loaded": True, "function_signature_extended": None},
        ],
    }]
    rows = flatten_imports_rows(data)
    assert len(rows) == 1
    iat = rows[0][7]
    assert iat is None, "delay-load imports must yield NULL iat_ea"
    assert rows[0][3] is True  # is_delay_loaded


def test_flatten_skips_truncated_marker():
    """A trailing json_safety _truncated dict must not yield bogus import rows.

    json_safety.py:273-277 appends a trailing ``{'_truncated': True, ...}`` dict
    to lists exceeding max_list_items (imports use 1000). This test pins the
    contract that such a non-module marker produces zero rows (module_name
    would otherwise be NULL). The early ``isinstance(mod, dict) and
    'functions' in mod`` guard makes the skip explicit; even without it the
    downstream ``.get('functions', [])`` defaults to an empty list, so this
    test guards the *behavior* (no NULL-module rows), not a KeyError crash.
    """
    data = [
        {"module_name": "a.dll", "functions": []},
        {"_truncated": True, "original_count": 1001, "shown_count": 1000},
    ]
    rows = flatten_imports_rows(data)
    assert rows == []


def test_flatten_non_list_returns_empty():
    assert flatten_imports_rows(None) == []
    assert flatten_imports_rows("not a list") == []


def test_flatten_skips_non_dict_module_entries():
    data = ["oops", 42, {"module_name": "b.dll", "functions": [
        {"address": "0x10", "mangled_name": "X", "is_delay_loaded": False}]}]
    rows = flatten_imports_rows(data)
    assert len(rows) == 1
    assert rows[0][0] == "b.dll"


def test_merge_global_access_dedups_by_ea():
    acc = {}
    merge_global_access(acc, [
        {"address": "0x140020000", "name": "g_counter", "access_type": "Read"},
        {"address": "0x140020000", "name": "g_counter", "access_type": "Write"},
    ])
    assert set(acc.keys()) == {0x140020000}
    slot = acc[0x140020000]
    assert slot["name"] == "g_counter"
    assert slot["access_types"] == {"Read", "Write"}


def test_merge_global_access_parses_hex_and_skips_invalid():
    acc = {}
    merge_global_access(acc, [
        {"address": "0x140030000", "name": "g_a", "access_type": "Read"},
        {"address": "not-hex", "name": "g_bad", "access_type": "Read"},
        {"address": None, "name": "g_bad2", "access_type": "Read"},
    ])
    assert set(acc.keys()) == {0x140030000}


def test_merge_global_access_name_backfill_from_non_placeholder():
    acc = {}
    # First sighting is a hex placeholder name.
    merge_global_access(acc, [{"address": "0x140040000", "name": "0x140040000", "access_type": "Write"}])
    # Second sighting provides a real name -> backfill.
    merge_global_access(acc, [{"address": "0x140040000", "name": "g_real", "access_type": "Read"}])
    assert acc[0x140040000]["name"] == "g_real"
    assert acc[0x140040000]["access_types"] == {"Read", "Write"}


def test_merge_global_access_non_list_is_noop():
    acc = {}
    merge_global_access(acc, None)
    merge_global_access(acc, "not a list")
    assert acc == {}
