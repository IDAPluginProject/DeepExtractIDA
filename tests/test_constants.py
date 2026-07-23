"""Unit tests for ``deep_extract.constants`` pure helpers.

Covers the IDA-free logic that is otherwise only exercised inside the IDA
plugin: API-set resolution (exact / version-prefix best-fit / fuzzy base /
fallback), API-set map sanitization & loading, import-prefix stripping,
dangerous-API detection, and decompilation-failure sentinel detection.

``resolve_apiset`` reads the module globals ``APISET_MAP`` and
``_APISET_KEYS_SORTED`` (the latter is a precomputed ``sorted(keys)`` used for
binary search). To keep the tests deterministic and independent of the shipped
``apisets.json``, we monkeypatch both globals and recompute the sorted key list.
"""
import json

import pytest

from deep_extract import constants


# ---------------------------------------------------------------------------
# resolve_apiset
# ---------------------------------------------------------------------------

@pytest.fixture
def fake_apiset_map(monkeypatch):
    """Install a small, controlled APISET_MAP + sorted key list."""
    m = {
        "api-ms-win-core-foo-l1-1-0.dll": "kernel32.dll",
        "api-ms-win-core-foo-l1-1-1.dll": "kernel32.dll",
        "api-ms-win-core-bar-l2-1-0.dll": "other.dll",
    }
    monkeypatch.setattr(constants, "APISET_MAP", m)
    monkeypatch.setattr(constants, "_APISET_KEYS_SORTED", sorted(m.keys()))
    return m


def test_resolve_apiset_empty_returns_input():
    assert constants.resolve_apiset("") == ""


def test_resolve_apiset_exact_match(fake_apiset_map):
    # Without .dll and with mixed case -> normalized + .dll appended -> exact hit.
    assert constants.resolve_apiset("api-ms-win-core-foo-l1-1-0") == "kernel32.dll"
    assert constants.resolve_apiset("API-MS-WIN-CORE-FOO-L1-1-1.DLL") == "kernel32.dll"


def test_resolve_apiset_best_fit_version_prefix(fake_apiset_map):
    """Requested version not present -> highest available version prefix wins.

    Requesting l1-1-5: Strategy A shortens the version components until the
    l1-1-* prefix matches, then picks the highest key (l1-1-1).
    """
    assert constants.resolve_apiset("api-ms-win-core-foo-l1-1-5") == "kernel32.dll"


def test_resolve_apiset_fuzzy_base_name_match(fake_apiset_map):
    """No version prefix matches at all -> Strategy B fuzzy '-l' base match."""
    assert constants.resolve_apiset("api-ms-win-core-foo-l9-9-9") == "kernel32.dll"


def test_resolve_apiset_no_match_returns_original(fake_apiset_map):
    """An apiset-shaped name with no mapping returns the original name."""
    name = "api-ms-win-core-baz-l1-1-0"
    assert constants.resolve_apiset(name, log_unresolved=False) == name


def test_resolve_apiset_non_apiset_no_match_returns_original(fake_apiset_map):
    """A plain DLL name that is not an apiset and not in the map passes through."""
    assert constants.resolve_apiset("kernel32.dll", log_unresolved=False) == "kernel32.dll"


def test_resolve_apiset_appends_dll_for_lookup(fake_apiset_map):
    # Exact key in map already ends with .dll; passing without extension still hits.
    assert constants.resolve_apiset("api-ms-win-core-bar-l2-1-0") == "other.dll"


# ---------------------------------------------------------------------------
# _sanitize_apiset_map
# ---------------------------------------------------------------------------

def test_sanitize_normalizes_case_and_appends_dll():
    out = constants._sanitize_apiset_map({"API-MS-FOO-l1-1-0": "KERNEL32.DLL"})
    assert out == {"api-ms-foo-l1-1-0.dll": "kernel32.dll"}


def test_sanitize_skips_self_reference_and_bad_values():
    out = constants._sanitize_apiset_map({
        "x.dll": "x.dll",            # self-reference -> skipped
        "a.dll": "noextension",      # no valid PE ext -> skipped
        "b.dll": "good.sys",         # .sys is valid -> kept
        1: 2,                        # non-string -> skipped
    })
    assert out == {"b.dll": "good.sys"}


def test_sanitize_non_dict_returns_empty():
    assert constants._sanitize_apiset_map(None) == {}
    assert constants._sanitize_apiset_map("nope") == {}


# ---------------------------------------------------------------------------
# _load_apiset_map_from_path (list + dict forms)
# ---------------------------------------------------------------------------

def test_load_apiset_map_list_form(tmp_path):
    raw = [
        {"apiSetName": "api-ms-foo", "hosts": ["kernel32"]},
        {"apiSetName": "api-ms-bar", "hosts": ["  "]},          # whitespace host -> skip
        {"apiSetName": "api-ms-baz", "hosts": []},              # no hosts -> skip
        {"not-a-dict": True},                                    # non-dict -> skip
        {"apiSetName": "api-ms-qux", "hosts": ["rpcrt4.sys"]},  # .sys kept as-is
    ]
    p = tmp_path / "apisets.json"
    p.write_text(json.dumps(raw), encoding="utf-8")
    out = constants._load_apiset_map_from_path(str(p))
    assert out == {
        "api-ms-foo.dll": "kernel32.dll",
        "api-ms-qux.dll": "rpcrt4.sys",
    }


def test_load_apiset_map_dict_form(tmp_path):
    raw = {"Api-Ms-Foo": "KERNEL32.DLL"}
    p = tmp_path / "apisets.json"
    p.write_text(json.dumps(raw), encoding="utf-8")
    out = constants._load_apiset_map_from_path(str(p))
    assert out == {"api-ms-foo.dll": "kernel32.dll"}


def test_load_apiset_map_missing_file_returns_empty(tmp_path):
    assert constants._load_apiset_map_from_path(str(tmp_path / "nope.json")) == {}


def test_load_apiset_map_malformed_json_returns_empty(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("{not json", encoding="utf-8")
    assert constants._load_apiset_map_from_path(str(p)) == {}


# ---------------------------------------------------------------------------
# _strip_import_prefix
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("inp,expected", [
    ("", ""),
    ("__imp_load_foo", "foo"),
    ("__imp_bar", "bar"),
    ("_imp_baz", "baz"),
    ("_o__qux", "qux"),
    ("_o_foo", "foo"),
    ("normal", "normal"),
])
def test_strip_import_prefix(inp, expected):
    assert constants._strip_import_prefix(inp) == expected


# ---------------------------------------------------------------------------
# is_dangerous_api
# ---------------------------------------------------------------------------

def test_is_dangerous_api_empty():
    assert constants.is_dangerous_api("") is False
    assert constants.is_dangerous_api(None) is False


def test_is_dangerous_api_known_exact_lowercase():
    # The shipped dangerous_apis.json stores mostly lowercase names; the query
    # is lowercased before lookup, so lowercase entries match.
    assert constants.is_dangerous_api("createremotethreadex") is True
    assert constants.is_dangerous_api("duplicatetokenex") is True


def test_is_dangerous_api_with_import_prefix():
    # Prefix stripping happens before the (lowercased) set lookup.
    assert constants.is_dangerous_api("__imp_createremotethreadex") is True
    assert constants.is_dangerous_api("_imp_duplicatetokenex") is True


def test_is_dangerous_api_wpp_prefix():
    assert constants.is_dangerous_api("WPP_Init_Tracing") is True


def test_is_dangerous_api_benign():
    assert constants.is_dangerous_api("somebenignhelper") is False


def test_is_dangerous_api_mixed_case_entry_is_reachable():
    """After lowercasing DANGEROUS_API_CALLS at load time, mixed-case data-file
    entries (e.g. 'CreateMutex') are reachable via the lowercased query."""
    assert constants.is_dangerous_api("CreateMutex") is True
    assert constants.is_dangerous_api("CryptEncrypt") is True
    assert constants.is_dangerous_api("initiatesystemshutdowna") is True  # query lowercased -> matches


def test_is_dangerous_api_case_collision_pair_both_reachable():
    """SetFileAttributes/setfileattributes collapse to one lowercase key; both
    casings of the query must match (no information loss from the merge)."""
    assert constants.is_dangerous_api("SetFileAttributes") is True
    assert constants.is_dangerous_api("setfileattributes") is True


def test_dangerous_api_calls_set_is_all_lowercase():
    """Invariant: every key in DANGEROUS_API_CALLS is lowercase, matching the
    lowercased query used by is_dangerous_api."""
    assert all(k == k.lower() for k in constants.DANGEROUS_API_CALLS)


def test_is_dangerous_api_mixed_case_with_import_prefix():
    """Prefix stripping happens before the lowercased set lookup, so a mixed-case
    data-file entry reached via an import prefix (``__imp_`` / ``_imp_``) must
    match after the prefix is stripped and the remainder is lowercased."""
    assert constants.is_dangerous_api("__imp_CreateMutex") is True
    assert constants.is_dangerous_api("_imp_CryptEncrypt") is True


@pytest.mark.parametrize("name", ["CREATEMUTEX", "createMutex", "CrEaTeMuTeX", "CreateMutex"])
def test_is_dangerous_api_case_insensitive(name):
    """The lookup is fully case-insensitive: any casing of a known dangerous API
    must match (the stored set is lowercase and the query is lowercased)."""
    assert constants.is_dangerous_api(name) is True


def test_is_dangerous_api_prefix_only_is_false():
    """A bare import prefix with no real name must not match (strips to empty)."""
    assert constants.is_dangerous_api("__imp_") is False
    assert constants.is_dangerous_api("_imp_") is False


# ---------------------------------------------------------------------------
# is_decompilation_failure
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("code", ["", None, "Decompiler not available",
                                   "Decompiler returned None",
                                   "Decompilation produced empty output",
                                   "Decompilation timed out",
                                   "Decompilation failed: hexrays blew up"])
def test_is_decompilation_failure_true(code):
    assert constants.is_decompilation_failure(code) is True


def test_is_decompilation_failure_real_code():
    assert constants.is_decompilation_failure("int main() { return 0; }") is False


# ---------------------------------------------------------------------------
# SQL filter / match constants stay consistent with the sentinel set
# ---------------------------------------------------------------------------

def test_sql_filter_mentions_every_exact_sentinel():
    for sentinel in constants.DECOMPILATION_FAILURE_EXACT:
        assert sentinel in constants.DECOMPILATION_FAILURE_SQL_FILTER
    assert constants.DECOMPILATION_FAILURE_PREFIX.rstrip(":") in constants.DECOMPILATION_FAILURE_SQL_FILTER


def test_sql_match_mentions_every_exact_sentinel():
    for sentinel in constants.DECOMPILATION_FAILURE_EXACT:
        assert sentinel in constants.DECOMPILATION_FAILURE_SQL_MATCH
    assert constants.DECOMPILATION_FAILURE_PREFIX.rstrip(":") in constants.DECOMPILATION_FAILURE_SQL_MATCH
