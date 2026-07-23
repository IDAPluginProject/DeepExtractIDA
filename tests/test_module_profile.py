"""Unit tests for ``deep_extract.module_profile`` section builders.

``module_profile`` is fully IDA-free at load time (it imports ``constants``,
``db_connection``, ``cpp_generator`` -- all IDA-free). The pure helpers and the
per-section builders (which take a SQLite cursor / Row) are otherwise only
exercised through the full extraction pipeline writing ``module_profile.json``.

Tests cover:
- Pure helpers: ``_safe_parse_json``, ``_api_matches_any``, ``_categorise_api``,
  ``_long_path``.
- DB-backed builders against an in-memory DB populated with a deterministic
  set of functions + a file_info row: ``_build_identity``, ``_build_scale``,
  ``_build_library_profile``, ``_build_api_profile``, ``_build_complexity_profile``,
  ``_build_security_posture``.
"""
import json
import sqlite3
import sys

import pytest

from deep_extract import module_profile as mp


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------

def test_safe_parse_json_none_and_empty():
    assert mp._safe_parse_json(None) is None
    assert mp._safe_parse_json("") is None


def test_safe_parse_json_valid():
    assert mp._safe_parse_json('{"a": 1}') == {"a": 1}
    assert mp._safe_parse_json('[1, 2]') == [1, 2]


def test_safe_parse_json_invalid():
    assert mp._safe_parse_json("{bad") is None
    assert mp._safe_parse_json("not json") is None


def test_api_matches_any_case_insensitive_prefix():
    assert mp._api_matches_any("CreateProcessW", ("CreateProcess",)) is True
    assert mp._api_matches_any("createprocess", ("CreateProcess",)) is True


def test_api_matches_any_no_match():
    assert mp._api_matches_any("SomeRandomFunc", ("CreateProcess",)) is False


@pytest.mark.parametrize("api,expected", [
    ("AdjustTokenPrivileges", ["security"]),
    ("BCryptGenRandom", ["crypto"]),
    ("CoCreateInstance", ["com"]),
    ("RpcServerListen", ["rpc"]),
    ("RoActivateInstance", ["winrt"]),
    ("CreateNamedPipeW", ["named_pipe"]),
    ("CreateProcessW", ["process"]),
    ("SomeRandomFunc", []),
])
def test_categorise_api(api, expected):
    assert mp._categorise_api(api) == expected


def test_long_path_win32_prefix(tmp_path):
    out = mp._long_path(tmp_path / "x.json")
    s = str(out)
    if sys.platform == "win32":
        assert s.startswith("\\\\?\\")
    else:
        assert s == str((tmp_path / "x.json").resolve())


def test_long_path_idempotent_when_already_prefixed(tmp_path):
    if sys.platform != "win32":
        pytest.skip("win32-only behavior")
    once = mp._long_path(tmp_path / "x.json")
    twice = mp._long_path(once)
    assert str(twice) == str(once)


# ---------------------------------------------------------------------------
# DB fixture
# ---------------------------------------------------------------------------

def _build_db():
    """In-memory DB with the columns the section builders query + sample rows."""
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute(
        "CREATE TABLE functions ("
        " function_id INTEGER PRIMARY KEY, function_name TEXT, mangled_name TEXT,"
        " decompiled_code TEXT, assembly_code TEXT, loop_analysis TEXT,"
        " dangerous_api_calls TEXT, outbound_xrefs TEXT, simple_outbound_xrefs TEXT)"
    )
    cur.execute(
        "CREATE TABLE file_info ("
        " file_name TEXT, file_description TEXT, company_name TEXT,"
        " file_version TEXT, product_version TEXT, exports TEXT, imports TEXT,"
        " security_features TEXT)"
    )

    funcs = [
        # (name, mangled, decompiled, asm, loop, dangerous, outbound, simple_outbound)
        ("sub_1000", "sub_1000", "int sub_1000(){}", "nop",
         json.dumps({"loops": [{"id": 1}, {"id": 2}]}),
         json.dumps(["CreateProcess", "AdjustTokenPrivileges"]),
         json.dumps([{"function_name": "__security_check_cookie"}]), None),
        ("RealFunc", "RealFunc", "int RealFunc(){}", "nop\nnop",
         json.dumps([{"id": 1}]),
         json.dumps(["BCryptGenRandom"]),
         None, json.dumps([{"function_name": "__GSHandlerCheck"}])),
        ("MyClass::Method", "?Method", None, None, None, None, None, None),
        ("std::helper", "std::helper", "Decompiler not available", "nop",
         None, None, None, None),
    ]
    for i, (n, m, dec, asm, loop, dang, ob, sob) in enumerate(funcs, start=1):
        cur.execute(
            "INSERT INTO functions (function_id, function_name, mangled_name,"
            " decompiled_code, assembly_code, loop_analysis, dangerous_api_calls,"
            " outbound_xrefs, simple_outbound_xrefs) VALUES (?,?,?,?,?,?,?,?,?)",
            (i, n, m, dec, asm, loop, dang, ob, sob),
        )

    file_info = {
        "file_name": "app.dll", "file_description": "App", "company_name": "Corp",
        "file_version": "1.0", "product_version": "1.0.0",
        "exports": json.dumps(["e1", "e2", "e3"]),
        "imports": json.dumps([
            {"module_name": "combase.dll", "functions": [{"function_name": "CoCreateInstance"}]},
            {"module_name": "rpcrt4.dll"},
            {"raw_module_name": "api-ms-winrt-something"},
            {"module_name": "x.dll", "functions": [{"function_name": "CreateNamedPipe"}]},
        ]),
        "security_features": json.dumps({"aslr_enabled": True, "dep_enabled": True,
                                          "cfg_enabled": False, "seh_enabled": None}),
    }
    cur.execute(
        "INSERT INTO file_info (" + ", ".join(file_info.keys()) + ") VALUES ("
        + ", ".join("?" * len(file_info)) + ")",
        tuple(file_info.values()),
    )
    conn.commit()
    return conn


@pytest.fixture
def db():
    conn = _build_db()
    yield conn
    conn.close()


def _file_info(conn):
    cur = conn.cursor()
    cur.execute("SELECT * FROM file_info LIMIT 1")
    return cur.fetchone()


# ---------------------------------------------------------------------------
# _build_identity
# ---------------------------------------------------------------------------

def test_build_identity_none_file_info():
    ident = mp._build_identity(None, "app")
    assert ident == {"module_name": "app", "file_name": None, "description": None,
                     "company": None, "version": None}


def test_build_identity_maps_columns(db):
    fi = _file_info(db)
    ident = mp._build_identity(fi, "app")
    assert ident["module_name"] == "app"
    assert ident["file_name"] == "app.dll"
    assert ident["description"] == "App"
    assert ident["company"] == "Corp"
    assert ident["version"] == "1.0"  # file_version present and truthy


def test_build_identity_version_falls_back_to_product(db):
    cur = db.cursor()
    cur.execute("UPDATE file_info SET file_version = NULL")
    db.commit()
    fi = _file_info(db)
    ident = mp._build_identity(fi, "app")
    assert ident["version"] == "1.0.0"  # product_version fallback


# ---------------------------------------------------------------------------
# _build_scale
# ---------------------------------------------------------------------------

def test_build_scale_counts(db):
    cur = db.cursor()
    fi = _file_info(db)
    scale = mp._build_scale(cur, fi)
    assert scale["total_functions"] == 4
    assert scale["named_functions"] == 3          # excludes sub_1000
    assert scale["unnamed_sub_functions"] == 1
    assert scale["with_decompiled"] == 2          # sub_1000, RealFunc (sentinel & NULL excluded)
    assert scale["with_assembly"] == 3            # sub_1000, RealFunc, std::helper
    assert scale["class_count"] == 2              # MyClass + std (std::helper contains '::')
    assert scale["export_count"] == 3            # 3 exports in file_info


def test_build_scale_no_file_info(db):
    cur = db.cursor()
    scale = mp._build_scale(cur, None)
    assert scale["export_count"] == 0


# ---------------------------------------------------------------------------
# _build_library_profile
# ---------------------------------------------------------------------------

def test_build_library_profile(db):
    cur = db.cursor()
    lib = mp._build_library_profile(cur)
    assert lib["app_functions"] == 3
    assert lib["library_functions"] == 1        # std::helper -> STL
    assert lib["noise_ratio"] == 0.25
    assert lib["breakdown"] == {"STL": 1}


def test_build_library_profile_empty(db):
    cur = db.cursor()
    cur.execute("DELETE FROM functions")
    db.commit()
    lib = mp._build_library_profile(cur)
    assert lib["app_functions"] == 0
    assert lib["library_functions"] == 0
    assert lib["noise_ratio"] == 0.0
    assert lib["breakdown"] == {}


# ---------------------------------------------------------------------------
# _build_api_profile
# ---------------------------------------------------------------------------

def test_build_api_profile_aggregation_and_surface(db):
    cur = db.cursor()
    fi = _file_info(db)
    api = mp._build_api_profile(cur, fi)
    assert api["dangerous_api_functions"] == 2   # sub_1000, RealFunc
    assert api["total_dangerous_refs"] == 3      # 2 + 1
    assert api["security_api_count"] == 1        # AdjustTokenPrivileges
    assert api["crypto_api_count"] == 1         # BCryptGenRandom
    assert api["process_api_count"] == 1         # CreateProcess

    surf = api["import_surface"]
    assert surf["com_present"] is True and surf["com_modules"] == ["combase.dll"]
    assert surf["rpc_present"] is True and surf["rpc_modules"] == ["rpcrt4.dll"]
    assert surf["winrt_present"] is True and "api-ms-winrt-something" in surf["winrt_apisets"]
    assert surf["named_pipes_present"] is True and surf["named_pipe_functions"] == ["CreateNamedPipe"]


def test_build_api_profile_no_file_info(db):
    cur = db.cursor()
    api = mp._build_api_profile(cur, None)
    assert api["import_surface"]["com_present"] is False
    assert api["import_surface"]["rpc_modules"] == []


# ---------------------------------------------------------------------------
# _build_complexity_profile
# ---------------------------------------------------------------------------

def test_build_complexity_profile(db):
    cur = db.cursor()
    c = mp._build_complexity_profile(cur)
    assert c["functions_with_loops"] == 2        # sub_1000 (dict form), RealFunc (list form)
    assert c["total_loops"] == 3                # 2 + 1
    # asm line counts: sub_1000=1, RealFunc=2, std::helper=1
    assert c["avg_asm_size"] == 1               # round(4/3) == 1
    assert c["max_asm_size"] == 2
    assert c["functions_over_500_instructions"] == 0


def test_build_complexity_profile_empty(db):
    cur = db.cursor()
    cur.execute("DELETE FROM functions")
    db.commit()
    c = mp._build_complexity_profile(cur)
    assert c["functions_with_loops"] == 0
    assert c["avg_asm_size"] == 0 and c["max_asm_size"] == 0


# ---------------------------------------------------------------------------
# _build_security_posture
# ---------------------------------------------------------------------------

def test_build_security_posture(db):
    cur = db.cursor()
    fi = _file_info(db)
    sec = mp._build_security_posture(cur, fi)
    assert sec["aslr"] is True
    assert sec["dep"] is True
    assert sec["cfg"] is False
    assert sec["seh"] is None
    # 2 of 3 asm functions reference a canary symbol -> 66.7%
    assert sec["canary_coverage_pct"] == 66.7


def test_build_security_posture_no_file_info(db):
    cur = db.cursor()
    sec = mp._build_security_posture(cur, None)
    assert sec["aslr"] is None and sec["dep"] is None
    # canary coverage still computed from functions
    assert sec["canary_coverage_pct"] == 66.7


def test_build_security_posture_no_canary_refs(db):
    cur = db.cursor()
    cur.execute("UPDATE functions SET outbound_xrefs = NULL, simple_outbound_xrefs = NULL")
    db.commit()
    sec = mp._build_security_posture(cur, _file_info(db))
    assert sec["canary_coverage_pct"] == 0.0
