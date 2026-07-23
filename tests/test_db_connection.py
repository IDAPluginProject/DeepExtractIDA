"""Unit tests for ``deep_extract.db_connection``.

``db_connection`` is fully IDA-free and is the single entry point every module
uses to open SQLite connections, so its PRAGMA sanitization (whitelist + int
coercion with fallback) must be airtight. Tests cover:

- ``normalize_sqlite_pragmas``: default merge, whitelist enforcement for
  journal_mode / synchronous / temp_store, case normalization, int coercion
  for cache_size / busy_timeout_ms with fallback to defaults on garbage input.
- ``apply_sqlite_pragmas`` / ``connect_sqlite``: real on-disk DB (tmp_path so
  WAL can actually be set), verifying the PRAGMAs land and that overrides win.
"""
import sqlite3

import pytest

from deep_extract import db_connection as dbc


# ---------------------------------------------------------------------------
# normalize_sqlite_pragmas
# ---------------------------------------------------------------------------

def test_normalize_no_args_returns_defaults():
    p = dbc.normalize_sqlite_pragmas()
    assert p == dbc.DEFAULT_SQLITE_PRAGMAS
    # returns a copy, not the module global
    p["journal_mode"] = "OFF"
    assert dbc.DEFAULT_SQLITE_PRAGMAS["journal_mode"] == "WAL"


def test_normalize_none_returns_defaults():
    assert dbc.normalize_sqlite_pragmas(None) == dbc.DEFAULT_SQLITE_PRAGMAS


def test_normalize_merges_overrides():
    p = dbc.normalize_sqlite_pragmas({"busy_timeout_ms": 5000, "cache_size": -1000})
    assert p["busy_timeout_ms"] == 5000
    assert p["cache_size"] == -1000
    # untouched keys keep defaults
    assert p["journal_mode"] == "WAL"


@pytest.mark.parametrize("mode", ["wal", "WAL", "delete", "DELETE", "truncate",
                                   "persist", "memory", "off"])
def test_normalize_journal_mode_whitelist(mode):
    assert dbc.normalize_sqlite_pragmas({"journal_mode": mode})["journal_mode"] == mode.upper()


def test_normalize_journal_mode_invalid_falls_back():
    assert dbc.normalize_sqlite_pragmas({"journal_mode": "WAL2"})["journal_mode"] == "WAL"
    assert dbc.normalize_sqlite_pragmas({"journal_mode": None})["journal_mode"] == "WAL"


@pytest.mark.parametrize("syn", ["OFF", "NORMAL", "FULL", "EXTRA"])
def test_normalize_synchronous_whitelist(syn):
    assert dbc.normalize_sqlite_pragmas({"synchronous": syn})["synchronous"] == syn


def test_normalize_synchronous_invalid_falls_back():
    assert dbc.normalize_sqlite_pragmas({"synchronous": "DANGEROUS"})["synchronous"] == "NORMAL"
    assert dbc.normalize_sqlite_pragmas({"synchronous": None})["synchronous"] == "NORMAL"


@pytest.mark.parametrize("ts", ["DEFAULT", "FILE", "MEMORY"])
def test_normalize_temp_store_whitelist(ts):
    assert dbc.normalize_sqlite_pragmas({"temp_store": ts})["temp_store"] == ts


def test_normalize_temp_store_invalid_falls_back():
    assert dbc.normalize_sqlite_pragmas({"temp_store": "CLOUD"})["temp_store"] == "MEMORY"


def test_normalize_cache_size_int_coercion():
    assert dbc.normalize_sqlite_pragmas({"cache_size": "1234"})["cache_size"] == 1234


def test_normalize_cache_size_garbage_falls_back():
    assert dbc.normalize_sqlite_pragmas({"cache_size": "abc"})["cache_size"] == dbc.DEFAULT_SQLITE_PRAGMAS["cache_size"]
    assert dbc.normalize_sqlite_pragmas({"cache_size": None})["cache_size"] == dbc.DEFAULT_SQLITE_PRAGMAS["cache_size"]


def test_normalize_busy_timeout_int_coercion():
    assert dbc.normalize_sqlite_pragmas({"busy_timeout_ms": "7000"})["busy_timeout_ms"] == 7000


def test_normalize_busy_timeout_garbage_falls_back():
    assert dbc.normalize_sqlite_pragmas({"busy_timeout_ms": "abc"})["busy_timeout_ms"] == dbc.DEFAULT_SQLITE_PRAGMAS["busy_timeout_ms"]


# ---------------------------------------------------------------------------
# apply_sqlite_pragmas / connect_sqlite (real on-disk DB)
# ---------------------------------------------------------------------------

def test_apply_sqlite_pragmas_lands_on_connection(tmp_path):
    db = tmp_path / "x.db"
    conn = sqlite3.connect(str(db))
    try:
        dbc.apply_sqlite_pragmas(conn, {"busy_timeout_ms": 12345, "cache_size": -500})
        bt = conn.execute("PRAGMA busy_timeout").fetchone()[0]
        cs = conn.execute("PRAGMA cache_size").fetchone()[0]
        jm = conn.execute("PRAGMA journal_mode").fetchone()[0]
        assert bt == 12345
        assert cs == -500
        assert str(jm).lower() == "wal"
    finally:
        conn.close()


def test_connect_sqlite_returns_configured_connection(tmp_path):
    db = tmp_path / "y.db"
    conn = dbc.connect_sqlite(str(db))
    try:
        assert conn.isolation_level == "IMMEDIATE"
        bt = conn.execute("PRAGMA busy_timeout").fetchone()[0]
        assert bt == dbc.DEFAULT_SQLITE_PRAGMAS["busy_timeout_ms"]
        assert str(conn.execute("PRAGMA journal_mode").fetchone()[0]).lower() == "wal"
    finally:
        conn.close()


def test_connect_sqlite_custom_pragmas_override(tmp_path):
    db = tmp_path / "z.db"
    conn = dbc.connect_sqlite(str(db), pragmas={"busy_timeout_ms": 999, "synchronous": "OFF"})
    try:
        assert conn.execute("PRAGMA busy_timeout").fetchone()[0] == 999
        # synchronous OFF == 0
        assert conn.execute("PRAGMA synchronous").fetchone()[0] == 0
    finally:
        conn.close()
