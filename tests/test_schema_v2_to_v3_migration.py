"""Unit test for the v2 -> v3 schema migration (P5).

Fails without ``_migrate_v2_to_v3`` (the (2,3) migration key is absent so
``migrate_schema`` returns False and the assertions below fail); passes with
it. Also exercises idempotency, sequential v1->v2->v3 migration, and
post-migration structure validation.
"""
import sqlite3

from deep_extract import schema


_V3_ONLY_FUNCTION_COLS = {"function_end_address", "function_size", "function_flags"}
_V3_ONLY_TABLES = {"imports", "globals"}


def _make_v2_db() -> sqlite3.Connection:
    """Build a realistic v2 DB from get_expected_schema() minus v3 additions.

    v2 = expected schema with the three new function columns removed and the
    imports/globals tables dropped. This mirrors what a real v2 database
    looks like, so post-migration structure validation can succeed.
    """
    conn = sqlite3.connect(":memory:")
    conn.execute(
        "CREATE TABLE schema_version (version INTEGER PRIMARY KEY, description TEXT, "
        "applied_timestamp TIMESTAMP, migration_notes TEXT)"
    )
    conn.execute("INSERT INTO schema_version (version, description) VALUES (2, 'v2')")
    for table_name, cols in schema.get_expected_schema().items():
        if table_name == "schema_version" or table_name in _V3_ONLY_TABLES:
            continue
        kept = []
        for col_def in cols:
            parts = col_def.strip().split()
            if parts and parts[0] in _V3_ONLY_FUNCTION_COLS:
                continue
            kept.append(col_def)
        conn.execute(f"CREATE TABLE {table_name} ({', '.join(kept)})")
    return conn


def _columns(conn, table):
    cur = conn.execute(f"PRAGMA table_info({table})")
    return {row[1] for row in cur.fetchall()}


def _tables(conn):
    cur = conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
    return {row[0] for row in cur.fetchall()}


def test_v2_to_v3_migration_adds_columns_and_tables():
    conn = _make_v2_db()
    assert schema.get_current_schema_version(conn) == 2

    ok = schema.migrate_schema(conn, 2, 3)
    assert ok, "migrate_schema v2->v3 must succeed"
    assert schema.get_current_schema_version(conn) == 3

    cols = _columns(conn, "functions")
    assert "function_end_address" in cols
    assert "function_size" in cols
    assert "function_flags" in cols

    tables = _tables(conn)
    assert "imports" in tables
    assert "globals" in tables


def test_migration_is_idempotent():
    conn = _make_v2_db()
    assert schema.migrate_schema(conn, 2, 3)
    # Second run must not raise even though columns/tables already exist.
    assert schema.migrate_schema(conn, 2, 3)
    assert schema.get_current_schema_version(conn) == 3


def test_indices_created():
    conn = _make_v2_db()
    schema.migrate_schema(conn, 2, 3)
    idx = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='index'")}
    assert "idx_imports_func_name" in idx
    assert "idx_imports_module" in idx
    assert "idx_globals_name" in idx


def test_sequential_v1_to_v3_migration():
    conn = sqlite3.connect(":memory:")
    conn.execute(
        "CREATE TABLE schema_version (version INTEGER PRIMARY KEY, description TEXT, "
        "applied_timestamp TIMESTAMP, migration_notes TEXT)"
    )
    conn.execute("INSERT INTO schema_version (version, description) VALUES (1, 'v1')")
    v1_drop = _V3_ONLY_FUNCTION_COLS | {"function_address"}
    for table_name, cols in schema.get_expected_schema().items():
        if table_name == "schema_version" or table_name in _V3_ONLY_TABLES:
            continue
        kept = [c for c in cols if not (c.strip().split() and c.strip().split()[0] in v1_drop)]
        conn.execute(f"CREATE TABLE {table_name} ({', '.join(kept)})")
    assert schema.migrate_schema(conn, 1, 3)
    assert schema.get_current_schema_version(conn) == 3
    cols = _columns(conn, "functions")
    assert {"function_address", "function_end_address", "function_size", "function_flags"} <= cols


def test_structure_validation_passes_after_migration():
    conn = _make_v2_db()
    schema.migrate_schema(conn, 2, 3)
    ok, errors = schema.validate_schema_structure(conn)
    assert ok, f"structure validation must pass after v3 migration: {errors}"


def test_current_schema_version_is_three():
    assert schema.CURRENT_SCHEMA_VERSION == 3
