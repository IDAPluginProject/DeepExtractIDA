"""End-to-end smoke test of schema.py's full lifecycle entry point
``check_and_validate_schema`` (P5).

Exercises the real on-disk validation/migration flow (not just the
migrate_schema unit) across every realistic DB state a user can hit:
new DB, legacy v1, legacy v2, current v3, force-reanalyze, a future
(v4) version, a missing schema_version table, and a structurally
corrupt v3 DB. Uses tmp_path so each scenario gets a fresh file.
"""
import sqlite3

from deep_extract import schema


_V3_ONLY_FUNCTION_COLS = {"function_end_address", "function_size", "function_flags"}
_V3_ONLY_TABLES = {"imports", "globals"}


def _build_db(path, version, *, drop_v3=True, drop_func_address=False, corrupt=False):
    """Build a complete DB at ``version`` on disk.

    v3 = full expected schema. v2 = expected minus the 3 v3 function cols and
    the imports/globals tables. v1 = v2 minus function_address. ``corrupt``
    omits a required table to simulate a damaged DB.
    """
    conn = sqlite3.connect(str(path))
    conn.execute(
        "CREATE TABLE schema_version (version INTEGER PRIMARY KEY, description TEXT, "
        "applied_timestamp TIMESTAMP, migration_notes TEXT)"
    )
    conn.execute("INSERT INTO schema_version (version, description) VALUES (?, ?)",
                 (version, f"v{version}"))
    drop = set(_V3_ONLY_FUNCTION_COLS) if (drop_v3 and version < 3) else set()
    if drop_func_address and version < 2:
        drop.add("function_address")
    for table_name, cols in schema.get_expected_schema().items():
        if table_name == "schema_version":
            continue
        if corrupt and table_name == "imports":
            continue  # omit imports to corrupt a "v3" DB
        if table_name in _V3_ONLY_TABLES and version < 3:
            continue
        kept = [c for c in cols if not (c.strip().split() and c.strip().split()[0] in drop)]
        conn.execute(f"CREATE TABLE {table_name} ({', '.join(kept)})")
    conn.commit()
    conn.close()


def test_new_database_initializes_to_v3(tmp_path):
    db = tmp_path / "new.db"
    assert not db.exists()
    ok, msg = schema.check_and_validate_schema(str(db))
    assert ok, msg
    assert "New database initialized" in msg
    conn = sqlite3.connect(str(db))
    assert schema.get_current_schema_version(conn) == 3
    conn.close()


def test_v1_db_migrates_to_v3(tmp_path):
    db = tmp_path / "v1.db"
    _build_db(db, 1, drop_func_address=True)
    ok, msg = schema.check_and_validate_schema(str(db))
    assert ok, msg
    conn = sqlite3.connect(str(db))
    assert schema.get_current_schema_version(conn) == 3
    cur = conn.execute("PRAGMA table_info(functions)")
    cols = {r[1] for r in cur.fetchall()}
    assert {"function_address", "function_end_address", "function_size", "function_flags"} <= cols
    conn.close()


def test_v2_db_migrates_to_v3(tmp_path):
    db = tmp_path / "v2.db"
    _build_db(db, 2)
    ok, msg = schema.check_and_validate_schema(str(db))
    assert ok, msg
    conn = sqlite3.connect(str(db))
    assert schema.get_current_schema_version(conn) == 3
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"imports", "globals"} <= tables
    conn.close()


def test_v3_db_validates_clean(tmp_path):
    db = tmp_path / "v3.db"
    _build_db(db, 3)
    ok, msg = schema.check_and_validate_schema(str(db))
    assert ok, msg
    assert "v3" in msg


def test_force_reanalyze_on_v2_reinitializes(tmp_path):
    db = tmp_path / "v2_force.db"
    _build_db(db, 2)
    ok, msg = schema.check_and_validate_schema(str(db), force_reanalyze=True)
    assert ok, msg
    conn = sqlite3.connect(str(db))
    assert schema.get_current_schema_version(conn) == 3
    conn.close()


def test_future_version_db_is_rejected(tmp_path):
    db = tmp_path / "v4.db"
    _build_db(db, 4)
    ok, msg = schema.check_and_validate_schema(str(db))
    assert not ok
    assert "Update extraction_tool" in msg or "version" in msg.lower()


def test_missing_schema_version_without_force_is_rejected(tmp_path):
    db = tmp_path / "noschema.db"
    conn = sqlite3.connect(str(db))
    conn.execute("CREATE TABLE functions (function_id INTEGER PRIMARY KEY)")
    conn.commit()
    conn.close()
    ok, msg = schema.check_and_validate_schema(str(db))
    assert not ok
    assert "force-reanalyze" in msg.lower() or "Schema version missing" in msg


def test_missing_schema_version_with_force_initializes(tmp_path):
    db = tmp_path / "noschema_force.db"
    conn = sqlite3.connect(str(db))
    conn.execute("CREATE TABLE functions (function_id INTEGER PRIMARY KEY)")
    conn.commit()
    conn.close()
    ok, msg = schema.check_and_validate_schema(str(db), force_reanalyze=True)
    assert ok, msg


def test_corrupt_v3_db_is_rejected(tmp_path):
    """A v3-versioned DB missing a required table must fail structure validation."""
    db = tmp_path / "corrupt.db"
    _build_db(db, 3, corrupt=True)  # imports table omitted
    ok, msg = schema.check_and_validate_schema(str(db))
    assert not ok
    assert "structure validation failed" in msg.lower() or "corrupted" in msg.lower()


def test_repeated_validation_is_idempotent(tmp_path):
    db = tmp_path / "idem.db"
    _build_db(db, 2)
    assert schema.check_and_validate_schema(str(db))[0]
    # Second call on the now-v3 DB must still pass (no double-migration issues).
    assert schema.check_and_validate_schema(str(db))[0]
    conn = sqlite3.connect(str(db))
    versions = [r[0] for r in conn.execute("SELECT version FROM schema_version ORDER BY version")]
    assert max(versions) == 3
    conn.close()


def test_pragmas_applied_when_supplied(tmp_path):
    db = tmp_path / "pragma.db"
    _build_db(db, 2)
    ok, msg = schema.check_and_validate_schema(
        str(db), pragmas={"journal_mode": "MEMORY", "busy_timeout_ms": 5000}
    )
    assert ok, msg
