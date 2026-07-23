"""SQL validity + arity smoke test for pe_context_extractor.py (P1-P4).

The module cannot be imported outside IDA (top-level ida_auto import), so this
test parses the SOURCE FILE with ``ast`` to extract every SQL string passed to
``cursor.execute`` / ``cursor.executemany`` / ``conn.execute``, then:

1. Executes all DDL (CREATE TABLE/INDEX, DROP) in SOURCE LINE ORDER against an
   in-memory SQLite DB -> confirms the actual SQL is valid and builds the v3
   schema. (Source order matters: the force_reanalyze DROPs precede the CREATEs
   in the file, so DROP-then-CREATE leaves all tables present. ast.walk does
   NOT preserve source order, so we sort by node.lineno.)
2. Executes all parameterless DELETEs (after the schema is built) -> they run.
3. For the v3 INSERTs (functions/imports/globals), parses the column list and
   the placeholder list and asserts column-count == placeholder-count (catches
   the arity-mismatch bug class that py_compile cannot detect). Scoped to v3
   tables because other legacy INSERTs mix literal values (CURRENT_TIMESTAMP,
   NULL) with ``?`` placeholders, which a naive placeholder count would
   mis-report.
4. Cross-checks the imports INSERT arity (9) against flatten_imports_rows tuple
   arity, the globals INSERT arity (6), and the functions INSERT named
   placeholders against the function record's insertable keys (record keys
   minus the _raw_* popped keys), extracted from _process_single_function's
   return dict via AST.
"""
import ast
import pathlib
import re
import sqlite3

from deep_extract import schema
from deep_extract.imports_globals_helpers import flatten_imports_rows

_SRC = pathlib.Path(__file__).resolve().parent.parent / "deep_extract" / "pe_context_extractor.py"
_V3_INSERT_TABLES = ("functions", "imports", "globals")


def _collect_sql():
    """Return list of (lineno, sql) for every execute/executemany string arg."""
    tree = ast.parse(_SRC.read_text(encoding="utf-8"))
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            f = node.func
            if isinstance(f, ast.Attribute) and f.attr in ("execute", "executemany"):
                if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                    out.append((node.lineno, node.args[0].value))
    return out


def _sorted(pred):
    return [s for _, s in sorted(_collect_sql(), key=lambda t: t[0]) if pred(s)]


def _ddl_statements():
    return _sorted(lambda s: re.match(r"\s*(CREATE|DROP)\b", s, re.IGNORECASE))


def _delete_statements():
    return _sorted(lambda s: re.match(r"\s*DELETE\b", s, re.IGNORECASE))


def _v3_insert_statements():
    return [s for s in _sorted(lambda s: re.match(r"\s*INSERT\b", s, re.IGNORECASE))
            if any(f"INTO {t} " in s or f"INTO {t}(" in s for t in _V3_INSERT_TABLES)]


def _process_single_function_record_keys():
    tree = ast.parse(_SRC.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "_process_single_function":
            best = None
            for sub in ast.walk(node):
                if isinstance(sub, ast.Return) and isinstance(sub.value, ast.Dict):
                    keys = [k.value for k in sub.value.keys
                            if isinstance(k, ast.Constant) and isinstance(k.value, str)]
                    if best is None or len(keys) > len(best):
                        best = keys
            return best or []
    return []


def _parse_insert(sql):
    m = re.search(r"INSERT\s+(?:OR\s+\w+\s+)?INTO\s+(\w+)\s*\(([^)]*)\)\s*VALUES\s*\(([^)]*)\)",
                   sql, re.IGNORECASE | re.DOTALL)
    assert m, f"could not parse INSERT: {sql[:60]!r}"
    table = m.group(1)
    cols = [c.strip() for c in m.group(2).split(",") if c.strip()]
    vals = m.group(3)
    if ":" in vals:
        ph = [v.strip().lstrip(":") for v in vals.split(",") if v.strip().startswith(":")]
    else:
        ph = ["?"] * vals.count("?")
    return table, cols, ph


def test_all_ddl_executes_against_sqlite_in_source_order():
    """Every CREATE/DROP in source order is valid SQL and yields the v3 schema."""
    conn = sqlite3.connect(":memory:")
    for sql in _ddl_statements():
        conn.execute(sql)
    conn.commit()
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"functions", "imports", "globals", "function_xrefs", "file_info", "schema_version"} <= tables
    fcols = {r[1] for r in conn.execute("PRAGMA table_info(functions)")}
    assert {"function_address", "function_end_address", "function_size", "function_flags"} <= fcols
    icols = {r[1] for r in conn.execute("PRAGMA table_info(imports)")}
    assert {"module_name", "mangled_name", "iat_ea", "is_delay_loaded"} <= icols
    gcols = {r[1] for r in conn.execute("PRAGMA table_info(globals)")}
    assert {"ea", "name", "size", "section", "writable", "access_types"} <= gcols
    conn.close()


def test_all_delete_statements_execute_after_schema_built():
    conn = sqlite3.connect(":memory:")
    for sql in _ddl_statements():
        conn.execute(sql)
    conn.commit()
    for sql in _delete_statements():
        conn.execute(sql)
    conn.close()


def test_v3_inserts_have_matching_column_placeholder_arity():
    inserts = _v3_insert_statements()
    assert len(inserts) == 3, f"expected exactly 3 v3 INSERTs, got {len(inserts)}"
    for sql in inserts:
        table, cols, ph = _parse_insert(sql)
        assert len(cols) == len(ph), f"INSERT INTO {table}: {len(cols)} cols vs {len(ph)} placeholders"


def test_imports_insert_arity_matches_flatten_tuple():
    sql = next(s for s in _v3_insert_statements() if "INTO imports" in s)
    _, cols, ph = _parse_insert(sql)
    assert len(cols) == 9 and len(ph) == 9
    sample = flatten_imports_rows([{"module_name": "x.dll", "functions": [
        {"address": "0x10", "mangled_name": "M"}]}])
    assert sample and all(len(r) == 9 for r in sample), (
        "flatten_imports_rows must yield 9-tuples matching the 9 imports columns")


def test_globals_insert_arity_is_six():
    sql = next(s for s in _v3_insert_statements() if "INTO globals" in s)
    _, cols, ph = _parse_insert(sql)
    assert len(cols) == 6 and len(ph) == 6


def test_functions_insert_placeholders_match_record_insertable_keys():
    sql = next(s for s in _v3_insert_statements() if "INTO functions" in s)
    _, cols, ph = _parse_insert(sql)
    assert len(cols) == len(ph)
    assert set(cols) == set(ph), "functions INSERT columns must match placeholders by name"
    record_keys = set(_process_single_function_record_keys())
    assert record_keys, "could not extract _process_single_function record keys"
    insertable = {k for k in record_keys if not k.startswith("_raw_")}
    assert set(ph) == insertable, (
        f"functions INSERT placeholders != record insertable keys; "
        f"missing from INSERT: {insertable - set(ph)}; "
        f"extra in INSERT: {set(ph) - insertable}")


def test_functions_insert_columns_are_valid_schema_columns():
    sql = next(s for s in _v3_insert_statements() if "INTO functions" in s)
    _, cols, _ = _parse_insert(sql)
    expected = set()
    for c in schema.get_expected_schema()["functions"]:
        parts = c.strip().split()
        if parts and parts[0].upper() not in ("PRIMARY", "FOREIGN", "UNIQUE", "CHECK", "CONSTRAINT"):
            expected.add(parts[0])
    assert set(cols) <= expected, f"INSERT references unknown columns: {set(cols) - expected}"
