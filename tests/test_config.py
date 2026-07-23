"""Unit tests for ``deep_extract.config.AnalysisConfig``.

``config`` is fully IDA-free. These tests pin the validation rules in
``__post_init__`` (path coercion, input-file existence, numeric range guards,
boolean-flag type checks, derived-path computation, env pragma overrides), the
``from_ida_args`` factory (path-traversal / shell-metacharacter rejection,
argument coercion & defaults), and the serialization helpers
(``to_dict`` / ``to_analysis_flags_json`` / ``get_analysis_args_dict``).
"""
import json
from pathlib import Path

import pytest

from deep_extract.config import AnalysisConfig


def _make_input(tmp_path, name="target.dll"):
    p = tmp_path / name
    p.write_bytes(b"MZ")
    return p


# ---------------------------------------------------------------------------
# __post_init__: happy path + derived paths
# ---------------------------------------------------------------------------

def test_post_init_happy_path_computes_derived_paths(tmp_path):
    inp = _make_input(tmp_path)
    db = tmp_path / "sub" / "out.db"
    cfg = AnalysisConfig(sqlite_db_path=db, input_file_path=inp)
    assert cfg.output_dir == db.parent
    assert cfg.common_db_path == db.parent / "analyzed_files.db"


def test_post_init_coerces_str_paths_to_path(tmp_path):
    inp = _make_input(tmp_path)
    cfg = AnalysisConfig(sqlite_db_path=str(tmp_path / "x.db"), input_file_path=str(inp))
    assert isinstance(cfg.sqlite_db_path, Path)
    assert isinstance(cfg.input_file_path, Path)


def test_post_init_defaults_pragmas_present(tmp_path):
    inp = _make_input(tmp_path)
    cfg = AnalysisConfig(sqlite_db_path=tmp_path / "x.db", input_file_path=inp)
    assert cfg.get_sqlite_pragmas()["journal_mode"] == "WAL"
    assert cfg.get_common_db_pragmas()["journal_mode"] == "WAL"
    # getters return copies
    cfg.get_sqlite_pragmas()["journal_mode"] = "DELETE"
    assert cfg.get_sqlite_pragmas()["journal_mode"] == "WAL"


# ---------------------------------------------------------------------------
# __post_init__: input file validation
# ---------------------------------------------------------------------------

def test_post_init_missing_input_file_raises(tmp_path):
    with pytest.raises(ValueError, match="Input file does not exist"):
        AnalysisConfig(sqlite_db_path=tmp_path / "x.db", input_file_path=tmp_path / "nope.dll")


def test_post_init_input_is_directory_raises(tmp_path):
    with pytest.raises(ValueError, match="Input path is not a file"):
        AnalysisConfig(sqlite_db_path=tmp_path / "x.db", input_file_path=tmp_path)


# ---------------------------------------------------------------------------
# __post_init__: numeric range guards
# ---------------------------------------------------------------------------

def _cfg(tmp_path, **kw):
    inp = _make_input(tmp_path)
    return AnalysisConfig(sqlite_db_path=tmp_path / "x.db", input_file_path=inp, **kw)


def test_post_init_thunk_depth_bounds(tmp_path):
    _cfg(tmp_path, thunk_depth=0)   # 0 allowed (non-negative)
    _cfg(tmp_path, thunk_depth=100) # 100 allowed
    with pytest.raises(ValueError, match="thunk_depth"):
        _cfg(tmp_path, thunk_depth=-1)
    with pytest.raises(ValueError, match="thunk_depth"):
        _cfg(tmp_path, thunk_depth=101)


def test_post_init_min_conf_bounds(tmp_path):
    _cfg(tmp_path, min_conf=10)
    _cfg(tmp_path, min_conf=100)
    _cfg(tmp_path, min_conf=50.5)  # floats allowed
    with pytest.raises(ValueError, match="min_conf"):
        _cfg(tmp_path, min_conf=9)
    with pytest.raises(ValueError, match="min_conf"):
        _cfg(tmp_path, min_conf=101)


def test_post_init_loop_analysis_max_depth(tmp_path):
    _cfg(tmp_path, loop_analysis_max_depth=1)
    with pytest.raises(ValueError, match="loop_analysis_max_depth"):
        _cfg(tmp_path, loop_analysis_max_depth=0)


def test_post_init_max_xrefs(tmp_path):
    _cfg(tmp_path, max_xrefs=1)
    with pytest.raises(ValueError, match="max_xrefs"):
        _cfg(tmp_path, max_xrefs=0)


# ---------------------------------------------------------------------------
# __post_init__: boolean flag type checks
# ---------------------------------------------------------------------------

def test_post_init_non_boolean_flag_raises(tmp_path):
    with pytest.raises(ValueError, match="extract_strings must be a boolean"):
        _cfg(tmp_path, extract_strings="yes")


def test_post_init_non_boolean_generate_cpp_raises(tmp_path):
    with pytest.raises(ValueError, match="generate_cpp must be a boolean"):
        _cfg(tmp_path, generate_cpp=1)  # int 1 is not bool (isinstance(1, bool) is False)


# ---------------------------------------------------------------------------
# __post_init__: env pragma overrides
# ---------------------------------------------------------------------------

def test_post_init_env_pragma_override_applied(tmp_path, monkeypatch):
    monkeypatch.setenv("EXTRACTOR_SQLITE_PRAGMAS_JSON", '{"journal_mode": "DELETE"}')
    inp = _make_input(tmp_path)
    cfg = AnalysisConfig(sqlite_db_path=tmp_path / "x.db", input_file_path=inp)
    assert cfg.get_sqlite_pragmas()["journal_mode"] == "DELETE"


def test_post_init_env_pragma_malformed_keeps_defaults(tmp_path, monkeypatch):
    monkeypatch.setenv("EXTRACTOR_SQLITE_PRAGMAS_JSON", "{not json")
    inp = _make_input(tmp_path)
    cfg = AnalysisConfig(sqlite_db_path=tmp_path / "x.db", input_file_path=inp)
    assert cfg.get_sqlite_pragmas()["journal_mode"] == "WAL"


def test_post_init_env_pragma_non_dict_keeps_defaults(tmp_path, monkeypatch):
    monkeypatch.setenv("EXTRACTOR_SQLITE_PRAGMAS_JSON", "[1,2,3]")
    inp = _make_input(tmp_path)
    cfg = AnalysisConfig(sqlite_db_path=tmp_path / "x.db", input_file_path=inp)
    assert cfg.get_sqlite_pragmas()["journal_mode"] == "WAL"


# ---------------------------------------------------------------------------
# from_ida_args
# ---------------------------------------------------------------------------

def _args(tmp_path, **kw):
    a = {"sqlite_db": str(tmp_path / "out.db")}
    a.update(kw)
    return a


def test_from_ida_args_happy_path(tmp_path):
    inp = _make_input(tmp_path)
    cfg = AnalysisConfig.from_ida_args(_args(tmp_path), str(inp))
    assert isinstance(cfg, AnalysisConfig)
    assert cfg.input_file_path == inp.resolve()
    assert cfg.sqlite_db_path == (tmp_path / "out.db").resolve()
    # defaults preserved
    assert cfg.extract_dangerous_apis is True
    assert cfg.generate_cpp is False
    assert cfg.use_interprocedural_analysis is True


def test_from_ida_args_rejects_shell_metachar_in_db_path(tmp_path):
    inp = _make_input(tmp_path)
    bad = {"sqlite_db": str(tmp_path / "a~b.db")}
    with pytest.raises(ValueError, match="Suspicious path component"):
        AnalysisConfig.from_ida_args(bad, str(inp))


def test_from_ida_args_rejects_shell_metachar_in_input_path(tmp_path):
    # '~' survives Path.resolve (pathlib does not expand it) -> caught by the
    # suspicious-component check before the existence check.
    with pytest.raises(ValueError, match="Suspicious path component"):
        AnalysisConfig.from_ida_args(_args(tmp_path), str(tmp_path / "a;b.dll"))


def test_from_ida_args_missing_input_raises(tmp_path):
    with pytest.raises(ValueError, match="Input file does not exist"):
        AnalysisConfig.from_ida_args(_args(tmp_path), str(tmp_path / "nope.dll"))


def test_from_ida_args_thunk_depth_validation(tmp_path):
    inp = _make_input(tmp_path)
    with pytest.raises(ValueError, match="thunk_depth"):
        AnalysisConfig.from_ida_args(_args(tmp_path, thunk_depth=200), str(inp))
    with pytest.raises(ValueError, match="thunk_depth"):
        AnalysisConfig.from_ida_args(_args(tmp_path, thunk_depth="abc"), str(inp))


def test_from_ida_args_min_conf_validation(tmp_path):
    inp = _make_input(tmp_path)
    with pytest.raises(ValueError, match="min_conf"):
        AnalysisConfig.from_ida_args(_args(tmp_path, min_call_conf=5), str(inp))


def test_from_ida_args_max_xrefs_validation(tmp_path):
    inp = _make_input(tmp_path)
    with pytest.raises(ValueError, match="max_xrefs"):
        AnalysisConfig.from_ida_args(_args(tmp_path, max_xrefs=0), str(inp))


def test_from_ida_args_accepts_min_conf_alias(tmp_path):
    inp = _make_input(tmp_path)
    cfg = AnalysisConfig.from_ida_args(_args(tmp_path, min_call_conf=50), str(inp))
    assert cfg.min_conf == 50.0


# ---------------------------------------------------------------------------
# Serialization helpers
# ---------------------------------------------------------------------------

def test_to_dict_includes_sqlite_db_and_flags(tmp_path):
    inp = _make_input(tmp_path)
    cfg = AnalysisConfig(sqlite_db_path=tmp_path / "x.db", input_file_path=inp,
                         thunk_depth=5, min_conf=50, max_xrefs=2000)
    d = cfg.to_dict()
    assert d["sqlite_db"] == str(tmp_path / "x.db")
    assert d["thunk_depth"] == 5 and d["min_conf"] == 50 and d["max_xrefs"] == 2000
    # to_dict deliberately omits volatile/runtime fields
    assert "sqlite_pragmas" not in d
    assert "input_file_path" not in d


def test_to_analysis_flags_json_excludes_force_reanalyze_and_sorted(tmp_path):
    inp = _make_input(tmp_path)
    cfg = AnalysisConfig(sqlite_db_path=tmp_path / "x.db", input_file_path=inp,
                         force_reanalyze=True)
    j = cfg.to_analysis_flags_json()
    parsed = json.loads(j)
    assert "force_reanalyze" not in parsed
    assert list(parsed.keys()) == sorted(parsed.keys())


def test_get_analysis_args_dict_shape(tmp_path):
    inp = _make_input(tmp_path)
    cfg = AnalysisConfig(sqlite_db_path=tmp_path / "x.db", input_file_path=inp,
                         force_reanalyze=True, max_xrefs=2000)
    a = cfg.get_analysis_args_dict()
    assert a["force_reanalyze"] is True
    assert a["max_xrefs"] == 2000
    assert "extract_dangerous_apis" in a and "generate_cpp" in a
