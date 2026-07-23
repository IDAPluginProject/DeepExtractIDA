"""Isolation smoke test for asm_generator.py's address/ID changes (bonus fix).

asm_generator.py and its whole dependency chain (cpp_generator, db_connection,
constants) are IDA-free at module load, so the AsmGenerator class can be
imported and its pure formatting/index methods exercised directly with
synthetic function dicts -- no IDA needed. Covers the bonus fix that replaced
the mislabeled sequential function_id with the true function_address:

- _build_file_header: address range from function_address (None -> "unknown")
- _build_function_header: '; Address: 0x<EA>' only when function_address is
  not None (pre-v2 rows have NULL); '; ID: <id>' separated from the address
- _index_functions: 'address' hex string or None
- merge_into_function_index: backfill address for C++-path entries; never
  overwrite an existing real address with a None
"""
import json
import pathlib

from deep_extract.asm_generator import AsmGenerator


def _func(**overrides):
    base = {
        "function_id": 7,
        "function_address": 0x140001000,
        "function_name": "DoThing",
        "mangled_name": "?DoThing@@YAHH@Z",
        "function_signature": "int DoThing(int)",
        "assembly_code": "0x140001000  push rbp\n0x140001005  ret",
    }
    base.update(overrides)
    return base


def test_file_header_range_from_true_address(tmp_path):
    gen = AsmGenerator(tmp_path, "mod.dll")
    funcs = [_func(function_address=0x1000), _func(function_address=0x5000)]
    header = gen._build_file_header("grp", funcs)
    assert "0x1000 - 0x5000" in header[3]


def test_file_header_range_unknown_when_all_addresses_none(tmp_path):
    gen = AsmGenerator(tmp_path, "mod.dll")
    funcs = [_func(function_address=None), _func(function_address=None)]
    header = gen._build_file_header("grp", funcs)
    assert "Address range: unknown" in header[3]


def test_file_header_range_ignores_none_addresses(tmp_path):
    gen = AsmGenerator(tmp_path, "mod.dll")
    funcs = [_func(function_address=None), _func(function_address=0x3000)]
    header = gen._build_file_header("grp", funcs)
    assert "0x3000 - 0x3000" in header[3]


def test_function_header_shows_address_and_id_when_present(tmp_path):
    gen = AsmGenerator(tmp_path, "mod.dll")
    lines = gen._build_function_header(_func(function_id=7, function_address=0x140001000))
    joined = "\n".join(lines)
    assert "; Address: 0x140001000" in joined
    assert "; ID: 7" in joined


def test_function_header_omits_address_when_null_pre_v2(tmp_path):
    """Pre-v2 rows have function_address NULL -> no '; Address:' line, but '; ID:' still shows."""
    gen = AsmGenerator(tmp_path, "mod.dll")
    lines = gen._build_function_header(_func(function_address=None))
    joined = "\n".join(lines)
    assert "; Address:" not in joined
    assert "; ID: 7" in joined


def test_function_header_omits_id_when_zero(tmp_path):
    gen = AsmGenerator(tmp_path, "mod.dll")
    lines = gen._build_function_header(_func(function_id=0, function_address=0x1000))
    joined = "\n".join(lines)
    assert "; Address: 0x1000" in joined
    assert "; ID:" not in joined


def test_index_entry_address_hex_when_present(tmp_path):
    gen = AsmGenerator(tmp_path, "mod.dll")
    idx = {}
    gen._index_functions([_func(function_address=0x140001000)], "f.asm", idx)
    assert idx["DoThing"]["address"] == "0x140001000"
    assert idx["DoThing"]["has_assembly"] is True


def test_index_entry_address_none_when_null(tmp_path):
    gen = AsmGenerator(tmp_path, "mod.dll")
    idx = {}
    gen._index_functions([_func(function_address=None)], "f.asm", idx)
    assert idx["DoThing"]["address"] is None


def test_index_entry_skips_unnamed_functions(tmp_path):
    gen = AsmGenerator(tmp_path, "mod.dll")
    idx = {}
    gen._index_functions([_func(function_name=None)], "f.asm", idx)
    assert idx == {}


def test_index_entry_duplicate_name_appends_asm_file(tmp_path):
    gen = AsmGenerator(tmp_path, "mod.dll")
    idx = {}
    gen._index_functions([_func(function_address=0x1000)], "a.asm", idx)
    gen._index_functions([_func(function_address=0x1000)], "b.asm", idx)
    assert idx["DoThing"]["asm_files"] == ["a.asm", "b.asm"]


def test_merge_backfills_address_for_cpp_path_entries(tmp_path):
    """Existing C++-path entry (no address) + ASM entry with address -> backfilled."""
    gen = AsmGenerator(tmp_path, "mod.dll")
    existing = {"DoThing": {"files": ["DoThing.cpp"], "function_id": 7}}  # no 'address'
    asm_index = {"DoThing": {"asm_files": ["DoThing.asm"], "address": "0x140001000",
                             "has_assembly": True, "function_id": 7}}
    gen.merge_into_function_index(asm_index)
    merged = json.loads((tmp_path / "function_index.json").read_text(encoding="utf-8"))
    assert merged["DoThing"]["address"] == "0x140001000"
    assert "DoThing.asm" in merged["DoThing"]["asm_files"]


def test_merge_does_not_overwrite_real_address_with_none(tmp_path):
    """An existing real address must not be clobbered by a None ASM entry."""
    gen = AsmGenerator(tmp_path, "mod.dll")
    existing = {"DoThing": {"files": ["DoThing.cpp"], "address": "0x140001000",
                            "function_id": 7}}
    (tmp_path / "function_index.json").write_text(json.dumps(existing), encoding="utf-8")
    asm_index = {"DoThing": {"asm_files": ["DoThing.asm"], "address": None,
                             "has_assembly": True, "function_id": 7}}
    gen.merge_into_function_index(asm_index)
    merged = json.loads((tmp_path / "function_index.json").read_text(encoding="utf-8"))
    assert merged["DoThing"]["address"] == "0x140001000"
