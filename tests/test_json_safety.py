"""Unit tests for ``deep_extract.json_safety`` pure serialization helpers.

``json_safety`` is fully IDA-free and central to every JSON column written to
the DB. These tests pin the size-bounding / type-coercion / truncation contracts
that downstream readers (and the imports/globals flatteners) depend on:

- ``to_json_safe``: type preservation, drop_keys, string/dict/list/byte-size
  truncation markers, type coercion (bytes, set, datetime, Decimal, complex,
  custom objects, deep nesting).
- ``validate_json_field``: size / parse / cardinality validation.
- ``create_truncation_summary`` / ``apply_field_limits``: summary shape and
  defensive clamping of negative / inverted counts.
- ``_get_max_xrefs`` / ``safe_serialize_xrefs``: env override + lower-bound
  clamping.
"""
import datetime
import json
from decimal import Decimal
from enum import Enum

import pytest

from deep_extract import json_safety as js


# ---------------------------------------------------------------------------
# to_json_safe: basic type preservation
# ---------------------------------------------------------------------------

def test_to_json_safe_preserves_basic_types():
    out = json.loads(js.to_json_safe({"s": "x", "i": 1, "f": 1.5, "b": True, "n": None}))
    assert out == {"s": "x", "i": 1, "f": 1.5, "b": True, "n": None}


def test_to_json_safe_returns_valid_json_string():
    s = js.to_json_safe({"a": [1, 2, {"b": 3}]})
    assert isinstance(s, str)
    assert json.loads(s) == {"a": [1, 2, {"b": 3}]}


# ---------------------------------------------------------------------------
# to_json_safe: drop_keys
# ---------------------------------------------------------------------------

def test_to_json_safe_drop_keys_removed():
    out = json.loads(js.to_json_safe({"keep": 1, "drop": 2, "alsodrop": 3},
                                     drop_keys={"drop", "alsodrop"}))
    assert out == {"keep": 1}


def test_to_json_safe_drop_keys_recursive():
    out = json.loads(js.to_json_safe({"outer": {"keep": 1, "drop": 2}},
                                     drop_keys={"drop"}))
    assert out == {"outer": {"keep": 1}}


# ---------------------------------------------------------------------------
# to_json_safe: string / dict-key / list-count truncation
# ---------------------------------------------------------------------------

def test_to_json_safe_truncates_long_strings():
    out = json.loads(js.to_json_safe("x" * 50, max_string_length=10))
    assert out.endswith("...[TRUNCATED]")
    assert out.startswith("x" * 10)


def test_to_json_safe_truncates_dict_keys_and_marks():
    out = json.loads(js.to_json_safe({"a": 1, "b": 2, "c": 3, "d": 4}, max_dict_keys=2))
    # Only the first 2 data keys survive; truncation markers are added.
    assert out["a"] == 1 and out["b"] == 2
    assert "_truncated_keys" in out and out["_truncated_keys"] == 2
    assert out["_serialization_metadata"]["truncated"] is True


def test_to_json_safe_truncates_list_count_and_marks():
    out = json.loads(js.to_json_safe([1, 2, 3, 4, 5], max_list_items=3))
    assert out[:3] == [1, 2, 3]
    markers = [e for e in out if isinstance(e, dict)]
    kinds = {next(iter(m.keys())) for m in markers}
    assert "_truncated" in kinds and "_serialization_metadata" in kinds


def test_to_json_safe_truncate_lists_false_keeps_all():
    """truncate_lists=False disables count-based truncation (byte cap still applies)."""
    out = json.loads(js.to_json_safe([1, 2, 3, 4, 5], max_list_items=3, truncate_lists=False))
    assert out == [1, 2, 3, 4, 5]


# ---------------------------------------------------------------------------
# to_json_safe: type coercion
# ---------------------------------------------------------------------------

def test_to_json_safe_bytes_utf8_decoded():
    assert json.loads(js.to_json_safe(b"hi")) == "hi"


def test_to_json_safe_bytes_non_utf8_as_hex():
    out = json.loads(js.to_json_safe(b"\xff\x00\x01"))
    assert out == "<hex:FF0001>"  # uppercase hex


def test_to_json_safe_set_to_sorted_list():
    assert json.loads(js.to_json_safe({3, 1, 2})) == [1, 2, 3]


def test_to_json_safe_datetime_isoformat():
    assert json.loads(js.to_json_safe(datetime.datetime(2020, 1, 2, 3, 4, 5))) == "2020-01-02T03:04:05"


def test_to_json_safe_decimal_to_float():
    assert json.loads(js.to_json_safe(Decimal("1.5"))) == 1.5


def test_to_json_safe_complex_to_dict():
    out = json.loads(js.to_json_safe(complex(1, 2)))
    assert out == {"real": 1.0, "imag": 2.0, "_type": "complex"}


def test_to_json_safe_custom_object_uses_dict():
    class C:
        def __init__(self):
            self.x = 1
            self.y = "z"
    out = json.loads(js.to_json_safe(C()))
    assert out == {"x": 1, "y": "z"}


def test_to_json_safe_enum_returns_value():
    """An Enum member serializes to ``obj.value`` (not its internal __dict__).

    Before the fix, the Enum handler was positioned after the ``__dict__``
    handler; since Enum members have ``__dict__``, the ``__dict__`` handler fired
    first and returned the member's internal dict (containing ``_value_``).
    Moving the Enum handler before the ``__dict__`` handler makes this branch
    reachable. This test fails without the reorder (returns a dict) and passes
    with it (returns the bare value).
    """
    class E(Enum):
        A = "aval"
    out = json.loads(js.to_json_safe(E.A))
    assert out == "aval"


def test_to_json_safe_int_enum_returns_int_no_regression():
    """IntEnum members are int subclasses, so the basic-types handler (step 1)
    returns their int value BEFORE the Enum block. The reorder must not change
    this: IntEnum still serializes to its int value, not to obj.value or a dict.
    """
    from enum import IntEnum
    class IE(IntEnum):
        A = 7
    out = json.loads(js.to_json_safe(IE.A))
    assert out == 7


def test_to_json_safe_int_flag_returns_int_no_regression():
    """IntFlag members are int subclasses -> caught by the basic-types handler
    (step 1) before the Enum block, so the reorder does not change them.
    Combined flags (A|B) must serialize to the integer bitmask.
    """
    from enum import IntFlag
    class IF(IntFlag):
        A = 1
        B = 2
    assert json.loads(js.to_json_safe(IF.A)) == 1
    assert json.loads(js.to_json_safe(IF.A | IF.B)) == 3


def test_to_json_safe_flag_returns_int_bitmask():
    """Plain Flag members are NOT int subclasses and HAVE __dict__, so before the
    fix they fell through to the __dict__ handler (junk internal dict). After the
    reorder they reach the Enum branch and return obj.value (the int bitmask).
    """
    from enum import Flag
    class F(Flag):
        A = 1
        B = 2
    assert json.loads(js.to_json_safe(F.A)) == 1
    assert json.loads(js.to_json_safe(F.A | F.B)) == 3


def test_to_json_safe_str_enum_returns_str():
    """StrEnum (Py3.11+) members are str subclasses -> caught by step 1; the
    reorder must not change them. Skipped on interpreters without StrEnum.
    """
    import sys
    if sys.version_info < (3, 11):
        pytest.skip("StrEnum requires Python 3.11+")
    from enum import StrEnum
    class SE(StrEnum):
        X = "xval"
    assert json.loads(js.to_json_safe(SE.X)) == "xval"


def test_to_json_safe_enum_int_value():
    """A plain Enum (not IntEnum) with an int value is not an int subclass, so it
    reaches the Enum branch and returns obj.value (the int)."""
    class E(Enum):
        A = 5
    assert json.loads(js.to_json_safe(E.A)) == 5


def test_to_json_safe_enum_tuple_value_becomes_array():
    """An Enum whose value is a tuple serializes to a JSON array (the tuple is
    returned by the Enum branch and json.dumps converts it)."""
    class E(Enum):
        A = (1, 2)
    assert json.loads(js.to_json_safe(E.A)) == [1, 2]


def test_to_json_safe_nested_enum_in_dict_and_list():
    """Enums nested inside dicts/lists are reached by the recursive dict/list
    handlers and normalized to obj.value (the bug previously produced nested
    internal __dict__s)."""
    class E(Enum):
        A = "aval"
    class EI(Enum):
        B = 5
    out = json.loads(js.to_json_safe({"k": E.A, "list": [EI.B, E.A]}))
    assert out == {"k": "aval", "list": [5, "aval"]}


def test_to_json_safe_pe_metadata_like_structure_with_enum():
    """Regression guard for the active pe_context_extractor usage: to_json_safe is
    called on many nested PE-metadata fields. A realistic structure containing a
    buried enum must serialize without crashing, with the enum normalized to its
    value and all other fields preserved.
    """
    class SectionType(Enum):
        TEXT = ".text"
        DATA = ".data"

    pe_meta = {
        "sections": [
            {"name": SectionType.TEXT, "vaddr": 0x1000, "size": 0x200},
            {"name": SectionType.DATA, "vaddr": 0x3000, "size": 0x100},
        ],
        "rich_header": {"count": 3, "tool": "linker"},
        "dll_characteristics": 0x140,
        "tls_callbacks": [0x401000, 0x401020],
    }
    out = json.loads(js.to_json_safe(pe_meta, max_list_items=200, field_name="sections"))
    assert out["sections"][0]["name"] == ".text"
    assert out["sections"][1]["name"] == ".data"
    assert out["sections"][0]["vaddr"] == 0x1000
    assert out["rich_header"] == {"count": 3, "tool": "linker"}
    assert out["dll_characteristics"] == 0x140
    assert out["tls_callbacks"] == [0x401000, 0x401020]


def test_to_json_safe_non_enum_object_with_dict_still_uses_dict():
    """The reorder must NOT break the generic __dict__ handler: a non-Enum object
    with __dict__ still serializes to its instance dict (not str fallback)."""
    class Obj:
        def __init__(self):
            self.x = 1
            self.name = "foo"
    out = json.loads(js.to_json_safe(Obj()))
    assert out == {"x": 1, "name": "foo"}


def test_to_json_safe_safe_serialize_helpers_handle_enum():
    """The safe_serialize_* helpers all funnel through to_json_safe, so an enum
    inside an xrefs/strings payload is normalized identically."""
    class Severity(Enum):
        HIGH = "high"
    xrefs = [{"function_name": "CreateFile", "severity": Severity.HIGH}]
    out = json.loads(js.safe_serialize_xrefs(xrefs, field_name="xrefs"))
    assert out[0]["severity"] == "high"
    assert out[0]["function_name"] == "CreateFile"


def test_to_json_safe_max_depth_sentinel():
    nested = "leaf"
    for _ in range(60):
        nested = {"k": nested}
    out = json.loads(js.to_json_safe(nested))
    assert "<max_recursion_depth_exceeded>" in json.dumps(out)
    assert out["_serialization_metadata"]["truncated"] is True


# ---------------------------------------------------------------------------
# to_json_safe: byte-size truncation
# ---------------------------------------------------------------------------

def test_to_json_safe_byte_size_list_truncation():
    big = ["x" * 100] * 1000
    out = json.loads(js.to_json_safe(big, max_bytes=2000, field_name="BIG"))
    marker = out[-1]
    assert isinstance(marker, dict)
    assert marker["_truncated"] is True
    assert marker["reason"] == "byte_size_limit_exceeded"
    assert marker["original_count"] == 1000
    assert marker["shown_count"] < 1000
    assert len(out) == marker["shown_count"] + 1


def test_to_json_safe_byte_size_dict_removes_large_fields():
    bigd = {"a": "x" * 2000, "b": "y" * 2000, "small": "ok"}
    out = json.loads(js.to_json_safe(bigd, max_bytes=500, field_name="BIGD"))
    assert "small" in out and out["small"] == "ok"
    assert "a" not in out and "b" not in out
    assert "_removed_fields" in out


# ---------------------------------------------------------------------------
# validate_json_field
# ---------------------------------------------------------------------------

def test_validate_json_field_valid():
    ok, msg = js.validate_json_field('[1,2,3]', 'f')
    assert ok and msg is None


def test_validate_json_field_oversized():
    ok, msg = js.validate_json_field('x' * 100, 'f', max_bytes=10)
    assert not ok and 'exceeds size limit' in msg


def test_validate_json_field_invalid_json():
    ok, msg = js.validate_json_field('{not json', 'f')
    assert not ok and 'not valid JSON' in msg


def test_validate_json_field_too_many_keys():
    payload = json.dumps({f"k{i}": i for i in range(js.DEFAULT_MAX_DICT_KEYS + 1)})
    ok, msg = js.validate_json_field(payload, 'f')
    assert not ok and 'too many keys' in msg


def test_validate_json_field_too_many_items():
    payload = json.dumps([0] * (js.DEFAULT_MAX_LIST_ITEMS + 1))
    ok, msg = js.validate_json_field(payload, 'f')
    assert not ok and 'too many items' in msg


# ---------------------------------------------------------------------------
# create_truncation_summary / apply_field_limits
# ---------------------------------------------------------------------------

def test_create_truncation_summary_normal():
    s = js.create_truncation_summary(100, 30, "xrefs")
    assert s["_truncated"] is True
    assert s["original_count"] == 100 and s["shown_count"] == 30
    assert s["item_type"] == "xrefs"
    assert s["truncation_percentage"] == 70.0


def test_create_truncation_summary_negative_counts_clamped():
    s = js.create_truncation_summary(-5, -1, "x")
    assert s["original_count"] == 0 and s["shown_count"] == 0
    assert s["truncation_percentage"] == 0


def test_create_truncation_summary_shown_capped_to_original():
    s = js.create_truncation_summary(10, 20, "x")
    assert s["shown_count"] == 10
    assert s["truncation_percentage"] == 0


def test_create_truncation_summary_zero_original():
    s = js.create_truncation_summary(0, 0, "x")
    assert s["truncation_percentage"] == 0


def test_apply_field_limits_under_limit_unchanged():
    lst = [1, 2, 3]
    assert js.apply_field_limits(lst, max_xrefs=10) is lst


def test_apply_field_limits_over_limit_truncates_with_summary():
    out = js.apply_field_limits(list(range(5)), max_xrefs=3)
    assert out[:3] == [0, 1, 2]
    summary = out[-1]
    assert summary["_truncated"] is True
    assert summary["original_count"] == 5 and summary["shown_count"] == 3
    assert summary["item_type"] == "xrefs"


# ---------------------------------------------------------------------------
# _get_max_xrefs / safe_serialize_xrefs
# ---------------------------------------------------------------------------

def test_get_max_xrefs_override_used():
    assert js._get_max_xrefs(5000) == 5000


def test_get_max_xrefs_override_clamped_to_min():
    assert js._get_max_xrefs(500) == js.constants.MIN_MAX_XREFS


def test_get_max_xrefs_invalid_env_falls_back(monkeypatch):
    monkeypatch.setenv("EXTRACTOR_MAX_XREFS", "abc")
    assert js._get_max_xrefs() == js.constants.DEFAULT_MAX_XREFS


def test_get_max_xrefs_env_clamped_to_min(monkeypatch):
    monkeypatch.setenv("EXTRACTOR_MAX_XREFS", "50")
    assert js._get_max_xrefs() == js.constants.MIN_MAX_XREFS


def test_get_max_xrefs_env_used(monkeypatch):
    monkeypatch.setenv("EXTRACTOR_MAX_XREFS", "5000")
    assert js._get_max_xrefs() == 5000


def test_safe_serialize_xrefs_returns_valid_json_list():
    xrefs = [{"function_name": "a"}, {"function_name": "b"}]
    out = json.loads(js.safe_serialize_xrefs(xrefs))
    assert out == xrefs


def test_safe_serialize_strings_keeps_small_list():
    out = json.loads(js.safe_serialize_strings(["a", "b", "c"]))
    assert out == ["a", "b", "c"]
