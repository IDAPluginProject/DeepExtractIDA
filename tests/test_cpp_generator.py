"""Unit tests for ``deep_extract.cpp_generator.CppGenerator`` pure static helpers.

``cpp_generator`` is fully IDA-free at load time. These tests exercise the pure
formatting helpers that decide filenames, library tagging, and C++ header /
code wrapping -- the parts that are otherwise only reached through the full
extraction pipeline:

- ``sanitize_filename``: scope-resolution & invalid-char replacement + length cap.
- ``_cap_filename_length``: static cap, path-aware cap, hash-suffix uniqueness,
  and the 60-char floor for very deep output dirs.
- ``_detect_library_tag``: WIL/STL/WRL/CRT/ETW pattern matching against display
  and mangled names.
- ``_build_function_header_lines``: conditional header lines (name, mangled,
  library, extended vs base signature).
- ``_wrap_cpp_code_lines``: comment wrapping, long-line preservation, multi-line
  comment passthrough, ``\\n`` / backtick normalization.
- ``_estimate_function_lines``: header + code + trailing blank accounting.
- ``_write_info_field``: N/A substitution and code formatting.
"""
import io
import pathlib

import pytest

from deep_extract.cpp_generator import CppGenerator


# ---------------------------------------------------------------------------
# sanitize_filename
# ---------------------------------------------------------------------------

def test_sanitize_filename_replaces_scope_resolution():
    assert CppGenerator.sanitize_filename("Foo::Bar") == "Foo_Bar"


def test_sanitize_filename_replaces_invalid_chars():
    assert CppGenerator.sanitize_filename("a b/c") == "a_b_c"


def test_sanitize_filename_keeps_dot_and_dash():
    assert CppGenerator.sanitize_filename("abc.def-ghi") == "abc.def-ghi"


def test_sanitize_filename_caps_length():
    assert len(CppGenerator.sanitize_filename("x" * 150)) == 100


# ---------------------------------------------------------------------------
# _cap_filename_length
# ---------------------------------------------------------------------------

def test_cap_filename_short_unchanged():
    assert CppGenerator._cap_filename_length("short") == "short"


def test_cap_filename_no_dir_caps_to_200_with_hash():
    capped = CppGenerator._cap_filename_length("A" * 300)
    assert len(capped) == 200
    # last 11 chars are "_" + 10-char md5 hash
    assert capped[-11] == "_" and len(capped[-10:]) == 10


def test_cap_filename_hash_preserves_uniqueness():
    a = CppGenerator._cap_filename_length("B" * 300)
    b = CppGenerator._cap_filename_length("C" * 300)
    assert a != b


def test_cap_filename_same_input_is_deterministic():
    assert CppGenerator._cap_filename_length("D" * 300) == CppGenerator._cap_filename_length("D" * 300)


def test_cap_filename_path_aware_respects_dir_length(tmp_path):
    # The cap is computed from the real resolved dir length, so assert the
    # deterministic computed limit rather than a hard-coded 200 (tmp_path is
    # long enough to shrink the cap below the static 200 ceiling).
    dir_len = len(str(pathlib.Path(tmp_path).resolve()))
    expected_limit = max(60, min(200, CppGenerator.WINDOWS_MAX_PATH - dir_len - 1 - len(".cpp") - 5))
    capped = CppGenerator._cap_filename_length("E" * 300, output_dir=tmp_path)
    assert len(capped) == expected_limit


def test_cap_filename_floors_at_60_for_very_long_dir():
    long_dir = pathlib.Path("C:/" + "Z" * 240)
    capped = CppGenerator._cap_filename_length("F" * 300, output_dir=long_dir)
    assert len(capped) == 60


# ---------------------------------------------------------------------------
# _detect_library_tag
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name,tag", [
    ("wil::foo", "WIL"),
    ("wistd::bar", "WIL"),
    ("std::vector", "STL"),
    ("stdext::x", "STL"),
    ("Microsoft::WRL::Foo", "WRL"),
    ("__scrt_main", "CRT"),
    ("__acrt_thing", "CRT"),
    ("_CRT_INIT", "CRT"),
    ("_tlgWriteSomething", "ETW/TraceLogging"),
    ("TraceLoggingCorrelationVector::x", "ETW/TraceLogging"),
])
def test_detect_library_tag_display_name(name, tag):
    assert CppGenerator._detect_library_tag(name) == tag


@pytest.mark.parametrize("mangled,tag", [
    ("@wil@@", "WIL"),
    ("@std@@", "STL"),
    ("@wistd@@", "WIL"),
])
def test_detect_library_tag_mangled_name(mangled, tag):
    assert CppGenerator._detect_library_tag("plainname", mangled_name=mangled) == tag


def test_detect_library_tag_none_for_app_code():
    assert CppGenerator._detect_library_tag("MyApp::DoThing") is None


def test_detect_library_tag_none_inputs():
    assert CppGenerator._detect_library_tag(None) is None
    assert CppGenerator._detect_library_tag(None, mangled_name=None) is None


def test_detect_library_tag_mangled_equal_to_name_only_checks_once():
    # When mangled == function_name it is not added a second time (no crash, no false tag).
    assert CppGenerator._detect_library_tag("plain", mangled_name="plain") is None


# ---------------------------------------------------------------------------
# _build_function_header_lines
# ---------------------------------------------------------------------------

def test_header_minimal_name_and_signature():
    lines = CppGenerator._build_function_header_lines("int Foo()", function_name="Foo")
    assert lines == ["// Function Name: Foo", "// Function Signature: int Foo()"]


def test_header_adds_mangled_when_different():
    lines = CppGenerator._build_function_header_lines("int Foo()", function_name="Foo",
                                                       mangled_name="?Foo@@YAHH@Z")
    assert "// Mangled Name: ?Foo@@YAHH@Z" in lines


def test_header_omits_mangled_when_equal_to_name():
    lines = CppGenerator._build_function_header_lines("int Foo()", function_name="Foo",
                                                       mangled_name="Foo")
    assert not any(l.startswith("// Mangled Name") for l in lines)


def test_header_adds_library_tag():
    lines = CppGenerator._build_function_header_lines("int DoThing()", function_name="DoThing",
                                                       mangled_name="std::vec")
    assert "// Library: STL" in lines


def test_header_extended_replaces_base_when_sig_equals_name():
    lines = CppGenerator._build_function_header_lines("Foo", function_name="Foo",
                                                       signature_extended="int Foo(int)")
    assert "// Function Signature (Extended): int Foo(int)" in lines
    assert not any(l.startswith("// Function Signature:") and "Extended" not in l for l in lines)


def test_header_keeps_base_sig_when_sig_equals_name_and_no_extended():
    lines = CppGenerator._build_function_header_lines("Foo", function_name="Foo")
    assert "// Function Signature: Foo" in lines


# ---------------------------------------------------------------------------
# _wrap_cpp_code_lines
# ---------------------------------------------------------------------------

def test_wrap_short_code_kept():
    assert CppGenerator._wrap_cpp_code_lines("int x = 1;") == ["int x = 1;"]


def test_wrap_long_comment_with_spaces_wraps():
    line = "// " + "word " * 40  # multiple words -> wrappable
    out = CppGenerator._wrap_cpp_code_lines(line)
    assert len(out) > 1
    assert all(l.startswith("// ") for l in out)
    assert all(len(l) <= 120 for l in out)


def test_wrap_long_single_word_comment_not_broken():
    # break_long_words=False -> a single long word is kept on one line.
    line = "// " + "a" * 200
    out = CppGenerator._wrap_cpp_code_lines(line)
    assert len(out) == 1
    assert out[0] == line


def test_wrap_long_non_comment_line_kept_as_is():
    line = "int " + "x" * 200 + ";"
    out = CppGenerator._wrap_cpp_code_lines(line)
    assert out == [line]


def test_wrap_multiline_comment_preserved_verbatim():
    block = "/*\n" + "x" * 200 + "\n*/"
    out = CppGenerator._wrap_cpp_code_lines(block)
    assert out == block.splitlines()


def test_wrap_literal_backslash_n_becomes_newline():
    out = CppGenerator._wrap_cpp_code_lines("a\\nb")
    assert out == ["a", "b"]


def test_wrap_backtick_replaced_with_single_quote():
    out = CppGenerator._wrap_cpp_code_lines("a`b")
    assert out == ["a'b"]


# ---------------------------------------------------------------------------
# _estimate_function_lines
# ---------------------------------------------------------------------------

def test_estimate_function_lines_counts_header_plus_code_plus_blank(tmp_path):
    gen = CppGenerator(tmp_path, "mod")
    code = "line1\nline2\nline3"  # 3 lines
    est = gen._estimate_function_lines("int Foo()", code, function_name="Foo")
    # header: Function Name + Function Signature = 2 ; code = 3 ; trailing blank = 1
    assert est == 2 + 3 + 1


# ---------------------------------------------------------------------------
# _write_info_field
# ---------------------------------------------------------------------------

def test_write_info_field_na_for_none():
    buf = io.StringIO()
    CppGenerator._write_info_field(buf, "Label", None)
    assert buf.getvalue() == "- **Label:** N/A\n"


def test_write_info_field_na_for_empty():
    buf = io.StringIO()
    CppGenerator._write_info_field(buf, "Label", "   ")
    assert buf.getvalue() == "- **Label:** N/A\n"


def test_write_info_field_code_formatted():
    buf = io.StringIO()
    CppGenerator._write_info_field(buf, "Label", "value", is_code=True)
    assert buf.getvalue() == "- **Label:** `value`\n"


def test_write_info_field_plain_formatted():
    buf = io.StringIO()
    CppGenerator._write_info_field(buf, "Label", "value", is_code=False)
    assert buf.getvalue() == "- **Label:** value\n"
