"""Test bootstrap: load the IDA-free modules under test in isolated namespaces.

The ``deep_extract`` package ``__init__`` imports IDA-bound modules
(``pe_context_extractor``, ``gui_dialog``), so importing ``deep_extract``
outside IDA fails. The modules under test here (``schema``, ``logging_utils``,
``imports_globals_helpers``) are IDA-free at top level. We pre-empt the
package ``__init__`` by registering a bare ``deep_extract`` package stub in
``sys.modules``, then load each IDA-free submodule by file path. This lets
tests use normal ``from deep_extract import schema`` imports without
triggering the IDA-bound package init. Deterministic importlib isolation,
not IDA stubbing.
"""
import importlib.util
import pathlib
import sys
import types

_DEEP = (pathlib.Path(__file__).resolve().parent.parent / "deep_extract").resolve()


def _ensure_pkg_stub() -> None:
    if "deep_extract" not in sys.modules:
        pkg = types.ModuleType("deep_extract")
        pkg.__path__ = [str(_DEEP)]
        sys.modules["deep_extract"] = pkg


def _load_isolated(modname: str, filename: str) -> types.ModuleType:
    _ensure_pkg_stub()
    full = f"deep_extract.{modname}"
    if full in sys.modules:
        return sys.modules[full]
    spec = importlib.util.spec_from_file_location(full, str(_DEEP / filename))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[full] = mod
    spec.loader.exec_module(mod)
    return mod


# Load in dependency order so transitive ``from . import X`` resolves to the
# isolated copies (logging_utils first; it is imported by most others).
_load_isolated("logging_utils", "logging_utils.py")
_load_isolated("constants", "constants.py")
_load_isolated("db_connection", "db_connection.py")
_load_isolated("schema", "schema.py")
_load_isolated("imports_globals_helpers", "imports_globals_helpers.py")
_load_isolated("cpp_generator", "cpp_generator.py")
_load_isolated("asm_generator", "asm_generator.py")
_load_isolated("json_safety", "json_safety.py")
_load_isolated("config", "config.py")
_load_isolated("module_profile", "module_profile.py")
