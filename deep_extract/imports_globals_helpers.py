"""Pure, IDA-free helpers for populating the structured ``imports`` and
``globals`` tables (schema v3).

These helpers are deliberately kept free of any IDA Pro imports so they can be
unit-tested outside the IDA environment. The caller (``pe_context_extractor``)
is responsible for parsing the source JSON and for the IDA-dependent
enrichment (segment/item size and permissions) that happens in the extraction
loop.
"""

from typing import Any, Dict, List


def flatten_imports_rows(imports_data: Any) -> List[tuple]:
    """Flatten the imports structure (module -> functions) into rows for the
    structured ``imports`` table.

    Applies the guards required for delay-load imports (``address: None`` from
    pe_metadata.py) and for json_safety truncation markers (a trailing
    ``{'_truncated': True, ...}`` dict appended when imports exceed
    max_list_items). Returns rows as tuples matching the imports INSERT
    column order:
    (module_name, raw_module_name, is_api_set, is_delay_loaded,
     function_name, mangled_name, ordinal, iat_ea, function_signature_extended)
    """
    rows: List[tuple] = []
    if not isinstance(imports_data, list):
        return rows
    for mod in imports_data:
        # Skip non-module entries (e.g. json_safety trailing _truncated dict).
        if not isinstance(mod, dict) or 'functions' not in mod:
            continue
        module_name = mod.get('module_name')
        raw_module_name = mod.get('raw_module_name')
        is_api_set = mod.get('is_api_set')
        for imp in mod.get('functions', []) or []:
            if not isinstance(imp, dict):
                continue
            addr = imp.get('address')
            # Delay-load imports set address: None (pe_metadata.py); guard the
            # hex->int conversion so iat_ea is nullable for them.
            iat_ea = int(addr, 16) if isinstance(addr, str) and addr else None
            rows.append((
                module_name,
                raw_module_name,
                is_api_set,
                imp.get('is_delay_loaded', False),
                imp.get('function_name'),
                imp.get('mangled_name'),
                imp.get('ordinal'),
                iat_ea,
                imp.get('function_signature_extended'),
            ))
    return rows


def merge_global_access(global_acc: Dict[int, Dict[str, Any]],
                         global_accesses: Any) -> None:
    """Merge one function's raw ``global_accesses`` list into the module-level
    accumulator dict keyed by EA.

    ``access_types`` is stored as a set so the final join ordering is
    deterministic (sorted at insert time). The name is backfilled from a
    non-placeholder source when the first sighting was a hex placeholder
    (xref_analysis.py guarantees a name, falling back to ``0x{ea:X}``).
    """
    if not isinstance(global_accesses, list):
        return
    for entry in global_accesses:
        if not isinstance(entry, dict):
            continue
        addr = entry.get('address')
        if not isinstance(addr, str) or not addr:
            continue
        try:
            ea = int(addr, 16)
        except ValueError:
            continue
        name = entry.get('name') or addr
        slot = global_acc.setdefault(ea, {'name': name, 'access_types': set()})
        # Prefer a non-placeholder name if the existing one is a hex placeholder.
        if (not slot['name'] or slot['name'].startswith('0x')) and name and not name.startswith('0x'):
            slot['name'] = name
        atype = entry.get('access_type')
        if isinstance(atype, str) and atype:
            slot['access_types'].add(atype)
