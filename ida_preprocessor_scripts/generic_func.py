from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from pdb_resolver import resolve_public_symbol


def _parse_tool_json_result(tool_result: Any) -> Any | None:
    try:
        text = tool_result.content[0].text
        payload = json.loads(text)
        return json.loads(payload["result"])
    except Exception:
        return None


def _parse_int_value(value: Any) -> int:
    if isinstance(value, int):
        return value
    text = str(value).strip()
    return int(text, 0 if text.lower().startswith("0x") else 10)


def _is_explicit_address_literal(value: Any) -> bool:
    return isinstance(value, str) and value.strip().lower().startswith("0x")


def _intersect_addr_sets(candidate_sets: list[set[int]]) -> set[int]:
    if not candidate_sets:
        return set()

    common = set(candidate_sets[0])
    for addr_set in candidate_sets[1:]:
        common &= set(addr_set)
    return common


async def _collect_func_starts_for_code_addrs(
    *,
    session,
    code_addrs: set[int],
    debug: bool = False,
) -> set[int] | None:
    if not code_addrs:
        return set()

    py_code = (
        "import ida_funcs, json\n"
        f"code_addrs = {json.dumps([hex(addr) for addr in sorted(code_addrs)])}\n"
        "func_starts = set()\n"
        "for raw_ea in code_addrs:\n"
        "    try:\n"
        "        ea = int(str(raw_ea), 16)\n"
        "    except Exception:\n"
        "        continue\n"
        "    func = ida_funcs.get_func(ea)\n"
        "    if func is not None:\n"
        "        func_starts.add(int(func.start_ea))\n"
        "result = json.dumps({'func_starts': [hex(ea) for ea in sorted(func_starts)]})\n"
    )
    try:
        result = await session.call_tool(
            name="py_eval",
            arguments={"code": py_code},
        )
    except Exception as exc:
        if debug:
            print(f"    Preprocess: py_eval failed while normalizing function starts: {exc}")
        return None

    payload = _parse_tool_json_result(result)
    starts = payload.get("func_starts") if isinstance(payload, dict) else None
    if not isinstance(starts, list):
        return None

    parsed: set[int] = set()
    for item in starts:
        try:
            parsed.add(_parse_int_value(item))
        except (TypeError, ValueError):
            continue
    return parsed


async def _collect_xref_func_starts_for_string(
    *,
    session,
    xref_string: str,
    unicode_only: bool = False,
    debug: bool = False,
) -> set[int] | None:
    if not isinstance(xref_string, str) or not xref_string:
        return set()

    search_str = xref_string
    match_expr = "search_str in current_str"
    if xref_string.startswith("FULLMATCH:"):
        search_str = xref_string[len("FULLMATCH:") :]
        if not search_str:
            return set()
        match_expr = "current_str == search_str"

    py_lines = [
        "import ida_funcs, ida_nalt, idautils, json",
        f"search_str = {json.dumps(search_str)}",
        f"unicode_only = {bool(unicode_only)!r}",
        "unicode_type_names = ('STRTYPE_C_16', 'STRTYPE_C_32', 'STRTYPE_LEN2_16', 'STRTYPE_LEN2_32')",
        "unicode_types = {getattr(ida_nalt, name) for name in unicode_type_names if hasattr(ida_nalt, name)}",
        "strings = idautils.Strings(default_setup=False)",
        "try:",
        "    if unicode_only and unicode_types:",
        "        strings.setup(strtypes=list(unicode_types), minlen=2)",
        "    else:",
        "        strings.setup(minlen=2)",
        "except Exception:",
        "    pass",
        "func_starts = set()",
        "for s in strings:",
        "    current_str = str(s)",
        "    string_type = getattr(s, 'type', None)",
        "    if unicode_only and unicode_types and string_type not in unicode_types:",
        "        continue",
        f"    if {match_expr}:",
        "        for xref in idautils.XrefsTo(s.ea, 0):",
        "            func = ida_funcs.get_func(xref.frm)",
        "            if func is not None:",
        "                func_starts.add(int(func.start_ea))",
        "result = json.dumps({'func_starts': [hex(ea) for ea in sorted(func_starts)]})",
    ]
    try:
        result = await session.call_tool(
            name="py_eval",
            arguments={"code": "\n".join(py_lines) + "\n"},
        )
    except Exception as exc:
        if debug:
            print(f"    Preprocess: py_eval failed for xref string search: {exc}")
        return None

    payload = _parse_tool_json_result(result)
    starts = payload.get("func_starts") if isinstance(payload, dict) else None
    if not isinstance(starts, list):
        return None

    parsed: set[int] = set()
    for item in starts:
        try:
            parsed.add(_parse_int_value(item))
        except (TypeError, ValueError):
            continue
    return parsed


async def _collect_xref_func_starts_for_signature(
    *,
    session,
    xref_signature: str,
    debug: bool = False,
) -> set[int] | None:
    if not isinstance(xref_signature, str) or not xref_signature:
        return set()

    try:
        result = await session.call_tool(
            name="find_bytes",
            arguments={"patterns": [xref_signature]},
        )
    except Exception as exc:
        if debug:
            print(f"    Preprocess: find_bytes failed for xref signature: {exc}")
        return None

    payload = _parse_tool_json_result(result)
    if not isinstance(payload, list) or not payload:
        return set()

    raw_matches = payload[0].get("matches", [])
    if not isinstance(raw_matches, list):
        return set()

    code_addrs: set[int] = set()
    for item in raw_matches:
        try:
            code_addrs.add(_parse_int_value(item))
        except (TypeError, ValueError):
            continue

    return await _collect_func_starts_for_code_addrs(
        session=session,
        code_addrs=code_addrs,
        debug=debug,
    )


async def _collect_xref_func_starts_for_ea(
    *,
    session,
    target_ea: int,
    debug: bool = False,
) -> set[int] | None:
    py_code = (
        "import ida_funcs, idautils, json\n"
        f"target_ea = {int(target_ea)}\n"
        "func_starts = set()\n"
        "for xref in idautils.XrefsTo(target_ea, 0):\n"
        "    func = ida_funcs.get_func(xref.frm)\n"
        "    if func is not None:\n"
        "        func_starts.add(int(func.start_ea))\n"
        "result = json.dumps({'func_starts': [hex(ea) for ea in sorted(func_starts)]})\n"
    )
    try:
        result = await session.call_tool(
            name="py_eval",
            arguments={"code": py_code},
        )
    except Exception as exc:
        if debug:
            print(f"    Preprocess: py_eval failed for xref ea {hex(target_ea)}: {exc}")
        return None

    payload = _parse_tool_json_result(result)
    starts = payload.get("func_starts") if isinstance(payload, dict) else None
    if not isinstance(starts, list):
        return None

    parsed: set[int] = set()
    for item in starts:
        try:
            parsed.add(_parse_int_value(item))
        except (TypeError, ValueError):
            continue
    return parsed


def _load_yaml_symbol_addr(
    *,
    binary_dir,
    symbol_name: str,
    va_field: str,
    rva_field: str,
    image_base: int,
    debug: bool = False,
) -> int | None:
    if binary_dir is None:
        return None

    path = Path(binary_dir) / f"{symbol_name}.yaml"
    try:
        payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except OSError:
        if debug:
            print(f"    Preprocess: missing xref dependency YAML: {path}")
        return None

    if not isinstance(payload, dict):
        return None

    for field_name in (va_field, rva_field):
        if field_name not in payload:
            continue
        try:
            parsed = _parse_int_value(payload[field_name])
        except (TypeError, ValueError):
            continue
        if field_name == va_field:
            return parsed
        return image_base + parsed

    if debug:
        print(f"    Preprocess: YAML {path} lacks {va_field}/{rva_field}")
    return None


def _load_xref_ea(
    *,
    binary_dir,
    item: str,
    va_field: str,
    rva_field: str,
    image_base: int,
    debug: bool = False,
) -> int | None:
    if _is_explicit_address_literal(item):
        try:
            return _parse_int_value(item)
        except (TypeError, ValueError):
            return None

    return _load_yaml_symbol_addr(
        binary_dir=binary_dir,
        symbol_name=item,
        va_field=va_field,
        rva_field=rva_field,
        image_base=image_base,
        debug=debug,
    )


async def _append_ea_candidate_sets(
    *,
    session,
    candidate_sets: list[set[int]],
    items: list[str],
    binary_dir,
    va_field: str,
    rva_field: str,
    image_base: int,
    debug: bool,
) -> bool:
    for item in items:
        target_ea = _load_xref_ea(
            binary_dir=binary_dir,
            item=item,
            va_field=va_field,
            rva_field=rva_field,
            image_base=image_base,
            debug=debug,
        )
        if target_ea is None:
            return False

        addr_set = await _collect_xref_func_starts_for_ea(
            session=session,
            target_ea=target_ea,
            debug=debug,
        )
        if addr_set is None or not addr_set:
            return False

        candidate_sets.append(addr_set)
    return True


async def _collect_excluded_ea_func_addrs(
    *,
    session,
    items: list[str],
    binary_dir,
    va_field: str,
    rva_field: str,
    image_base: int,
    debug: bool,
) -> set[int] | None:
    excluded: set[int] = set()
    for item in items:
        target_ea = _load_xref_ea(
            binary_dir=binary_dir,
            item=item,
            va_field=va_field,
            rva_field=rva_field,
            image_base=image_base,
            debug=debug,
        )
        if target_ea is None:
            return None

        addr_set = await _collect_xref_func_starts_for_ea(
            session=session,
            target_ea=target_ea,
            debug=debug,
        )
        if addr_set is None:
            return None

        excluded |= addr_set
    return excluded


async def preprocess_func_xrefs_symbol(
    *,
    session,
    symbol_name: str,
    func_xref: dict,
    binary_dir,
    image_base: int = 0x140000000,
    debug: bool = False,
) -> dict[str, int | str] | None:
    candidate_sets: list[set[int]] = []

    for item in func_xref.get("xref_strings", []):
        addr_set = await _collect_xref_func_starts_for_string(
            session=session,
            xref_string=item,
            unicode_only=False,
            debug=debug,
        )
        if addr_set is None or not addr_set:
            return None
        candidate_sets.append(addr_set)

    for item in func_xref.get("xref_unicode_strings", []):
        addr_set = await _collect_xref_func_starts_for_string(
            session=session,
            xref_string=item,
            unicode_only=True,
            debug=debug,
        )
        if addr_set is None or not addr_set:
            return None
        candidate_sets.append(addr_set)

    if not await _append_ea_candidate_sets(
        session=session,
        candidate_sets=candidate_sets,
        items=func_xref.get("xref_gvs", []),
        binary_dir=binary_dir,
        va_field="gv_va",
        rva_field="gv_rva",
        image_base=image_base,
        debug=debug,
    ):
        return None

    for item in func_xref.get("xref_signatures", []):
        addr_set = await _collect_xref_func_starts_for_signature(
            session=session,
            xref_signature=item,
            debug=debug,
        )
        if addr_set is None or not addr_set:
            return None
        candidate_sets.append(addr_set)

    if not await _append_ea_candidate_sets(
        session=session,
        candidate_sets=candidate_sets,
        items=func_xref.get("xref_funcs", []),
        binary_dir=binary_dir,
        va_field="func_va",
        rva_field="func_rva",
        image_base=image_base,
        debug=debug,
    ):
        return None

    common_funcs = _intersect_addr_sets(candidate_sets)
    if not common_funcs:
        return None

    excluded: set[int] = set()

    for item in func_xref.get("exclude_strings", []):
        addr_set = await _collect_xref_func_starts_for_string(
            session=session,
            xref_string=item,
            unicode_only=False,
            debug=debug,
        )
        if addr_set is None:
            return None
        excluded |= addr_set

    for item in func_xref.get("exclude_unicode_strings", []):
        addr_set = await _collect_xref_func_starts_for_string(
            session=session,
            xref_string=item,
            unicode_only=True,
            debug=debug,
        )
        if addr_set is None:
            return None
        excluded |= addr_set

    excluded_gv_addrs = await _collect_excluded_ea_func_addrs(
        session=session,
        items=func_xref.get("exclude_gvs", []),
        binary_dir=binary_dir,
        va_field="gv_va",
        rva_field="gv_rva",
        image_base=image_base,
        debug=debug,
    )
    if excluded_gv_addrs is None:
        return None
    excluded |= excluded_gv_addrs

    excluded_func_addrs = await _collect_excluded_ea_func_addrs(
        session=session,
        items=func_xref.get("exclude_funcs", []),
        binary_dir=binary_dir,
        va_field="func_va",
        rva_field="func_rva",
        image_base=image_base,
        debug=debug,
    )
    if excluded_func_addrs is None:
        return None
    excluded |= excluded_func_addrs

    for item in func_xref.get("exclude_signatures", []):
        addr_set = await _collect_xref_func_starts_for_signature(
            session=session,
            xref_signature=item,
            debug=debug,
        )
        if addr_set is None:
            return None
        excluded |= addr_set

    common_funcs -= excluded
    if debug:
        print(
            "    Preprocess: func_xrefs candidates for "
            f"{symbol_name}: {[hex(addr) for addr in sorted(common_funcs)]}"
        )

    if len(common_funcs) != 1:
        return None

    func_va = next(iter(common_funcs))
    return {
        "func_name": symbol_name,
        "func_va": func_va,
        "func_rva": func_va - image_base,
    }


async def preprocess_func_symbol(
    *,
    session,
    symbol_name: str,
    metadata: dict,
    pdb_path,
    debug: bool,
    llm_config,
    binary_dir=None,
    image_base: int = 0x140000000,
    func_xref: dict | None = None,
):
    aliases = metadata.get("alias") or [symbol_name]
    lookup_name = aliases[0]

    if pdb_path is not None:
        try:
            payload = resolve_public_symbol(pdb_path, lookup_name)
            return {"func_name": symbol_name, "func_rva": payload["rva"]}
        except KeyError:
            pass

    if func_xref is not None:
        return await preprocess_func_xrefs_symbol(
            session=session,
            symbol_name=symbol_name,
            func_xref=func_xref,
            binary_dir=binary_dir,
            image_base=image_base,
            debug=debug,
        )

    return None
