from __future__ import annotations

import re
import subprocess
from pathlib import Path


PUBLIC_RE = re.compile(r"^[0-9A-Fa-f]{4}:[0-9A-Fa-f]{8}\s+([^\s]+)$", re.MULTILINE)
TYPE_HEADER_RE = re.compile(r"^\s*([0-9A-Fa-fx]+)\s*\|\s*(LF_[A-Z0-9_]+)\b")
FIELD_LIST_RE = re.compile(r"field list:\s*(?:<fieldlist\s+)?([0-9A-Fa-fx]+)")
OFFSET_RE = re.compile(r"offset\s*=\s*(0x[0-9A-Fa-f]+|\d+)")
TYPE_REF_RE = re.compile(r"(?:type|Type)\s*=\s*([^,\]\s]+)")
BIT_OFFSET_RE = re.compile(r"(?:position|bit offset)\s*=\s*(\d+)")


def run_llvm_pdbutil(
    pdb_path: str | Path,
    mode: str,
    pdbutil_path: str = "llvm-pdbutil",
) -> str:
    cmd = [pdbutil_path, "dump", mode, str(pdb_path)]
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    return result.stdout


def _normalize_record_id(record_id: str) -> str:
    return record_id.strip().lower().removeprefix("0x")


def _parse_int(value: str) -> int:
    if value.lower().startswith("0x"):
        return int(value, 16)
    return int(value, 10)


def _find_field_list_id(
    lines: list[str],
    type_name: str | None = None,
    type_id: str | None = None,
) -> str | None:
    allowed_kinds = {
        "LF_STRUCTURE",
        "LF_STRUCTURE2",
        "LF_UNION",
        "LF_UNION2",
        "LF_CLASS",
        "LF_CLASS2",
    }
    normalized_type_id = _normalize_record_id(type_id) if type_id else None

    for index, line in enumerate(lines):
        header_match = TYPE_HEADER_RE.match(line)
        if not header_match:
            continue

        record_id, kind = header_match.groups()
        if kind not in allowed_kinds:
            continue
        if type_name is not None and f"`{type_name}`" not in line:
            continue
        if normalized_type_id is not None and _normalize_record_id(record_id) != normalized_type_id:
            continue

        for body_line in lines[index + 1 :]:
            if TYPE_HEADER_RE.match(body_line):
                break
            field_list_match = FIELD_LIST_RE.search(body_line)
            if field_list_match:
                return field_list_match.group(1)

    return None


def _get_field_list_lines(lines: list[str], field_list_id: str) -> list[str]:
    normalized_field_list_id = _normalize_record_id(field_list_id)

    for index, line in enumerate(lines):
        header_match = TYPE_HEADER_RE.match(line)
        if not header_match:
            continue

        record_id, kind = header_match.groups()
        if kind != "LF_FIELDLIST":
            continue
        if _normalize_record_id(record_id) != normalized_field_list_id:
            continue

        field_list_lines: list[str] = []
        for body_line in lines[index + 1 :]:
            if TYPE_HEADER_RE.match(body_line):
                break
            field_list_lines.append(body_line)
        return field_list_lines

    return []


def _extract_member_name(line: str) -> str | None:
    member_name_match = re.search(r"member name = `([^`]+)`", line)
    if member_name_match:
        return member_name_match.group(1)

    bracket_name_match = re.search(r"name\s*=\s*`([^`]+)`", line)
    if bracket_name_match:
        return bracket_name_match.group(1)

    return None


def _find_member_entry(
    lines: list[str],
    field_list_id: str,
    member_name: str,
) -> dict[str, int | str | None] | None:
    field_list_lines = _get_field_list_lines(lines, field_list_id)

    for index, line in enumerate(field_list_lines):
        if "LF_MEMBER" not in line:
            continue
        if _extract_member_name(line) != member_name:
            continue

        offset_match = OFFSET_RE.search(line)
        if not offset_match:
            continue

        type_match = TYPE_REF_RE.search(line)
        bit_offset = None
        if index > 0 and "LF_BITFIELD" in field_list_lines[index - 1]:
            bit_match = BIT_OFFSET_RE.search(field_list_lines[index - 1])
            if bit_match:
                bit_offset = int(bit_match.group(1))

        return {
            "offset": _parse_int(offset_match.group(1)),
            "type_id": type_match.group(1) if type_match else None,
            "bit_offset": bit_offset,
        }

    return None


def _lookup_type_bit_offset(lines: list[str], type_id: str | None) -> int | None:
    if type_id is None:
        return None

    normalized_type_id = _normalize_record_id(type_id)
    for index, line in enumerate(lines):
        header_match = TYPE_HEADER_RE.match(line)
        if not header_match:
            continue

        record_id, kind = header_match.groups()
        if kind != "LF_BITFIELD":
            continue
        if _normalize_record_id(record_id) != normalized_type_id:
            continue

        same_line_match = BIT_OFFSET_RE.search(line)
        if same_line_match:
            return int(same_line_match.group(1))

        for body_line in lines[index + 1 :]:
            if TYPE_HEADER_RE.match(body_line):
                break
            bit_match = BIT_OFFSET_RE.search(body_line)
            if bit_match:
                return int(bit_match.group(1))
        break

    return None


def _resolve_direct_member(
    lines: list[str],
    struct_name: str,
    member_name: str,
) -> dict[str, int | str | None] | None:
    field_list_id = _find_field_list_id(lines, type_name=struct_name)
    if field_list_id is None:
        return None
    return _find_member_entry(lines, field_list_id, member_name)


def _resolve_member_by_type_id(
    lines: list[str],
    type_id: str | None,
    member_name: str,
) -> dict[str, int | str | None] | None:
    if type_id is None:
        return None

    field_list_id = _find_field_list_id(lines, type_id=type_id)
    if field_list_id is None:
        return None
    return _find_member_entry(lines, field_list_id, member_name)


def _resolve_member(
    lines: list[str],
    struct_name: str,
    member_name: str,
) -> dict[str, int | str | None] | None:
    if "." not in member_name:
        return _resolve_direct_member(lines, struct_name, member_name)

    parent_name, nested_name = member_name.split(".", 1)
    parent_entry = _resolve_direct_member(lines, struct_name, parent_name)
    if parent_entry is None:
        return None

    nested_entry = _resolve_member_by_type_id(
        lines,
        parent_entry.get("type_id"),
        nested_name,
    )
    if nested_entry is None:
        nested_entry = _resolve_direct_member(lines, struct_name, nested_name)
        if nested_entry is None:
            return None

    return {
        "offset": int(parent_entry["offset"]) + int(nested_entry["offset"]),
        "type_id": nested_entry.get("type_id"),
        "bit_offset": nested_entry.get("bit_offset"),
    }


def resolve_struct_symbol_from_text(
    types_output: str,
    symbol_expr: str,
    bits: bool = False,
) -> dict[str, int | str]:
    lines = types_output.splitlines()

    for candidate in symbol_expr.split(","):
        struct_name, member_name = candidate.split("->", 1)
        member_entry = _resolve_member(lines, struct_name, member_name)
        if member_entry is None:
            continue

        payload: dict[str, int | str] = {
            "struct_name": struct_name,
            "member_name": member_name,
            "offset": int(member_entry["offset"]),
        }

        if bits:
            bit_offset = member_entry.get("bit_offset")
            if bit_offset is None:
                bit_offset = _lookup_type_bit_offset(lines, member_entry.get("type_id"))
            if bit_offset is None:
                raise KeyError(f"bitfield position missing for {symbol_expr}")
            payload["bit_offset"] = int(bit_offset)

        return payload

    raise KeyError(symbol_expr)


def resolve_public_symbol_from_text(
    publics_output: str,
    sections_output: str,
    symbol_name: str,
) -> dict[str, int | str]:
    symbol_pattern = re.compile(
        rf"^[0-9A-Fa-f]{{4}}:([0-9A-Fa-f]{{8}})\s+{re.escape(symbol_name)}$",
        re.MULTILINE,
    )
    match = symbol_pattern.search(publics_output)
    if not match:
        raise KeyError(symbol_name)

    return {
        "name": symbol_name,
        "rva": int(match.group(1), 16),
    }


def resolve_struct_symbol(
    pdb_path: str | Path,
    symbol_expr: str,
    bits: bool = False,
    pdbutil_path: str = "llvm-pdbutil",
) -> dict[str, int | str]:
    return resolve_struct_symbol_from_text(
        run_llvm_pdbutil(pdb_path, "-types", pdbutil_path=pdbutil_path),
        symbol_expr,
        bits=bits,
    )


def resolve_public_symbol(
    pdb_path: str | Path,
    symbol_name: str,
    pdbutil_path: str = "llvm-pdbutil",
) -> dict[str, int | str]:
    publics_output = run_llvm_pdbutil(
        pdb_path,
        "-publics",
        pdbutil_path=pdbutil_path,
    )
    sections_output = run_llvm_pdbutil(
        pdb_path,
        "-section-headers",
        pdbutil_path=pdbutil_path,
    )
    return resolve_public_symbol_from_text(publics_output, sections_output, symbol_name)
