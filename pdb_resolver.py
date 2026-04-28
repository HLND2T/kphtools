from __future__ import annotations

import re
import subprocess
from pathlib import Path


PUBLIC_RE = re.compile(r"^[0-9A-Fa-f]{4}:[0-9A-Fa-f]{8}\s+([^\s]+)$", re.MULTILINE)


def run_llvm_pdbutil(
    pdb_path: str | Path,
    mode: str,
    pdbutil_path: str = "llvm-pdbutil",
) -> str:
    cmd = [pdbutil_path, "dump", mode, str(pdb_path)]
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    return result.stdout


def resolve_struct_symbol_from_text(
    types_output: str,
    symbol_expr: str,
    bits: bool = False,
) -> dict[str, int | str]:
    for candidate in symbol_expr.split(","):
        struct_name, member_name = candidate.split("->", 1)
        member_pattern = re.compile(
            rf"offset = 0x([0-9A-Fa-f]+), member name = `{re.escape(member_name)}`"
        )
        struct_marker = f"`{struct_name}`"
        if struct_marker not in types_output:
            continue
        member_match = member_pattern.search(types_output)
        if not member_match:
            continue

        payload: dict[str, int | str] = {
            "struct_name": struct_name,
            "member_name": member_name,
            "offset": int(member_match.group(1), 16),
        }

        if bits:
            bit_match = re.search(r"position = ([0-9]+)", types_output)
            if not bit_match:
                raise KeyError(f"bitfield position missing for {symbol_expr}")
            payload["bit_offset"] = int(bit_match.group(1))

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
