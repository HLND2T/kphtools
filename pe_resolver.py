from __future__ import annotations

import subprocess
from collections.abc import Iterator
from pathlib import Path

from llvm_tools import LlvmToolNotFoundError, resolve_llvm_tool


LLVM_READOBJ_TIMEOUT_SECONDS = 300


def run_llvm_readobj_exports(
    binary_path: str | Path,
    readobj_path: str | None = None,
) -> str:
    readobj_path = resolve_llvm_tool("llvm-readobj", readobj_path)
    cmd = [readobj_path, "--coff-exports", str(binary_path)]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True,
            timeout=LLVM_READOBJ_TIMEOUT_SECONDS,
        )
    except FileNotFoundError as exc:
        raise LlvmToolNotFoundError("llvm-readobj", f"cannot launch {readobj_path!r}") from exc
    return result.stdout


def _parse_int(value: str) -> int:
    text = value.strip()
    return int(text, 0 if text.lower().startswith("0x") else 10)


def _iter_export_blocks(coff_exports_output: str) -> Iterator[dict[str, str]]:
    in_export = False
    current: dict[str, str] = {}

    for line in coff_exports_output.splitlines():
        stripped = line.strip()
        if stripped == "Export {":
            in_export = True
            current = {}
            continue

        if not in_export:
            continue

        if stripped == "}":
            yield current
            in_export = False
            current = {}
            continue

        key, separator, value = stripped.partition(":")
        if separator:
            current[key.strip()] = value.strip()


def resolve_export_symbol_from_text(
    coff_exports_output: str,
    symbol_name: str,
) -> dict[str, int | str]:
    for export_block in _iter_export_blocks(coff_exports_output):
        if export_block.get("Name") != symbol_name:
            continue
        rva_text = export_block.get("RVA")
        if rva_text is None:
            continue
        return {
            "name": symbol_name,
            "rva": _parse_int(rva_text),
        }

    raise KeyError(symbol_name)


def resolve_export_symbol(
    binary_path: str | Path,
    symbol_name: str,
    readobj_path: str | None = None,
) -> dict[str, int | str]:
    try:
        exports_output = run_llvm_readobj_exports(
            binary_path,
            readobj_path=readobj_path,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise KeyError(symbol_name) from exc

    return resolve_export_symbol_from_text(exports_output, symbol_name)
