"""Validate LLM_DECOMPILE results against target instructions and request context."""

from __future__ import annotations

import re
from typing import Any

from ida_llm_response import (
    LLM_DECOMPILE_RESULT_SECTIONS,
    get_llm_result_symbol_name,
    iter_llm_instruction_entries,
    normalize_requested_symbol_names,
)


_DISASM_ADDRESS_LINE_RE = re.compile(
    r"^\s*(?:[^:\s]+:)?([0-9A-Fa-f]{4,16})\s+(.+?)\s*$"
)


def normalize_disasm_whitespace(value: Any) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip()


def _strip_disasm_comment(line: str) -> str:
    quote = None
    escaped = False
    for index, char in enumerate(line):
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in ("'", '"'):
            quote = char
        elif char == ";":
            return line[:index]
    return line


def build_target_disasm_index(
    target_disasm_codes: Any,
) -> tuple[dict[int, set[str]], dict[str, set[int]]]:
    if isinstance(target_disasm_codes, str):
        target_disasm_codes = [target_disasm_codes]
    if not isinstance(target_disasm_codes, (list, tuple)):
        target_disasm_codes = []
    instructions_by_va: dict[int, set[str]] = {}
    addresses_by_instruction: dict[str, set[int]] = {}
    for code in target_disasm_codes:
        for raw_line in str(code or "").splitlines():
            line = _strip_disasm_comment(raw_line).rstrip()
            match = _DISASM_ADDRESS_LINE_RE.match(line)
            if match is None:
                continue
            instruction = normalize_disasm_whitespace(match.group(2))
            if not instruction:
                continue
            insn_va = int(match.group(1), 16)
            instructions_by_va.setdefault(insn_va, set()).add(instruction)
            addresses_by_instruction.setdefault(instruction, set()).add(insn_va)
    return instructions_by_va, addresses_by_instruction


def normalize_expected_result_sections(value: Any) -> dict[str, set[str]]:
    if not isinstance(value, dict):
        return {}
    normalized: dict[str, set[str]] = {}
    for symbol_name, sections in value.items():
        name = str(symbol_name or "").strip()
        if isinstance(sections, str):
            sections = [sections]
        if not name or not isinstance(sections, (list, tuple, set, frozenset)):
            continue
        valid = {
            str(section or "").strip()
            for section in sections
            if str(section or "").strip() in LLM_DECOMPILE_RESULT_SECTIONS
        }
        if valid:
            normalized[name] = valid
    return normalized


def _parse_int(value: Any) -> int | None:
    text = str(value or "").strip().replace("_", "")
    if not text:
        return None
    if text.lower().endswith("h"):
        try:
            return int(text[:-1], 16)
        except ValueError:
            return None
    try:
        return int(text, 0)
    except ValueError:
        return None


def _validate_instruction_pairs(
    result: dict[str, Any],
    disasm_index: tuple[dict[int, set[str]], dict[str, set[int]]],
) -> list[dict[str, Any]]:
    instructions_by_va, addresses_by_instruction = disasm_index
    issues = []
    for section_name, entry_index, entry in iter_llm_instruction_entries(result):
        insn_va_text = str(entry.get("insn_va", "")).strip()
        reported_disasm = normalize_disasm_whitespace(entry.get("insn_disasm"))
        insn_va = _parse_int(insn_va_text)
        actual_disasms = instructions_by_va.get(insn_va, set()) if insn_va is not None else set()
        if reported_disasm in actual_disasms:
            continue
        issues.append(
            {
                "issue_type": "instruction_mismatch",
                "section_name": section_name,
                "entry_index": entry_index,
                "insn_va": insn_va_text,
                "reported_disasm": reported_disasm,
                "actual_disasms": sorted(actual_disasms),
                "candidate_vas": sorted(addresses_by_instruction.get(reported_disasm, set())),
            }
        )
    return issues


def _validate_symbols_and_sections(
    result: dict[str, Any],
    requested_symbol_names: Any,
    expected_result_sections: Any,
) -> list[dict[str, Any]]:
    requested = set(normalize_requested_symbol_names(requested_symbol_names))
    expected = normalize_expected_result_sections(expected_result_sections)
    issues = []
    for section_name, entry_index, entry in iter_llm_instruction_entries(result):
        symbol_name = get_llm_result_symbol_name(section_name, entry)
        if requested and symbol_name not in requested:
            issues.append(
                {
                    "issue_type": "unexpected_result_symbol",
                    "section_name": section_name,
                    "entry_index": entry_index,
                    "symbol_name": symbol_name,
                    "requested_symbols": sorted(requested),
                    "message": (
                        f"{section_name}[{entry_index}] identifies {symbol_name!r}, "
                        f"which is not in the requested symbol set."
                    ),
                }
            )
        expected_sections = expected.get(symbol_name, set())
        if expected_sections and section_name not in expected_sections:
            issues.append(
                {
                    "issue_type": "result_section_mismatch",
                    "section_name": section_name,
                    "entry_index": entry_index,
                    "symbol_name": symbol_name,
                    "reported_disasm": normalize_disasm_whitespace(entry.get("insn_disasm")),
                    "expected_sections": sorted(expected_sections),
                }
            )
    return issues


def validate_llm_decompile_result(
    result: dict[str, Any],
    disasm_index: tuple[dict[int, set[str]], dict[str, set[int]]],
    expected_result_sections: Any,
    *,
    requested_symbol_names: Any = None,
) -> list[dict[str, Any]]:
    return _validate_instruction_pairs(result, disasm_index) + _validate_symbols_and_sections(
        result,
        requested_symbol_names,
        expected_result_sections,
    )
