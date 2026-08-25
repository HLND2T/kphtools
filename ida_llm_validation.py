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
_DISASM_MEMORY_DISPLACEMENT_RE = re.compile(
    r"(?P<sign>^|[+-])\s*"
    r"(?P<value>0x[0-9A-Fa-f]+|[0-9A-Fa-f]+[hH]|\d+)"
    r"(?=\s*(?:[+-]|$))"
)
_DISASM_ARM64_MEMORY_DISPLACEMENT_RE = re.compile(
    r"(?:^|,)\s*#\s*(?P<sign>[+-]?)\s*"
    r"(?P<value>0x[0-9A-Fa-f]+|\d+)"
    r"(?=\s*(?:,|$))",
    re.IGNORECASE,
)
_DISASM_BASE_REGISTER_PATTERN = (
    r"(?:[re](?:ax|bx|cx|dx|si|di|bp|sp)|r(?:[89]|1[0-5])d?|[re]ip)"
)
_DISASM_ARM64_BASE_REGISTER_PATTERN = r"(?:[xw](?:[0-9]|[12][0-9]|30)|sp)"
_DISASM_ZERO_OFFSET_MEMORY_RE = re.compile(
    rf"^\s*(?:"
    rf"{_DISASM_BASE_REGISTER_PATTERN}(?:\s*\+\s*(?:0x0+|0+[hH]?))?"
    rf"|{_DISASM_ARM64_BASE_REGISTER_PATTERN}(?:\s*,\s*#\s*[+]?\s*(?:0x0+|0+))?"
    rf")\s*$",
    re.IGNORECASE,
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


def normalize_instruction_validations(
    instruction_validations: Any,
) -> dict[str, dict[str, Any]] | None:
    if instruction_validations is None:
        return {}
    if not isinstance(instruction_validations, dict):
        return None

    normalized: dict[str, dict[str, Any]] = {}
    for symbol_name, raw_validation in instruction_validations.items():
        name = str(symbol_name or "").strip()
        if not name or not isinstance(raw_validation, dict):
            return None
        if set(raw_validation) - {"instruction_rules", "expected_size"}:
            return None

        validation: dict[str, Any] = {}
        if "instruction_rules" in raw_validation:
            raw_rules = raw_validation.get("instruction_rules")
            if not isinstance(raw_rules, (tuple, list)) or not raw_rules:
                return None
            compiled_rules = []
            for raw_rule in raw_rules:
                if not isinstance(raw_rule, dict) or set(raw_rule) != {"regex", "text"}:
                    return None
                regex_value = raw_rule.get("regex")
                instruction_text = raw_rule.get("text")
                regex_pattern = getattr(regex_value, "pattern", regex_value)
                if (
                    not isinstance(regex_value, (str, re.Pattern))
                    or not isinstance(regex_pattern, str)
                    or not regex_pattern.strip()
                    or not isinstance(instruction_text, str)
                    or not instruction_text.strip()
                ):
                    return None
                try:
                    compiled_regex = (
                        regex_value
                        if isinstance(regex_value, re.Pattern)
                        else re.compile(regex_value)
                    )
                except re.error:
                    return None
                compiled_rules.append(
                    {"regex": compiled_regex, "text": instruction_text}
                )
            validation["instruction_rules"] = tuple(compiled_rules)

        if "expected_size" in raw_validation:
            expected_size = raw_validation.get("expected_size")
            if (
                isinstance(expected_size, bool)
                or not isinstance(expected_size, int)
                or expected_size <= 0
            ):
                return None
            validation["expected_size"] = expected_size

        if validation:
            normalized[name] = validation
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
    required_result_symbols: Any,
) -> list[dict[str, Any]]:
    requested = set(normalize_requested_symbol_names(requested_symbol_names))
    required = (
        requested
        if required_result_symbols is None
        else set(normalize_requested_symbol_names(required_result_symbols))
    )
    expected = normalize_expected_result_sections(expected_result_sections)
    issues = []
    symbols_in_expected_sections: set[str] = set()
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
        elif expected_sections:
            symbols_in_expected_sections.add(symbol_name)
    for symbol_name in sorted(requested & required & expected.keys()):
        if symbol_name in symbols_in_expected_sections:
            continue
        expected_sections = sorted(expected[symbol_name])
        issues.append(
            {
                "issue_type": "missing_result_symbol",
                "symbol_name": symbol_name,
                "expected_sections": expected_sections,
                "message": (
                    f"Requested symbol {symbol_name!r} is missing; return it in "
                    f"one of these sections: {', '.join(expected_sections)}."
                ),
            }
        )
    return issues


def _extract_memory_operands(disasm: Any) -> list[str]:
    return re.findall(r"\[([^\]]+)\]", str(disasm or ""))


def _extract_memory_displacements(disasm: Any) -> set[int]:
    displacements = set()
    for memory_operand in _extract_memory_operands(disasm):
        for match in _DISASM_MEMORY_DISPLACEMENT_RE.finditer(memory_operand):
            value = _parse_int(match.group("value"))
            if value is None:
                continue
            if match.group("sign") == "-":
                value = -value
            displacements.add(value)
        for match in _DISASM_ARM64_MEMORY_DISPLACEMENT_RE.finditer(memory_operand):
            value = _parse_int(match.group("value"))
            if value is None:
                continue
            if match.group("sign") == "-":
                value = -value
            displacements.add(value)
    return displacements


def _instruction_contains_memory_offset(disasm: Any, offset: int | None) -> bool:
    if offset is None:
        return False
    if offset != 0:
        return offset in _extract_memory_displacements(disasm)
    return any(
        _DISASM_ZERO_OFFSET_MEMORY_RE.fullmatch(operand)
        for operand in _extract_memory_operands(disasm)
    )


def _validate_instruction_constraints(
    result: dict[str, Any],
    instruction_validations: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    issues = []
    for section_name, entry_index, entry in iter_llm_instruction_entries(result):
        symbol_name = get_llm_result_symbol_name(section_name, entry)
        validation = instruction_validations.get(symbol_name)
        if not validation:
            continue

        reported_disasm = normalize_disasm_whitespace(entry.get("insn_disasm"))
        instruction_rules = validation.get("instruction_rules", ())
        if instruction_rules and not any(
            rule["regex"].fullmatch(reported_disasm)
            for rule in instruction_rules
        ):
            issues.append(
                {
                    "issue_type": "instruction_rule_mismatch",
                    "section_name": section_name,
                    "entry_index": entry_index,
                    "symbol_name": symbol_name,
                    "reported_disasm": reported_disasm,
                    "instruction_rule_texts": [
                        rule["text"] for rule in instruction_rules
                    ],
                }
            )

        if section_name != "found_struct_offset":
            continue

        if "expected_size" in validation:
            reported_size_text = str(entry.get("size", "")).strip()
            reported_size = _parse_int(reported_size_text)
            if reported_size != validation["expected_size"]:
                issues.append(
                    {
                        "issue_type": "instruction_size_mismatch",
                        "section_name": section_name,
                        "entry_index": entry_index,
                        "symbol_name": symbol_name,
                        "reported_disasm": reported_disasm,
                        "reported_size": reported_size_text,
                        "expected_size": validation["expected_size"],
                    }
                )

        offset_text = str(entry.get("offset", "")).strip()
        offset = _parse_int(offset_text)
        displacements = _extract_memory_displacements(reported_disasm)
        if not _instruction_contains_memory_offset(reported_disasm, offset):
            issues.append(
                {
                    "issue_type": "struct_offset_displacement_mismatch",
                    "section_name": section_name,
                    "entry_index": entry_index,
                    "symbol_name": symbol_name,
                    "reported_disasm": reported_disasm,
                    "offset": offset_text,
                    "instruction_displacements": sorted(displacements),
                }
            )
    return issues


def validate_llm_decompile_result(
    result: dict[str, Any],
    disasm_index: tuple[dict[int, set[str]], dict[str, set[int]]],
    expected_result_sections: Any,
    *,
    requested_symbol_names: Any = None,
    required_result_symbols: Any = None,
    instruction_validations: Any = None,
) -> list[dict[str, Any]]:
    normalized_validations = normalize_instruction_validations(
        instruction_validations
    )
    if normalized_validations is None:
        raise ValueError("invalid instruction_validations")
    return (
        _validate_instruction_pairs(result, disasm_index)
        + _validate_symbols_and_sections(
            result,
            requested_symbol_names,
            expected_result_sections,
            required_result_symbols,
        )
        + _validate_instruction_constraints(result, normalized_validations)
    )
