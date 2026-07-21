"""Parse and normalize the four-section LLM_DECOMPILE YAML contract."""

from __future__ import annotations

import re
from typing import Any

import yaml


LLM_DECOMPILE_RESULT_SECTIONS = (
    "found_call",
    "found_funcptr",
    "found_gv",
    "found_struct_offset",
)

_RESULT_SYMBOL_KEYS = {
    "found_call": "func_name",
    "found_funcptr": "funcptr_name",
    "found_gv": "gv_name",
}
_RESULT_REQUIRED_KEYS = {
    "found_call": ("insn_va", "insn_disasm", "func_name"),
    "found_funcptr": ("insn_va", "insn_disasm", "funcptr_name"),
    "found_gv": ("insn_va", "insn_disasm", "gv_name"),
    "found_struct_offset": (
        "insn_va",
        "insn_disasm",
        "offset",
        "size",
        "struct_name",
        "member_name",
    ),
}


def empty_llm_decompile_result() -> dict[str, list[dict[str, str]]]:
    return {section: [] for section in LLM_DECOMPILE_RESULT_SECTIONS}


def normalize_requested_symbol_names(values: Any) -> tuple[str, ...]:
    if not isinstance(values, (list, tuple, set, frozenset)):
        values = [values]
    return tuple(
        dict.fromkeys(
            text
            for value in values
            if (text := str(value or "").strip())
        )
    )


def get_llm_result_symbol_name(section_name: str, entry: dict[str, Any]) -> str:
    if section_name == "found_struct_offset":
        struct_name = str(entry.get("struct_name", "")).strip()
        member_name = str(entry.get("member_name", "")).strip()
        return f"{struct_name}->{member_name}" if struct_name and member_name else ""
    symbol_key = _RESULT_SYMBOL_KEYS.get(section_name)
    return str(entry.get(symbol_key, "") if symbol_key else "").strip()


def iter_llm_instruction_entries(result: dict[str, Any]):
    for section_name in LLM_DECOMPILE_RESULT_SECTIONS:
        for entry_index, entry in enumerate(result.get(section_name, [])):
            yield section_name, entry_index, entry


def _new_issue(issue_type: str, message: str, **details: Any) -> dict[str, Any]:
    return {"issue_type": issue_type, "message": message, **details}


def _extract_yaml_candidates(response_text: str) -> list[str]:
    text = str(response_text or "").strip()
    if not text:
        return []
    candidates = [
        match.group(1).strip()
        for match in re.finditer(
            r"```(?:yaml|yml)[ \t]*\n?(.*?)```",
            text,
            re.IGNORECASE | re.DOTALL,
        )
    ]
    if not candidates:
        candidates = [
            match.group(1).strip()
            for match in re.finditer(r"```[ \t]*\n(.*?)```", text, re.DOTALL)
        ]
    return candidates or [text]


def _repair_glued_headers(text: str) -> str:
    section_pattern = "|".join(re.escape(section) for section in LLM_DECOMPILE_RESULT_SECTIONS)
    return re.sub(
        rf"(?<!^)(?<!\n)(?P<section>{section_pattern}):(?=\s*(?:\[|\n))",
        r"\n\g<section>:",
        text,
    )


def _load_yaml_document(response_text: str):
    candidates = _extract_yaml_candidates(response_text)
    if not candidates:
        return None, [_new_issue("yaml_parse_error", "The YAML response was blank.")]
    last_issue = None
    for candidate in candidates:
        for candidate_text in dict.fromkeys((candidate, _repair_glued_headers(candidate))):
            try:
                parsed = yaml.load(candidate_text, Loader=yaml.BaseLoader)
            except yaml.YAMLError as exc:
                last_issue = _new_issue(
                    "yaml_parse_error",
                    f"The YAML could not be parsed: {exc}.",
                )
                continue
            if isinstance(parsed, dict):
                return parsed, []
            root_type = type(parsed).__name__ if parsed is not None else "null"
            last_issue = _new_issue(
                "yaml_root_type_mismatch",
                f"The YAML root must be a mapping, but it was {root_type}.",
                actual_type=root_type,
            )
    return None, [last_issue or _new_issue("yaml_parse_error", "The YAML response was empty.")]


def _normalize_entries(section_name: str, entries: Any) -> list[dict[str, str]]:
    if not isinstance(entries, list):
        return []
    normalized = []
    best_index_by_member: dict[tuple[str, str], int] = {}
    best_offset_by_member: dict[tuple[str, str], int] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        item = {
            key: str(entry.get(key, "")).strip()
            for key in _RESULT_REQUIRED_KEYS[section_name]
        }
        if not all(item.values()):
            continue
        if section_name == "found_struct_offset":
            bit_offset = str(entry.get("bit_offset", "")).strip()
            if bit_offset:
                item["bit_offset"] = bit_offset
            try:
                offset = int(item["offset"].rstrip("hH"), 16) if item["offset"].lower().endswith("h") else int(item["offset"], 0)
            except ValueError:
                offset = None
            if offset is not None:
                member_key = (item["struct_name"], item["member_name"])
                existing_index = best_index_by_member.get(member_key)
                if existing_index is not None:
                    if offset < best_offset_by_member[member_key]:
                        normalized[existing_index] = item
                        best_offset_by_member[member_key] = offset
                    continue
                best_index_by_member[member_key] = len(normalized)
                best_offset_by_member[member_key] = offset
        normalized.append(item)
    return normalized


def _normalize_mapping(parsed: dict[str, Any]) -> dict[str, list[dict[str, str]]]:
    return {
        section: _normalize_entries(section, parsed.get(section, []))
        for section in LLM_DECOMPILE_RESULT_SECTIONS
    }


def _validate_raw_section(
    section_name: str,
    entries: Any,
    location_prefix: str = "",
) -> tuple[list[dict[str, Any]], int]:
    location = f"{location_prefix}{section_name}"
    if not isinstance(entries, list):
        return [
            _new_issue(
                "yaml_section_type_mismatch",
                f"{location} must be a list, but it was {type(entries).__name__}.",
                section_name=section_name,
                actual_type=type(entries).__name__,
            )
        ], 0
    issues = []
    valid_count = 0
    for entry_index, entry in enumerate(entries):
        entry_location = f"{location}[{entry_index}]"
        if not isinstance(entry, dict):
            issues.append(
                _new_issue(
                    "yaml_entry_shape_mismatch",
                    f"{entry_location} must be a mapping, but it was {type(entry).__name__}.",
                )
            )
            continue
        invalid_fields = [
            key
            for key in _RESULT_REQUIRED_KEYS[section_name]
            if isinstance(entry.get(key), (dict, list))
            or not str(entry.get(key, "") or "").strip()
        ]
        if invalid_fields:
            issues.append(
                _new_issue(
                    "yaml_entry_shape_mismatch",
                    f"{entry_location} has missing or invalid fields: {', '.join(invalid_fields)}.",
                    section_name=section_name,
                    entry_index=entry_index,
                    invalid_fields=invalid_fields,
                )
            )
            continue
        valid_count += 1
    return issues, valid_count


def _classify_canonical(parsed: dict[str, Any], root_keys: set[str]):
    recognized = set(LLM_DECOMPILE_RESULT_SECTIONS)
    unknown_keys = sorted(root_keys - recognized)
    issues = []
    if unknown_keys:
        message = f"Unknown or mixed top-level YAML keys: {', '.join(unknown_keys)}."
        if "found_vcall" in unknown_keys:
            message += " found_vcall is unsupported by kphtools."
        issues.append(
            _new_issue(
                "yaml_schema_mismatch",
                message,
                unknown_keys=unknown_keys,
            )
        )
    valid_count = 0
    for section_name in LLM_DECOMPILE_RESULT_SECTIONS:
        if section_name not in parsed:
            continue
        section_issues, section_count = _validate_raw_section(
            section_name,
            parsed[section_name],
        )
        issues.extend(section_issues)
        valid_count += section_count
    result = _normalize_mapping(parsed)
    if issues:
        return result, "invalid", issues
    if valid_count:
        return result, "canonical", []
    if root_keys == recognized and all(not parsed[section] for section in recognized):
        return result, "explicit_empty", []
    return result, "invalid", [
        _new_issue(
            "yaml_schema_mismatch",
            "A no-result response must contain all four canonical sections with empty lists.",
        )
    ]


def _classify_wrapped(
    parsed: dict[str, Any],
    root_keys: set[str],
    requested_symbols: set[str],
):
    unknown_wrappers = sorted(root_keys - requested_symbols)
    if unknown_wrappers:
        return empty_llm_decompile_result(), "invalid", [
            _new_issue(
                "yaml_schema_mismatch",
                f"Top-level wrapper symbols were not requested: {', '.join(unknown_wrappers)}.",
                unknown_keys=unknown_wrappers,
            )
        ]
    flattened = empty_llm_decompile_result()
    issues = []
    valid_count = 0
    recognized = set(LLM_DECOMPILE_RESULT_SECTIONS)
    for wrapper_symbol, wrapped_sections in parsed.items():
        if not isinstance(wrapped_sections, dict):
            issues.append(
                _new_issue(
                    "yaml_schema_mismatch",
                    f"Wrapper {wrapper_symbol!r} must contain a mapping of result sections.",
                )
            )
            continue
        nested_keys = set(wrapped_sections)
        unknown_sections = sorted(nested_keys - recognized)
        if unknown_sections:
            message = (
                f"Wrapper {wrapper_symbol!r} contains unknown result sections: "
                f"{', '.join(unknown_sections)}."
            )
            if "found_vcall" in unknown_sections:
                message += " found_vcall is unsupported by kphtools."
            issues.append(_new_issue("yaml_schema_mismatch", message))
        for section_name in nested_keys & recognized:
            entries = wrapped_sections[section_name]
            section_issues, section_count = _validate_raw_section(
                section_name,
                entries,
                f"{wrapper_symbol}.",
            )
            issues.extend(section_issues)
            valid_count += section_count
            if not isinstance(entries, list):
                continue
            for entry_index, entry in enumerate(entries):
                if not isinstance(entry, dict):
                    continue
                entry_symbol = get_llm_result_symbol_name(section_name, entry)
                if entry_symbol != wrapper_symbol:
                    issues.append(
                        _new_issue(
                            "wrapped_symbol_mismatch",
                            f"{wrapper_symbol}.{section_name}[{entry_index}] identifies "
                            f"{entry_symbol!r}, not wrapper {wrapper_symbol!r}.",
                        )
                    )
                flattened[section_name].append(entry)
    if not valid_count:
        issues.append(
            _new_issue(
                "yaml_schema_mismatch",
                "A symbol-wrapped compatibility response must contain at least one valid result entry.",
            )
        )
    result = _normalize_mapping(flattened)
    return (result, "invalid", issues) if issues else (result, "symbol_wrapped", [])


def parse_llm_decompile_response_with_issues(
    response_text: str,
    requested_symbol_names: Any = None,
) -> dict[str, Any]:
    parsed, load_issues = _load_yaml_document(response_text)
    if load_issues:
        return {
            "result": empty_llm_decompile_result(),
            "schema_kind": "invalid",
            "issues": load_issues,
            "root_keys": [],
            "compatibility_flattened": False,
        }
    if parsed is None:
        raise AssertionError("YAML loader returned no document without an issue")
    root_keys = set(parsed)
    if not root_keys:
        result, schema_kind, issues = empty_llm_decompile_result(), "invalid", [
            _new_issue("yaml_schema_mismatch", "The YAML mapping must not be empty.")
        ]
    elif root_keys & set(LLM_DECOMPILE_RESULT_SECTIONS) or "found_vcall" in root_keys:
        result, schema_kind, issues = _classify_canonical(parsed, root_keys)
    else:
        requested = set(normalize_requested_symbol_names(requested_symbol_names))
        result, schema_kind, issues = _classify_wrapped(parsed, root_keys, requested)
    return {
        "result": result,
        "schema_kind": schema_kind,
        "issues": issues,
        "root_keys": sorted(str(key) for key in root_keys),
        "compatibility_flattened": schema_kind == "symbol_wrapped",
    }


def parse_llm_decompile_response(response_text: str) -> dict[str, list[dict[str, str]]]:
    return parse_llm_decompile_response_with_issues(response_text)["result"]
