"""Render LLM_DECOMPILE prompts and validation correction messages."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from ida_llm_response import LLM_DECOMPILE_RESULT_SECTIONS


SYSTEM_PROMPT = "You are a Windows-kernel reverse-engineering expert."


def _strip_line_comment_outside_quotes(line: str, marker: str) -> str:
    quote = None
    escaped = False
    index = 0
    while index < len(line):
        char = line[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            index += 1
            continue
        if char in ("'", '"'):
            quote = char
        elif line.startswith(marker, index):
            return line[:index]
        index += 1
    return line


def strip_disasm_comments(text: Any) -> str:
    cleaned_lines = []
    for line in str(text or "").splitlines():
        cleaned = _strip_line_comment_outside_quotes(line, ";").rstrip()
        stripped = cleaned.strip()
        if not stripped:
            continue
        if re.fullmatch(r"[\w.$?@]+:[0-9A-Fa-f`]+", stripped):
            continue
        cleaned_lines.append(cleaned)
    return "\n".join(cleaned_lines)


def strip_c_like_comments(text: Any) -> str:
    chars = []
    quote = None
    escaped = False
    state = "code"
    index = 0
    text = str(text or "")
    while index < len(text):
        char = text[index]
        pair = text[index : index + 2]
        if state == "line_comment":
            if char in "\r\n":
                chars.append(char)
                state = "code"
            index += 1
            continue
        if state == "block_comment":
            if pair == "*/":
                state = "code"
                index += 2
                continue
            if char in "\r\n":
                chars.append(char)
            index += 1
            continue
        if quote:
            chars.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            index += 1
            continue
        if char in ("'", '"'):
            quote = char
            chars.append(char)
            index += 1
            continue
        if pair == "//":
            state = "line_comment"
            index += 2
            continue
        if pair == "/*":
            state = "block_comment"
            index += 2
            continue
        chars.append(char)
        index += 1
    return "\n".join(line.rstrip() for line in "".join(chars).splitlines() if line.strip())


def render_llm_decompile_blocks(
    reference_items: Any,
    target_items: Any,
) -> tuple[str, str]:
    def normalize_items(items: Any) -> list[dict[str, Any]]:
        if isinstance(items, dict):
            return [items]
        if isinstance(items, (list, tuple)):
            return [item for item in items if isinstance(item, dict)]
        return []

    def render_block(kind: str, item: dict[str, Any]) -> str:
        func_name = str(item.get("func_name", "")).strip() or "<unknown>"
        disasm_code = str(item.get("disasm_code", "") or "")
        procedure = str(item.get("procedure", "") or "")
        if kind == "Target":
            disasm_code = strip_disasm_comments(disasm_code)
            procedure = strip_c_like_comments(procedure)
        return (
            f"### {kind} Function: {func_name}\n\n"
            "**Disassembly**\n\n"
            f"```c\n{disasm_code}\n```\n\n"
            "**Procedure**\n\n"
            f"```c\n{procedure}\n```"
        )

    references = "\n\n".join(
        render_block("Reference", item) for item in normalize_items(reference_items)
    )
    targets = "\n\n".join(
        render_block("Target", item) for item in normalize_items(target_items)
    )
    return references, targets


def derive_module_name(binary_path: Any) -> str:
    if not binary_path:
        return ""
    path = Path(str(binary_path))
    candidates = [path.name, *reversed(path.parts)]
    for candidate in candidates:
        lowered = candidate.lower()
        if lowered in {"amd64", "arm64", "x64", "x86"}:
            continue
        exe_index = lowered.find(".exe")
        if exe_index > 0:
            return candidate[:exe_index]
        if path.is_file() and candidate == path.name and path.suffix:
            return path.stem
    return ""


def format_prompt_template(
    prompt_template: str,
    *,
    symbol_name_list: str,
    reference_blocks: str,
    target_blocks: str,
    arch: str,
    platform: str | None = None,
    module_name: str = "",
    disasm_for_reference: str = "",
    procedure_for_reference: str = "",
    disasm_code: str = "",
    procedure: str = "",
) -> str:
    values = {
        "symbol_name_list": symbol_name_list,
        "reference_blocks": reference_blocks,
        "target_blocks": target_blocks,
        "arch": arch,
        "platform": platform or arch,
        "module_name": module_name,
        "disasm_for_reference": disasm_for_reference,
        "procedure_for_reference": procedure_for_reference,
        "disasm_code": disasm_code,
        "procedure": procedure,
    }
    return str(prompt_template or "").format(**values)


def build_result_section_requirements(expected_sections: dict[str, set[str]]) -> str:
    if not expected_sections:
        return ""
    lines = ["Required result sections:"]
    for symbol_name, sections in expected_sections.items():
        lines.append(f"- {symbol_name}: {' or '.join(sorted(sections))}")
    lines.extend(
        [
            "",
            "A direct tail jump or jump thunk to a requested function is `found_call`.",
            "A direct reference to a regular function address is `found_funcptr`.",
            "A function pointer stored in a regular struct field is `found_struct_offset`.",
            "`found_vcall` is unsupported and must never be returned.",
        ]
    )
    return "\n".join(lines)


def _format_validation_issue(issue: dict[str, Any]) -> str:
    issue_type = issue.get("issue_type")
    if issue_type in {
        "yaml_parse_error",
        "yaml_root_type_mismatch",
        "yaml_schema_mismatch",
        "yaml_section_type_mismatch",
        "yaml_entry_shape_mismatch",
        "wrapped_symbol_mismatch",
        "unexpected_result_symbol",
    }:
        return f"- {issue.get('message', issue_type)}"
    location = f"{issue.get('section_name')}[{issue.get('entry_index')}]"
    if issue_type == "result_section_mismatch":
        expected = " or ".join(f"`{value}`" for value in issue.get("expected_sections", []))
        return (
            f"- {location}: symbol {issue.get('symbol_name')!r} was returned in "
            f"`{issue.get('section_name')}`, but it requires {expected}."
        )
    actual = " | ".join(issue.get("actual_disasms", [])) or "<no instruction found>"
    text = (
        f"- {location}: insn_va {issue.get('insn_va')!r} reports "
        f"`{issue.get('reported_disasm')}`, but the target instruction at that VA is `{actual}`."
    )
    candidates = issue.get("candidate_vas", [])
    if candidates:
        text += " The reported instruction appears at: " + ", ".join(
            f"0x{value:X}" for value in candidates
        ) + "."
    return text


def build_validation_correction_prompt(
    validation_issues: list[dict[str, Any]],
    expected_result_sections: dict[str, set[str]] | None = None,
) -> str:
    issue_text = "\n".join(_format_validation_issue(issue) for issue in validation_issues)
    permitted = ", ".join(LLM_DECOMPILE_RESULT_SECTIONS)
    requirements = build_result_section_requirements(expected_result_sections or {})
    requirement_block = f"\n{requirements}\n" if requirements else ""
    return f"""Your previous YAML output contains invalid references.
Each insn_va must identify the exact target instruction written in insn_disasm; only whitespace differences are allowed.

Mismatches:
{issue_text}

The only permitted top-level keys are: {permitted}.
`found_vcall` is unsupported by kphtools. Do not return it.
Symbol names must never be top-level keys. For batched requests, append every result to its category list.

Canonical empty response:
```yaml
found_call: []
found_funcptr: []
found_gv: []
found_struct_offset: []
```
{requirement_block}
For `found_struct_offset`, report the exact member-access instruction plus `offset`, `size`, `struct_name`, and `member_name`.
Re-check every entry and return the complete YAML for all requested symbols. Do not return a patch, explanation, or text outside YAML."""
