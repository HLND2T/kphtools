"""Validated LLM_DECOMPILE facade with a shared transport/retry budget."""

from __future__ import annotations

import asyncio
import json
import uuid
from typing import Any, Awaitable, Callable

from ida_llm_prompt import (
    SYSTEM_PROMPT,
    build_result_section_requirements,
    build_validation_correction_prompt,
    derive_module_name,
    format_prompt_template,
    render_llm_decompile_blocks,
)
from ida_llm_response import (
    LLM_DECOMPILE_RESULT_SECTIONS,
    empty_llm_decompile_result,
    normalize_requested_symbol_names,
    parse_llm_decompile_response_with_issues,
)
from ida_llm_validation import (
    build_target_disasm_index,
    normalize_expected_result_sections,
    validate_llm_decompile_result,
)
from ida_llm_utils import call_llm_text, normalize_optional_temperature


CallLlmText = Callable[..., Awaitable[str]]


def _debug_print_multiline(label: str, value: Any, debug: bool) -> None:
    if not debug:
        return
    print(f"[debug] BEGIN {label}")
    print("" if value is None else str(value))
    print(f"[debug] END {label}")


def _debug_print_json(label: str, value: Any, debug: bool) -> None:
    if debug:
        _debug_print_multiline(
            label,
            json.dumps(value, indent=2, ensure_ascii=False, sort_keys=False),
            True,
        )


def _normalize_retry_attempts(value: Any, default: int = 3) -> int:
    try:
        attempts = int(value)
    except (TypeError, ValueError):
        attempts = default
    return max(1, attempts)


def _normalize_retry_delay(value: Any, default: float, minimum: float = 0.0) -> float:
    try:
        delay = float(value)
    except (TypeError, ValueError):
        delay = default
    return max(minimum, delay)


def _extract_error_status_code(exc: Exception) -> int | None:
    for source in (exc, getattr(exc, "response", None)):
        status_code = getattr(source, "status_code", None) if source is not None else None
        if status_code is None:
            continue
        try:
            return int(status_code)
        except (TypeError, ValueError):
            pass
    return None


def is_transient_llm_error(exc: Exception) -> bool:
    status_code = _extract_error_status_code(exc)
    if status_code == 429 or status_code is not None and 500 <= status_code < 600:
        return True
    message = str(exc or "").lower()
    fragments = (
        "transport received error",
        "timeout",
        "timed out",
        "rate limit",
        "rate_limit",
        "too many requests",
        "http 429",
        "status 429",
        "server error",
        "service unavailable",
        "temporarily unavailable",
    )
    return any(fragment in message for fragment in fragments)


def _new_message(role: str, content: Any) -> dict[str, str]:
    return {
        "id": f"msg_{uuid.uuid4()}",
        "role": role,
        "content": str(content or ""),
    }


def _build_prompt(
    *,
    prompt_template: str,
    symbol_name_text: str,
    reference_items: Any,
    target_items: Any,
    arch: str,
    platform: str | None,
    module_name: str,
    expected_result_sections: dict[str, set[str]],
) -> tuple[str, list[str]]:
    reference_blocks, target_blocks = render_llm_decompile_blocks(
        reference_items,
        target_items,
    )
    first_reference = reference_items[0] if isinstance(reference_items, list) and reference_items else {}
    first_target = target_items[0] if isinstance(target_items, list) and target_items else {}
    prompt = format_prompt_template(
        prompt_template,
        symbol_name_list=symbol_name_text,
        reference_blocks=reference_blocks,
        target_blocks=target_blocks,
        arch=arch,
        platform=platform,
        module_name=module_name,
        disasm_for_reference=str(first_reference.get("disasm_code", "")),
        procedure_for_reference=str(first_reference.get("procedure", "")),
        disasm_code=str(first_target.get("disasm_code", "")),
        procedure=str(first_target.get("procedure", "")),
    )
    requirements = build_result_section_requirements(expected_result_sections)
    if requirements:
        prompt = f"{prompt}\n\n{requirements}"
    target_disasm_codes = [
        str(item.get("disasm_code", ""))
        for item in target_items or []
        if isinstance(item, dict)
    ]
    return prompt, target_disasm_codes


def _parse_and_validate(
    content: str,
    *,
    requested_symbol_names: tuple[str, ...],
    expected_result_sections: dict[str, set[str]],
    disasm_index: tuple[dict[int, set[str]], dict[str, set[int]]],
    debug: bool,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    outcome = parse_llm_decompile_response_with_issues(
        content,
        requested_symbol_names,
    )
    semantic_issues = validate_llm_decompile_result(
        outcome["result"],
        disasm_index,
        expected_result_sections,
        requested_symbol_names=requested_symbol_names,
    )
    issues = outcome["issues"] + semantic_issues
    _debug_print_json(
        "llm_decompile schema outcome",
        {
            "schema_kind": outcome["schema_kind"],
            "root_keys": outcome["root_keys"],
            "compatibility_flattened": outcome["compatibility_flattened"],
            "issues": issues,
        },
        debug,
    )
    return outcome["result"], issues


async def _run_llm_attempts(
    *,
    transport: CallLlmText,
    request_kwargs: dict[str, Any],
    messages: list[dict[str, str]],
    max_attempts: int,
    retry_delay: float,
    retry_backoff: float,
    retry_max_delay: float,
    requested_symbols: tuple[str, ...],
    expected_sections: dict[str, set[str]],
    disasm_index: tuple[dict[int, set[str]], dict[str, set[int]]],
    debug: bool,
) -> dict[str, list[dict[str, str]]]:
    for attempt_index in range(max_attempts):
        request_kwargs["messages"] = list(messages)
        try:
            content = await transport(**request_kwargs)
        except Exception as exc:
            last_attempt = attempt_index >= max_attempts - 1
            if not is_transient_llm_error(exc) or last_attempt:
                if debug:
                    print(f"[debug] llm_decompile transport failed: {exc}")
                return empty_llm_decompile_result()
            if retry_delay > 0:
                await asyncio.sleep(retry_delay)
            retry_delay = min(retry_delay * retry_backoff, retry_max_delay)
            continue

        _debug_print_multiline("llm_decompile raw response", content, debug)
        parsed_result, issues = _parse_and_validate(
            content,
            requested_symbol_names=requested_symbols,
            expected_result_sections=expected_sections,
            disasm_index=disasm_index,
            debug=debug,
        )
        if not issues:
            return parsed_result
        if attempt_index >= max_attempts - 1:
            return empty_llm_decompile_result()
        messages.extend(
            [
                _new_message("assistant", content),
                _new_message(
                    "user",
                    build_validation_correction_prompt(issues, expected_sections),
                ),
            ]
        )
    return empty_llm_decompile_result()


async def call_llm_decompile(
    *,
    model: str,
    symbol_name_list: Any,
    expected_result_sections: Any,
    reference_items: Any,
    target_items: Any,
    prompt_template: str,
    arch: str,
    platform: str | None = None,
    binary_path: Any = None,
    client: Any = None,
    temperature: Any = None,
    effort: Any = None,
    api_key: Any = None,
    base_url: Any = None,
    fake_as: Any = None,
    max_retries: Any = None,
    retry_initial_delay: Any = None,
    retry_backoff_factor: Any = None,
    retry_max_delay: Any = None,
    debug: bool = False,
    call_llm_text_func: CallLlmText | None = None,
) -> dict[str, list[dict[str, str]]]:
    transport = call_llm_text_func or call_llm_text
    requested_symbols = normalize_requested_symbol_names(symbol_name_list)
    symbol_name_text = ", ".join(requested_symbols)
    expected_sections = normalize_expected_result_sections(expected_result_sections)
    module_name = derive_module_name(binary_path)
    try:
        prompt, target_disasm_codes = _build_prompt(
            prompt_template=prompt_template,
            symbol_name_text=symbol_name_text,
            reference_items=reference_items,
            target_items=target_items,
            arch=str(arch or "").strip(),
            platform=platform,
            module_name=module_name,
            expected_result_sections=expected_sections,
        )
        normalized_temperature = normalize_optional_temperature(temperature)
    except Exception as exc:
        if debug:
            print(f"[debug] failed to prepare llm_decompile request: {exc}")
        return empty_llm_decompile_result()

    messages = [_new_message("system", SYSTEM_PROMPT), _new_message("user", prompt)]
    prompt_cache_key = str(uuid.uuid4())
    request_kwargs = {
        "client": client,
        "model": str(model or "").strip(),
        "messages": messages,
        "api_key": api_key,
        "base_url": base_url,
        "fake_as": fake_as,
        "prompt_cache_key": prompt_cache_key,
        "debug": debug,
    }
    if normalized_temperature is not None:
        request_kwargs["temperature"] = normalized_temperature
    if effort is not None:
        request_kwargs["effort"] = effort

    max_attempts = _normalize_retry_attempts(max_retries)
    delay = _normalize_retry_delay(retry_initial_delay, 1.0)
    backoff = _normalize_retry_delay(retry_backoff_factor, 2.0, 1.0)
    max_delay = _normalize_retry_delay(retry_max_delay, 8.0)
    disasm_index = build_target_disasm_index(target_disasm_codes)
    _debug_print_multiline("llm_decompile system prompt", SYSTEM_PROMPT, debug)
    _debug_print_multiline("llm_decompile user prompt", prompt, debug)

    return await _run_llm_attempts(
        transport=transport,
        request_kwargs=request_kwargs,
        messages=messages,
        max_attempts=max_attempts,
        retry_delay=delay,
        retry_backoff=backoff,
        retry_max_delay=max_delay,
        requested_symbols=requested_symbols,
        expected_sections=expected_sections,
        disasm_index=disasm_index,
        debug=debug,
    )


__all__ = [
    "LLM_DECOMPILE_RESULT_SECTIONS",
    "call_llm_decompile",
    "empty_llm_decompile_result",
    "is_transient_llm_error",
]
