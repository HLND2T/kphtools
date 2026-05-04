from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from symbol_artifacts import artifact_path, write_code_yaml


PREPROCESS_STATUS_SUCCESS = "success"
PREPROCESS_STATUS_FAILED = "failed"
PREPROCESS_STATUS_ABSENT_OK = "absent_ok"

TARGET_CODE_NAMES = ["PgInitContext"]

CODE_SIGNATURES = {
    "PgInitContext": ["FB 48 8D 05 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00"],
}


def _field(value: Any, field_name: str) -> Any:
    if isinstance(value, Mapping):
        return value.get(field_name)
    return getattr(value, field_name, None)


def _parse_tool_json_result(tool_result: Any) -> Any | None:
    try:
        text = tool_result.content[0].text
        payload = json.loads(text)
        if not isinstance(payload, dict) or "result" not in payload:
            return payload
        result_payload = payload["result"]
        if isinstance(result_payload, str):
            return json.loads(result_payload)
        return result_payload
    except Exception:
        return None


def _parse_int_value(value: Any) -> int:
    if isinstance(value, int):
        return value
    text = str(value).strip()
    return int(text, 0 if text.lower().startswith("0x") else 10)


def _arch_from_binary_dir(binary_dir: str | Path) -> str | None:
    for part in Path(binary_dir).parts:
        normalized = part.lower()
        if normalized in {"amd64", "arm64"}:
            return normalized
    return None


async def _find_signature_matches(
    *,
    session,
    signatures: list[str],
    debug: bool,
) -> set[int] | None:
    try:
        result = await session.call_tool(
            name="find_bytes",
            arguments={"patterns": signatures},
        )
    except Exception as exc:
        if debug:
            print(f"    Preprocess: find_bytes failed for PgInitContext: {exc}")
        return None

    payload = _parse_tool_json_result(result)
    if not isinstance(payload, list):
        return None

    matches: set[int] = set()
    for item in payload:
        raw_matches = item.get("matches", []) if isinstance(item, Mapping) else []
        if not isinstance(raw_matches, list):
            return None
        for raw_ea in raw_matches:
            try:
                matches.add(_parse_int_value(raw_ea))
            except (TypeError, ValueError):
                continue
    return matches


async def _extract_code_candidates(
    *,
    session,
    match_eas: set[int],
    debug: bool,
) -> list[dict[str, int | str]] | None:
    if not match_eas:
        return []

    py_lines = [
        "import ida_bytes, ida_idaapi, ida_nalt, ida_segment, idc, json",
        f"match_eas = {json.dumps([hex(ea) for ea in sorted(match_eas)])}",
        "image_base = int(ida_nalt.get_imagebase())",
        "candidates = []",
        "for raw_ea in match_eas:",
        "    try:",
        "        start_ea = int(str(raw_ea), 16)",
        "    except Exception:",
        "        continue",
        "    if ida_bytes.get_byte(start_ea) != 0xFB:",
        "        continue",
        "    seg = ida_segment.getseg(start_ea)",
        "    if seg is None:",
        "        continue",
        "    seg_name = ida_segment.get_segm_name(seg)",
        "    if seg_name != 'INIT':",
        "        continue",
        "    cli_ea = None",
        "    current = start_ea",
        "    end_ea = min(int(seg.end_ea), start_ea + 0x2000)",
        "    while current != ida_idaapi.BADADDR and current < end_ea:",
        "        if current != start_ea and idc.print_insn_mnem(current).lower() == 'cli':",
        "            cli_ea = current",
        "            break",
        "        next_ea = idc.next_head(current, end_ea)",
        "        if next_ea == ida_idaapi.BADADDR or next_ea <= current:",
        "            break",
        "        current = next_ea",
        "    if cli_ea is None:",
        "        continue",
        "    candidates.append({",
        "        'code_va': hex(start_ea),",
        "        'code_rva': hex(start_ea - image_base),",
        "        'code_size': hex(cli_ea - start_ea),",
        "        'cli_ea': hex(cli_ea),",
        "        'segment': seg_name,",
        "    })",
        "result = json.dumps({'candidates': candidates})",
    ]

    try:
        result = await session.call_tool(
            name="py_eval",
            arguments={"code": "\n".join(py_lines) + "\n"},
        )
    except Exception as exc:
        if debug:
            print(f"    Preprocess: py_eval failed for PgInitContext: {exc}")
        return None

    payload = _parse_tool_json_result(result)
    candidates = payload.get("candidates") if isinstance(payload, Mapping) else None
    if not isinstance(candidates, list):
        return None

    parsed: list[dict[str, int | str]] = []
    for item in candidates:
        if not isinstance(item, Mapping):
            continue
        try:
            parsed.append(
                {
                    "code_va": _parse_int_value(item["code_va"]),
                    "code_rva": _parse_int_value(item["code_rva"]),
                    "code_size": _parse_int_value(item["code_size"]),
                    "segment": str(item["segment"]),
                }
            )
        except (KeyError, TypeError, ValueError):
            continue
    return parsed


async def _resolve_pg_init_context(
    *,
    session,
    symbol_name: str,
    signatures: list[str],
    debug: bool,
) -> dict[str, int | str] | None:
    matches = await _find_signature_matches(
        session=session,
        signatures=signatures,
        debug=debug,
    )
    if matches is None or not matches:
        return None

    candidates = await _extract_code_candidates(
        session=session,
        match_eas=matches,
        debug=debug,
    )
    if candidates is None:
        return None

    by_va: dict[int, dict[str, int | str]] = {
        int(candidate["code_va"]): candidate
        for candidate in candidates
    }
    if debug:
        print(
            "    Preprocess: PgInitContext candidates: "
            f"{[hex(va) for va in sorted(by_va)]}"
        )
    if len(by_va) != 1:
        return None

    candidate = next(iter(by_va.values()))
    return {
        "code_name": symbol_name,
        "code_rva": int(candidate["code_rva"]),
        "code_size": int(candidate["code_size"]),
    }


def _write_outputs(
    *,
    binary_dir: str | Path,
    symbol_name: str,
    payload: dict[str, int | str],
) -> None:
    output_dir = Path(binary_dir)
    write_code_yaml(artifact_path(output_dir, symbol_name), payload)


async def preprocess_skill(session, skill, symbol, binary_dir, pdb_path, debug, llm_config):
    symbol_name = _field(symbol, "name")
    if symbol_name not in TARGET_CODE_NAMES:
        return PREPROCESS_STATUS_FAILED

    arch = _arch_from_binary_dir(binary_dir)
    if arch == "arm64":
        return PREPROCESS_STATUS_ABSENT_OK

    payload = await _resolve_pg_init_context(
        session=session,
        symbol_name=symbol_name,
        signatures=CODE_SIGNATURES[symbol_name],
        debug=debug,
    )
    if payload is None:
        return PREPROCESS_STATUS_FAILED

    _write_outputs(
        binary_dir=binary_dir,
        symbol_name=symbol_name,
        payload=payload,
    )
    return PREPROCESS_STATUS_SUCCESS
