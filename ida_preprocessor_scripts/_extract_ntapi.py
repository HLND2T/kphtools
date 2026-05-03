from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from pdb_resolver import resolve_public_symbol
from symbol_artifacts import artifact_path, write_func_yaml


PREPROCESS_STATUS_SUCCESS = "success"
PREPROCESS_STATUS_FAILED = "failed"

_ALLOWED_SEGMENTS = frozenset({"PAGE", ".text"})
_ALLOWED_FUNC_FIELDS = frozenset({"func_name", "func_rva"})


def _field(value: Any, field_name: str) -> Any:
    if isinstance(value, Mapping):
        return value.get(field_name)
    return getattr(value, field_name, None)


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


def _normalize_desired_fields(
    generate_yaml_desired_fields: Any,
    symbol_name: str,
) -> list[str] | None:
    if not isinstance(generate_yaml_desired_fields, Mapping):
        return None
    fields = generate_yaml_desired_fields.get(symbol_name)
    if not isinstance(fields, list) or not fields:
        return None
    if any(not isinstance(field, str) for field in fields):
        return None
    if any(field not in _ALLOWED_FUNC_FIELDS for field in fields):
        return None
    if "func_name" not in fields or "func_rva" not in fields:
        return None
    return fields


def _filter_payload(payload: dict[str, Any], fields: list[str]) -> dict[str, Any] | None:
    if any(field not in payload for field in fields):
        return None
    return {field: payload[field] for field in fields}


def _normalize_signatures(
    ntapi_signatures: Any,
    symbol_name: str,
) -> list[str] | None:
    if not isinstance(ntapi_signatures, Mapping):
        return None
    signatures = ntapi_signatures.get(symbol_name)
    if not isinstance(signatures, Iterable) or isinstance(signatures, (str, bytes)):
        return None
    normalized = list(signatures)
    if not normalized or any(not isinstance(item, str) or not item for item in normalized):
        return None
    return normalized


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
            print(f"    Preprocess: find_bytes failed for NtAPI signatures: {exc}")
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


async def _extract_candidates_from_matches(
    *,
    session,
    match_eas: set[int],
    debug: bool,
) -> list[dict[str, int | str]] | None:
    if not match_eas:
        return []

    py_lines = [
        "import ida_bytes, ida_nalt, ida_segment, json",
        f"match_eas = {json.dumps([hex(ea) for ea in sorted(match_eas)])}",
        f"allowed_segments = {json.dumps(sorted(_ALLOWED_SEGMENTS))}",
        "image_base = int(ida_nalt.get_imagebase())",
        "candidates = []",
        "for raw_ea in match_eas:",
        "    try:",
        "        ea = int(str(raw_ea), 16)",
        "        ptr_ea = ea + 8",
        "        func_va = int(ida_bytes.get_qword(ptr_ea))",
        "    except Exception:",
        "        continue",
        "    seg = ida_segment.getseg(func_va)",
        "    if seg is None:",
        "        continue",
        "    seg_name = ida_segment.get_segm_name(seg)",
        "    if seg_name not in allowed_segments:",
        "        continue",
        "    candidates.append({",
        "        'match_ea': hex(ea),",
        "        'ptr_ea': hex(ptr_ea),",
        "        'func_va': hex(func_va),",
        "        'func_rva': hex(func_va - image_base),",
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
            print(f"    Preprocess: py_eval failed for NtAPI candidates: {exc}")
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
            segment = str(item.get("segment", ""))
            if segment not in _ALLOWED_SEGMENTS:
                continue
            parsed.append(
                {
                    "func_va": _parse_int_value(item["func_va"]),
                    "func_rva": _parse_int_value(item["func_rva"]),
                    "segment": segment,
                }
            )
        except (KeyError, TypeError, ValueError):
            continue
    return parsed


async def _resolve_by_signature(
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

    candidates = await _extract_candidates_from_matches(
        session=session,
        match_eas=matches,
        debug=debug,
    )
    if candidates is None:
        return None

    by_va: dict[int, dict[str, int | str]] = {
        int(candidate["func_va"]): candidate
        for candidate in candidates
    }
    if debug:
        print(
            "    Preprocess: NtAPI candidates for "
            f"{symbol_name}: {[hex(va) for va in sorted(by_va)]}"
        )
    if len(by_va) != 1:
        return None

    candidate = next(iter(by_va.values()))
    return {
        "func_name": symbol_name,
        "func_rva": int(candidate["func_rva"]),
    }


async def preprocess_ntapi_symbols(
    *,
    session,
    skill,
    symbol,
    binary_dir: str | Path,
    pdb_path: str | Path | None,
    debug: bool,
    target_function_names: list[str],
    ntapi_signatures,
    generate_yaml_desired_fields,
):
    symbol_name = _field(symbol, "name")
    if not isinstance(symbol_name, str) or symbol_name not in target_function_names:
        return PREPROCESS_STATUS_FAILED

    desired_fields = _normalize_desired_fields(
        generate_yaml_desired_fields,
        symbol_name,
    )
    signatures = _normalize_signatures(ntapi_signatures, symbol_name)
    if desired_fields is None or signatures is None:
        return PREPROCESS_STATUS_FAILED

    payload: dict[str, int | str] | None = None
    if pdb_path is not None:
        try:
            resolved = resolve_public_symbol(pdb_path, symbol_name)
            payload = {
                "func_name": symbol_name,
                "func_rva": resolved["rva"],
            }
        except Exception as exc:
            if debug:
                print(f"    Preprocess: PDB miss for {symbol_name}: {exc}")

    if payload is None:
        payload = await _resolve_by_signature(
            session=session,
            symbol_name=symbol_name,
            signatures=signatures,
            debug=debug,
        )
    if payload is None:
        return PREPROCESS_STATUS_FAILED

    filtered_payload = _filter_payload(payload, desired_fields)
    if filtered_payload is None:
        return PREPROCESS_STATUS_FAILED

    write_func_yaml(artifact_path(binary_dir, symbol_name), filtered_payload)
    return PREPROCESS_STATUS_SUCCESS
