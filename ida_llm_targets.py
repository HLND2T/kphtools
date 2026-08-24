"""Export target code details and resolve direct references through IDA MCP."""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import yaml

from ida_reference_export import (
    build_code_region_detail_export_py_eval,
    build_function_detail_export_py_eval,
    build_remote_text_export_py_eval,
)


_DEBUG_RESPONSE_PREVIEW_LIMIT = 1000


class ReferenceResolutionStatus(str, Enum):
    SUCCESS = "success"
    NO_MATCH = "no_match"
    AMBIGUOUS = "ambiguous"
    TRANSPORT_ERROR = "transport_error"
    MALFORMED_RESPONSE = "malformed_response"


@dataclass(frozen=True)
class ReferenceResolution:
    status: ReferenceResolutionStatus
    address: int | None = None
    matches: tuple[int, ...] = ()
    detail: str = ""
    error: Exception | None = field(default=None, compare=False, repr=False)


def _debug_log(debug: bool, message: str) -> None:
    if debug:
        print(f"[debug] {message}")


def _parse_py_eval_result(tool_result: Any) -> dict[str, Any]:
    text = tool_result.content[0].text
    payload = json.loads(text)
    return json.loads(payload["result"])


def _parse_offset_value(value: Any) -> int:
    if isinstance(value, int):
        return value
    text = str(value).strip()
    return int(text, 0 if text.lower().startswith("0x") else 10)


def _tool_result_response_preview(tool_result: Any) -> str:
    content = getattr(tool_result, "content", None)
    try:
        item = content[0] if content else None
    except (IndexError, KeyError, TypeError):
        item = None
    text = getattr(item, "text", None)
    if not isinstance(text, str):
        return f"<{type(tool_result).__name__}>"
    if len(text) > _DEBUG_RESPONSE_PREVIEW_LIMIT:
        text = text[:_DEBUG_RESPONSE_PREVIEW_LIMIT] + "..."
    return repr(text)


def _debug_reference_resolution(
    debug: bool,
    insn_va: Any,
    resolution: ReferenceResolution,
    *,
    response_preview: str,
) -> None:
    if not debug or resolution.status == ReferenceResolutionStatus.SUCCESS:
        return
    exception = resolution.error
    exception_text = (
        f"{type(exception).__name__}: {exception}"
        if exception is not None
        else "<none>"
    )
    _debug_log(
        True,
        "reference resolution "
        f"{resolution.status.value}: insn_va={insn_va} "
        f"detail={resolution.detail or '<none>'} "
        f"exception={exception_text} response={response_preview}",
    )


def _reference_resolution(
    status: ReferenceResolutionStatus,
    *,
    insn_va: Any,
    debug: bool,
    response_preview: str,
    address: int | None = None,
    matches: tuple[int, ...] = (),
    detail: str = "",
    error: Exception | None = None,
) -> ReferenceResolution:
    resolution = ReferenceResolution(
        status=status,
        address=address,
        matches=matches,
        detail=detail,
        error=error,
    )
    _debug_reference_resolution(
        debug,
        insn_va,
        resolution,
        response_preview=response_preview,
    )
    return resolution


def _is_valid_remote_json_ack(ack: Any, output_path: Path) -> bool:
    if not isinstance(ack, dict) or not ack.get("ok"):
        return False
    if os.fspath(output_path) != str(ack.get("output_path", "")).strip():
        return False
    if str(ack.get("format", "")).strip() != "json":
        return False
    bytes_written = ack.get("bytes_written")
    if bytes_written is None:
        return False
    try:
        return int(bytes_written) >= 0
    except (TypeError, ValueError):
        return False


async def _find_function_addr_by_name_via_mcp(session, func_name: str) -> int | None:
    normalized_name = str(func_name or "").strip()
    if not normalized_name:
        return None
    py_code = (
        "import ida_funcs, ida_name, idaapi, json\n"
        f"func_name = {normalized_name!r}\n"
        "matches = []\n"
        "ea = ida_name.get_name_ea(idaapi.BADADDR, func_name)\n"
        "if ea != idaapi.BADADDR:\n"
        "    func = ida_funcs.get_func(ea)\n"
        "    if func is not None:\n"
        "        matches.append(hex(int(func.start_ea)))\n"
        "result = json.dumps({'matches': sorted(set(matches))})\n"
    )
    try:
        payload = _parse_py_eval_result(await session.call_tool("py_eval", {"code": py_code}))
    except Exception:
        return None
    matches = payload.get("matches") if isinstance(payload, dict) else None
    if not isinstance(matches, list) or len(matches) != 1:
        return None
    try:
        return int(str(matches[0]), 0)
    except (TypeError, ValueError):
        return None


def _load_target_yaml_payload(
    binary_dir: str | Path,
    target_name: str,
) -> dict[str, Any] | None:
    artifact_path = Path(binary_dir) / f"{target_name}.yaml"
    if not artifact_path.is_file():
        return None
    try:
        payload = yaml.safe_load(artifact_path.read_text(encoding="utf-8")) or {}
    except Exception:
        return None
    return payload if isinstance(payload, dict) else None


def _load_target_func_va_from_current_yaml(
    binary_dir: str | Path,
    func_name: str,
    image_base: int,
) -> int | None:
    payload = _load_target_yaml_payload(binary_dir, func_name)
    if payload is None:
        return None
    for key in ("func_va", "func_rva"):
        value = payload.get(key)
        if value is None:
            continue
        try:
            parsed = _parse_offset_value(value)
        except (TypeError, ValueError):
            continue
        return parsed if key == "func_va" else image_base + parsed
    return None


def _load_target_code_region_from_current_yaml(
    binary_dir: str | Path,
    code_name: str,
    image_base: int,
) -> dict[str, Any] | None:
    payload = _load_target_yaml_payload(binary_dir, code_name)
    if payload is None or payload.get("category") != "code":
        return None
    try:
        code_size = _parse_offset_value(payload.get("code_size"))
    except (TypeError, ValueError):
        return None
    if code_size <= 0:
        return None
    for key in ("code_va", "code_rva"):
        value = payload.get(key)
        if value is None:
            continue
        try:
            parsed = _parse_offset_value(value)
        except (TypeError, ValueError):
            continue
        return {
            "code_name": str(payload.get("code_name") or code_name).strip() or code_name,
            "code_va": parsed if key == "code_va" else image_base + parsed,
            "code_size": code_size,
        }
    return None


async def _export_detail_payload_via_mcp(
    session,
    producer_code: str,
) -> dict[str, Any] | None:
    with tempfile.TemporaryDirectory(
        prefix=".llm_decompile_",
        dir=os.fspath(Path(__file__).resolve().parent),
    ) as temp_dir:
        detail_path = Path(temp_dir) / "function-detail.json"
        py_code = build_remote_text_export_py_eval(
            output_path=detail_path,
            producer_code=producer_code.rstrip() + "\npayload_text = result\n",
            content_var="payload_text",
            format_name="json",
        )
        try:
            ack = _parse_py_eval_result(await session.call_tool("py_eval", {"code": py_code}))
        except Exception:
            return None
        if not _is_valid_remote_json_ack(ack, detail_path):
            return None
        try:
            payload = json.loads(detail_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, TypeError):
            return None
    return payload if isinstance(payload, dict) else None


def _normalize_target_detail_payload(
    target_name: str,
    payload: dict[str, Any] | None,
) -> dict[str, str] | None:
    if not isinstance(payload, dict):
        return None
    normalized = {
        "func_name": str(target_name or payload.get("func_name", "")).strip(),
        "func_va": str(payload.get("func_va", "")).strip(),
        "disasm_code": str(payload.get("disasm_code", "") or "").strip(),
        "procedure": str(payload.get("procedure", "") or ""),
    }
    if not normalized["func_name"] or not normalized["func_va"] or not normalized["disasm_code"]:
        return None
    return normalized


async def _export_function_detail_via_mcp(
    session,
    func_name: str,
    func_va: int,
) -> dict[str, str] | None:
    payload = await _export_detail_payload_via_mcp(
        session,
        build_function_detail_export_py_eval(int(func_va)),
    )
    return _normalize_target_detail_payload(func_name, payload)


async def _export_code_region_detail_via_mcp(
    session,
    code_name: str,
    code_va: int,
    code_size: int,
) -> dict[str, str] | None:
    try:
        payload = await _export_detail_payload_via_mcp(
            session,
            build_code_region_detail_export_py_eval(
                int(code_va),
                int(code_size),
                code_name=code_name,
            ),
        )
    except (TypeError, ValueError):
        return None
    return _normalize_target_detail_payload(code_name, payload)


async def _load_code_region_target_detail_via_mcp(
    session,
    target_name: str,
    *,
    binary_dir: str | Path,
    image_base: int,
    debug: bool,
) -> tuple[bool, dict[str, str] | None]:
    code_region = _load_target_code_region_from_current_yaml(
        binary_dir,
        target_name,
        image_base,
    )
    if code_region is None:
        return False, None
    target_detail = await _export_code_region_detail_via_mcp(
        session,
        code_region["code_name"],
        code_region["code_va"],
        code_region["code_size"],
    )
    if target_detail is None:
        _debug_log(debug, f"llm_decompile failed to export target code region: {target_name}")
    return True, target_detail


async def load_llm_decompile_target_details_via_mcp(
    session,
    target_func_names: list[str],
    *,
    binary_dir: str | Path,
    image_base: int,
    debug: bool = False,
) -> list[dict[str, str]]:
    target_items = []
    for target_name in target_func_names:
        handled, target_detail = await _load_code_region_target_detail_via_mcp(
            session,
            target_name,
            binary_dir=binary_dir,
            image_base=image_base,
            debug=debug,
        )
        if handled:
            if target_detail is not None:
                target_items.append(target_detail)
            continue
        func_va = _load_target_func_va_from_current_yaml(binary_dir, target_name, image_base)
        if func_va is None:
            func_va = await _find_function_addr_by_name_via_mcp(session, target_name)
        if func_va is None:
            _debug_log(debug, f"llm_decompile target function not found in current IDB: {target_name}")
            continue
        target_detail = await _export_function_detail_via_mcp(session, target_name, func_va)
        if target_detail is not None:
            target_items.append(target_detail)
        else:
            _debug_log(debug, f"llm_decompile failed to export target detail: {target_name}")
    return target_items


def has_all_required_target_details(
    target_items: list[dict[str, Any]],
    required_target_func_names: list[str],
) -> bool:
    available_names = {
        str(item.get("func_name", "")).strip()
        for item in target_items
        if str(item.get("func_name", "")).strip()
    }
    return all(name in available_names for name in required_target_func_names)


async def _resolve_unique_reference(
    session,
    insn_va: Any,
    producer_code: str,
    *,
    debug: bool = False,
) -> ReferenceResolution:
    try:
        insn_va_int = _parse_offset_value(insn_va)
    except (TypeError, ValueError) as exc:
        return _reference_resolution(
            ReferenceResolutionStatus.MALFORMED_RESPONSE,
            insn_va=insn_va,
            debug=debug,
            response_preview="<not-called>",
            detail="invalid instruction address",
            error=exc,
        )

    try:
        tool_result = await session.call_tool(
            "py_eval",
            {"code": producer_code.replace("{insn_va}", str(insn_va_int))},
        )
    except Exception as exc:
        return _reference_resolution(
            ReferenceResolutionStatus.TRANSPORT_ERROR,
            insn_va=insn_va,
            debug=debug,
            response_preview="<unavailable>",
            detail="IDA MCP py_eval call failed",
            error=exc,
        )

    try:
        payload = _parse_py_eval_result(tool_result)
    except (AttributeError, IndexError, KeyError, TypeError, json.JSONDecodeError) as exc:
        return _reference_resolution(
            ReferenceResolutionStatus.MALFORMED_RESPONSE,
            insn_va=insn_va,
            debug=debug,
            response_preview=_tool_result_response_preview(tool_result),
            detail="invalid IDA MCP py_eval response",
            error=exc,
        )

    matches = payload.get("matches") if isinstance(payload, dict) else None
    if not isinstance(matches, list):
        return _reference_resolution(
            ReferenceResolutionStatus.MALFORMED_RESPONSE,
            insn_va=insn_va,
            debug=debug,
            response_preview=_tool_result_response_preview(tool_result),
            detail="py_eval response field 'matches' must be a list",
        )

    parsed_matches: list[int] = []
    try:
        parsed_matches.extend(int(str(match), 0) for match in matches)
    except (TypeError, ValueError) as exc:
        return _reference_resolution(
            ReferenceResolutionStatus.MALFORMED_RESPONSE,
            insn_va=insn_va,
            debug=debug,
            response_preview=_tool_result_response_preview(tool_result),
            detail="py_eval response contains an invalid match address",
            error=exc,
        )

    normalized_matches = tuple(parsed_matches)
    if not normalized_matches:
        status = ReferenceResolutionStatus.NO_MATCH
        detail = "IDA found no matching reference"
        address = None
    elif len(normalized_matches) > 1:
        status = ReferenceResolutionStatus.AMBIGUOUS
        detail = f"IDA found {len(normalized_matches)} matching references"
        address = None
    else:
        status = ReferenceResolutionStatus.SUCCESS
        detail = ""
        address = normalized_matches[0]
    return _reference_resolution(
        status,
        insn_va=insn_va,
        debug=debug,
        response_preview=_tool_result_response_preview(tool_result),
        address=address,
        matches=normalized_matches,
        detail=detail,
    )


async def resolve_direct_call_target_via_mcp(
    session,
    insn_va: Any,
    *,
    debug: bool = False,
) -> ReferenceResolution:
    code = (
        "import ida_funcs, idautils, json\n"
        "insn_ea = {insn_va}\n"
        "matches = []\n"
        "for target_ea in idautils.CodeRefsFrom(insn_ea, False):\n"
        "    func = ida_funcs.get_func(target_ea)\n"
        "    if func is not None:\n"
        "        matches.append(hex(int(func.start_ea)))\n"
        "result = json.dumps({'matches': sorted(set(matches))})\n"
    )
    return await _resolve_unique_reference(session, insn_va, code, debug=debug)


async def resolve_funcptr_target_via_mcp(
    session,
    insn_va: Any,
    *,
    debug: bool = False,
) -> ReferenceResolution:
    code = (
        "import ida_funcs, idautils, json\n"
        "insn_ea = {insn_va}\n"
        "matches = []\n"
        "for target_ea in idautils.DataRefsFrom(insn_ea):\n"
        "    func = ida_funcs.get_func(target_ea)\n"
        "    if func is not None and int(func.start_ea) == int(target_ea):\n"
        "        matches.append(hex(int(target_ea)))\n"
        "result = json.dumps({'matches': sorted(set(matches))})\n"
    )
    return await _resolve_unique_reference(session, insn_va, code, debug=debug)


async def resolve_direct_gv_target_via_mcp(
    session,
    insn_va: Any,
    *,
    debug: bool = False,
) -> ReferenceResolution:
    code = (
        "import idautils, json\n"
        "insn_ea = {insn_va}\n"
        "matches = [hex(int(target_ea)) for target_ea in idautils.DataRefsFrom(insn_ea)]\n"
        "result = json.dumps({'matches': sorted(set(matches))})\n"
    )
    return await _resolve_unique_reference(session, insn_va, code, debug=debug)


# Thin compatibility aliases during the resolver split.
_load_llm_decompile_target_details_via_mcp = load_llm_decompile_target_details_via_mcp
_has_all_required_target_details = has_all_required_target_details
_resolve_direct_call_target_via_mcp = resolve_direct_call_target_via_mcp
_resolve_funcptr_target_via_mcp = resolve_funcptr_target_via_mcp
_resolve_direct_gv_target_via_mcp = resolve_direct_gv_target_via_mcp
