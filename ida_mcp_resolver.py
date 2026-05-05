from __future__ import annotations

import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any

import yaml

from ida_reference_export import (
    build_code_region_detail_export_py_eval,
    build_function_detail_export_py_eval,
    build_remote_text_export_py_eval,
    validate_reference_yaml_payload,
)


_LLM_DECOMPILE_RESULT_CACHE: dict[tuple[Any, ...], dict[str, list[dict[str, str]]]] = {}


def _debug_log(debug: bool, message: str) -> None:
    if debug:
        print(f"[debug] {message}")


def _debug_print_multiline(label: str, value: Any, debug: bool = False) -> None:
    if not debug:
        return
    print(f"[debug] BEGIN {label}")
    print("" if value is None else str(value))
    print(f"[debug] END {label}")


def _debug_print_json(label: str, value: Any, debug: bool = False) -> None:
    if not debug:
        return
    try:
        rendered = json.dumps(value, indent=2, ensure_ascii=False, sort_keys=False)
    except Exception:
        rendered = repr(value)
    _debug_print_multiline(label, rendered, debug=debug)


def _parse_py_eval_result(tool_result: Any) -> dict:
    text = tool_result.content[0].text
    payload = json.loads(text)
    return json.loads(payload["result"])


def _parse_offset_value(value: Any) -> int:
    if isinstance(value, int):
        return value
    text = str(value).strip()
    return int(text, 0 if text.lower().startswith("0x") else 10)


def _strip_yaml_fence(raw: str) -> str:
    text = raw.strip()
    if not text.startswith("```"):
        return raw

    lines = text.splitlines()
    if len(lines) >= 2 and lines[0].startswith("```") and lines[-1] == "```":
        return "\n".join(lines[1:-1]).strip()
    return raw


def _parse_rva_value(payload: dict[str, Any], symbol_name: str) -> int:
    if payload.get("missing") == symbol_name:
        raise KeyError(symbol_name)

    if "rva" not in payload:
        raise ValueError("missing rva in py_eval result")

    value = payload["rva"]
    if isinstance(value, int):
        return value
    if not isinstance(value, str):
        raise TypeError("rva must be an int or hex string")
    return int(value, 16)


async def call_llm_text(*args, **kwargs):
    from ida_llm_utils import call_llm_text as _call_llm_text

    return await _call_llm_text(*args, **kwargs)


async def resolve_public_name_via_mcp(
    session,
    symbol_name: str,
    image_base: int,
) -> dict[str, int | str]:
    py_code = (
        "import json\n"
        "import idc\n"
        f"symbol_name = {symbol_name!r}\n"
        f"image_base = {image_base}\n"
        "ea = idc.get_name_ea_simple(symbol_name)\n"
        "if ea == idc.BADADDR:\n"
        "    result = json.dumps({'missing': symbol_name})\n"
        "else:\n"
        "    rva = ea - image_base\n"
        "    result = json.dumps({'rva': hex(rva)})\n"
    )
    tool_result = await session.call_tool("py_eval", {"code": py_code})
    payload = _parse_py_eval_result(tool_result)
    return {"name": symbol_name, "rva": _parse_rva_value(payload, symbol_name)}


def _empty_llm_decompile_result() -> dict[str, list[dict[str, str]]]:
    return {
        "found_call": [],
        "found_funcptr": [],
        "found_gv": [],
        "found_struct_offset": [],
    }


def _normalize_llm_entries(entries: Any, required_keys: tuple[str, ...]) -> list[dict[str, str]]:
    if isinstance(entries, (str, bytes, bytearray)) or not isinstance(entries, (list, tuple)):
        return []

    normalized: list[dict[str, str]] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        item: dict[str, str] = {}
        for key in required_keys:
            value = str(entry.get(key, "")).strip()
            if not value:
                item = {}
                break
            item[key] = value
        if item:
            normalized.append(item)
    return normalized


def _normalize_llm_struct_offset_entries(entries: Any) -> list[dict[str, str]]:
    if isinstance(entries, (str, bytes, bytearray)) or not isinstance(entries, (list, tuple)):
        return []

    normalized: list[dict[str, str]] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        item: dict[str, str] = {}
        for key in ("insn_va", "insn_disasm", "offset", "struct_name", "member_name"):
            value = str(entry.get(key, "")).strip()
            if not value:
                item = {}
                break
            item[key] = value
        if not item:
            continue
        size = str(entry.get("size", "")).strip()
        if size:
            item["size"] = size
        bit_offset = str(entry.get("bit_offset", "")).strip()
        if bit_offset:
            item["bit_offset"] = bit_offset
        normalized.append(item)
    return normalized


def _parse_yaml_mapping(text: str) -> dict[str, Any] | None:
    try:
        parsed = yaml.load(text, Loader=yaml.BaseLoader)
    except yaml.YAMLError:
        return None
    if parsed is None:
        return {}
    return parsed if isinstance(parsed, dict) else None


def _repair_glued_llm_yaml_headers(text: str) -> str:
    return re.sub(
        r"([^\n])((?:found_call|found_funcptr|found_gv|found_struct_offset):)",
        r"\1\n\2",
        text,
    )


def parse_llm_decompile_response(response_text: str) -> dict[str, list[dict[str, str]]]:
    text = str(response_text or "").strip()
    if not text:
        return _empty_llm_decompile_result()

    candidates: list[str] = []
    for match in re.finditer(
        r"```(?:yaml|yml)[ \t]*\n?(.*?)```",
        text,
        re.IGNORECASE | re.DOTALL,
    ):
        candidates.append(match.group(1).strip())
    if not candidates:
        for match in re.finditer(r"```[ \t]*\n(.*?)```", text, re.DOTALL):
            candidates.append(match.group(1).strip())
    if not candidates:
        candidates.append(_strip_yaml_fence(text) if text.startswith("```") else text)

    parsed: Any = None
    for candidate in candidates:
        if not candidate:
            continue
        parsed = _parse_yaml_mapping(candidate)
        if parsed is None:
            repaired_candidate = _repair_glued_llm_yaml_headers(candidate)
            if repaired_candidate != candidate:
                parsed = _parse_yaml_mapping(repaired_candidate)
        if parsed is not None:
            break

    if not isinstance(parsed, dict):
        return _empty_llm_decompile_result()

    return {
        "found_call": _normalize_llm_entries(
            parsed.get("found_call", []),
            ("insn_va", "insn_disasm", "func_name"),
        ),
        "found_funcptr": _normalize_llm_entries(
            parsed.get("found_funcptr", []),
            ("insn_va", "insn_disasm", "funcptr_name"),
        ),
        "found_gv": _normalize_llm_entries(
            parsed.get("found_gv", []),
            ("insn_va", "insn_disasm", "gv_name"),
        ),
        "found_struct_offset": _normalize_llm_struct_offset_entries(
            parsed.get("found_struct_offset", []),
        ),
    }


def _get_preprocessor_scripts_dir() -> Path:
    return Path(__file__).resolve().parent / "ida_preprocessor_scripts"


def _infer_arch_from_binary_dir(binary_dir: str | Path | None) -> str:
    if binary_dir is None:
        return ""
    for part in reversed(Path(binary_dir).parts):
        lowered = part.lower()
        if lowered in {"amd64", "arm64"}:
            return lowered
    return ""


def _resolve_llm_template_value(value: Any, arch: str) -> str:
    resolved = str(value or "")
    if arch:
        resolved = resolved.replace("{arch}", arch)
        resolved = resolved.replace("{platform}", arch)
    return resolved


def _build_llm_decompile_specs_map(
    llm_decompile_specs: Any,
) -> dict[str, list[dict[str, str]]] | None:
    specs_map: dict[str, list[dict[str, str]]] = {}
    for spec in llm_decompile_specs or []:
        if not isinstance(spec, (tuple, list)) or len(spec) != 4:
            return None
        if not all(isinstance(item, str) and item for item in spec):
            return None
        symbol_name, llm_symbol_name, prompt_path, reference_yaml_path = spec
        current = {
            "llm_symbol_name": llm_symbol_name,
            "prompt_path": prompt_path,
            "reference_yaml_path": reference_yaml_path,
        }
        existing = specs_map.setdefault(symbol_name, [])
        if existing and (
            existing[0]["prompt_path"] != prompt_path
            or existing[0]["llm_symbol_name"] != llm_symbol_name
        ):
            return None
        existing.append(current)
    return specs_map


def _llm_decompile_specs_signature(
    specs: list[dict[str, str]] | None,
) -> tuple[str, tuple[str, ...]] | None:
    if not specs:
        return None
    prompt_path = specs[0].get("prompt_path", "")
    reference_paths = tuple(spec.get("reference_yaml_path", "") for spec in specs)
    if not prompt_path or not reference_paths or not all(reference_paths):
        return None
    return prompt_path, reference_paths


def _collect_grouped_llm_symbol_names(
    specs_map: dict[str, list[dict[str, str]]],
    symbol_name: str,
) -> list[str]:
    signature = _llm_decompile_specs_signature(specs_map.get(symbol_name))
    if signature is None:
        return []

    llm_symbol_names: list[str] = []
    seen: set[str] = set()
    for candidate_specs in specs_map.values():
        if _llm_decompile_specs_signature(candidate_specs) != signature:
            continue
        for spec in candidate_specs:
            llm_symbol_name = str(spec.get("llm_symbol_name", "")).strip()
            if llm_symbol_name and llm_symbol_name not in seen:
                seen.add(llm_symbol_name)
                llm_symbol_names.append(llm_symbol_name)
    return llm_symbol_names


def _build_llm_decompile_result_cache_key(
    *,
    request: dict[str, Any],
    llm_config: dict,
    binary_dir: str | Path,
    image_base: int,
) -> tuple[Any, ...] | None:
    prompt_path = str(request.get("prompt_path", "")).strip()
    reference_paths = tuple(
        str(path).strip()
        for path in request.get("reference_paths", [])
        if str(path).strip()
    )
    target_func_names = tuple(
        str(name).strip()
        for name in request.get("target_func_names", [])
        if str(name).strip()
    )
    llm_symbol_names = tuple(
        str(name).strip()
        for name in request.get("llm_symbol_names", [])
        if str(name).strip()
    )
    model = str(llm_config.get("model", "")).strip()
    if not prompt_path or not reference_paths or not target_func_names:
        return None
    if not llm_symbol_names or not model:
        return None
    return (
        os.fspath(Path(binary_dir).resolve()),
        int(image_base),
        model,
        str(llm_config.get("base_url", "") or "").strip(),
        str(llm_config.get("temperature", "") or "").strip(),
        str(llm_config.get("effort", "") or "").strip(),
        str(llm_config.get("fake_as", "") or "").strip().lower(),
        str(request.get("arch", "") or "").strip(),
        prompt_path,
        reference_paths,
        target_func_names,
        llm_symbol_names,
    )


def _append_unique_text(items: list[str], seen: set[str], value: Any) -> None:
    text = str(value or "").strip()
    if not text or text in seen:
        return
    seen.add(text)
    items.append(text)


def _load_reference_item(reference_yaml_path: Path) -> dict[str, str] | None:
    try:
        data = yaml.safe_load(reference_yaml_path.read_text(encoding="utf-8")) or {}
        return validate_reference_yaml_payload(data)
    except Exception:
        return None


def _prepare_llm_decompile_request(
    *,
    symbol_name: str,
    llm_decompile_specs: Any,
    llm_config: dict | None,
    binary_dir: str | Path,
    debug: bool = False,
) -> dict[str, Any] | None:
    if not isinstance(llm_config, dict):
        _debug_log(debug, f"llm_decompile skipped for {symbol_name}: llm_config missing")
        return None

    model = str(llm_config.get("model", "")).strip()
    api_key = str(llm_config.get("api_key", "")).strip()
    if not model:
        _debug_log(debug, f"llm_decompile skipped for {symbol_name}: llm model missing")
        return None
    if not api_key:
        _debug_log(
            debug,
            f"llm_decompile skipped for {symbol_name}: llm api key missing",
        )
        return None

    specs_map = _build_llm_decompile_specs_map(llm_decompile_specs)
    if specs_map is None:
        _debug_log(debug, f"llm_decompile skipped for {symbol_name}: invalid specs")
        return None
    llm_specs = specs_map.get(symbol_name)
    if not llm_specs:
        _debug_log(debug, f"llm_decompile skipped for {symbol_name}: no matching spec")
        return None

    arch = _infer_arch_from_binary_dir(binary_dir) or str(llm_config.get("arch", "")).strip()
    scripts_dir = _get_preprocessor_scripts_dir()

    prompt_path = Path(_resolve_llm_template_value(llm_specs[0]["prompt_path"], arch))
    if not prompt_path.is_absolute():
        prompt_path = scripts_dir / prompt_path
    if not prompt_path.is_file():
        _debug_log(
            debug,
            f"llm_decompile skipped for {symbol_name}: prompt missing at {prompt_path}",
        )
        return None
    try:
        prompt_template = prompt_path.read_text(encoding="utf-8")
    except OSError:
        _debug_log(
            debug,
            f"llm_decompile skipped for {symbol_name}: failed to read prompt {prompt_path}",
        )
        return None

    reference_items: list[dict[str, str]] = []
    reference_paths: list[str] = []
    target_func_names: list[str] = []
    required_target_func_names: list[str] = []
    seen_target_func_names: set[str] = set()
    for spec in llm_specs:
        reference_path = Path(
            _resolve_llm_template_value(spec["reference_yaml_path"], arch)
        )
        if not reference_path.is_absolute():
            reference_path = scripts_dir / reference_path
        if not reference_path.is_file():
            _debug_log(
                debug,
                f"llm_decompile skipped for {symbol_name}: reference missing at {reference_path}",
            )
            return None
        reference_item = _load_reference_item(reference_path)
        if reference_item is None:
            _debug_log(
                debug,
                f"llm_decompile skipped for {symbol_name}: invalid reference {reference_path}",
            )
            return None
        reference_items.append(reference_item)
        reference_paths.append(os.fspath(reference_path.resolve()))
        required_func_name = reference_item["func_name"]
        required_target_func_names.append(required_func_name)
        _append_unique_text(
            target_func_names,
            seen_target_func_names,
            required_func_name,
        )
        for optional_func_name in reference_item.get("optional_funcs", []):
            _append_unique_text(
                target_func_names,
                seen_target_func_names,
                optional_func_name,
            )

    llm_symbol_names = _collect_grouped_llm_symbol_names(specs_map, symbol_name)
    if not llm_symbol_names:
        llm_symbol_names = [llm_specs[0]["llm_symbol_name"]]

    return {
        "prompt_template": prompt_template,
        "prompt_path": os.fspath(prompt_path.resolve()),
        "llm_symbol_name": llm_specs[0]["llm_symbol_name"],
        "llm_symbol_names": llm_symbol_names,
        "reference_items": reference_items,
        "reference_paths": reference_paths,
        "target_func_names": target_func_names,
        "required_target_func_names": required_target_func_names,
        "arch": arch,
    }


def _render_llm_decompile_blocks(
    reference_items: list[dict[str, Any]],
    target_items: list[dict[str, Any]],
) -> tuple[str, str]:
    def _render(kind: str, item: dict[str, Any]) -> str:
        func_name = str(item.get("func_name", "") or "").strip() or "<unknown>"
        disasm_code = str(item.get("disasm_code", "") or "")
        procedure = str(item.get("procedure", "") or "")
        return (
            f"### {kind} Function: {func_name}\n\n"
            f"**Disassembly for {func_name}**\n\n"
            f"```c\n; Function: {func_name}\n{disasm_code}\n```\n\n"
            f"**Procedure for {func_name}**\n\n"
            f"```c\n{procedure}\n```"
        )

    return (
        "\n\n".join(_render("Reference", item) for item in reference_items),
        "\n\n".join(_render("Target", item) for item in target_items),
    )


async def call_llm_decompile(
    *,
    llm_config: dict,
    symbol_name_list: list[str] | tuple[str, ...] | str,
    reference_items: list[dict[str, Any]],
    target_items: list[dict[str, Any]],
    prompt_template: str,
    arch: str = "",
    debug: bool = False,
) -> dict[str, list[dict[str, str]]]:
    if isinstance(symbol_name_list, str):
        symbol_name_text = symbol_name_list.strip()
    else:
        symbol_name_text = ", ".join(
            str(item).strip() for item in symbol_name_list if str(item).strip()
        )
    reference_blocks, target_blocks = _render_llm_decompile_blocks(
        reference_items,
        target_items,
    )
    prompt = _resolve_llm_template_value(prompt_template, arch).format(
        symbol_name_list=symbol_name_text,
        reference_blocks=reference_blocks,
        target_blocks=target_blocks,
        disasm_for_reference=reference_blocks,
        procedure_for_reference="",
        disasm_code=target_blocks,
        procedure="",
        platform=arch,
        arch=arch,
    )
    _debug_log(
        debug,
        f"calling llm_decompile for {symbol_name_text} with model={llm_config.get('model', '')}",
    )
    _debug_print_multiline(
        f"llm_decompile prompt for {symbol_name_text}",
        prompt,
        debug=debug,
    )
    raw = await call_llm_text(
        model=llm_config["model"],
        prompt=prompt,
        api_key=llm_config.get("api_key", ""),
        base_url=llm_config.get("base_url"),
        temperature=llm_config.get("temperature"),
        effort=llm_config.get("effort"),
        fake_as=llm_config.get("fake_as"),
    )
    _debug_print_multiline(
        f"llm_decompile raw response for {symbol_name_text}",
        raw,
        debug=debug,
    )
    parsed = parse_llm_decompile_response(raw)
    _debug_print_json(
        f"llm_decompile parsed response for {symbol_name_text}",
        parsed,
        debug=debug,
    )
    return parsed


def _is_valid_remote_json_ack(ack: Any, output_path: Path) -> bool:
    if not isinstance(ack, dict) or not ack.get("ok"):
        return False
    if os.fspath(output_path) != str(ack.get("output_path", "")).strip():
        return False
    if str(ack.get("format", "")).strip() != "json":
        return False
    try:
        return int(ack.get("bytes_written")) >= 0
    except (TypeError, ValueError):
        return False


async def _find_function_addr_by_name_via_mcp(
    session,
    func_name: str,
) -> int | None:
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
        resolved_name = str(payload.get("code_name") or code_name).strip() or code_name
        return {
            "code_name": resolved_name,
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
    debug: bool = False,
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
        _debug_log(
            debug,
            f"llm_decompile failed to export target code region: {target_name}",
        )
    return True, target_detail


async def _load_llm_decompile_target_details_via_mcp(
    session,
    target_func_names: list[str],
    *,
    binary_dir: str | Path,
    image_base: int,
    debug: bool = False,
) -> list[dict[str, str]]:
    target_items: list[dict[str, str]] = []
    for target_func_name in target_func_names:
        handled_code_region, target_detail = await _load_code_region_target_detail_via_mcp(
            session,
            target_func_name,
            binary_dir=binary_dir,
            image_base=image_base,
            debug=debug,
        )
        if handled_code_region:
            if target_detail is not None:
                target_items.append(target_detail)
            continue

        func_va = _load_target_func_va_from_current_yaml(
            binary_dir,
            target_func_name,
            image_base,
        )
        if func_va is None:
            func_va = await _find_function_addr_by_name_via_mcp(session, target_func_name)
        if func_va is None:
            _debug_log(
                debug,
                f"llm_decompile target function not found in current IDB: {target_func_name}",
            )
            continue
        target_detail = await _export_function_detail_via_mcp(
            session,
            target_func_name,
            func_va,
        )
        if target_detail is not None:
            target_items.append(target_detail)
        else:
            _debug_log(
                debug,
                f"llm_decompile failed to export target detail: {target_func_name}",
            )
    return target_items


def _has_all_required_target_details(
    target_items: list[dict[str, Any]],
    required_target_func_names: list[str],
) -> bool:
    available_names = {
        str(item.get("func_name", "")).strip()
        for item in target_items
        if str(item.get("func_name", "")).strip()
    }
    return all(name in available_names for name in required_target_func_names)


async def _resolve_direct_call_target_via_mcp(session, insn_va: Any) -> int | None:
    try:
        insn_va_int = _parse_offset_value(insn_va)
    except Exception:
        return None
    py_code = (
        "import ida_funcs, idautils, json\n"
        f"insn_ea = {insn_va_int}\n"
        "matches = []\n"
        "for target_ea in idautils.CodeRefsFrom(insn_ea, False):\n"
        "    func = ida_funcs.get_func(target_ea)\n"
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


async def _resolve_funcptr_target_via_mcp(session, insn_va: Any) -> int | None:
    try:
        insn_va_int = _parse_offset_value(insn_va)
    except Exception:
        return None
    py_code = (
        "import ida_funcs, idautils, json\n"
        f"insn_ea = {insn_va_int}\n"
        "matches = []\n"
        "for target_ea in idautils.DataRefsFrom(insn_ea):\n"
        "    func = ida_funcs.get_func(target_ea)\n"
        "    if func is not None and int(func.start_ea) == int(target_ea):\n"
        "        matches.append(hex(int(target_ea)))\n"
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


async def _resolve_direct_gv_target_via_mcp(session, insn_va: Any) -> int | None:
    try:
        insn_va_int = _parse_offset_value(insn_va)
    except Exception:
        return None
    py_code = (
        "import idautils, json\n"
        f"insn_ea = {insn_va_int}\n"
        "matches = [hex(int(target_ea)) for target_ea in idautils.DataRefsFrom(insn_ea)]\n"
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


def _build_struct_member_symbol_name(struct_name: str, member_name: str) -> str:
    return f"{struct_name}_{member_name}"


async def resolve_symbol_via_llm_decompile(
    *,
    session,
    symbol_name: str,
    category: str,
    binary_dir: str | Path,
    image_base: int,
    llm_decompile_specs: Any,
    llm_config: dict | None,
    struct_metadata: dict[str, Any] | None = None,
    debug: bool = False,
) -> dict[str, Any] | None:
    request = _prepare_llm_decompile_request(
        symbol_name=symbol_name,
        llm_decompile_specs=llm_decompile_specs,
        llm_config=llm_config,
        binary_dir=binary_dir,
        debug=debug,
    )
    if request is None or not isinstance(llm_config, dict):
        return None
    _debug_log(debug, f"llm_decompile request prepared for {symbol_name}")

    llm_symbol_name = str(request["llm_symbol_name"]).strip()
    llm_symbol_names = [
        str(name).strip()
        for name in request.get("llm_symbol_names", [llm_symbol_name])
        if str(name).strip()
    ] or [llm_symbol_name]
    cache_key = _build_llm_decompile_result_cache_key(
        request={**request, "llm_symbol_names": llm_symbol_names},
        llm_config=llm_config,
        binary_dir=binary_dir,
        image_base=image_base,
    )
    if cache_key is not None and cache_key in _LLM_DECOMPILE_RESULT_CACHE:
        result = _LLM_DECOMPILE_RESULT_CACHE[cache_key]
        _debug_log(
            debug,
            "using cached llm_decompile result for "
            f"{symbol_name}: {', '.join(llm_symbol_names)}",
        )
    else:
        target_func_names = request.get("target_func_names", [])
        required_target_func_names = [
            str(name).strip()
            for name in request.get("required_target_func_names", target_func_names)
            if str(name).strip()
        ]
        target_items = await _load_llm_decompile_target_details_via_mcp(
            session,
            target_func_names,
            binary_dir=binary_dir,
            image_base=image_base,
            debug=debug,
        )
        if not target_items and target_func_names:
            _debug_log(
                debug,
                f"llm_decompile skipped for {symbol_name}: no target function details",
            )
            return None
        if not _has_all_required_target_details(
            target_items,
            required_target_func_names,
        ):
            _debug_log(
                debug,
                f"llm_decompile skipped for {symbol_name}: missing required target function details",
            )
            return None
        _debug_log(
            debug,
            f"calling llm_decompile for {symbol_name}: {', '.join(llm_symbol_names)}",
        )
        result = await call_llm_decompile(
            llm_config=llm_config,
            symbol_name_list=llm_symbol_names,
            reference_items=request.get("reference_items", []),
            target_items=target_items,
            prompt_template=request.get(
                "prompt_template",
                "{reference_blocks}\n{target_blocks}\n{symbol_name_list}",
            ),
            arch=request.get("arch", ""),
            debug=debug,
        )
        if cache_key is not None:
            _LLM_DECOMPILE_RESULT_CACHE[cache_key] = result
    _debug_log(
        debug,
        "llm_decompile result for "
        f"{symbol_name}: found_call={len(result.get('found_call', []))}, "
        f"found_funcptr={len(result.get('found_funcptr', []))}, "
        f"found_gv={len(result.get('found_gv', []))}, "
        f"found_struct_offset={len(result.get('found_struct_offset', []))}",
    )

    if category == "func":
        for entry in result.get("found_call", []):
            if entry.get("func_name") not in {symbol_name, llm_symbol_name}:
                continue
            func_va = await _resolve_direct_call_target_via_mcp(session, entry.get("insn_va"))
            if func_va is not None:
                return {
                    "func_name": symbol_name,
                    "func_va": func_va,
                    "func_rva": func_va - image_base,
                }
        for entry in result.get("found_funcptr", []):
            if entry.get("funcptr_name") not in {symbol_name, llm_symbol_name}:
                continue
            func_va = await _resolve_funcptr_target_via_mcp(session, entry.get("insn_va"))
            if func_va is not None:
                return {
                    "func_name": symbol_name,
                    "func_va": func_va,
                    "func_rva": func_va - image_base,
                }
        return None

    if category == "gv":
        for entry in result.get("found_gv", []):
            if entry.get("gv_name") not in {symbol_name, llm_symbol_name}:
                continue
            gv_va = await _resolve_direct_gv_target_via_mcp(session, entry.get("insn_va"))
            if gv_va is not None:
                return {
                    "gv_name": symbol_name,
                    "gv_va": gv_va,
                    "gv_rva": gv_va - image_base,
                }
        return None

    if category == "struct_offset":
        expected_struct_name = str((struct_metadata or {}).get("struct_name", "")).strip()
        expected_member_name = str((struct_metadata or {}).get("member_name", "")).strip()
        for entry in result.get("found_struct_offset", []):
            struct_name = str(entry.get("struct_name", "")).strip()
            member_name = str(entry.get("member_name", "")).strip()
            if expected_struct_name and expected_member_name:
                if struct_name != expected_struct_name or member_name != expected_member_name:
                    continue
            elif _build_struct_member_symbol_name(struct_name, member_name) != symbol_name:
                continue
            try:
                offset = _parse_offset_value(entry.get("offset"))
            except (TypeError, ValueError):
                continue
            payload = {
                "struct_name": struct_name,
                "member_name": member_name,
                "offset": offset,
            }
            bit_offset = str(entry.get("bit_offset", "")).strip()
            if bit_offset:
                try:
                    payload["bit_offset"] = _parse_offset_value(bit_offset)
                except (TypeError, ValueError):
                    if bool((struct_metadata or {}).get("bits", False)):
                        continue
            return payload

    return None
