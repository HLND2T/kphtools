from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import yaml

from ida_llm_decompile import call_llm_decompile as _validated_call_llm_decompile
from ida_llm_response import empty_llm_decompile_result, parse_llm_decompile_response
from ida_llm_specs import build_llm_decompile_specs_map
from ida_llm_targets import (
    has_all_required_target_details, load_llm_decompile_target_details_via_mcp,
    resolve_direct_call_target_via_mcp, resolve_direct_gv_target_via_mcp,
    resolve_funcptr_target_via_mcp,
)
from ida_reference_export import validate_reference_yaml_payload

_LLM_DECOMPILE_RESULT_CACHE: dict[tuple[Any, ...], dict[str, list[dict[str, str]]]] = {}
_LLM_RESULT_CONTRACT_VERSION = "kphtools-four-section-v1"


def _debug_log(debug: bool, message: str) -> None:
    if debug:
        print(f"[debug] {message}")


def _parse_py_eval_result(tool_result: Any) -> dict[str, Any]:
    payload = json.loads(tool_result.content[0].text)
    result = json.loads(payload["result"])
    if not isinstance(result, dict):
        raise TypeError("py_eval result must be a mapping")
    return result


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


def _parse_offset_value(value: Any) -> int:
    if isinstance(value, int):
        return value
    text = str(value).strip()
    return int(text, 0 if text.lower().startswith("0x") else 10)


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


_load_llm_decompile_target_details_via_mcp = load_llm_decompile_target_details_via_mcp
_has_all_required_target_details = has_all_required_target_details
_resolve_direct_call_target_via_mcp = resolve_direct_call_target_via_mcp
_resolve_funcptr_target_via_mcp = resolve_funcptr_target_via_mcp
_resolve_direct_gv_target_via_mcp = resolve_direct_gv_target_via_mcp

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


def _resolve_request_path(value: Any, arch: str, scripts_dir: Path) -> Path:
    resolved = str(value or "")
    if arch:
        resolved = resolved.replace("{arch}", arch).replace("{platform}", arch)
    path = Path(resolved)
    return path if path.is_absolute() else scripts_dir / path


def _load_reference_item(reference_path: Path) -> dict[str, Any] | None:
    try:
        data = yaml.safe_load(reference_path.read_text(encoding="utf-8")) or {}
        return validate_reference_yaml_payload(data)
    except Exception:
        return None


def _llm_decompile_specs_signature(
    spec: dict[str, Any] | None,
) -> tuple[str, tuple[str, ...], tuple[tuple[str, str], ...]] | None:
    if not spec:
        return None
    prompt_path = str(spec.get("prompt_path", ""))
    reference_paths = tuple(spec.get("reference_yaml_paths", []))
    dependency_policy = tuple(sorted(spec.get("dependency_policy", {}).items()))
    if not prompt_path or not reference_paths or not all(reference_paths):
        return None
    return prompt_path, reference_paths, dependency_policy


def _collect_batch_context(
    specs_map: dict[str, dict[str, Any]],
    llm_spec: dict[str, Any],
    semantic_query_names: dict[str, str],
) -> tuple[list[str], dict[str, list[str]]] | None:
    signature = _llm_decompile_specs_signature(llm_spec)
    names: list[str] = []
    expected_sections: dict[str, list[str]] = {}
    semantic_owners: dict[str, str] = {}
    for artifact_name, candidate_spec in specs_map.items():
        if _llm_decompile_specs_signature(candidate_spec) != signature:
            continue
        semantic_name = str(semantic_query_names.get(artifact_name, artifact_name)).strip()
        sections = list(candidate_spec.get("expected_result_sections", []))
        existing_owner = semantic_owners.get(semantic_name)
        existing = expected_sections.get(semantic_name)
        owner_conflict = existing_owner is not None and existing_owner != artifact_name
        section_conflict = existing is not None and set(existing) != set(sections)
        if not semantic_name or owner_conflict or section_conflict:
            return None
        semantic_owners[semantic_name] = artifact_name
        if semantic_name not in names:
            names.append(semantic_name)
        expected_sections[semantic_name] = sections
    return names, expected_sections


def _append_unique_text(items: list[str], seen: set[str], value: Any) -> None:
    text = str(value or "").strip()
    if text and text not in seen:
        seen.add(text)
        items.append(text)


def _load_reference_context(
    *,
    llm_spec: dict[str, Any],
    arch: str,
    scripts_dir: Path,
    symbol_name: str,
    debug: bool,
) -> dict[str, Any] | None:
    items: list[dict[str, Any]] = []
    paths: list[str] = []
    target_names: list[str] = []
    required_names: list[str] = []
    seen: set[str] = set()
    policy = dict(llm_spec.get("dependency_policy", {}))
    for reference_value in llm_spec.get("reference_yaml_paths", []):
        path = _resolve_request_path(reference_value, arch, scripts_dir)
        item = _load_reference_item(path) if path.is_file() else None
        if item is None:
            _debug_log(debug, f"llm_decompile skipped for {symbol_name}: invalid reference {path}")
            return None
        target_name = str(item["func_name"])
        target_policy = policy.get(f"{target_name}.yaml")
        if target_policy not in {"required", "optional"}:
            _debug_log(debug, f"llm_decompile skipped for {symbol_name}: missing dependency policy for {target_name}.yaml")
            return None
        items.append(item)
        paths.append(os.fspath(path.resolve()))
        _append_unique_text(target_names, seen, target_name)
        if target_policy == "required":
            required_names.append(target_name)
        for optional_name in item.get("optional_funcs", []):
            _append_unique_text(target_names, seen, optional_name)
    return {
        "reference_items": items,
        "reference_paths": paths,
        "target_func_names": target_names,
        "required_target_func_names": required_names,
        "dependency_policy": policy,
    }


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
    has_model = bool(str(llm_config.get("model", "")).strip())
    has_api_key = bool(str(llm_config.get("api_key", "")).strip())
    if not has_model or not has_api_key:
        _debug_log(debug, f"llm_decompile skipped for {symbol_name}: llm credentials missing")
        return None
    specs_map = build_llm_decompile_specs_map(llm_decompile_specs)
    llm_spec = specs_map.get(symbol_name) if specs_map is not None else None
    semantic_names = llm_config.get("_semantic_query_names", {})
    if llm_spec is None or not isinstance(semantic_names, dict):
        _debug_log(debug, f"llm_decompile skipped for {symbol_name}: invalid spec context")
        return None
    arch = _infer_arch_from_binary_dir(binary_dir)
    arch = arch or str(llm_config.get("arch", "")).strip()
    scripts_dir = _get_preprocessor_scripts_dir()
    prompt_path = _resolve_request_path(llm_spec["prompt_path"], arch, scripts_dir)
    try:
        prompt_template = prompt_path.read_text(encoding="utf-8")
    except OSError:
        _debug_log(debug, f"llm_decompile skipped for {symbol_name}: invalid prompt {prompt_path}")
        return None
    references = _load_reference_context(
        llm_spec=llm_spec,
        arch=arch,
        scripts_dir=scripts_dir,
        symbol_name=symbol_name,
        debug=debug,
    )
    batch = _collect_batch_context(specs_map or {}, llm_spec, semantic_names)
    if references is None or batch is None or not batch[0]:
        _debug_log(debug, f"llm_decompile skipped for {symbol_name}: invalid request context")
        return None
    llm_symbol_name = str(semantic_names.get(symbol_name, symbol_name)).strip()
    return {
        **references,
        "prompt_template": prompt_template,
        "prompt_path": os.fspath(prompt_path.resolve()),
        "llm_symbol_name": llm_symbol_name,
        "llm_symbol_names": batch[0],
        "expected_result_sections": batch[1],
        "arch": arch,
    }


def _normalized_expected_sections(request: dict[str, Any]) -> tuple[Any, ...]:
    expected = request.get("expected_result_sections", {})
    return tuple(sorted((str(name), tuple(sorted(map(str, sections)))) for name, sections in expected.items()))


def _build_llm_decompile_result_cache_key(
    *,
    request: dict[str, Any],
    llm_config: dict,
    binary_dir: str | Path,
    image_base: int,
) -> tuple[Any, ...] | None:
    prompt_path = str(request.get("prompt_path", "")).strip()
    reference_paths = tuple(map(str, request.get("reference_paths", [])))
    target_names = tuple(map(str, request.get("target_func_names", [])))
    query_names = tuple(map(str, request.get("llm_symbol_names", [])))
    model = str(llm_config.get("model", "")).strip()
    if not all((prompt_path, reference_paths, target_names, query_names, model)):
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
        target_names,
        tuple(map(str, request.get("required_target_func_names", []))),
        tuple(sorted(request.get("dependency_policy", {}).items())),
        query_names,
        _normalized_expected_sections(request),
        _LLM_RESULT_CONTRACT_VERSION,
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
    return await _validated_call_llm_decompile(
        model=llm_config.get("model", ""),
        symbol_name_list=symbol_name_list,
        expected_result_sections=llm_config.get("_expected_result_sections", {}),
        reference_items=reference_items,
        target_items=target_items,
        prompt_template=prompt_template,
        arch=arch,
        platform=arch,
        binary_path=llm_config.get("_binary_path"),
        temperature=llm_config.get("temperature"),
        effort=llm_config.get("effort"),
        api_key=llm_config.get("api_key"),
        base_url=llm_config.get("base_url"),
        fake_as=llm_config.get("fake_as"),
        max_retries=llm_config.get("max_retries"),
        retry_initial_delay=llm_config.get("retry_initial_delay"),
        retry_backoff_factor=llm_config.get("retry_backoff_factor"),
        retry_max_delay=llm_config.get("retry_max_delay"),
        debug=debug,
    )


async def _load_or_call_llm_result(
    *,
    session,
    symbol_name: str,
    request: dict[str, Any],
    llm_config: dict,
    binary_dir: str | Path,
    image_base: int,
    debug: bool,
) -> dict[str, list[dict[str, str]]] | None:
    cache_key = _build_llm_decompile_result_cache_key(
        request=request,
        llm_config=llm_config,
        binary_dir=binary_dir,
        image_base=image_base,
    )
    if cache_key is not None and cache_key in _LLM_DECOMPILE_RESULT_CACHE:
        _debug_log(debug, f"using cached llm_decompile result for {symbol_name}")
        return _LLM_DECOMPILE_RESULT_CACHE[cache_key]
    target_items = await _load_llm_decompile_target_details_via_mcp(
        session,
        request.get("target_func_names", []),
        binary_dir=binary_dir,
        image_base=image_base,
        debug=debug,
    )
    if not _has_all_required_target_details(
        target_items,
        request.get("required_target_func_names", []),
    ):
        _debug_log(debug, f"llm_decompile skipped for {symbol_name}: missing required target details")
        return None
    call_config = {
        **llm_config,
        "_expected_result_sections": request.get("expected_result_sections", {}),
        "_binary_path": binary_dir,
    }
    result = await call_llm_decompile(
        llm_config=call_config,
        symbol_name_list=request.get("llm_symbol_names", []),
        reference_items=request.get("reference_items", []),
        target_items=target_items,
        prompt_template=request["prompt_template"],
        arch=request.get("arch", ""),
        debug=debug,
    )
    if cache_key is not None and any(result.values()):
        _LLM_DECOMPILE_RESULT_CACHE[cache_key] = result
    return result


async def _consume_function_result(
    session,
    result: dict[str, list[dict[str, str]]],
    symbol_name: str,
    query_name: str,
    image_base: int,
) -> dict[str, Any] | None:
    resolvers = (
        ("found_call", "func_name", _resolve_direct_call_target_via_mcp),
        ("found_funcptr", "funcptr_name", _resolve_funcptr_target_via_mcp),
    )
    for section, field_name, resolver in resolvers:
        for entry in result.get(section, []):
            if entry.get(field_name) not in {symbol_name, query_name}:
                continue
            func_va = await resolver(session, entry.get("insn_va"))
            if func_va is not None:
                return {
                    "func_name": symbol_name,
                    "func_va": func_va,
                    "func_rva": func_va - image_base,
                }
    return None


async def _consume_gv_result(
    session,
    result: dict[str, list[dict[str, str]]],
    symbol_name: str,
    query_name: str,
    image_base: int,
) -> dict[str, Any] | None:
    for entry in result.get("found_gv", []):
        if entry.get("gv_name") not in {symbol_name, query_name}:
            continue
        gv_va = await _resolve_direct_gv_target_via_mcp(session, entry.get("insn_va"))
        if gv_va is not None:
            return {"gv_name": symbol_name, "gv_va": gv_va, "gv_rva": gv_va - image_base}
    return None


def _consume_struct_offset_result(
    result: dict[str, list[dict[str, str]]],
    symbol_name: str,
    struct_metadata: dict[str, Any] | None,
) -> dict[str, Any] | None:
    metadata = struct_metadata or {}
    expected_struct = str(metadata.get("struct_name", "")).strip()
    expected_member = str(metadata.get("member_name", "")).strip()
    for entry in result.get("found_struct_offset", []):
        struct_name = str(entry.get("struct_name", "")).strip()
        member_name = str(entry.get("member_name", "")).strip()
        if expected_struct and expected_member:
            if (struct_name, member_name) != (expected_struct, expected_member):
                continue
        elif f"{struct_name}_{member_name}" != symbol_name:
            continue
        try:
            offset = _parse_offset_value(entry.get("offset"))
        except (TypeError, ValueError):
            continue
        payload: dict[str, Any] = {
            "struct_name": struct_name,
            "member_name": member_name,
            "offset": offset,
        }
        bit_offset = str(entry.get("bit_offset", "")).strip()
        try:
            if bit_offset:
                payload["bit_offset"] = _parse_offset_value(bit_offset)
        except (TypeError, ValueError):
            if bool(metadata.get("bits", False)):
                continue
        return payload
    return None


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
    result = await _load_or_call_llm_result(
        session=session,
        symbol_name=symbol_name,
        request=request,
        llm_config=llm_config,
        binary_dir=binary_dir,
        image_base=image_base,
        debug=debug,
    )
    if result is None:
        return None
    query_name = str(request["llm_symbol_name"]).strip()
    if category == "func":
        return await _consume_function_result(
            session, result, symbol_name, query_name, image_base
        )
    if category == "gv":
        return await _consume_gv_result(
            session, result, symbol_name, query_name, image_base
        )
    if category == "struct_offset":
        return _consume_struct_offset_result(result, symbol_name, struct_metadata)
    return None
