from __future__ import annotations

from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from ida_preprocessor_scripts.generic_func import preprocess_func_symbol
from ida_preprocessor_scripts.generic_gv import preprocess_gv_symbol
from ida_preprocessor_scripts.generic_struct_offset import preprocess_struct_symbol
from ida_mcp_resolver import resolve_symbol_via_llm_decompile
from symbol_artifacts import artifact_path, write_func_yaml, write_gv_yaml, write_struct_yaml


PREPROCESS_STATUS_SUCCESS = "success"
PREPROCESS_STATUS_FAILED = "failed"

_ALLOWED_FIELDS_BY_CATEGORY = {
    "struct_offset": frozenset({"struct_name", "member_name", "offset", "bit_offset"}),
    "gv": frozenset({"gv_name", "gv_rva", "gv_va"}),
    "func": frozenset({"func_name", "func_rva", "func_va", "func_size"}),
}


def _normalize_desired_fields(
    generate_yaml_desired_fields: Any,
) -> dict[str, list[str]] | None:
    if generate_yaml_desired_fields is None:
        return {}

    if isinstance(generate_yaml_desired_fields, Mapping):
        items = generate_yaml_desired_fields.items()
    elif isinstance(generate_yaml_desired_fields, Iterable):
        items = generate_yaml_desired_fields
    else:
        return None

    normalized: dict[str, list[str]] = {}
    for item in items:
        if not isinstance(item, (tuple, list)) or len(item) != 2:
            return None
        symbol_name, raw_fields = item
        if not isinstance(symbol_name, str) or not isinstance(raw_fields, list):
            return None
        if not raw_fields or any(not isinstance(field, str) for field in raw_fields):
            return None
        normalized[symbol_name] = raw_fields
    return normalized


def _filter_payload(
    *,
    payload: dict[str, Any],
    category: str,
    desired_fields: list[str],
) -> dict[str, Any] | None:
    allowed_fields = _ALLOWED_FIELDS_BY_CATEGORY.get(category)
    if allowed_fields is None:
        return None
    if any(field not in allowed_fields for field in desired_fields):
        return None
    if any(field not in payload for field in desired_fields):
        return None
    return {field: payload[field] for field in desired_fields}


async def preprocess_common_skill(
    *,
    session,
    skill,
    symbol,
    binary_dir: str | Path,
    pdb_path: str | Path | None,
    debug: bool,
    llm_config,
    struct_member_names: list[str] | None = None,
    struct_metadata: dict[str, dict[str, Any]] | None = None,
    gv_names: list[str] | None = None,
    gv_metadata: dict[str, dict[str, Any]] | None = None,
    func_names: list[str] | None = None,
    func_metadata: dict[str, dict[str, Any]] | None = None,
    llm_decompile_specs=None,
    generate_yaml_desired_fields=None,
):
    target_symbol_name = symbol.name
    has_pdb = pdb_path is not None

    desired_fields_by_symbol = _normalize_desired_fields(generate_yaml_desired_fields)
    if desired_fields_by_symbol is None:
        return PREPROCESS_STATUS_FAILED

    desired_fields = desired_fields_by_symbol.get(target_symbol_name)
    if not desired_fields:
        return PREPROCESS_STATUS_FAILED

    metadata: dict[str, Any] | None = None
    payload: dict[str, Any] | None = None
    if symbol.category == "struct_offset":
        if struct_member_names is not None and target_symbol_name not in struct_member_names:
            return PREPROCESS_STATUS_FAILED
        metadata = (struct_metadata or {}).get(target_symbol_name)
        if not isinstance(metadata, dict):
            return PREPROCESS_STATUS_FAILED
        if has_pdb:
            payload = await preprocess_struct_symbol(
                session=session,
                symbol_name=target_symbol_name,
                metadata=metadata,
                binary_dir=binary_dir,
                pdb_path=pdb_path,
                debug=debug,
                llm_config=llm_config,
                llm_decompile_specs=llm_decompile_specs,
            )
        writer = write_struct_yaml
    elif symbol.category == "gv":
        if gv_names is not None and target_symbol_name not in gv_names:
            return PREPROCESS_STATUS_FAILED
        metadata = (gv_metadata or {}).get(target_symbol_name, {})
        if not isinstance(metadata, dict):
            return PREPROCESS_STATUS_FAILED
        if has_pdb:
            payload = await preprocess_gv_symbol(
                session=session,
                symbol_name=target_symbol_name,
                metadata=metadata,
                pdb_path=pdb_path,
                debug=debug,
                llm_config=llm_config,
            )
        writer = write_gv_yaml
    elif symbol.category == "func":
        if func_names is not None and target_symbol_name not in func_names:
            return PREPROCESS_STATUS_FAILED
        metadata = (func_metadata or {}).get(target_symbol_name, {})
        if not isinstance(metadata, dict):
            return PREPROCESS_STATUS_FAILED
        if has_pdb:
            payload = await preprocess_func_symbol(
                session=session,
                symbol_name=target_symbol_name,
                metadata=metadata,
                pdb_path=pdb_path,
                debug=debug,
                llm_config=llm_config,
            )
        writer = write_func_yaml
    else:
        return PREPROCESS_STATUS_FAILED

    if payload is None:
        payload = await resolve_symbol_via_llm_decompile(
            session=session,
            symbol_name=target_symbol_name,
            category=symbol.category,
            binary_dir=binary_dir,
            image_base=0x140000000,
            llm_decompile_specs=llm_decompile_specs,
            llm_config=llm_config,
            struct_metadata=metadata if symbol.category == "struct_offset" else None,
            debug=debug,
        )
    if payload is None:
        return PREPROCESS_STATUS_FAILED

    filtered_payload = _filter_payload(
        payload=payload,
        category=symbol.category,
        desired_fields=desired_fields,
    )
    if filtered_payload is None:
        return PREPROCESS_STATUS_FAILED

    writer(artifact_path(binary_dir, target_symbol_name), filtered_payload)
    return PREPROCESS_STATUS_SUCCESS
