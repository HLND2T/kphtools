from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from ida_preprocessor_scripts.generic_func import preprocess_func_symbol
from ida_preprocessor_scripts.generic_gv import preprocess_gv_symbol
from ida_preprocessor_scripts.generic_struct_offset import preprocess_struct_symbol
from ida_mcp_resolver import resolve_symbol_via_llm_decompile
from ida_llm_specs import (
    build_llm_decompile_specs_map,
    build_semantic_query_names,
    validate_llm_decompile_specs,
)
from symbol_artifacts import artifact_path, write_func_yaml, write_gv_yaml, write_struct_yaml


PREPROCESS_STATUS_SUCCESS = "success"
PREPROCESS_STATUS_FAILED = "failed"
PREPROCESS_STATUS_ABSENT_OK = "absent_ok"
STACK_INFORMATION_EX_BUILDNUM = 18305

_VERSION_DIR_RE = re.compile(r"\.(\d+)\.(\d+)\.(\d+)\.(\d+)$")
_SUPPORTED_BINARY_ARCHES = frozenset({"amd64", "arm64"})

_ALLOWED_FIELDS_BY_CATEGORY = {
    "struct_offset": frozenset({"struct_name", "member_name", "offset", "bit_offset"}),
    "gv": frozenset({"gv_name", "gv_rva", "gv_va"}),
    "func": frozenset({"func_name", "func_rva", "func_va", "func_size"}),
}

_FUNC_XREFS_ALLOWED_KEYS = frozenset(
    {
        "func_name",
        "xref_strings",
        "xref_unicode_strings",
        "xref_gvs",
        "xref_signatures",
        "xref_funcs",
        "exclude_funcs",
        "exclude_strings",
        "exclude_unicode_strings",
        "exclude_gvs",
        "exclude_signatures",
    }
)

_FUNC_XREFS_LIST_KEYS = (
    "xref_strings",
    "xref_unicode_strings",
    "xref_gvs",
    "xref_signatures",
    "xref_funcs",
    "exclude_funcs",
    "exclude_strings",
    "exclude_unicode_strings",
    "exclude_gvs",
    "exclude_signatures",
)

_FUNC_XREFS_POSITIVE_KEYS = (
    "xref_strings",
    "xref_unicode_strings",
    "xref_gvs",
    "xref_signatures",
    "xref_funcs",
)


def arch_from_binary_dir(binary_dir: str | Path) -> str | None:
    for part in Path(binary_dir).parts:
        normalized = part.lower()
        if normalized in _SUPPORTED_BINARY_ARCHES:
            return normalized
    return None


def buildnum_from_binary_dir(binary_dir: str | Path) -> str | None:
    for part in Path(binary_dir).parts:
        match = _VERSION_DIR_RE.search(part)
        if match:
            return match.group(3)
    return None


def buildnum_int_from_binary_dir(binary_dir: str | Path) -> int | None:
    buildnum = buildnum_from_binary_dir(binary_dir)
    if buildnum is None:
        return None
    return int(buildnum)


def has_current_stack_information_ex(binary_dir: str | Path) -> bool | None:
    buildnum = buildnum_int_from_binary_dir(binary_dir)
    if buildnum is None:
        return None
    return buildnum >= STACK_INFORMATION_EX_BUILDNUM


def _field(value: Any, field_name: str) -> Any:
    if isinstance(value, Mapping):
        return value.get(field_name)
    return getattr(value, field_name, None)


def _infer_symbol_category(*, symbol: Any, desired_fields: list[str]) -> str | None:
    explicit_category = _field(symbol, "category")
    if explicit_category in _ALLOWED_FIELDS_BY_CATEGORY:
        return explicit_category
    if explicit_category is not None:
        return None

    candidates = [
        category
        for category, allowed_fields in _ALLOWED_FIELDS_BY_CATEGORY.items()
        if all(field in allowed_fields for field in desired_fields)
    ]
    if len(candidates) != 1:
        return None
    return candidates[0]


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


def _normalize_func_xrefs(
    func_xrefs: Any,
    *,
    debug: bool = False,
) -> dict[str, dict[str, list[Any]]] | None:
    if func_xrefs is None:
        return {}
    if not isinstance(func_xrefs, Iterable) or isinstance(func_xrefs, (str, bytes)):
        return None

    normalized: dict[str, dict[str, list[Any]]] = {}
    for spec in func_xrefs:
        if not isinstance(spec, Mapping):
            return None
        unknown_keys = sorted(set(spec) - _FUNC_XREFS_ALLOWED_KEYS)
        if unknown_keys:
            if debug:
                print(
                    "    Preprocess: unknown func_xrefs keys for "
                    f"{spec.get('func_name')}: {unknown_keys}"
                )
            return None
        func_name = spec.get("func_name")
        if not isinstance(func_name, str) or not func_name:
            return None
        if func_name in normalized:
            return None

        normalized_spec: dict[str, list[Any]] = {}
        for field_name in _FUNC_XREFS_LIST_KEYS:
            field_value = spec.get(field_name, [])
            if not isinstance(field_value, (list, tuple)):
                return None
            normalized_spec[field_name] = list(field_value)

        if not any(
            normalized_spec[field_name] for field_name in _FUNC_XREFS_POSITIVE_KEYS
        ):
            if debug:
                print(f"    Preprocess: empty func_xrefs spec for {func_name}")
            return None

        normalized[func_name] = normalized_spec
    return normalized


def _prepare_llm_decompile_context(
    *,
    llm_decompile_specs: Any,
    llm_config: Any,
    desired_fields_by_symbol: dict[str, list[str]],
    struct_metadata: dict[str, dict[str, Any]] | None,
    binary_dir: str | Path,
    debug: bool,
) -> tuple[Any, Any] | None:
    specs_map = build_llm_decompile_specs_map(llm_decompile_specs, debug=debug)
    if specs_map is None:
        return None
    if not specs_map:
        return llm_decompile_specs, llm_config
    category_by_symbol = {
        name: category
        for name, raw_fields in desired_fields_by_symbol.items()
        if (
            category := _infer_symbol_category(
                symbol={"category": None},
                desired_fields=raw_fields,
            )
        )
        is not None
    }
    config = dict(llm_config) if isinstance(llm_config, dict) else {}
    if not validate_llm_decompile_specs(
        specs_map,
        expected_inputs=config.get("_expected_inputs"),
        optional_inputs=config.get("_optional_inputs"),
        category_by_symbol=category_by_symbol,
        arch=arch_from_binary_dir(binary_dir),
        debug=debug,
    ):
        return None
    semantic_query_names = build_semantic_query_names(
        specs_map,
        category_by_symbol=category_by_symbol,
        struct_metadata=struct_metadata,
        debug=debug,
    )
    if semantic_query_names is None:
        return None
    config["_semantic_query_names"] = semantic_query_names
    return list(specs_map.values()), config


async def _preprocess_category_fast_path(
    *,
    session: Any,
    target_symbol_name: str,
    symbol_category: str,
    binary_dir: str | Path,
    pdb_path: str | Path | None,
    debug: bool,
    llm_config: Any,
    llm_decompile_specs: Any,
    struct_member_names: list[str] | None,
    struct_metadata: dict[str, dict[str, Any]] | None,
    gv_names: list[str] | None,
    gv_metadata: dict[str, dict[str, Any]] | None,
    func_names: list[str] | None,
    func_metadata: dict[str, dict[str, Any]] | None,
    func_xrefs_map: dict[str, Any],
) -> tuple[dict[str, Any] | None, dict[str, Any], Any] | None:
    has_pdb = pdb_path is not None
    if symbol_category == "struct_offset":
        if struct_member_names is not None and target_symbol_name not in struct_member_names:
            return None
        metadata = (struct_metadata or {}).get(target_symbol_name)
        if not isinstance(metadata, dict):
            return None
        payload = None
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
        return payload, metadata, write_struct_yaml
    if symbol_category == "gv":
        if gv_names is not None and target_symbol_name not in gv_names:
            return None
        metadata = (gv_metadata or {}).get(target_symbol_name, {})
        if not isinstance(metadata, dict):
            return None
        payload = None
        if has_pdb:
            payload = await preprocess_gv_symbol(
                session=session,
                symbol_name=target_symbol_name,
                metadata=metadata,
                pdb_path=pdb_path,
                debug=debug,
                llm_config=llm_config,
            )
        return payload, metadata, write_gv_yaml
    if symbol_category != "func":
        return None
    allowed_func_names = set(func_names or []) | set(func_xrefs_map)
    if func_names is not None and target_symbol_name not in allowed_func_names:
        return None
    metadata = (func_metadata or {}).get(target_symbol_name, {})
    if not isinstance(metadata, dict):
        return None
    func_xref = func_xrefs_map.get(target_symbol_name)
    aliases = metadata.get("alias")
    should_resolve = has_pdb or func_xref is not None or (
        not has_pdb and isinstance(aliases, (list, tuple)) and bool(aliases)
    )
    payload = None
    if should_resolve:
        payload = await preprocess_func_symbol(
            session=session,
            symbol_name=target_symbol_name,
            metadata=metadata,
            pdb_path=pdb_path,
            debug=debug,
            llm_config=llm_config,
            binary_dir=Path(binary_dir),
            image_base=0x140000000,
            func_xref=func_xref,
        )
    return payload, metadata, write_func_yaml


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
    func_xrefs=None,
    llm_decompile_specs=None,
    generate_yaml_desired_fields=None,
):
    target_symbol_name = _field(symbol, "name")
    if not isinstance(target_symbol_name, str) or not target_symbol_name:
        return PREPROCESS_STATUS_FAILED
    desired_fields_by_symbol = _normalize_desired_fields(generate_yaml_desired_fields)
    if desired_fields_by_symbol is None:
        return PREPROCESS_STATUS_FAILED
    func_xrefs_map = _normalize_func_xrefs(func_xrefs, debug=debug)
    if func_xrefs_map is None:
        return PREPROCESS_STATUS_FAILED

    llm_context = _prepare_llm_decompile_context(
        llm_decompile_specs=llm_decompile_specs,
        llm_config=llm_config,
        desired_fields_by_symbol=desired_fields_by_symbol,
        struct_metadata=struct_metadata,
        binary_dir=binary_dir,
        debug=debug,
    )
    if llm_context is None:
        return PREPROCESS_STATUS_FAILED
    llm_decompile_specs, llm_config = llm_context

    desired_fields = desired_fields_by_symbol.get(target_symbol_name)
    if not desired_fields:
        return PREPROCESS_STATUS_FAILED

    symbol_category = _infer_symbol_category(
        symbol=symbol,
        desired_fields=desired_fields,
    )
    if symbol_category is None:
        return PREPROCESS_STATUS_FAILED

    fast_path = await _preprocess_category_fast_path(
        session=session,
        target_symbol_name=target_symbol_name,
        symbol_category=symbol_category,
        binary_dir=binary_dir,
        pdb_path=pdb_path,
        debug=debug,
        llm_config=llm_config,
        llm_decompile_specs=llm_decompile_specs,
        struct_member_names=struct_member_names,
        struct_metadata=struct_metadata,
        gv_names=gv_names,
        gv_metadata=gv_metadata,
        func_names=func_names,
        func_metadata=func_metadata,
        func_xrefs_map=func_xrefs_map,
    )
    if fast_path is None:
        return PREPROCESS_STATUS_FAILED
    payload, metadata, writer = fast_path

    if payload is None:
        payload = await resolve_symbol_via_llm_decompile(
            session=session,
            symbol_name=target_symbol_name,
            category=symbol_category,
            binary_dir=binary_dir,
            image_base=0x140000000,
            llm_decompile_specs=llm_decompile_specs,
            llm_config=llm_config,
            struct_metadata=metadata if symbol_category == "struct_offset" else None,
            debug=debug,
        )
    if payload is None:
        return PREPROCESS_STATUS_FAILED

    filtered_payload = _filter_payload(
        payload=payload,
        category=symbol_category,
        desired_fields=desired_fields,
    )
    if filtered_payload is None:
        return PREPROCESS_STATUS_FAILED

    writer(artifact_path(binary_dir, target_symbol_name), filtered_payload)
    return PREPROCESS_STATUS_SUCCESS
