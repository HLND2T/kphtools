from __future__ import annotations

import os
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

import yaml


LLM_DECOMPILE_RESULT_SECTIONS = frozenset(
    {"found_call", "found_funcptr", "found_gv", "found_struct_offset"}
)
_LLM_DECOMPILE_REQUIRED_SPEC_KEYS = frozenset(
    {
        "symbol_name",
        "prompt_path",
        "reference_yaml_paths",
        "expected_result_sections",
        "dependency_policy",
    }
)
_LLM_DECOMPILE_SPEC_KEYS = _LLM_DECOMPILE_REQUIRED_SPEC_KEYS
_LLM_DECOMPILE_DEPENDENCY_POLICIES = frozenset({"required", "optional"})
_LLM_RESULT_SECTIONS_BY_CATEGORY = {
    "func": frozenset({"found_call", "found_funcptr"}),
    "gv": frozenset({"found_gv"}),
    "struct_offset": frozenset({"found_struct_offset"}),
}


def _debug_log(debug: bool, message: str) -> None:
    if debug:
        print(f"    Preprocess: {message}")


def _normalize_string_list(
    values: Any,
    *,
    field_name: str,
    symbol_name: str,
    valid_values: frozenset[str] | None = None,
    allow_empty: bool = False,
    debug: bool = False,
) -> list[str] | None:
    if (
        not isinstance(values, (tuple, list, set))
        or isinstance(values, (str, bytes))
        or (not values and not allow_empty)
    ):
        _debug_log(
            debug,
            f"invalid llm_decompile {field_name} for {symbol_name}: {values!r}",
        )
        return None

    normalized: list[str] = []
    for value in values:
        if not isinstance(value, str):
            _debug_log(
                debug,
                f"invalid llm_decompile {field_name} entry for {symbol_name}: {value!r}",
            )
            return None
        value = value.strip()
        if not value or (valid_values is not None and value not in valid_values):
            _debug_log(
                debug,
                f"invalid llm_decompile {field_name} entry for {symbol_name}: {value!r}",
            )
            return None
        if value not in normalized:
            normalized.append(value)
    return normalized


def _normalize_llm_decompile_spec(
    spec: Any, *, debug: bool = False
) -> dict[str, Any] | None:
    if not isinstance(spec, Mapping):
        _debug_log(debug, f"invalid llm_decompile spec: {spec!r}")
        return None

    spec_keys = set(spec)
    missing_keys = sorted(_LLM_DECOMPILE_REQUIRED_SPEC_KEYS - spec_keys)
    unknown_keys = sorted(spec_keys - _LLM_DECOMPILE_SPEC_KEYS)
    if missing_keys or unknown_keys:
        _debug_log(
            debug,
            "invalid llm_decompile spec keys: "
            f"missing={missing_keys}, unknown={unknown_keys}, spec={spec!r}",
        )
        return None

    symbol_name = spec.get("symbol_name")
    prompt_path = spec.get("prompt_path")
    if not isinstance(symbol_name, str) or not symbol_name.strip():
        _debug_log(debug, f"invalid llm_decompile symbol_name: {symbol_name!r}")
        return None
    if not isinstance(prompt_path, str) or not prompt_path.strip():
        _debug_log(debug, f"invalid llm_decompile prompt_path for {symbol_name}")
        return None
    symbol_name = symbol_name.strip()
    prompt_path = prompt_path.strip()

    references = _normalize_string_list(
        spec.get("reference_yaml_paths"),
        field_name="reference paths",
        symbol_name=symbol_name,
        debug=debug,
    )
    sections = _normalize_string_list(
        spec.get("expected_result_sections"),
        field_name="expected result sections",
        symbol_name=symbol_name,
        valid_values=LLM_DECOMPILE_RESULT_SECTIONS,
        debug=debug,
    )
    if references is None or sections is None:
        return None

    raw_policy = spec.get("dependency_policy")
    if not isinstance(raw_policy, Mapping) or not raw_policy:
        _debug_log(
            debug,
            f"invalid llm_decompile dependency_policy for {symbol_name}: {raw_policy!r}",
        )
        return None

    dependency_policy: dict[str, str] = {}
    seen_keys: set[str] = set()
    for artifact_name, policy in raw_policy.items():
        if not isinstance(artifact_name, str) or not artifact_name.strip():
            _debug_log(debug, f"invalid dependency artifact for {symbol_name}")
            return None
        artifact_name = artifact_name.strip()
        artifact_key = os.path.normcase(artifact_name)
        if (
            "/" in artifact_name
            or "\\" in artifact_name
            or not artifact_name.endswith(".yaml")
            or artifact_key in seen_keys
            or not isinstance(policy, str)
            or policy not in _LLM_DECOMPILE_DEPENDENCY_POLICIES
        ):
            _debug_log(
                debug,
                "invalid llm_decompile dependency_policy entry for "
                f"{symbol_name}: {artifact_name!r} -> {policy!r}",
            )
            return None
        seen_keys.add(artifact_key)
        dependency_policy[artifact_name] = policy

    return {
        "symbol_name": symbol_name,
        "prompt_path": prompt_path,
        "reference_yaml_paths": references,
        "expected_result_sections": sections,
        "dependency_policy": dependency_policy,
    }


def _build_llm_decompile_specs_map(
    llm_decompile_specs: Any, *, debug: bool = False
) -> dict[str, dict[str, Any]] | None:
    if llm_decompile_specs is None:
        return {}
    if not isinstance(llm_decompile_specs, Iterable) or isinstance(
        llm_decompile_specs, (str, bytes, Mapping)
    ):
        _debug_log(debug, "llm_decompile specs must be a list")
        return None

    specs_map: dict[str, dict[str, Any]] = {}
    for raw_spec in llm_decompile_specs:
        spec = _normalize_llm_decompile_spec(raw_spec, debug=debug)
        if spec is None:
            return None
        symbol_name = spec["symbol_name"]
        if symbol_name in specs_map:
            _debug_log(debug, f"duplicate llm_decompile target: {symbol_name}")
            return None
        specs_map[symbol_name] = spec
    return specs_map


def _resolve_template(value: str, *, arch: str | None) -> str:
    resolved = value
    if arch:
        resolved = resolved.replace("{arch}", arch)
        resolved = resolved.replace("{platform}", arch)
    return resolved


def _load_reference_artifact_name(
    reference_value: str,
    *,
    scripts_dir: Path,
    arch: str | None,
    debug: bool,
) -> str | None:
    reference_path = Path(_resolve_template(reference_value, arch=arch))
    if not reference_path.is_absolute():
        reference_path = scripts_dir / reference_path
    try:
        payload = yaml.safe_load(reference_path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        _debug_log(debug, f"invalid llm_decompile reference: {reference_path}")
        return None
    if not isinstance(payload, Mapping):
        _debug_log(debug, f"invalid llm_decompile reference payload: {reference_path}")
        return None
    func_name = str(payload.get("func_name", "") or "").strip()
    if not func_name:
        _debug_log(debug, f"llm_decompile reference func_name missing: {reference_path}")
        return None
    return f"{func_name}.yaml"


def _index_config_inputs(
    values: Any, *, field_name: str, debug: bool
) -> dict[str, list[str]] | None:
    if not isinstance(values, (tuple, list, set)) or isinstance(values, (str, bytes)):
        _debug_log(debug, f"{field_name} context missing for llm_decompile")
        return None
    indexed: dict[str, list[str]] = {}
    for value in values:
        try:
            path = os.fspath(value)
        except TypeError:
            _debug_log(debug, f"invalid {field_name} path: {value!r}")
            return None
        basename = os.path.normcase(Path(path).name)
        indexed.setdefault(basename, []).append(path)
    return indexed


def _validate_input_indexes(
    required_index: dict[str, list[str]],
    optional_index: dict[str, list[str]],
    *,
    debug: bool,
) -> bool:
    valid = True
    for field_name, index in (
        ("expected_input", required_index),
        ("optional_input", optional_index),
    ):
        for basename, paths in index.items():
            if len(paths) > 1:
                valid = False
                _debug_log(debug, f"ambiguous {field_name} basename: {basename} -> {paths}")
    overlap = sorted(set(required_index) & set(optional_index))
    if overlap:
        valid = False
        _debug_log(debug, f"llm_decompile input overlap: {overlap}")
    return valid


def validate_llm_decompile_specs(
    specs_map: Mapping[str, Mapping[str, Any]],
    *,
    expected_inputs: Any,
    optional_inputs: Any,
    category_by_symbol: Mapping[str, str],
    scripts_dir: str | Path | None = None,
    arch: str | None = None,
    debug: bool = False,
) -> bool:
    if not specs_map:
        return True
    required_index = _index_config_inputs(
        expected_inputs, field_name="expected_input", debug=debug
    )
    optional_index = _index_config_inputs(
        optional_inputs, field_name="optional_input", debug=debug
    )
    if required_index is None or optional_index is None:
        return False

    valid = _validate_input_indexes(required_index, optional_index, debug=debug)

    root = (
        Path(scripts_dir)
        if scripts_dir
        else Path(__file__).resolve().parent / "ida_preprocessor_scripts"
    )
    for symbol_name, spec in specs_map.items():
        category = category_by_symbol.get(symbol_name)
        allowed_sections = (
            _LLM_RESULT_SECTIONS_BY_CATEGORY.get(category)
            if category is not None
            else None
        )
        sections = set(spec["expected_result_sections"])
        if allowed_sections is None or not sections <= allowed_sections:
            valid = False
            _debug_log(
                debug,
                f"incompatible llm_decompile sections for {symbol_name}: "
                f"category={category!r}, sections={sorted(sections)}",
            )

        inferred: dict[str, str] = {}
        for reference in spec["reference_yaml_paths"]:
            artifact_name = _load_reference_artifact_name(
                reference, scripts_dir=root, arch=arch, debug=debug
            )
            if artifact_name is None:
                valid = False
                continue
            artifact_key = os.path.normcase(artifact_name)
            if artifact_key in inferred:
                valid = False
                _debug_log(
                    debug,
                    f"duplicate resolved llm_decompile reference artifact for "
                    f"{symbol_name}: {artifact_name}",
                )
            inferred[artifact_key] = artifact_name

        resolved_policy: dict[str, str] = {}
        for artifact_template, policy in spec["dependency_policy"].items():
            artifact_name = _resolve_template(artifact_template, arch=arch)
            artifact_key = os.path.normcase(artifact_name)
            if artifact_key in resolved_policy:
                valid = False
                _debug_log(
                    debug,
                    f"duplicate resolved llm_decompile policy artifact for "
                    f"{symbol_name}: {artifact_name}",
                )
            resolved_policy[artifact_key] = policy

        if set(inferred) != set(resolved_policy):
            valid = False
            _debug_log(
                debug,
                f"llm_decompile policy/reference mismatch for {symbol_name}: "
                f"references={sorted(inferred)}, policy={sorted(resolved_policy)}",
            )

        for artifact_key, policy in resolved_policy.items():
            declared = required_index if policy == "required" else optional_index
            other = optional_index if policy == "required" else required_index
            if len(declared.get(artifact_key, [])) != 1 or artifact_key in other:
                valid = False
                _debug_log(
                    debug,
                    f"llm_decompile policy/config mismatch for {symbol_name}: "
                    f"artifact={artifact_key}, policy={policy}",
                )
    return valid


def build_semantic_query_names(
    specs_map: Mapping[str, Mapping[str, Any]],
    *,
    category_by_symbol: Mapping[str, str],
    struct_metadata: Mapping[str, Mapping[str, Any]] | None = None,
    debug: bool = False,
) -> dict[str, str] | None:
    queries: dict[str, str] = {}
    metadata_map = struct_metadata or {}
    for symbol_name in specs_map:
        category = category_by_symbol.get(symbol_name)
        if category in {"func", "gv"}:
            queries[symbol_name] = symbol_name
            continue
        if category != "struct_offset":
            _debug_log(debug, f"unknown llm_decompile category for {symbol_name}: {category!r}")
            return None
        metadata = metadata_map.get(symbol_name)
        if not isinstance(metadata, Mapping):
            _debug_log(debug, f"missing struct metadata for {symbol_name}")
            return None
        symbol_expr = str(metadata.get("symbol_expr", "") or "").strip()
        if not symbol_expr:
            struct_name = str(metadata.get("struct_name", "") or "").strip()
            member_name = str(metadata.get("member_name", "") or "").strip()
            if not struct_name or not member_name:
                _debug_log(debug, f"invalid struct metadata for {symbol_name}")
                return None
            symbol_expr = f"{struct_name}->{member_name}"
        queries[symbol_name] = symbol_expr
    return queries


normalize_llm_decompile_spec = _normalize_llm_decompile_spec
build_llm_decompile_specs_map = _build_llm_decompile_specs_map
