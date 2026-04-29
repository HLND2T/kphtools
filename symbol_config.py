from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class SkillSpec:
    name: str
    symbol: str
    expected_output: list[str]
    expected_input: list[str]
    max_retries: int | None = None


@dataclass(frozen=True)
class SymbolSpec:
    name: str
    category: str
    data_type: str


@dataclass(frozen=True)
class ModuleSpec:
    name: str
    path: list[str]
    skills: list[SkillSpec]
    symbols: list[SymbolSpec]


@dataclass(frozen=True)
class ConfigSpec:
    modules: list[ModuleSpec]


def _require_field(entry: dict[str, Any], field_name: str, owner_name: str) -> Any:
    if field_name not in entry:
        raise ValueError(f"{owner_name}.{field_name} is required")
    return entry[field_name]


def _require_non_empty_string(
    entry: dict[str, Any], field_name: str, owner_name: str
) -> str:
    value = _require_field(entry, field_name, owner_name)
    if not isinstance(value, str):
        raise ValueError(f"{owner_name}.{field_name} must be a non-empty string")
    value = value.strip()
    if not value:
        raise ValueError(f"{owner_name}.{field_name} must be a non-empty string")
    return value


def _require_mapping(value: Any, field_name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{field_name} must be a mapping")
    return value


def _require_string_list(
    value: Any, field_name: str, *, allow_empty: bool = True
) -> list[str]:
    if not isinstance(value, list):
        raise ValueError(f"{field_name} must be a list")
    if not allow_empty and not value:
        raise ValueError(f"{field_name} must be a non-empty list")
    items: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise ValueError(f"{field_name} items must be strings")
        items.append(item.strip())
    return items


def _validate_expected_output_name(name: str) -> str:
    if not name.endswith(".yaml"):
        raise ValueError(f"expected_output must end with .yaml: {name}")
    if name.endswith(".amd64.yaml") or name.endswith(".arm64.yaml"):
        raise ValueError(f"expected_output must not encode arch in filename: {name}")
    return name


def _load_skill(entry: dict[str, Any]) -> SkillSpec:
    if "agent_skill" in entry:
        raise ValueError("skill.agent_skill is not supported; use skill.name")
    expected_output = _require_string_list(
        entry.get("expected_output", []), "expected_output"
    )
    expected_input = _require_string_list(entry.get("expected_input", []), "expected_input")
    return SkillSpec(
        name=_require_non_empty_string(entry, "name", "skill"),
        symbol=_require_non_empty_string(entry, "symbol", "skill"),
        expected_output=[_validate_expected_output_name(item) for item in expected_output],
        expected_input=expected_input,
        max_retries=entry.get("max_retries"),
    )


def _load_symbol(entry: dict[str, Any]) -> SymbolSpec:
    forbidden_fields = (
        "symbol_expr",
        "struct_name",
        "member_name",
        "bits",
        "alias",
    )
    for field_name in forbidden_fields:
        if field_name in entry:
            raise ValueError(
                f"symbol.{field_name} is not supported; move it to the skill script"
            )

    return SymbolSpec(
        name=_require_non_empty_string(entry, "name", "symbol"),
        category=_require_non_empty_string(entry, "category", "symbol"),
        data_type=_require_non_empty_string(entry, "data_type", "symbol"),
    )


def load_config(path: str | Path) -> ConfigSpec:
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    raw = _require_mapping(raw, "top-level config")
    module_entries = raw.get("modules", [])
    if not isinstance(module_entries, list):
        raise ValueError("modules must be a list")
    if not module_entries:
        raise ValueError("modules must be a non-empty list")

    modules: list[ModuleSpec] = []
    for module_entry in module_entries:
        module_data = _require_mapping(module_entry, "module")
        path_items = _require_string_list(module_data.get("path", []), "path", allow_empty=False)
        skill_items = module_data.get("skills", [])
        symbol_items = module_data.get("symbols", [])
        if not isinstance(skill_items, list) or not skill_items:
            raise ValueError("skills must be a non-empty list")
        if not isinstance(symbol_items, list) or not symbol_items:
            raise ValueError("symbols must be a non-empty list")

        symbols = [_load_symbol(_require_mapping(item, "symbol")) for item in symbol_items]
        symbol_names = {symbol.name for symbol in symbols}
        skills = [_load_skill(_require_mapping(item, "skill")) for item in skill_items]
        for skill in skills:
            if skill.symbol not in symbol_names:
                raise ValueError(f"skill.symbol references unknown symbol: {skill.symbol}")

        modules.append(
            ModuleSpec(
                name=_require_non_empty_string(module_data, "name", "module"),
                path=path_items,
                skills=skills,
                symbols=symbols,
            )
        )
    return ConfigSpec(modules=modules)
