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
    agent_skill: str
    max_retries: int | None = None


@dataclass(frozen=True)
class SymbolSpec:
    name: str
    category: str
    data_type: str
    symbol_expr: str | None = None
    struct_name: str | None = None
    member_name: str | None = None
    alias: list[str] | None = None
    bits: bool = False


@dataclass(frozen=True)
class ModuleSpec:
    name: str
    path: list[str]
    skills: list[SkillSpec]
    symbols: list[SymbolSpec]


@dataclass(frozen=True)
class ConfigSpec:
    modules: list[ModuleSpec]


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
    expected_output = _require_string_list(
        entry.get("expected_output", []), "expected_output"
    )
    expected_input = _require_string_list(entry.get("expected_input", []), "expected_input")
    return SkillSpec(
        name=str(entry["name"]).strip(),
        symbol=str(entry["symbol"]).strip(),
        expected_output=[_validate_expected_output_name(item) for item in expected_output],
        expected_input=expected_input,
        agent_skill=str(entry.get("agent_skill", "")).strip() or "find-kph-func",
        max_retries=entry.get("max_retries"),
    )


def _load_symbol(entry: dict[str, Any]) -> SymbolSpec:
    struct_name = entry.get("struct_name")
    member_name = entry.get("member_name")
    symbol_expr = entry.get("symbol_expr")
    if symbol_expr is None and (struct_name is None) != (member_name is None):
        raise ValueError(
            "struct_name and member_name must be provided together when symbol_expr is omitted"
        )
    if symbol_expr is None and struct_name and member_name:
        symbol_expr = f"{struct_name}->{member_name}"
    alias_value = entry.get("alias")
    alias = None
    if alias_value is not None:
        alias = _require_string_list(alias_value, "alias") or None

    return SymbolSpec(
        name=str(entry["name"]).strip(),
        category=str(entry["category"]).strip(),
        data_type=str(entry["data_type"]).strip(),
        symbol_expr=symbol_expr,
        struct_name=struct_name,
        member_name=member_name,
        alias=alias,
        bits=bool(entry.get("bits", False)),
    )


def load_config(path: str | Path) -> ConfigSpec:
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
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
                name=str(module_data["name"]).strip(),
                path=path_items,
                skills=skills,
                symbols=symbols,
            )
        )
    return ConfigSpec(modules=modules)
