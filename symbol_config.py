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


def _validate_expected_output_name(name: str) -> str:
    if not name.endswith(".yaml"):
        raise ValueError(f"expected_output must end with .yaml: {name}")
    if name.endswith(".amd64.yaml") or name.endswith(".arm64.yaml"):
        raise ValueError(f"expected_output must not encode arch in filename: {name}")
    return name


def _load_skill(entry: dict[str, Any]) -> SkillSpec:
    return SkillSpec(
        name=str(entry["name"]).strip(),
        symbol=str(entry["symbol"]).strip(),
        expected_output=[
            _validate_expected_output_name(str(item).strip())
            for item in entry.get("expected_output", [])
        ],
        expected_input=[str(item).strip() for item in entry.get("expected_input", [])],
        agent_skill=str(entry.get("agent_skill", "")).strip() or "find-kph-func",
        max_retries=entry.get("max_retries"),
    )


def _load_symbol(entry: dict[str, Any]) -> SymbolSpec:
    struct_name = entry.get("struct_name")
    member_name = entry.get("member_name")
    symbol_expr = entry.get("symbol_expr")
    if symbol_expr is None and struct_name and member_name:
        symbol_expr = f"{struct_name}->{member_name}"

    return SymbolSpec(
        name=str(entry["name"]).strip(),
        category=str(entry["category"]).strip(),
        data_type=str(entry["data_type"]).strip(),
        symbol_expr=symbol_expr,
        struct_name=struct_name,
        member_name=member_name,
        alias=list(entry.get("alias", [])) or None,
        bits=bool(entry.get("bits", False)),
    )


def load_config(path: str | Path) -> ConfigSpec:
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    modules: list[ModuleSpec] = []
    for module_entry in raw.get("modules", []):
        modules.append(
            ModuleSpec(
                name=str(module_entry["name"]).strip(),
                path=[str(item).strip() for item in module_entry.get("path", [])],
                skills=[_load_skill(item) for item in module_entry.get("skills", [])],
                symbols=[_load_symbol(item) for item in module_entry.get("symbols", [])],
            )
        )
    return ConfigSpec(modules=modules)
