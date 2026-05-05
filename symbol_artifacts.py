from __future__ import annotations

from pathlib import Path

import yaml


def artifact_path(binary_dir: str | Path, symbol_name: str) -> Path:
    return Path(binary_dir) / f"{symbol_name}.yaml"


def _hexify_fields(payload: dict) -> dict:
    normalized = dict(payload)
    for key in (
        "offset",
        "bit_offset",
        "gv_rva",
        "gv_va",
        "func_rva",
        "func_va",
        "func_size",
        "code_rva",
        "code_va",
        "code_size",
    ):
        if key in normalized and isinstance(normalized[key], int):
            normalized[key] = hex(normalized[key])
    return normalized


def write_struct_yaml(path: str | Path, payload: dict) -> None:
    body = {**_hexify_fields(payload), "category": "struct_offset"}
    Path(path).write_text(yaml.safe_dump(body, sort_keys=False), encoding="utf-8")


def write_gv_yaml(path: str | Path, payload: dict) -> None:
    body = {**_hexify_fields(payload), "category": "gv"}
    Path(path).write_text(yaml.safe_dump(body, sort_keys=False), encoding="utf-8")


def write_func_yaml(path: str | Path, payload: dict) -> None:
    body = {**_hexify_fields(payload), "category": "func"}
    Path(path).write_text(yaml.safe_dump(body, sort_keys=False), encoding="utf-8")


def write_code_yaml(path: str | Path, payload: dict) -> None:
    body = {**_hexify_fields(payload), "category": "code"}
    Path(path).write_text(yaml.safe_dump(body, sort_keys=False), encoding="utf-8")


def load_artifact(path: str | Path) -> dict:
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    loaded = dict(raw)
    for key in (
        "offset",
        "bit_offset",
        "gv_rva",
        "gv_va",
        "func_rva",
        "func_va",
        "func_size",
        "code_rva",
        "code_va",
        "code_size",
    ):
        if isinstance(loaded.get(key), str) and loaded[key].startswith("0x"):
            loaded[key] = int(loaded[key], 16)
    return loaded
