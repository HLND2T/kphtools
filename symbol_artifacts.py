from __future__ import annotations

from pathlib import Path

import yaml


_SAFE_LOADER = getattr(yaml, "CSafeLoader", yaml.SafeLoader)
ARTIFACTS_MANIFEST_NAME = "artifacts.yaml"


def artifact_path(binary_dir: str | Path, symbol_name: str) -> Path:
    return Path(binary_dir) / f"{symbol_name}.yaml"


def artifacts_manifest_path(binary_dir: str | Path) -> Path:
    return Path(binary_dir) / ARTIFACTS_MANIFEST_NAME


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


def write_artifacts_manifest(
    binary_dir: str | Path,
    artifacts: dict[str, dict | None],
) -> bool:
    body = {
        symbol_name: _hexify_fields(payload) if payload is not None else None
        for symbol_name, payload in artifacts.items()
    }
    content = yaml.safe_dump(body, sort_keys=False)
    manifest_path = artifacts_manifest_path(binary_dir)
    try:
        if manifest_path.read_text(encoding="utf-8") == content:
            manifest_path.touch()
            return False
    except FileNotFoundError:
        pass
    manifest_path.write_text(content, encoding="utf-8")
    return True


def _normalize_fields(payload: dict) -> dict:
    loaded = dict(payload)
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


def load_artifact(path: str | Path) -> dict:
    raw = yaml.load(
        Path(path).read_text(encoding="utf-8"),
        Loader=_SAFE_LOADER,
    ) or {}
    return _normalize_fields(dict(raw))


def load_artifacts_manifest(
    binary_dir: str | Path,
) -> dict[str, dict | None]:
    manifest_path = artifacts_manifest_path(binary_dir)
    raw = yaml.load(
        manifest_path.read_text(encoding="utf-8"),
        Loader=_SAFE_LOADER,
    )
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ValueError(f"artifacts manifest must be a mapping: {manifest_path}")

    artifacts: dict[str, dict | None] = {}
    for symbol_name, payload in raw.items():
        if not isinstance(symbol_name, str):
            raise ValueError("artifact symbol name must be a string")
        if payload is None:
            artifacts[symbol_name] = None
            continue
        if not isinstance(payload, dict):
            raise ValueError(
                f"artifact payload for {symbol_name} must be a mapping or null"
            )
        artifacts[symbol_name] = _normalize_fields(payload)
    return artifacts
