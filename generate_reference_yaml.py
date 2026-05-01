#!/usr/bin/env python3

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from dump_symbols import _resolve_binary_path
from ida_reference_export import ReferenceGenerationError
from symbol_config import load_config

SUPPORTED_ARCHES = ("amd64", "arm64")
_INVALID_FILENAME_CHARS = frozenset(':?*<>|"')


def _invalid_reference_output_target_error() -> ReferenceGenerationError:
    return ReferenceGenerationError("invalid reference output target")


def _normalize_component(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text or text in {".", ".."}:
        return None
    if (
        "/" in text
        or "\\" in text
        or Path(text).name != text
        or any(ch in _INVALID_FILENAME_CHARS for ch in text)
    ):
        return None
    return text


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("-func_name", required=True)
    parser.add_argument("-module")
    parser.add_argument("-arch", choices=SUPPORTED_ARCHES)
    parser.add_argument("-mcp_host", default="127.0.0.1")
    parser.add_argument("-mcp_port", type=int, default=13337)
    parser.add_argument("-debug", action="store_true")
    parser.add_argument("-binary")
    parser.add_argument("-auto_start_mcp", action="store_true")

    args = parser.parse_args(argv)
    if args.auto_start_mcp and not args.binary:
        parser.error("-auto_start_mcp requires -binary")
    if args.binary and not args.auto_start_mcp:
        parser.error("-binary requires -auto_start_mcp")
    return args


def build_reference_output_path(
    repo_root: str | Path,
    *,
    module: str,
    func_name: str,
    arch: str,
) -> Path:
    module_name = _normalize_component(module)
    function_name = _normalize_component(func_name)
    normalized_arch = _normalize_component(arch)
    if normalized_arch is not None:
        normalized_arch = normalized_arch.lower()
    if (
        module_name is None
        or function_name is None
        or normalized_arch not in SUPPORTED_ARCHES
    ):
        raise _invalid_reference_output_target_error()
    return (
        Path(repo_root)
        / "ida_preprocessor_scripts"
        / "references"
        / module_name
        / f"{function_name}.{normalized_arch}.yaml"
    )


def _find_arch_from_path(binary_path: Path) -> str:
    for part in reversed(binary_path.parts):
        normalized_part = part.lower()
        if normalized_part in SUPPORTED_ARCHES:
            return normalized_part
    raise ReferenceGenerationError("unable to infer arch from binary path")


def _match_module_spec(config, binary_dir: Path, version_dir_name: str):
    matched_modules = []
    normalized_version_dir_name = version_dir_name.lower()

    for module_spec in config.modules:
        if any((binary_dir / candidate).exists() for candidate in module_spec.path):
            matched_modules.append(module_spec)
            continue
        if any(
            normalized_version_dir_name.startswith(f"{candidate.lower()}.")
            for candidate in module_spec.path
        ):
            matched_modules.append(module_spec)

    if len(matched_modules) != 1:
        raise ReferenceGenerationError("unable to infer module from binary path")
    return matched_modules[0]


def infer_context_from_binary_path(
    binary_hint_path: str | Path,
    *,
    config_path: str | Path = "config.yaml",
    module: str | None = None,
    arch: str | None = None,
) -> dict[str, Any]:
    resolved_hint = Path(binary_hint_path).expanduser().resolve(strict=False)
    binary_dir = resolved_hint.parent
    version_dir = binary_dir.parent
    resolved_arch = arch if arch is not None else _find_arch_from_path(resolved_hint)
    if resolved_arch not in SUPPORTED_ARCHES:
        raise ReferenceGenerationError("unable to infer arch from binary path")

    config = load_config(config_path)
    module_spec = _match_module_spec(config, binary_dir, version_dir.name)
    if module is not None and module != module_spec.name:
        raise ReferenceGenerationError(
            "module override does not match current binary directory"
        )

    resolved_binary_path = _resolve_binary_path(module_spec, binary_dir)
    return {
        "arch": resolved_arch,
        "module": module_spec.name,
        "binary_dir": binary_dir,
        "binary_path": resolved_binary_path,
        "module_spec": module_spec,
    }
