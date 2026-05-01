#!/usr/bin/env python3

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from ida_reference_export import ReferenceGenerationError

SUPPORTED_ARCHES = ("amd64", "arm64")


def _normalize_component(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text or text in {".", ".."}:
        return None
    if "/" in text or "\\" in text or Path(text).name != text:
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
        raise ReferenceGenerationError("invalid reference output target")
    return (
        Path(repo_root)
        / "ida_preprocessor_scripts"
        / "references"
        / module_name
        / f"{function_name}.{normalized_arch}.yaml"
    )
