#!/usr/bin/env python3
"""
Reference YAML Generator for LLM_DECOMPILE

Generates a single reference YAML for kphtools at:
    ida_preprocessor_scripts/references/<module>/<func_name>.<arch>.yaml

Usage:
    Attach to an existing MCP session:
        uv run python generate_reference_yaml.py -func_name=ExReferenceCallBackBlock

    Auto-start idalib-mcp for a specific binary:
        uv run python generate_reference_yaml.py -func_name=ExReferenceCallBackBlock -auto_start_mcp -binary=symbols/amd64/ntoskrnl.exe.10.0.26100.1/deadbeef/ntoskrnl.exe

Behavior:
    - Exports both `procedure` and `disasm_code`
    - Preserves instruction comments in exported output
    - Includes discontinuous function chunks when IDA associates them with the same function
    - Infers `module` and `arch` from the current binary path unless overridden

Parameters:
    -func_name       Required function name to export
    -module          Optional module override; must match the inferred current binary module
    -arch            Optional arch override; supported values: amd64, arm64
    -mcp_host        MCP host, default: 127.0.0.1
    -mcp_port        MCP port, default: 13337
    -debug           Enable debug mode
    -binary          Binary path used only with -auto_start_mcp
    -auto_start_mcp  Launch idalib-mcp automatically for -binary instead of attaching
"""

from __future__ import annotations

import argparse
import asyncio
import json
import subprocess
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

SUPPORTED_ARCHES = ("amd64", "arm64")
_INVALID_FILENAME_CHARS = frozenset(':?*<>|"')


def _reference_generation_error(message: str) -> Exception:
    from ida_reference_export import ReferenceGenerationError

    return ReferenceGenerationError(message)


def _invalid_reference_output_target_error() -> Exception:
    return _reference_generation_error("invalid reference output target")


def _load_reference_config(config_path: str | Path):
    from symbol_config import load_config

    return load_config(config_path)


def _resolve_binary_path_for_module(module_spec: Any, binary_dir: Path) -> Path:
    from dump_symbols import _resolve_binary_path

    return _resolve_binary_path(module_spec, binary_dir)


def _load_dump_symbols_module():
    import dump_symbols

    return dump_symbols


def _load_export_reference_yaml_via_mcp():
    from ida_reference_export import export_reference_yaml_via_mcp

    return export_reference_yaml_via_mcp


def _load_function_artifact(binary_dir: Path, func_name: str) -> dict[str, Any] | None:
    from symbol_artifacts import load_artifact

    artifact_path = binary_dir / f"{func_name}.yaml"
    if not artifact_path.is_file():
        return None
    return load_artifact(artifact_path)


def _parse_py_eval_result_json(result: Any) -> dict[str, Any] | None:
    content = getattr(result, "content", None)
    if not content:
        return None
    item = content[0]
    raw = getattr(item, "text", None)
    if not isinstance(raw, str):
        raw = str(item)
    try:
        payload = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(payload, dict):
        return None
    result_text = payload.get("result")
    if not isinstance(result_text, str) or not result_text:
        return None
    try:
        parsed = json.loads(result_text)
    except (json.JSONDecodeError, TypeError):
        return None
    return parsed if isinstance(parsed, dict) else None


async def _query_image_base_via_ida(session: Any) -> int:
    py_code = (
        "import json\n"
        "import idaapi\n"
        "result = json.dumps({'image_base': hex(idaapi.get_imagebase())})\n"
    )
    try:
        eval_result = await session.call_tool(
            name="py_eval",
            arguments={"code": py_code},
        )
        payload = _parse_py_eval_result_json(eval_result)
        image_base = payload.get("image_base") if isinstance(payload, dict) else None
        if isinstance(image_base, int):
            return image_base
        if isinstance(image_base, str):
            return int(image_base, 0)
    except Exception as exc:
        raise _reference_generation_error("unable to resolve function address") from exc
    raise _reference_generation_error("unable to resolve function address")


async def _lookup_function_start_addresses_by_exact_name(
    session: Any,
    func_name: str,
) -> set[int]:
    normalized_name = func_name.strip()
    if not normalized_name:
        return set()
    py_code = (
        "import json\n"
        "import ida_funcs\n"
        "import ida_name\n"
        "import idaapi\n"
        f"exact_names = {json.dumps([normalized_name])}\n"
        "matches = {}\n"
        "for name in exact_names:\n"
        "    ea = ida_name.get_name_ea(idaapi.BADADDR, name)\n"
        "    if ea == idaapi.BADADDR:\n"
        "        continue\n"
        "    func = ida_funcs.get_func(ea)\n"
        "    if func is None:\n"
        "        continue\n"
        "    matches.setdefault(hex(int(func.start_ea)), []).append(name)\n"
        "result = json.dumps({'matches': matches}, sort_keys=True)\n"
    )
    try:
        eval_result = await session.call_tool(
            name="py_eval",
            arguments={"code": py_code},
        )
        payload = _parse_py_eval_result_json(eval_result)
        raw_matches = payload.get("matches") if isinstance(payload, dict) else None
        if not isinstance(raw_matches, dict):
            return set()
        return {int(address_text, 0) for address_text in raw_matches}
    except Exception as exc:
        raise _reference_generation_error("unable to resolve function address") from exc


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


def _normalize_arch_override(arch: str | None) -> str | None:
    normalized_arch = _normalize_component(arch)
    if normalized_arch is None:
        return None
    return normalized_arch.lower()


def _normalize_module_override(module: str | None) -> str | None:
    return _normalize_component(module)


def _find_arch_from_path(binary_path: Path) -> str:
    for part in reversed(binary_path.parts):
        normalized_part = part.lower()
        if normalized_part in SUPPORTED_ARCHES:
            return normalized_part
    raise _reference_generation_error("unable to infer arch from binary path")


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
        raise _reference_generation_error("unable to infer module from binary path")
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
    normalized_module = _normalize_module_override(module) if module is not None else None
    normalized_arch = _normalize_arch_override(arch) if arch is not None else None
    resolved_arch = normalized_arch if arch is not None else _find_arch_from_path(resolved_hint)
    if resolved_arch not in SUPPORTED_ARCHES:
        raise _reference_generation_error("unable to infer arch from binary path")

    config = _load_reference_config(config_path)
    module_spec = _match_module_spec(config, binary_dir, version_dir.name)
    if module is not None and normalized_module != module_spec.name:
        raise _reference_generation_error(
            "module override does not match current binary directory"
        )

    resolved_binary_path = _resolve_binary_path_for_module(module_spec, binary_dir)
    return {
        "arch": resolved_arch,
        "module": module_spec.name,
        "binary_dir": binary_dir,
        "binary_path": resolved_binary_path,
        "module_spec": module_spec,
    }


async def resolve_func_va(*, session: Any, binary_dir: Path, func_name: str) -> str:
    artifact = _load_function_artifact(binary_dir, func_name)
    if artifact is not None:
        func_va = artifact.get("func_va")
        if isinstance(func_va, int):
            return hex(func_va)
        func_rva = artifact.get("func_rva")
        if isinstance(func_rva, int):
            image_base = await _query_image_base_via_ida(session)
            return hex(image_base + func_rva)

    matched_addresses = await _lookup_function_start_addresses_by_exact_name(
        session,
        func_name,
    )
    if not matched_addresses:
        raise _reference_generation_error("unable to resolve function address")
    if len(matched_addresses) != 1:
        raise _reference_generation_error("multiple function addresses")
    return hex(next(iter(matched_addresses)))


async def export_reference_yaml_via_mcp(
    session: Any,
    *,
    func_name: str,
    func_va: str,
    output_path: str | Path,
    debug: bool = False,
) -> Path:
    export_fn = _load_export_reference_yaml_via_mcp()
    return await export_fn(
        session,
        func_name=func_name,
        func_va=func_va,
        output_path=output_path,
        debug=debug,
    )


async def survey_current_binary_path(session: Any) -> Path:
    try:
        dump_symbols = _load_dump_symbols_module()
        result = await session.call_tool(
            name="py_eval",
            arguments={"code": dump_symbols.SURVEY_CURRENT_IDB_PATH_PY_EVAL},
        )
        payload = dump_symbols._parse_py_eval_result_json(result)
    except Exception as exc:
        raise _reference_generation_error("failed to survey current IDA binary") from exc
    if not isinstance(payload, dict):
        raise _reference_generation_error("failed to survey current IDA binary")
    metadata = payload.get("metadata")
    if not isinstance(metadata, dict):
        raise _reference_generation_error("failed to survey current IDA binary")
    raw_path = metadata.get("path")
    if not isinstance(raw_path, str) or not raw_path.strip():
        raise _reference_generation_error("failed to survey current IDA binary")
    return Path(raw_path).resolve(strict=False)


@asynccontextmanager
async def attach_existing_mcp_session(host: str, port: int, debug: bool):
    streams = None
    session = None
    try:
        dump_symbols = _load_dump_symbols_module()
        streams, session = await dump_symbols._open_session(
            f"http://{host}:{port}/mcp",
            debug=debug,
        )
    except Exception as exc:
        raise _reference_generation_error(
            f"unable to open MCP session at {host}:{port}"
        ) from exc
    try:
        yield session
    finally:
        if session is not None:
            await session.__aexit__(None, None, None)
        if streams is not None:
            await streams.__aexit__(None, None, None)


@asynccontextmanager
async def autostart_mcp_session(
    binary_path: Path,
    host: str,
    port: int,
    debug: bool,
):
    process = None
    streams = None
    session = None
    try:
        dump_symbols = _load_dump_symbols_module()
        process = dump_symbols.start_idalib_mcp(
            binary_path,
            host=host,
            port=port,
            debug=debug,
        )
    except Exception as exc:
        raise _reference_generation_error(
            f"failed to start idalib-mcp for {binary_path}"
        ) from exc
    try:
        streams, session = await dump_symbols._open_session(
            f"http://{host}:{port}/mcp",
            debug=debug,
        )
    except Exception as exc:
        raise _reference_generation_error(
            f"unable to open MCP session at {host}:{port}"
        ) from exc
    try:
        matches_target_binary = await dump_symbols._session_matches_binary(
            session,
            binary_path,
        )
        if not matches_target_binary:
            raise _reference_generation_error(
                f"MCP session target mismatch for {binary_path}"
            )
        yield session
    finally:
        if session is not None:
            try:
                await asyncio.wait_for(
                    session.call_tool(
                        name="py_eval",
                        arguments={"code": "import idc; idc.qexit(0)"},
                    ),
                    timeout=dump_symbols.IDALIB_QEXIT_TIMEOUT_SECONDS,
                )
            except Exception:
                pass
            await session.__aexit__(None, None, None)
        if streams is not None:
            await streams.__aexit__(None, None, None)
        if process is not None and process.poll() is None:
            try:
                await asyncio.to_thread(process.wait, timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                await asyncio.to_thread(process.wait, timeout=1)


def _is_reference_generation_error(exc: BaseException) -> bool:
    return isinstance(exc, type(_reference_generation_error("")))


async def run_reference_generation(
    args: argparse.Namespace,
    repo_root: str | Path | None = None,
) -> Path:
    resolved_repo_root = (
        Path(repo_root).resolve(strict=False)
        if repo_root is not None
        else Path(__file__).resolve().parent
    )
    session_cm = (
        autostart_mcp_session(
            Path(args.binary).resolve(strict=False),
            args.mcp_host,
            args.mcp_port,
            args.debug,
        )
        if args.auto_start_mcp
        else attach_existing_mcp_session(args.mcp_host, args.mcp_port, args.debug)
    )
    async with session_cm as session:
        binary_hint_path = (
            Path(args.binary).resolve(strict=False)
            if args.auto_start_mcp
            else await survey_current_binary_path(session)
        )
        context = infer_context_from_binary_path(
            binary_hint_path,
            config_path=resolved_repo_root / "config.yaml",
            module=args.module,
            arch=args.arch,
        )
        func_va = await resolve_func_va(
            session=session,
            binary_dir=context["binary_dir"],
            func_name=args.func_name,
        )
        output_path = build_reference_output_path(
            resolved_repo_root,
            module=context["module"],
            func_name=args.func_name,
            arch=context["arch"],
        )
        return await export_reference_yaml_via_mcp(
            session,
            func_name=args.func_name,
            func_va=func_va,
            output_path=output_path,
            debug=args.debug,
        )


def main(argv: list[str] | None = None) -> int:
    try:
        args = parse_args(argv)
        output_path = asyncio.run(run_reference_generation(args))
    except Exception as exc:
        if not _is_reference_generation_error(exc):
            raise
        print(str(exc), file=sys.stderr)
        return 1
    print(f"Generated reference YAML: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
