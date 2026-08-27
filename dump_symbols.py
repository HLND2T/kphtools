"""
按配置扫描符号目录，并将每个二进制的解析结果导出为 YAML symbol artifacts。

基本用法:
    uv run python dump_symbols.py
    uv run python dump_symbols.py -symboldir symbols -arch amd64
    uv run python dump_symbols.py -symboldir symbols -arch amd64,arm64 -force
    uv run python dump_symbols.py -symboldir symbols -arch amd64 -version 10.0.26100.8246

可用参数:
    -symboldir   符号根目录，默认 `symbols`。
                 可通过 `KPHTOOLS_SYMBOLDIR` 覆盖。
    -configyaml  模块与符号配置文件，默认 `config.yaml`。
    -arch        要扫描的架构列表，逗号分隔；当前支持 `amd64`、`arm64`。
    -version     只扫描指定版本目录，例如 `10.0.26100.8246`。
    -skill       只执行指定名称的 skill，其他 skill 会被跳过。
    -agent       回退到外部 Agent CLI 时使用的可执行文件名，默认 `codex`；支持 Claude、Codex 与 OpenCode。
    -agent_model 外部 Agent 使用的可选模型；OpenCode 要求 `provider/model` 格式。
    -force       即使预期 YAML 已存在，也强制重新生成。
    -debug       输出调试日志，并保留更多 MCP/子进程诊断信息。
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import socket
import subprocess
import time
from contextlib import AsyncExitStack
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

from agent_runner import DEFAULT_AGENT_MODEL, run_skill
from ida_llm_utils import create_openai_client
from ida_mcp_keepalive import keepalive_worker_during
from ida_mcp_session import McpDatabaseUnavailableError, open_ida_mcp_session
from ida_skill_preprocessor import (
    PREPROCESS_STATUS_ABSENT_OK as _PREPROCESS_STATUS_ABSENT_OK,
)
from ida_skill_preprocessor import (
    PREPROCESS_STATUS_FAILED as _PREPROCESS_STATUS_FAILED,
)
from ida_skill_preprocessor import (
    PREPROCESS_STATUS_SUCCESS,
    preprocess_single_skill_via_mcp,
)
from symbol_artifacts import (
    ARTIFACTS_MANIFEST_NAME,
    artifact_path,
    artifacts_manifest_path,
    load_artifact,
    write_artifacts_manifest,
)
from symbol_config import load_config, symbol_name_from_artifact_name

SURVEY_CURRENT_IDB_PATH_PY_EVAL = (
    "import json\n"
    "path = ''\n"
    "try:\n"
    "    import idaapi\n"
    "    path = idaapi.get_path(idaapi.PATH_TYPE_IDB) or ''\n"
    "except Exception:\n"
    "    pass\n"
    "if not path:\n"
    "    try:\n"
    "        import idc\n"
    "        path = idc.get_idb_path() or ''\n"
    "    except Exception:\n"
    "        pass\n"
    "result = json.dumps({'metadata': {'path': path}})\n"
)
MCP_STARTUP_TIMEOUT = 1200
MCP_SHUTDOWN_TIMEOUT = 10.0
MCP_PROCESS_STOP_TIMEOUT = 5.0
IDALIB_QEXIT_TIMEOUT_SECONDS = 3
_IS_WINDOWS = os.name == "nt"
SUPPORTED_ARCHES = ("amd64", "arm64")
DEFAULT_ARCH = ",".join(SUPPORTED_ARCHES)
DEFAULT_SYMBOL_DIR = "symbols"
DEFAULT_LLM_MODEL = "gpt-5.4"
PREPROCESS_STATUS_ABSENT_OK = _PREPROCESS_STATUS_ABSENT_OK
PREPROCESS_STATUS_FAILED = _PREPROCESS_STATUS_FAILED


@dataclass
class BinaryDirectorySnapshot:
    """One-pass inventory for direct children of a binary artifact directory."""

    binary_dir: Path
    file_names: set[str]
    original_names: dict[str, str]
    mtimes_ns: dict[str, int]
    directory_mtime_ns: int

    @staticmethod
    def _name_key(name: str) -> str:
        return os.path.normcase(os.path.normpath(name))

    @classmethod
    def capture(cls, binary_dir: str | Path) -> BinaryDirectorySnapshot:
        root = Path(binary_dir)
        file_names: set[str] = set()
        original_names: dict[str, str] = {}
        mtimes_ns: dict[str, int] = {}
        with os.scandir(root) as entries:
            for entry in entries:
                key = cls._name_key(entry.name)
                original_names[key] = entry.name
                try:
                    if not entry.is_file():
                        continue
                    file_names.add(key)
                    if entry.name.lower().endswith(".yaml"):
                        mtimes_ns[key] = entry.stat().st_mtime_ns
                except FileNotFoundError:
                    file_names.discard(key)
                    original_names.pop(key, None)
                    mtimes_ns.pop(key, None)
        return cls(
            binary_dir=root,
            file_names=file_names,
            original_names=original_names,
            mtimes_ns=mtimes_ns,
            directory_mtime_ns=root.stat().st_mtime_ns,
        )

    def _direct_entry(self, path: str | Path) -> tuple[str, Path] | None:
        candidate = Path(path)
        if not candidate.is_absolute() and len(candidate.parts) == 1:
            return self._name_key(candidate.name), self.binary_dir / candidate
        try:
            relative = candidate.relative_to(self.binary_dir)
        except ValueError:
            return None
        if len(relative.parts) != 1:
            return None
        return self._name_key(relative.name), candidate

    def name_exists(self, name: str) -> bool:
        candidate = Path(name)
        if candidate.is_absolute() or len(candidate.parts) != 1:
            return self.path_exists(self.binary_dir / candidate)
        return self._name_key(candidate.name) in self.original_names

    def name_is_file(self, name: str) -> bool:
        candidate = Path(name)
        if candidate.is_absolute() or len(candidate.parts) != 1:
            return self.path_is_file(self.binary_dir / candidate)
        return self._name_key(candidate.name) in self.file_names

    def name_mtime_ns(self, name: str) -> int | None:
        candidate = Path(name)
        if candidate.is_absolute() or len(candidate.parts) != 1:
            return self.mtime_ns(self.binary_dir / candidate)
        return self.mtimes_ns.get(self._name_key(candidate.name))

    def path_exists(self, path: str | Path) -> bool:
        direct_entry = self._direct_entry(path)
        if direct_entry is None:
            return Path(path).exists()
        key, _candidate = direct_entry
        return key in self.original_names

    def path_is_file(self, path: str | Path) -> bool:
        direct_entry = self._direct_entry(path)
        if direct_entry is None:
            return Path(path).is_file()
        key, _candidate = direct_entry
        return key in self.file_names

    def mtime_ns(self, path: str | Path) -> int | None:
        direct_entry = self._direct_entry(path)
        if direct_entry is None:
            try:
                return Path(path).stat().st_mtime_ns
            except FileNotFoundError:
                return None
        key, _candidate = direct_entry
        return self.mtimes_ns.get(key)

    def paths_ending_with(self, suffix: str) -> list[Path]:
        normalized_suffix = suffix.lower()
        return sorted(
            self.binary_dir / name
            for name in self.original_names.values()
            if name.lower().endswith(normalized_suffix)
        )

    def refresh_paths(self, paths: list[str | Path]) -> None:
        for path in paths:
            direct_entry = self._direct_entry(path)
            if direct_entry is None:
                continue
            key, candidate = direct_entry
            try:
                stat_result = candidate.stat()
            except FileNotFoundError:
                self.file_names.discard(key)
                self.original_names.pop(key, None)
                self.mtimes_ns.pop(key, None)
                continue
            self.original_names[key] = candidate.name
            if candidate.is_file():
                self.file_names.add(key)
                if candidate.name.lower().endswith(".yaml"):
                    self.mtimes_ns[key] = stat_result.st_mtime_ns
            else:
                self.file_names.discard(key)
                self.mtimes_ns.pop(key, None)
        self.directory_mtime_ns = self.binary_dir.stat().st_mtime_ns


class McpRecoveryBudget:
    """Limit owned MCP restarts for one binary processing lifecycle."""

    def __init__(self, restart_limit: int = 1) -> None:
        self.remaining_restarts = max(0, int(restart_limit))

    def consume_restart(self) -> bool:
        if self.remaining_restarts <= 0:
            return False
        self.remaining_restarts -= 1
        return True


def _field(item: Any, name: str, default: Any = None) -> Any:
    if isinstance(item, dict):
        return item.get(name, default)
    return getattr(item, name, default)


def _string_list(item: Any, name: str) -> list[str]:
    values = _field(item, name, []) or []
    return [str(value) for value in values if value]


def _infer_arch_from_binary_dir(binary_dir: str | Path) -> str | None:
    for part in Path(binary_dir).parts:
        normalized = part.lower()
        if normalized in SUPPORTED_ARCHES:
            return normalized
    return None


def _skill_arch(skill: Any) -> str | None:
    arch = _field(skill, "arch")
    if arch is None:
        return None
    return str(arch).strip().lower() or None


def _skill_matches_arch(skill: Any, arch: str | None) -> bool:
    required_arch = _skill_arch(skill)
    if required_arch is None or arch is None:
        return True
    return required_arch == arch.lower()


def _unique_strings(values: list[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def _skill_output_names(skill: Any) -> list[str]:
    return _unique_strings(
        _string_list(skill, "expected_output")
        + _string_list(skill, "optional_output")
        + _string_list(skill, "preprocessor_only_output")
    )


def _output_symbol_names(skill: Any) -> list[str]:
    return [symbol_name_from_artifact_name(output_path) for output_path in _skill_output_names(skill)]


def _output_symbol_path_pairs(
    binary_dir: str | Path,
    skill: Any,
) -> list[tuple[str, Path]]:
    return [
        (symbol_name_from_artifact_name(output_path), Path(binary_dir) / output_path)
        for output_path in _skill_output_names(skill)
    ]


def _symbol_for_output(symbol_map: dict[str, Any], symbol_name: str) -> Any:
    return symbol_map.get(symbol_name, {"name": symbol_name})


def _artifact_paths(binary_dir: str | Path, names: list[str]) -> list[str]:
    return [str(Path(binary_dir) / name) for name in names]


def _build_effective_llm_config_for_skill(
    llm_config: dict[str, Any] | None,
    skill: Any,
    binary_dir: str | Path,
) -> dict[str, Any]:
    effective = dict(llm_config) if isinstance(llm_config, dict) else {}
    arch = _infer_arch_from_binary_dir(binary_dir)
    expected_inputs = _string_list(skill, "expected_input")
    optional_inputs = _string_list(skill, "optional_input")
    if arch:
        expected_inputs.extend(_string_list(skill, f"expected_input_{arch}"))
        optional_inputs.extend(_string_list(skill, f"optional_input_{arch}"))
    configured_attempts = _field(skill, "max_retries")
    effective["max_retries"] = configured_attempts if configured_attempts is not None else 3
    effective.setdefault("retry_initial_delay", 1.0)
    effective.setdefault("retry_backoff_factor", 2.0)
    effective.setdefault("retry_max_delay", 8.0)
    effective["_expected_inputs"] = _unique_strings(expected_inputs)
    effective["_optional_inputs"] = _unique_strings(optional_inputs)
    effective["_required_output_symbols"] = list(_required_output_symbol_names(skill))
    return effective


def _path_exists(path: str | Path, snapshot: BinaryDirectorySnapshot | None = None) -> bool:
    if snapshot is not None:
        return snapshot.path_exists(path)
    return Path(path).exists()


def _all_paths_exist(
    paths: list[str],
    snapshot: BinaryDirectorySnapshot | None = None,
) -> bool:
    return bool(paths) and all(_path_exists(path, snapshot) for path in paths)


def _any_path_exists(
    paths: list[str],
    snapshot: BinaryDirectorySnapshot | None = None,
) -> bool:
    return bool(paths) and any(_path_exists(path, snapshot) for path in paths)


def _should_skip_for_existing_outputs(
    required_outputs: list[str],
    optional_outputs: list[str],
    snapshot: BinaryDirectorySnapshot | None = None,
) -> bool:
    if required_outputs:
        return _all_paths_exist(required_outputs, snapshot)
    return _all_paths_exist(optional_outputs, snapshot)


def _should_skip_for_existing_artifacts(
    binary_dir: str | Path,
    skill: Any,
    snapshot: BinaryDirectorySnapshot | None = None,
) -> bool:
    any_paths = _artifact_paths(binary_dir, _string_list(skill, "skip_if_any_exists"))
    all_paths = _artifact_paths(binary_dir, _string_list(skill, "skip_if_all_exists"))
    return _any_path_exists(any_paths, snapshot) or _all_paths_exist(all_paths, snapshot)


def _all_snapshot_names_exist(
    names: list[str],
    snapshot: BinaryDirectorySnapshot,
) -> bool:
    return bool(names) and all(snapshot.name_exists(name) for name in names)


def _any_snapshot_name_exists(
    names: list[str],
    snapshot: BinaryDirectorySnapshot,
) -> bool:
    return bool(names) and any(snapshot.name_exists(name) for name in names)


def _should_skip_skill_for_existing_outputs(
    skill: Any,
    snapshot: BinaryDirectorySnapshot,
) -> bool:
    required_names = _unique_strings(
        _string_list(skill, "expected_output")
        + _string_list(skill, "preprocessor_only_output")
    )
    if required_names:
        return _all_snapshot_names_exist(required_names, snapshot)
    return _all_snapshot_names_exist(
        _string_list(skill, "optional_output"),
        snapshot,
    )


def _should_skip_skill_for_existing_artifacts(
    skill: Any,
    snapshot: BinaryDirectorySnapshot,
) -> bool:
    any_names = _string_list(skill, "skip_if_any_exists")
    all_names = _string_list(skill, "skip_if_all_exists")
    return _any_snapshot_name_exists(
        any_names,
        snapshot,
    ) or _all_snapshot_names_exist(all_names, snapshot)


def _skill_output_paths(
    binary_dir: str | Path,
    skill: Any,
) -> tuple[list[str], list[str]]:
    required_outputs = _artifact_paths(
        binary_dir,
        _unique_strings(_string_list(skill, "expected_output") + _string_list(skill, "preprocessor_only_output")),
    )
    optional_outputs = _artifact_paths(
        binary_dir,
        _string_list(skill, "optional_output"),
    )
    return required_outputs, optional_outputs


def _required_output_symbol_names(skill: Any) -> set[str]:
    return {
        symbol_name_from_artifact_name(path)
        for path in _unique_strings(
            _string_list(skill, "expected_output") + _string_list(skill, "preprocessor_only_output")
        )
    }


def _preprocessor_only_output_symbol_names(skill: Any) -> set[str]:
    return {symbol_name_from_artifact_name(path) for path in _string_list(skill, "preprocessor_only_output")}


def _internal_output_symbol_names(skill: Any, symbol_map: dict[str, Any]) -> set[str]:
    return _preprocessor_only_output_symbol_names(skill) | (_required_output_symbol_names(skill) - set(symbol_map))


def _debug_log_written_yaml(debug: bool, path: str | Path) -> None:
    if not debug:
        return
    output_path = Path(path)
    if not output_path.exists():
        return
    _debug_log(
        debug,
        f"successfully wrote YAML: {output_path.resolve(strict=False)}",
    )


async def _run_fallback_skill_and_log_outputs(
    *,
    skill_name: str,
    agent: str,
    debug: bool,
    required_outputs: list[str],
    max_retries: int,
    agent_model: str = DEFAULT_AGENT_MODEL,
    mcp_url: str | None = None,
    session: Any = None,
) -> bool:
    run_kwargs = {
        "agent": agent,
        "debug": debug,
        "expected_yaml_paths": required_outputs,
        "max_retries": max_retries,
    }
    if agent_model:
        run_kwargs["agent_model"] = agent_model
    if mcp_url:
        run_kwargs["mcp_url"] = mcp_url
    bound_session = getattr(session, "session", None)
    if mcp_url and bound_session is not None:
        async with keepalive_worker_during(
            session,
            debug=debug,
            activity=f"Agent skill {skill_name}",
        ):
            fallback_ok = await asyncio.to_thread(run_skill, skill_name, **run_kwargs)
    else:
        fallback_ok = await asyncio.to_thread(run_skill, skill_name, **run_kwargs)
    if fallback_ok:
        for output_path in required_outputs:
            _debug_log_written_yaml(debug, output_path)
    return fallback_ok


async def _preprocess_skill_outputs(
    *,
    skill_name: str,
    skill: Any,
    symbol_map: dict[str, Any],
    binary_dir: str | Path,
    pdb_path: Path | None,
    debug: bool,
    llm_config: dict[str, Any] | None,
    session: Any,
) -> tuple[bool, set[str]]:
    effective_llm_config = _build_effective_llm_config_for_skill(
        llm_config,
        skill,
        binary_dir,
    )
    required_symbol_names = _required_output_symbol_names(skill)
    internal_symbol_names = _internal_output_symbol_names(skill, symbol_map)
    failed_required_symbol_names: set[str] = set()
    for symbol_name, output_path in _output_symbol_path_pairs(binary_dir, skill):
        status = await preprocess_single_skill_via_mcp(
            session=session,
            skill=skill,
            symbol=_symbol_for_output(symbol_map, symbol_name),
            binary_dir=Path(binary_dir),
            pdb_path=pdb_path,
            debug=debug,
            llm_config=effective_llm_config,
        )
        _debug_log(debug, f"preprocess status for {skill_name}/{symbol_name}: {status}")
        if isinstance(session, LazyIdalibSession) and session.recovery_failed:
            failed_required_symbol_names.update(required_symbol_names)
            return False, failed_required_symbol_names
        if status == PREPROCESS_STATUS_SUCCESS:
            _debug_log_written_yaml(debug, output_path)
            continue
        if symbol_name not in required_symbol_names:
            continue
        if symbol_name in internal_symbol_names:
            if status == PREPROCESS_STATUS_ABSENT_OK:
                continue
        failed_required_symbol_names.add(symbol_name)
    if not required_symbol_names:
        return False, failed_required_symbol_names
    return not failed_required_symbol_names, failed_required_symbol_names


async def _process_one_skill(
    *,
    skill_name: str,
    skill: Any,
    symbol_map: dict[str, Any],
    binary_dir: str | Path,
    pdb_path: Path | None,
    agent: str,
    debug: bool,
    force: bool,
    llm_config: dict[str, Any] | None,
    session: Any,
    activity: dict[str, bool] | None,
    agent_model: str = DEFAULT_AGENT_MODEL,
    snapshot: BinaryDirectorySnapshot | None = None,
) -> bool:
    _debug_log(debug, f"skill {skill_name} started")
    required_outputs, optional_outputs = _skill_output_paths(binary_dir, skill)
    if not force:
        if snapshot is not None:
            outputs_exist = _should_skip_skill_for_existing_outputs(skill, snapshot)
            skip_artifacts_exist = _should_skip_skill_for_existing_artifacts(
                skill,
                snapshot,
            )
        else:
            outputs_exist = _should_skip_for_existing_outputs(
                required_outputs,
                optional_outputs,
            )
            skip_artifacts_exist = _should_skip_for_existing_artifacts(
                binary_dir,
                skill,
            )
        if outputs_exist:
            _debug_log(debug, f"skipping {skill_name}; expected outputs already exist")
            return True
        if skip_artifacts_exist:
            _debug_log(debug, f"skipping {skill_name}; skip_if artifacts exist")
            return True
    if activity is not None:
        activity["did_work"] = True

    preprocessed_all, failed_required_symbol_names = await _preprocess_skill_outputs(
        skill_name=skill_name,
        skill=skill,
        symbol_map=symbol_map,
        binary_dir=binary_dir,
        pdb_path=pdb_path,
        debug=debug,
        llm_config=llm_config,
        session=session,
    )
    if snapshot is not None:
        snapshot.refresh_paths(
            [output_path for _symbol_name, output_path in _output_symbol_path_pairs(binary_dir, skill)]
        )
    if isinstance(session, LazyIdalibSession) and session.recovery_failed:
        _debug_log(debug, f"aborting {skill_name}; owned MCP worker is unavailable")
        return False
    if preprocessed_all:
        return True
    if not required_outputs and optional_outputs:
        _debug_log(debug, f"skipping {skill_name}; optional outputs not generated")
        return True
    internal_symbols = _internal_output_symbol_names(skill, symbol_map)
    if failed_required_symbol_names.issubset(internal_symbols):
        message = f"required internal outputs failed for {skill_name}; not falling back"
        _debug_log(debug, message)
        return False

    skill_max_retries = _field(skill, "max_retries") or 3
    mcp_url = None
    if isinstance(session, LazyIdalibSession) and session.port is not None:
        mcp_url = f"http://{session.host}:{session.port}/mcp"
    _debug_log(debug, f"falling back to run_skill for {skill_name}")
    fallback_ok = await _run_fallback_skill_and_log_outputs(
        skill_name=skill_name,
        agent=agent,
        debug=debug,
        required_outputs=required_outputs,
        max_retries=skill_max_retries,
        agent_model=agent_model,
        mcp_url=mcp_url,
        session=session,
    )
    if snapshot is not None:
        snapshot.refresh_paths(
            [output_path for _symbol_name, output_path in _output_symbol_path_pairs(binary_dir, skill)]
        )
    return fallback_ok


def _parse_arches(raw_value: str) -> list[str]:
    arches: list[str] = []
    seen: set[str] = set()
    for item in str(raw_value).split(","):
        arch = item.strip().lower()
        if not arch:
            continue
        if arch not in SUPPORTED_ARCHES:
            supported = ", ".join(SUPPORTED_ARCHES)
            raise argparse.ArgumentTypeError(
                f"invalid arch '{item.strip()}'; expected comma-separated values from: {supported}"
            )
        if arch not in seen:
            seen.add(arch)
            arches.append(arch)
    if not arches:
        supported = ", ".join(SUPPORTED_ARCHES)
        raise argparse.ArgumentTypeError(f"arch must include at least one value from: {supported}")
    return arches


def _parse_tool_json_content(result) -> dict[str, Any] | None:
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
    return payload if isinstance(payload, dict) else None


def _parse_optional_float(value: Any) -> float | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    return float(text)


def _parse_optional_llm_fake_as(raw_value: Any) -> str | None:
    text = str(raw_value or "").strip().lower()
    if not text:
        return None
    if text != "codex":
        raise argparse.ArgumentTypeError("invalid llm_fake_as; expected codex")
    return text


def _parse_optional_llm_effort(raw_value: Any) -> str | None:
    text = str(raw_value or "").strip().lower()
    if not text:
        return None
    valid_efforts = {"none", "minimal", "low", "medium", "high", "xhigh"}
    if text not in valid_efforts:
        valid = ", ".join(sorted(valid_efforts))
        raise argparse.ArgumentTypeError(f"invalid llm_effort; expected one of: {valid}")
    return text


def _build_llm_config(args: Any) -> dict[str, Any] | None:
    api_key = _field(args, "llm_apikey")
    if not api_key:
        return None

    config: dict[str, Any] = {
        "model": _field(args, "llm_model") or DEFAULT_LLM_MODEL,
        "api_key": api_key,
    }
    base_url = _field(args, "llm_baseurl")
    if base_url:
        config["base_url"] = base_url
    temperature = _field(args, "llm_temperature")
    if temperature is not None:
        config["temperature"] = temperature
    effort = _field(args, "llm_effort")
    if effort:
        config["effort"] = effort
    fake_as = _field(args, "llm_fake_as")
    if fake_as:
        config["fake_as"] = fake_as
    return config


def _parse_py_eval_result_json(result) -> dict[str, Any] | None:
    payload = _parse_tool_json_content(result)
    if not isinstance(payload, dict):
        return None

    result_text = payload.get("result", "")
    if not isinstance(result_text, str) or not result_text:
        return None
    try:
        parsed = json.loads(result_text)
    except (json.JSONDecodeError, TypeError):
        return None
    return parsed if isinstance(parsed, dict) else None


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Dump kphtools symbols into YAML artifacts",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "-symboldir",
        default=DEFAULT_SYMBOL_DIR,
        help=(
            f"Symbol artifact root directory (default: {DEFAULT_SYMBOL_DIR}); "
            "can be overridden by KPHTOOLS_SYMBOLDIR"
        ),
    )
    parser.add_argument("-configyaml", default="config.yaml")
    parser.add_argument(
        "-arch",
        default=DEFAULT_ARCH,
        help="Comma-separated architectures to scan",
    )
    parser.add_argument(
        "-version",
        default=None,
        help="Exact binary version directory suffix to scan",
    )
    parser.add_argument(
        "-skill",
        default=None,
        help="Exact skill name to run; all other skills are skipped",
    )
    parser.add_argument(
        "-agent",
        default=os.environ.get("KPHTOOLS_AGENT", "codex"),
        help=(
            "Agent executable for fallback analysis, e.g. claude, claude.cmd, "
            "codex, codex.cmd, opencode, or opencode.cmd; can also be set "
            "with KPHTOOLS_AGENT"
        ),
    )
    parser.add_argument(
        "-agent_model",
        default=os.environ.get("KPHTOOLS_AGENT_MODEL", DEFAULT_AGENT_MODEL),
        help=("Custom model for the selected agent; OpenCode requires provider/model format (or KPHTOOLS_AGENT_MODEL)"),
    )
    parser.add_argument("-force", action="store_true")
    parser.add_argument("-debug", action="store_true")
    parser.add_argument(
        "-llm_model",
        default=os.environ.get("KPHTOOLS_LLM_MODEL", DEFAULT_LLM_MODEL),
        help="OpenAI-compatible model for LLM_DECOMPILE, or KPHTOOLS_LLM_MODEL",
    )
    parser.add_argument(
        "-llm_apikey",
        default=os.environ.get("KPHTOOLS_LLM_APIKEY"),
        help="OpenAI-compatible API key for LLM_DECOMPILE, or KPHTOOLS_LLM_APIKEY",
    )
    parser.add_argument(
        "-llm_baseurl",
        default=os.environ.get("KPHTOOLS_LLM_BASEURL"),
        help="Optional OpenAI-compatible base URL, or KPHTOOLS_LLM_BASEURL",
    )
    parser.add_argument(
        "-llm_temperature",
        type=_parse_optional_float,
        default=_parse_optional_float(os.environ.get("KPHTOOLS_LLM_TEMPERATURE")),
        help="Optional LLM temperature, or KPHTOOLS_LLM_TEMPERATURE",
    )
    parser.add_argument(
        "-llm_effort",
        type=_parse_optional_llm_effort,
        default=_parse_optional_llm_effort(os.environ.get("KPHTOOLS_LLM_EFFORT")),
        help="Optional reasoning effort, or KPHTOOLS_LLM_EFFORT",
    )
    parser.add_argument(
        "-llm_fake_as",
        type=_parse_optional_llm_fake_as,
        default=_parse_optional_llm_fake_as(os.environ.get("KPHTOOLS_LLM_FAKE_AS")),
        help="Optional transport profile; currently only 'codex', or KPHTOOLS_LLM_FAKE_AS",
    )
    args = parser.parse_args(argv)

    env_symboldir = os.getenv("KPHTOOLS_SYMBOLDIR")
    if env_symboldir is not None:
        args.symboldir = env_symboldir
    if not args.symboldir:
        parser.error("-symboldir cannot be empty")

    try:
        args.arches = _parse_arches(args.arch)
    except argparse.ArgumentTypeError as exc:
        parser.error(str(exc))
    if args.version is not None:
        args.version = args.version.strip()
        if not args.version:
            parser.error("-version cannot be empty")
    if args.skill is not None:
        args.skill = args.skill.strip()
        if not args.skill:
            parser.error("-skill cannot be empty")
    return args


def topological_sort_skills(skills):
    skill_names = {_field(skill, "name") for skill in skills}

    def normalize(path: str) -> str:
        return os.path.normcase(os.path.normpath(path))

    producers: dict[str, set[str]] = {}
    for skill in skills:
        skill_name = _field(skill, "name")
        output_paths = _string_list(skill, "expected_output") + _string_list(skill, "preprocessor_only_output")
        for output_path in output_paths:
            normalized = normalize(output_path)
            basename = normalize(os.path.basename(output_path))
            producers.setdefault(normalized, set()).add(skill_name)
            producers.setdefault(basename, set()).add(skill_name)

    dependencies = {name: set() for name in skill_names}
    for skill in skills:
        consumer_name = _field(skill, "name")
        inputs = []
        inputs.extend(_string_list(skill, "expected_input"))
        inputs.extend(_string_list(skill, "expected_input_amd64"))
        inputs.extend(_string_list(skill, "expected_input_arm64"))
        for input_path in inputs:
            normalized = normalize(input_path)
            basename = normalize(os.path.basename(input_path))
            inferred = set(producers.get(normalized, set()))
            if not inferred:
                inferred.update(producers.get(basename, set()))
            inferred.discard(consumer_name)
            dependencies[consumer_name].update(inferred)
        for prereq in _string_list(skill, "prerequisite"):
            if prereq in skill_names and prereq != consumer_name:
                dependencies[consumer_name].add(prereq)

    in_degree = {name: len(dependencies[name]) for name in skill_names}
    dependents = {name: set() for name in skill_names}
    for consumer_name, prereqs in dependencies.items():
        for prereq in prereqs:
            dependents[prereq].add(consumer_name)

    queue = sorted(name for name, count in in_degree.items() if count == 0)
    sorted_names: list[str] = []
    while queue:
        current = queue.pop(0)
        sorted_names.append(current)
        for dependent in sorted(dependents[current]):
            in_degree[dependent] -= 1
            if in_degree[dependent] == 0:
                queue.append(dependent)
        queue.sort()

    if len(sorted_names) != len(skill_names):
        for skill in skills:
            skill_name = _field(skill, "name")
            if skill_name not in sorted_names:
                sorted_names.append(skill_name)
    return sorted_names


def _select_skills_by_name(skills, selected_skill_name):
    if selected_skill_name is None:
        return skills

    normalized_name = str(selected_skill_name).strip()
    selected_skills = [skill_item for skill_item in skills if _field(skill_item, "name") == normalized_name]
    if selected_skills:
        return selected_skills

    available_skills = ", ".join(str(_field(skill_item, "name")) for skill_item in skills if _field(skill_item, "name"))
    _progress(f"Skill '{normalized_name}' not found; available skills: {available_skills or '(none)'}")
    return None


def _module_skills_are_satisfied(
    *,
    module: Any,
    arch: str | None,
    selected_skill_name: str | None,
    force: bool,
    debug: bool,
    snapshot: BinaryDirectorySnapshot,
) -> bool:
    if force:
        return False
    if not any(snapshot.name_exists(candidate) for candidate in module.path):
        return False

    if selected_skill_name is None:
        selected_skills = module.skills
    else:
        selected_skills = [
            skill_item
            for skill_item in module.skills
            if _field(skill_item, "name") == selected_skill_name
        ]
        if not selected_skills:
            return False

    for current_skill in selected_skills:
        skill_name = _field(current_skill, "name")
        _debug_log(debug, f"skill {skill_name} started")
        if not _skill_matches_arch(current_skill, arch):
            _debug_log(
                debug,
                f"skipping {skill_name}; skill arch {_skill_arch(current_skill)} does not match {arch}",
            )
            continue
        if _should_skip_skill_for_existing_outputs(current_skill, snapshot):
            _debug_log(debug, f"skipping {skill_name}; expected outputs already exist")
            continue
        if _should_skip_skill_for_existing_artifacts(current_skill, snapshot):
            _debug_log(debug, f"skipping {skill_name}; skip_if artifacts exist")
            continue
        return False
    return True


async def process_binary_dir(
    binary_dir,
    pdb_path,
    skills,
    symbols,
    agent,
    debug,
    force,
    llm_config,
    session=None,
    activity=None,
    arch=None,
    skill=None,
    agent_model=DEFAULT_AGENT_MODEL,
    snapshot: BinaryDirectorySnapshot | None = None,
):
    if activity is not None and "did_work" not in activity:
        activity["did_work"] = False

    current_arch = str(arch).strip().lower() if arch else _infer_arch_from_binary_dir(binary_dir)
    resolved_pdb_path = Path(pdb_path) if pdb_path is not None else None
    skill_map = {_field(skill_item, "name"): skill_item for skill_item in skills}
    symbol_map = {_field(symbol, "name"): symbol for symbol in symbols}
    selected_skills = _select_skills_by_name(skills, skill)
    if selected_skills is None:
        return False

    for skill_name in topological_sort_skills(selected_skills):
        current_skill = skill_map[skill_name]
        if not _skill_matches_arch(current_skill, current_arch):
            _debug_log(
                debug,
                f"skipping {skill_name}; skill arch {_skill_arch(current_skill)} does not match {current_arch}",
            )
            continue
        ok = await _process_one_skill(
            skill_name=skill_name,
            skill=current_skill,
            symbol_map=symbol_map,
            binary_dir=binary_dir,
            pdb_path=resolved_pdb_path,
            agent=agent,
            agent_model=agent_model,
            debug=debug,
            force=force,
            llm_config=llm_config,
            session=session,
            activity=activity,
            snapshot=snapshot,
        )
        if not ok:
            return False
    return True


def _wait_for_port(host: str, port: int, timeout: float = 30.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1.0)
            if sock.connect_ex((host, port)) == 0:
                return True
        time.sleep(0.25)
    return False


def _allocate_local_port(host: str = "127.0.0.1") -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((host, 0))
        return int(sock.getsockname()[1])


def _is_port_in_use(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=1.0):
            return True
    except OSError:
        return False


def _wait_for_port_release(
    host: str,
    port: int,
    timeout: float = MCP_SHUTDOWN_TIMEOUT,
    retry_interval: float = 0.1,
) -> bool:
    deadline = time.monotonic() + max(0.0, timeout)
    while _is_port_in_use(host, port):
        if time.monotonic() >= deadline:
            return False
        time.sleep(max(0.0, retry_interval))
    return True


def start_idalib_mcp(
    binary_path: Path,
    host: str = "127.0.0.1",
    port: int = 13337,
    debug: bool = False,
):
    if _is_port_in_use(host, port):
        raise RuntimeError(f"MCP port {host}:{port} is already in use")

    cmd = [
        "idalib-mcp",
        "--unsafe",
        "--host",
        host,
        "--port",
        str(port),
        str(binary_path),
    ]
    popen_kwargs: dict[str, Any] = {"text": True}
    if not debug:
        popen_kwargs["stdout"] = subprocess.DEVNULL
        popen_kwargs["stderr"] = subprocess.DEVNULL
    process = subprocess.Popen(cmd, **popen_kwargs)
    if not _wait_for_port(host, port, timeout=MCP_STARTUP_TIMEOUT):
        stop_idalib_mcp_process(process, debug=debug)
        raise RuntimeError(f"idalib-mcp failed to start for {binary_path}")
    return process


def stop_idalib_mcp_process(
    process: Any,
    *,
    debug: bool = False,
    timeout: float = MCP_PROCESS_STOP_TIMEOUT,
) -> bool:
    """Stop an owned idalib-mcp process and its descendants."""
    if process is None or process.poll() is not None:
        return True

    pid = getattr(process, "pid", None)
    if _IS_WINDOWS and isinstance(pid, int) and pid > 0:
        taskkill_kwargs: dict[str, Any] = {
            "stdout": subprocess.DEVNULL,
            "stderr": subprocess.DEVNULL,
            "check": False,
            "timeout": max(0.1, timeout),
        }
        create_no_window = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        if create_no_window:
            taskkill_kwargs["creationflags"] = create_no_window
        try:
            completed = subprocess.run(
                ["taskkill", "/PID", str(pid), "/T", "/F"],
                **taskkill_kwargs,
            )
            if completed.returncode != 0:
                _debug_log(
                    debug,
                    f"taskkill failed for owned MCP process tree {pid}: exit code {completed.returncode}",
                )
        except (OSError, subprocess.TimeoutExpired) as exc:
            _debug_log(debug, f"taskkill failed for owned MCP process tree {pid}: {exc}")
    else:
        try:
            process.terminate()
        except Exception:
            pass

    try:
        process.wait(timeout=max(0.1, timeout))
        return True
    except subprocess.TimeoutExpired:
        try:
            process.kill()
        except Exception:
            pass
        try:
            process.wait(timeout=1)
            return True
        except (OSError, subprocess.TimeoutExpired):
            return process.poll() is not None
    except OSError:
        return process.poll() is not None


async def check_mcp_worker_health(host: str, port: int, binary_path: Path) -> bool:
    try:
        async with open_ida_mcp_session(
            host,
            port,
            expected_binary=binary_path,
        ) as session:
            await session.call_tool(name="py_eval", arguments={"code": "1"})
            return True
    except Exception:
        return False


class LazyIdalibSession:
    def __init__(
        self,
        binary_path: Path,
        host: str = "127.0.0.1",
        debug: bool = False,
    ) -> None:
        self.binary_path = Path(binary_path).resolve()
        self.host = host
        self.debug = debug
        self.port: int | None = None
        self.process = None
        self.session = None
        self.session_context = None
        self.recovery_budget = McpRecoveryBudget()
        self.recovery_failed = False

    async def _open_session(self):
        if self.port is None:
            raise RuntimeError("MCP port must be allocated before opening a session")
        if self.session_context is None:
            self.session_context = open_ida_mcp_session(
                self.host,
                self.port,
                expected_binary=self.binary_path,
                auto_started=True,
            )
        if self.session is None:
            self.session = await self.session_context.__aenter__()
        return self.session

    async def _cleanup_failed_start(self) -> None:
        process = self.process
        self.process = None
        try:
            await self._close_handles()
        except BaseException:
            pass
        if process is not None and process.poll() is None:
            await asyncio.to_thread(
                stop_idalib_mcp_process,
                process,
                debug=self.debug,
            )
        await self._wait_for_port_release()

    async def ensure_started(self):
        if self.session is not None:
            return self.session

        _debug_log(self.debug, f"allocating lazy MCP session for {self.binary_path}")
        if self.port is None:
            self.port = _allocate_local_port(self.host)
        try:
            if self.process is None:
                self.process = start_idalib_mcp(
                    self.binary_path,
                    host=self.host,
                    port=self.port,
                    debug=self.debug,
                )
            return await self._open_session()
        except McpDatabaseUnavailableError:
            await self._close_handles()
            raise
        except BaseException:
            _debug_log(self.debug, f"startup cleanup for {self.binary_path}")
            await self._cleanup_failed_start()
            raise

    async def _wait_for_port_release(self) -> bool:
        if self.port is None:
            return True
        released = await asyncio.to_thread(
            _wait_for_port_release,
            self.host,
            self.port,
            MCP_SHUTDOWN_TIMEOUT,
        )
        if self.debug and not released:
            _debug_log(
                True,
                f"MCP port {self.host}:{self.port} remained in use after shutdown",
            )
        return released

    async def _stop_for_recovery(self) -> bool:
        process = self.process
        self.process = None
        await self._close_handles()
        if process is not None and process.poll() is None:
            await asyncio.to_thread(
                stop_idalib_mcp_process,
                process,
                debug=self.debug,
            )
        return await self._wait_for_port_release()

    async def _restart_once(self) -> bool:
        if not self.recovery_budget.consume_restart():
            print("MCP recovery restart already used; aborting this binary")
            return False
        if not await self._stop_for_recovery():
            print(f"MCP port {self.host}:{self.port} remained in use; recovery restart aborted")
            return False
        print(f"Restarting unavailable MCP worker for {self.binary_path}")
        try:
            await self.ensure_started()
            return True
        except McpDatabaseUnavailableError:
            print("MCP worker remained unavailable after the single recovery restart")
            await self._cleanup_failed_start()
        except Exception as exc:
            print(f"MCP recovery restart failed: {exc}")
        return False

    async def _recover_unavailable_worker(self, reason: BaseException) -> bool:
        print(f"MCP worker unavailable for {self.binary_path}: {reason}")
        await self._close_handles()
        port = self.port
        if self.process is not None and self.process.poll() is None and port is not None:
            if await check_mcp_worker_health(self.host, port, self.binary_path):
                _debug_log(self.debug, "MCP worker recovered without a restart; rebinding")
                try:
                    await self.ensure_started()
                    return True
                except McpDatabaseUnavailableError:
                    await self._close_handles()
                    print("MCP worker remained unavailable after rebinding")
                    return False
        return await self._restart_once()

    async def ensure_available(self) -> bool:
        if self.session is None:
            try:
                await self.ensure_started()
                self.recovery_failed = False
                return True
            except McpDatabaseUnavailableError as exc:
                available = await self._recover_unavailable_worker(exc)
                self.recovery_failed = not available
                return available

        try:
            await self.session.call_tool(name="py_eval", arguments={"code": "1"})
            self.recovery_failed = False
            return True
        except Exception as exc:
            available = await self._recover_unavailable_worker(exc)
            self.recovery_failed = not available
            return available

    async def call_tool(self, name, arguments):
        if not await self.ensure_available():
            raise McpDatabaseUnavailableError(f"owned MCP worker for {self.binary_path} is unavailable")
        session = self.session
        if session is None:
            raise McpDatabaseUnavailableError(f"owned MCP worker for {self.binary_path} did not yield a session")
        try:
            return await session.call_tool(name=name, arguments=arguments)
        except Exception as exc:
            _debug_log(
                self.debug,
                f"MCP tool {name} failed; attempting one recovery: "
                f"{type(exc).__name__}: {exc}",
            )
            available = await self._recover_unavailable_worker(exc)
            self.recovery_failed = not available
            if not available:
                raise McpDatabaseUnavailableError(
                    f"owned MCP worker for {self.binary_path} failed during {name} and could not recover"
                ) from exc

            recovered_session = self.session
            if recovered_session is None:
                self.recovery_failed = True
                raise McpDatabaseUnavailableError(
                    f"owned MCP worker for {self.binary_path} recovered without a bound session"
                ) from exc
            return await recovered_session.call_tool(name=name, arguments=arguments)

    async def _close_handles(self) -> None:
        session_context = self.session_context
        self.session = None
        self.session_context = None
        cancel_error = None

        if session_context is not None:
            try:
                await session_context.__aexit__(None, None, None)
            except asyncio.CancelledError as exc:
                if _is_mcp_cancel_scope_cancelled(exc):
                    _debug_log(
                        self.debug,
                        _format_close_cancelled_message("session exit", exc),
                    )
                else:
                    cancel_error = exc
            except Exception:
                pass
        if cancel_error is not None:
            raise cancel_error

    async def close(self) -> bool:
        if self.process is not None or self.session_context is not None or self.session is not None:
            _debug_log(self.debug, f"closing lazy MCP session for {self.binary_path}")
        process = self.process
        self.process = None

        try:
            if process is None:
                await self._close_handles()
                return True
            if process.poll() is None:
                binding = getattr(self.session, "binding", None)
                if self.session is not None and getattr(binding, "should_auto_quit", False):
                    try:
                        await asyncio.wait_for(
                            self.session.call_tool(
                                name="py_eval",
                                arguments={"code": "import idc; idc.qexit(0)"},
                            ),
                            timeout=IDALIB_QEXIT_TIMEOUT_SECONDS,
                        )
                    except asyncio.CancelledError as exc:
                        if not _is_mcp_cancel_scope_cancelled(exc):
                            raise
                        _debug_log(
                            self.debug,
                            _format_close_cancelled_message("qexit request", exc),
                        )
                    except Exception:
                        pass

            await self._close_handles()
            if process.poll() is None:
                await asyncio.to_thread(
                    stop_idalib_mcp_process,
                    process,
                    debug=self.debug,
                )
            return await self._wait_for_port_release()
        except asyncio.CancelledError:
            try:
                await self._close_handles()
            except BaseException:
                pass
            if process is not None and process.poll() is None:
                await asyncio.to_thread(
                    stop_idalib_mcp_process,
                    process,
                    debug=self.debug,
                )
            await self._wait_for_port_release()
            raise


def _iter_binary_dirs(symboldir: Path, arch: str, config, version: str | None = None):
    arch_dir = Path(symboldir) / arch
    version_filter = version.strip() if version else None
    for module in config.modules:
        for module_path in module.path:
            if version_filter:
                version_dirs = [arch_dir / f"{module_path}.{version_filter}"]
            else:
                version_dirs = sorted(arch_dir.glob(f"{module_path}.*"))
            for version_dir in version_dirs:
                if not version_dir.is_dir():
                    continue
                for sha_dir in sorted(version_dir.iterdir()):
                    if not sha_dir.is_dir():
                        continue
                    snapshot = BinaryDirectorySnapshot.capture(sha_dir)
                    pdb_candidates = snapshot.paths_ending_with(".pdb")
                    if not pdb_candidates and not snapshot.path_is_file(sha_dir / module_path):
                        continue
                    pdb_path = pdb_candidates[0] if pdb_candidates else None
                    yield module, sha_dir, pdb_path, snapshot


def _resolve_binary_path(
    module,
    binary_dir: Path,
    snapshot: BinaryDirectorySnapshot | None = None,
) -> Path:
    for candidate in module.path:
        binary_path = binary_dir / candidate
        if snapshot is not None:
            if snapshot.path_exists(binary_path):
                return binary_path
        elif binary_path.exists():
            return binary_path
    raise FileNotFoundError(f"binary file not found in {binary_dir}")


def _progress(message: str) -> None:
    print(message)


def _debug_log(debug: bool, message: str) -> None:
    if debug:
        print(f"[debug] {message}")


def _is_mcp_cancel_scope_cancelled(exc: BaseException) -> bool:
    return "cancel scope" in str(exc).lower()


def _format_close_cancelled_message(stage: str, exc: BaseException) -> str:
    detail = str(exc).strip() or exc.__class__.__name__
    return f"MCP session close {stage} cancelled; suppressed teardown noise: {detail}"


def _write_binary_artifacts_manifest(binary_dir: Path, symbols) -> bool:
    artifacts: dict[str, dict | None] = {}
    for symbol in symbols:
        symbol_name = str(_field(symbol, "name"))
        try:
            artifacts[symbol_name] = load_artifact(
                artifact_path(binary_dir, symbol_name)
            )
        except FileNotFoundError:
            artifacts[symbol_name] = None
    return write_artifacts_manifest(binary_dir, artifacts)


def _binary_artifacts_manifest_is_fresh(
    binary_dir: Path,
    symbols,
    *,
    snapshot: BinaryDirectorySnapshot,
    config_mtime_ns: int | None,
) -> bool:
    if not snapshot.name_is_file(ARTIFACTS_MANIFEST_NAME):
        return False
    manifest_mtime_ns = snapshot.name_mtime_ns(ARTIFACTS_MANIFEST_NAME)
    if manifest_mtime_ns is None:
        return False

    newest_dependency_mtime_ns = snapshot.directory_mtime_ns
    if config_mtime_ns is not None:
        newest_dependency_mtime_ns = max(newest_dependency_mtime_ns, config_mtime_ns)
    for symbol in symbols:
        symbol_name = str(_field(symbol, "name"))
        artifact_mtime_ns = snapshot.name_mtime_ns(f"{symbol_name}.yaml")
        if artifact_mtime_ns is not None:
            newest_dependency_mtime_ns = max(
                newest_dependency_mtime_ns,
                artifact_mtime_ns,
            )
    return manifest_mtime_ns >= newest_dependency_mtime_ns


def _sync_binary_artifacts_manifest(
    binary_dir: Path,
    symbols,
    *,
    snapshot: BinaryDirectorySnapshot,
    config_mtime_ns: int | None,
    allow_cached: bool,
) -> bool:
    manifest_path = artifacts_manifest_path(binary_dir)
    if allow_cached and _binary_artifacts_manifest_is_fresh(
        binary_dir,
        symbols,
        snapshot=snapshot,
        config_mtime_ns=config_mtime_ns,
    ):
        manifest_path.touch()
        snapshot.refresh_paths([manifest_path])
        return False

    changed = _write_binary_artifacts_manifest(binary_dir, symbols)
    snapshot.refresh_paths([manifest_path])
    return changed


async def _process_module_binary(
    module,
    binary_dir,
    pdb_path,
    args,
    snapshot: BinaryDirectorySnapshot | None = None,
):
    binary_dir = Path(binary_dir)
    if snapshot is None:
        snapshot = BinaryDirectorySnapshot.capture(binary_dir)
    binary_path = _resolve_binary_path(module, binary_dir, snapshot)
    resolved_pdb_path = Path(pdb_path) if pdb_path is not None else None
    session = LazyIdalibSession(
        binary_path,
        host="127.0.0.1",
        debug=args.debug,
    )
    activity = {"did_work": False}
    llm_config = _build_llm_config(args)
    async with AsyncExitStack() as llm_stack:
        if (
            isinstance(llm_config, dict)
            and str(llm_config.get("fake_as") or "").strip().lower() != "codex"
        ):
            llm_client = await llm_stack.enter_async_context(
                create_openai_client(
                    llm_config["api_key"],
                    llm_config.get("base_url"),
                    api_key_required_message=(
                        "api_key is required for OpenAI-compatible LLM requests"
                    ),
                )
            )
            llm_config["client"] = llm_client

        try:
            ok = await process_binary_dir(
                binary_dir=Path(binary_dir),
                pdb_path=resolved_pdb_path,
                skills=module.skills,
                symbols=module.symbols,
                agent=args.agent,
                agent_model=getattr(args, "agent_model", DEFAULT_AGENT_MODEL),
                debug=args.debug,
                force=args.force,
                llm_config=llm_config,
                session=session,
                activity=activity,
                arch=getattr(args, "current_arch", None),
                skill=getattr(args, "skill", None),
                snapshot=snapshot,
            )
        finally:
            closed = await session.close()
        if closed is False:
            print(f"MCP cleanup failed for {binary_path}")
            ok = False
        if ok and module.symbols:
            if _sync_binary_artifacts_manifest(
                binary_dir,
                module.symbols,
                snapshot=snapshot,
                config_mtime_ns=getattr(args, "config_mtime_ns", None),
                allow_cached=not args.force and not activity["did_work"],
            ):
                activity["did_work"] = True
        return ok, bool(activity["did_work"])


def main(argv=None):
    load_dotenv(dotenv_path=Path(__file__).resolve().with_name(".env"), override=False)
    args = parse_args(argv)
    arches = getattr(args, "arches", _parse_arches(args.arch))
    config_path = Path(args.configyaml)
    config = load_config(config_path)
    try:
        args.config_mtime_ns = config_path.stat().st_mtime_ns
    except FileNotFoundError:
        args.config_mtime_ns = None
    succeeded = 0
    failed = 0
    skipped = 0
    total_candidates = 0
    for arch in arches:
        arch_dir = Path(args.symboldir) / arch
        _progress(f"Scanning {arch_dir}")

        if getattr(args, "version", None):
            candidates = list(_iter_binary_dirs(Path(args.symboldir), arch, config, args.version))
        else:
            candidates = list(_iter_binary_dirs(Path(args.symboldir), arch, config))
        total_candidates += len(candidates)
        _progress(f"Found {len(candidates)} candidate binary directories")
        for candidate in candidates:
            if len(candidate) == 4:
                module, binary_dir, pdb_path, snapshot = candidate
            else:
                module, binary_dir, pdb_path = candidate
                snapshot = None
            _progress(f"Processing {binary_dir}")
            try:
                args.current_arch = arch
                if snapshot is not None and _module_skills_are_satisfied(
                    module=module,
                    arch=arch,
                    selected_skill_name=getattr(args, "skill", None),
                    force=args.force,
                    debug=args.debug,
                    snapshot=snapshot,
                ):
                    ok = True
                    did_work = False
                    if module.symbols:
                        did_work = _sync_binary_artifacts_manifest(
                            Path(binary_dir),
                            module.symbols,
                            snapshot=snapshot,
                            config_mtime_ns=args.config_mtime_ns,
                            allow_cached=True,
                        )
                elif snapshot is not None:
                    ok, did_work = asyncio.run(
                        _process_module_binary(
                            module,
                            binary_dir,
                            pdb_path,
                            args,
                            snapshot=snapshot,
                        )
                    )
                else:
                    ok, did_work = asyncio.run(
                        _process_module_binary(module, binary_dir, pdb_path, args)
                    )
            except Exception:
                failed += 1
                _progress(f"Processing {binary_dir} failed")
                _progress(f"Summary: {succeeded} succeeded, {failed} failed, {skipped} skipped")
                raise
            if not ok:
                failed += 1
                _progress(f"Processing {binary_dir} failed")
                _progress(f"Summary: {succeeded} succeeded, {failed} failed, {skipped} skipped")
                return 1
            if did_work:
                succeeded += 1
                _progress(f"Processed {binary_dir} successfully")
            else:
                skipped += 1
                _progress(f"Skipped {binary_dir} (no work required)")
    if not total_candidates:
        _progress("No processable binary directories found")
        return 0
    _progress(f"Summary: {succeeded} succeeded, {failed} failed, {skipped} skipped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
