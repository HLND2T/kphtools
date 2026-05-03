"""
按配置扫描符号目录，并将每个二进制的解析结果导出为 YAML symbol artifacts。

基本用法:
    uv run python dump_symbols.py
    uv run python dump_symbols.py -symboldir symbols -arch amd64
    uv run python dump_symbols.py -symboldir symbols -arch amd64,arm64 -force

可用参数:
    -symboldir   符号根目录，默认 `symbols`。
    -configyaml  模块与符号配置文件，默认 `config.yaml`。
    -arch        要扫描的架构列表，逗号分隔；当前支持 `amd64`、`arm64`。
    -agent       回退到外部 Agent CLI 时使用的可执行文件名，默认 `codex`。
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
from pathlib import Path
from typing import Any

from ida_skill_preprocessor import (
    PREPROCESS_STATUS_ABSENT_OK as _PREPROCESS_STATUS_ABSENT_OK,
    PREPROCESS_STATUS_FAILED as _PREPROCESS_STATUS_FAILED,
    PREPROCESS_STATUS_SUCCESS,
    preprocess_single_skill_via_mcp,
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
IDALIB_QEXIT_TIMEOUT_SECONDS = 3
SUPPORTED_ARCHES = ("amd64", "arm64")
DEFAULT_ARCH = ",".join(SUPPORTED_ARCHES)
DEFAULT_SYMBOL_DIR = "symbols"
DEFAULT_LLM_MODEL = "gpt-4o"
PREPROCESS_STATUS_ABSENT_OK = _PREPROCESS_STATUS_ABSENT_OK
PREPROCESS_STATUS_FAILED = _PREPROCESS_STATUS_FAILED


def _field(item: Any, name: str, default: Any = None) -> Any:
    if isinstance(item, dict):
        return item.get(name, default)
    return getattr(item, name, default)


def _string_list(item: Any, name: str) -> list[str]:
    values = _field(item, name, []) or []
    return [str(value) for value in values if value]


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
    return [
        symbol_name_from_artifact_name(output_path)
        for output_path in _skill_output_names(skill)
    ]


def _symbol_for_output(symbol_map: dict[str, Any], symbol_name: str) -> Any:
    return symbol_map.get(symbol_name, {"name": symbol_name})


def _artifact_paths(binary_dir: str | Path, names: list[str]) -> list[str]:
    return [str(Path(binary_dir) / name) for name in names]


def _all_paths_exist(paths: list[str]) -> bool:
    return bool(paths) and all(Path(path).exists() for path in paths)


def _should_skip_for_existing_outputs(
    required_outputs: list[str],
    optional_outputs: list[str],
) -> bool:
    if required_outputs:
        return _all_paths_exist(required_outputs)
    return _all_paths_exist(optional_outputs)


def _should_skip_for_existing_artifacts(binary_dir: str | Path, skill: Any) -> bool:
    skip_paths = _artifact_paths(binary_dir, _string_list(skill, "skip_if_exists"))
    return _all_paths_exist(skip_paths)


def _skill_output_paths(
    binary_dir: str | Path,
    skill: Any,
) -> tuple[list[str], list[str]]:
    required_outputs = _artifact_paths(
        binary_dir,
        _unique_strings(
            _string_list(skill, "expected_output")
            + _string_list(skill, "preprocessor_only_output")
        ),
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
            _string_list(skill, "expected_output")
            + _string_list(skill, "preprocessor_only_output")
        )
    }


def _preprocessor_only_output_symbol_names(skill: Any) -> set[str]:
    return {
        symbol_name_from_artifact_name(path)
        for path in _string_list(skill, "preprocessor_only_output")
    }


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
    required_symbol_names = _required_output_symbol_names(skill)
    preprocessor_only_symbol_names = _preprocessor_only_output_symbol_names(skill)
    failed_required_symbol_names: set[str] = set()
    for symbol_name in _output_symbol_names(skill):
        status = await preprocess_single_skill_via_mcp(
            session=session,
            skill=skill,
            symbol=_symbol_for_output(symbol_map, symbol_name),
            binary_dir=Path(binary_dir),
            pdb_path=pdb_path,
            debug=debug,
            llm_config=llm_config,
        )
        _debug_log(debug, f"preprocess status for {skill_name}/{symbol_name}: {status}")
        if status == PREPROCESS_STATUS_SUCCESS or symbol_name not in required_symbol_names:
            continue
        if symbol_name in preprocessor_only_symbol_names:
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
    debug: bool, force: bool,
    llm_config: dict[str, Any] | None,
    session: Any,
    activity: dict[str, bool] | None,
) -> bool:
    _debug_log(debug, f"skill {skill_name} started")
    required_outputs, optional_outputs = _skill_output_paths(binary_dir, skill)
    if not force and _should_skip_for_existing_outputs(required_outputs, optional_outputs):
        _debug_log(debug, f"skipping {skill_name}; expected outputs already exist")
        return True
    if _should_skip_for_existing_artifacts(binary_dir, skill):
        _debug_log(debug, f"skipping {skill_name}; skip_if_exists artifacts exist")
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
    if preprocessed_all:
        return True
    if not required_outputs and optional_outputs:
        _debug_log(debug, f"skipping {skill_name}; optional outputs not generated")
        return True
    if failed_required_symbol_names.issubset(
        _preprocessor_only_output_symbol_names(skill)
    ):
        _debug_log(
            debug,
            f"required preprocessor-only outputs failed for {skill_name}; not falling back",
        )
        return False

    skill_max_retries = _field(skill, "max_retries") or 3
    _debug_log(debug, f"falling back to run_skill for {skill_name}")
    return run_skill(
        skill_name,
        agent=agent,
        debug=debug,
        expected_yaml_paths=required_outputs,
        max_retries=skill_max_retries,
    )


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
        raise argparse.ArgumentTypeError(
            f"arch must include at least one value from: {supported}"
        )
    return arches


def _strip_frontmatter(text: str) -> str:
    content = text.strip()
    if not content.startswith("---"):
        return content
    lines = content.splitlines()
    for index, line in enumerate(lines[1:], start=1):
        if line.strip() == "---":
            return "\n".join(lines[index + 1 :]).strip()
    return content


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


def _load_dotenv_file(path: str | Path = ".env") -> None:
    env_path = Path(path)
    if not env_path.is_file():
        return

    try:
        lines = env_path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return

    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if not key or key in os.environ:
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        os.environ[key] = value


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
    _load_dotenv_file()
    parser = argparse.ArgumentParser(
        description="Dump kphtools symbols into YAML artifacts",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("-symboldir", default=DEFAULT_SYMBOL_DIR, help="Symbol artifact root directory")
    parser.add_argument("-configyaml", default="config.yaml")
    parser.add_argument(
        "-arch",
        default=DEFAULT_ARCH,
        help="Comma-separated architectures to scan",
    )
    parser.add_argument("-agent", default="codex")
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
    try:
        args.arches = _parse_arches(args.arch)
    except argparse.ArgumentTypeError as exc:
        parser.error(str(exc))
    return args


def topological_sort_skills(skills):
    skill_names = {_field(skill, "name") for skill in skills}

    def normalize(path: str) -> str:
        return os.path.normcase(os.path.normpath(path))

    producers: dict[str, set[str]] = {}
    for skill in skills:
        skill_name = _field(skill, "name")
        for output_path in _string_list(skill, "expected_output"):
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


def run_skill(
    skill_name,
    agent,
    debug,
    expected_yaml_paths,
    max_retries=3,
):
    _debug_log(debug, f"starting fallback skill for {skill_name}")
    skill_md_path = Path(".claude") / "skills" / skill_name / "SKILL.md"
    if not skill_md_path.exists():
        return False

    system_prompt_path = Path(".claude") / "agents" / "sig-finder.md"
    try:
        developer_instructions = _strip_frontmatter(
            system_prompt_path.read_text(encoding="utf-8")
        )
    except OSError:
        return False

    if not developer_instructions:
        return False

    cmd = [
        agent,
        "-c",
        f"developer_instructions={json.dumps(developer_instructions)}",
        "-c",
        "model_reasoning_effort=high",
        "exec",
        "-",
    ]
    prompt = f"Run SKILL: {skill_md_path}"
    try:
        completed = subprocess.run(cmd, input=prompt, text=True, check=False)
    except FileNotFoundError as exc:
        missing_executable = exc.filename or agent
        _progress(
            f"Agent CLI not found: {missing_executable}. "
            "Install it or pass -agent with a valid executable path."
        )
        return False
    if completed.returncode != 0:
        _debug_log(debug, f"skill failed: {skill_name}")
        return False
    return all(Path(path).exists() for path in expected_yaml_paths)


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
):
    if activity is not None and "did_work" not in activity:
        activity["did_work"] = False

    resolved_pdb_path = Path(pdb_path) if pdb_path is not None else None
    skill_map = {_field(skill, "name"): skill for skill in skills}
    symbol_map = {_field(symbol, "name"): symbol for symbol in symbols}

    for skill_name in topological_sort_skills(skills):
        ok = await _process_one_skill(
            skill_name=skill_name,
            skill=skill_map[skill_name],
            symbol_map=symbol_map,
            binary_dir=binary_dir,
            pdb_path=resolved_pdb_path,
            agent=agent,
            debug=debug,
            force=force,
            llm_config=llm_config,
            session=session,
            activity=activity,
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


def start_idalib_mcp(
    binary_path: Path,
    host: str = "127.0.0.1",
    port: int = 13337,
    debug: bool = False,
):
    cmd = [
        "uv",
        "run",
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
        process.kill()
        process.wait()
        raise RuntimeError(f"idalib-mcp failed to start for {binary_path}")
    return process


async def _open_session(base_url: str, debug: bool = False):
    _debug_log(debug, f"opening MCP session at {base_url}")
    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client

    streams = None
    session = None
    streams_entered = False
    session_entered = False
    try:
        streams = streamable_http_client(base_url)
        read_stream, write_stream, _ = await streams.__aenter__()
        streams_entered = True

        session = ClientSession(read_stream, write_stream)
        await session.__aenter__()
        session_entered = True

        await session.initialize()
        return streams, session
    except BaseException:
        if session is not None and session_entered:
            try:
                await session.__aexit__(None, None, None)
            except BaseException:
                pass
        if streams is not None and streams_entered:
            try:
                await streams.__aexit__(None, None, None)
            except BaseException:
                pass
        raise


async def _session_matches_binary(session, binary_path: Path) -> bool:
    try:
        result = await session.call_tool(
            name="py_eval",
            arguments={"code": SURVEY_CURRENT_IDB_PATH_PY_EVAL},
        )
    except Exception:
        return False

    payload = _parse_py_eval_result_json(result)
    if not isinstance(payload, dict):
        return False

    metadata = payload.get("metadata")
    if not isinstance(metadata, dict):
        return False

    current_path = metadata.get("path")
    if not isinstance(current_path, str) or not current_path:
        return False

    try:
        current_idb_path = Path(current_path).resolve(strict=False)
        target_binary_path = Path(binary_path).resolve(strict=False)
    except OSError:
        return False

    return (
        current_idb_path.name.lower().startswith(target_binary_path.name.lower())
        and current_idb_path.parent == target_binary_path.parent
    )


class LazyIdalibSession:
    def __init__(
        self,
        binary_path: Path,
        host: str = "127.0.0.1",
        debug: bool = False,
    ) -> None:
        self.binary_path = Path(binary_path)
        self.host = host
        self.debug = debug
        self.port: int | None = None
        self.process = None
        self.streams = None
        self.session = None

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
            if self.streams is None or self.session is None:
                self.streams, self.session = await _open_session(
                    f"http://{self.host}:{self.port}/mcp",
                    debug=self.debug,
                )
            if not await _session_matches_binary(self.session, self.binary_path):
                _debug_log(self.debug, f"binary mismatch for {self.binary_path}, cleaning up startup state")
                raise RuntimeError(f"MCP session target mismatch for {self.binary_path}")
            return self.session
        except BaseException:
            _debug_log(self.debug, f"startup cleanup for {self.binary_path}")
            session = self.session
            streams = self.streams
            process = self.process

            self.process = None
            self.streams = None
            self.session = None

            if session is not None:
                try:
                    await session.__aexit__(None, None, None)
                except BaseException:
                    pass
            if streams is not None:
                try:
                    await streams.__aexit__(None, None, None)
                except BaseException:
                    pass

            if process is not None and process.poll() is None:
                try:
                    process.kill()
                except Exception:
                    pass
                try:
                    await asyncio.to_thread(process.wait, timeout=1)
                except BaseException:
                    pass
            raise

    async def call_tool(self, name, arguments):
        session = await self.ensure_started()
        return await session.call_tool(name=name, arguments=arguments)

    async def _close_handles(self) -> None:
        session = self.session
        streams = self.streams
        self.session = None
        self.streams = None
        cancel_error = None

        if session is not None:
            try:
                await session.__aexit__(None, None, None)
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
        if streams is not None:
            try:
                await streams.__aexit__(None, None, None)
            except asyncio.CancelledError as exc:
                if _is_mcp_cancel_scope_cancelled(exc):
                    _debug_log(
                        self.debug,
                        _format_close_cancelled_message("stream exit", exc),
                    )
                elif cancel_error is None:
                    cancel_error = exc
            except Exception:
                pass
        if cancel_error is not None:
            raise cancel_error

    async def close(self) -> None:
        if self.process is not None or self.streams is not None or self.session is not None:
            _debug_log(self.debug, f"closing lazy MCP session for {self.binary_path}")
        process = self.process
        self.process = None

        try:
            if process is None:
                await self._close_handles()
                return
            if process.poll() is not None:
                await self._close_handles()
                return

            if self.session is not None:
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
            try:
                await asyncio.to_thread(process.wait, timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                await asyncio.to_thread(process.wait, timeout=1)
        except asyncio.CancelledError:
            try:
                await self._close_handles()
            except BaseException:
                pass
            if process is not None and process.poll() is None:
                try:
                    process.kill()
                except Exception:
                    pass
                try:
                    await asyncio.to_thread(process.wait, timeout=1)
                except BaseException:
                    pass
            raise


def _iter_binary_dirs(symboldir: Path, arch: str, config):
    arch_dir = Path(symboldir) / arch
    for module in config.modules:
        for module_path in module.path:
            for version_dir in sorted(arch_dir.glob(f"{module_path}.*")):
                if not version_dir.is_dir():
                    continue
                for sha_dir in sorted(version_dir.iterdir()):
                    if not sha_dir.is_dir():
                        continue
                    pdb_candidates = sorted(sha_dir.glob("*.pdb"))
                    if not pdb_candidates and not (sha_dir / module_path).is_file():
                        continue
                    pdb_path = pdb_candidates[0] if pdb_candidates else None
                    yield module, sha_dir, pdb_path


def _resolve_binary_path(module, binary_dir: Path) -> Path:
    for candidate in module.path:
        binary_path = binary_dir / candidate
        if binary_path.exists():
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


async def _process_module_binary(module, binary_dir, pdb_path, args):
    binary_path = _resolve_binary_path(module, Path(binary_dir))
    resolved_pdb_path = Path(pdb_path) if pdb_path is not None else None
    session = LazyIdalibSession(
        binary_path,
        host="127.0.0.1",
        debug=args.debug,
    )
    activity = {"did_work": False}
    try:
        ok = await process_binary_dir(
            binary_dir=Path(binary_dir),
            pdb_path=resolved_pdb_path,
            skills=module.skills,
            symbols=module.symbols,
            agent=args.agent,
            debug=args.debug,
            force=args.force,
            llm_config=_build_llm_config(args),
            session=session,
            activity=activity,
        )
        return ok, bool(activity["did_work"])
    finally:
        await session.close()


def main(argv=None):
    args = parse_args(argv)
    arches = getattr(args, "arches", _parse_arches(args.arch))
    config = load_config(args.configyaml)
    succeeded = 0
    failed = 0
    skipped = 0
    total_candidates = 0
    for arch in arches:
        arch_dir = Path(args.symboldir) / arch
        _progress(f"Scanning {arch_dir}")

        candidates = list(_iter_binary_dirs(Path(args.symboldir), arch, config))
        total_candidates += len(candidates)
        _progress(f"Found {len(candidates)} candidate binary directories")
        for module, binary_dir, pdb_path in candidates:
            _progress(f"Processing {binary_dir}")
            try:
                ok, did_work = asyncio.run(_process_module_binary(module, binary_dir, pdb_path, args))
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
