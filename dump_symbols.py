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
    PREPROCESS_STATUS_SUCCESS,
    preprocess_single_skill_via_mcp,
)
from symbol_config import load_config

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


def _field(item: Any, name: str, default: Any = None) -> Any:
    if isinstance(item, dict):
        return item.get(name, default)
    return getattr(item, name, default)


def _string_list(item: Any, name: str) -> list[str]:
    values = _field(item, name, []) or []
    return [str(value) for value in values if value]


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
    parser = argparse.ArgumentParser(description="Dump kphtools symbols into YAML artifacts")
    parser.add_argument("-symboldir", required=True)
    parser.add_argument("-configyaml", default="config.yaml")
    parser.add_argument("-arch", choices=["amd64", "arm64"], required=True)
    parser.add_argument("-agent", default="codex")
    parser.add_argument("-force", action="store_true")
    parser.add_argument("-debug", action="store_true")
    return parser.parse_args(argv)


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
        inputs.extend(_string_list(skill, "expected_input_windows"))
        inputs.extend(_string_list(skill, "expected_input_linux"))
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
    completed = subprocess.run(cmd, input=prompt, text=True, check=False)
    if completed.returncode != 0:
        if debug:
            print(f"skill failed: {skill_name}")
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
):
    skill_map = {_field(skill, "name"): skill for skill in skills}
    symbol_map = {_field(symbol, "name"): symbol for symbol in symbols}

    for skill_name in topological_sort_skills(skills):
        skill = skill_map[skill_name]
        expected_outputs = [
            str(Path(binary_dir) / name) for name in _string_list(skill, "expected_output")
        ]
        if not force and expected_outputs and all(Path(path).exists() for path in expected_outputs):
            continue

        symbol_name = _field(skill, "symbol")
        status = await preprocess_single_skill_via_mcp(
            session=session,
            skill=skill,
            symbol=symbol_map[symbol_name],
            binary_dir=Path(binary_dir),
            pdb_path=Path(pdb_path),
            debug=debug,
            llm_config=llm_config,
        )
        if status == PREPROCESS_STATUS_SUCCESS:
            continue

        skill_max_retries = _field(skill, "max_retries") or 3
        if not run_skill(
            skill_name,
            agent=agent,
            debug=debug,
            expected_yaml_paths=expected_outputs,
            max_retries=skill_max_retries,
        ):
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


async def _open_session(base_url: str):
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
                    f"http://{self.host}:{self.port}/mcp"
                )
            if not await _session_matches_binary(self.session, self.binary_path):
                raise RuntimeError(f"MCP session target mismatch for {self.binary_path}")
            return self.session
        except BaseException:
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
                cancel_error = exc
            except Exception:
                pass
        if streams is not None:
            try:
                await streams.__aexit__(None, None, None)
            except asyncio.CancelledError as exc:
                if cancel_error is None:
                    cancel_error = exc
            except Exception:
                pass
        if cancel_error is not None:
            raise cancel_error

    async def close(self) -> None:
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
                    if not pdb_candidates:
                        continue
                    yield module, sha_dir, pdb_candidates[0]


def _resolve_binary_path(module, binary_dir: Path) -> Path:
    for candidate in module.path:
        binary_path = binary_dir / candidate
        if binary_path.exists():
            return binary_path
    raise FileNotFoundError(f"binary file not found in {binary_dir}")


async def _process_module_binary(module, binary_dir, pdb_path, args):
    binary_path = _resolve_binary_path(module, Path(binary_dir))
    session = LazyIdalibSession(
        binary_path,
        host="127.0.0.1",
        debug=args.debug,
    )
    try:
        return await process_binary_dir(
            binary_dir=Path(binary_dir),
            pdb_path=Path(pdb_path),
            skills=module.skills,
            symbols=module.symbols,
            agent=args.agent,
            debug=args.debug,
            force=args.force,
            llm_config=None,
            session=session,
        )
    finally:
        await session.close()


def main(argv=None):
    args = parse_args(argv)
    config = load_config(args.configyaml)
    for module, binary_dir, pdb_path in _iter_binary_dirs(Path(args.symboldir), args.arch, config):
        ok = asyncio.run(_process_module_binary(module, binary_dir, pdb_path, args))
        if not ok:
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
