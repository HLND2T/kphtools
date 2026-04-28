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
    agent_skill_name=None,
):
    selected_skill = agent_skill_name or skill_name
    skill_md_path = Path(".claude") / "skills" / selected_skill / "SKILL.md"
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
            print(f"skill failed: {selected_skill}")
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
            agent_skill_name=_field(skill, "agent_skill"),
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


def start_idalib_mcp(binary_path: Path, host: str = "127.0.0.1", port: int = 13337):
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
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if not _wait_for_port(host, port):
        process.kill()
        raise RuntimeError(f"idalib-mcp failed to start for {binary_path}")
    return process


async def _open_session(base_url: str):
    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client

    streams = streamable_http_client(base_url)
    read_stream, write_stream, _ = await streams.__aenter__()
    session = ClientSession(read_stream, write_stream)
    await session.__aenter__()
    await session.initialize()
    return streams, session


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
    process = start_idalib_mcp(_resolve_binary_path(module, Path(binary_dir)))
    streams = None
    session = None
    try:
        streams, session = await _open_session("http://127.0.0.1:13337/mcp")
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
        if session is not None:
            await session.__aexit__(None, None, None)
        if streams is not None:
            await streams.__aexit__(None, None, None)
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=1)


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
