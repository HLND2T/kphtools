"""OpenCode CLI execution, MCP preflight, retries, and output validation."""

import json
import os
import re
import subprocess
import sys
import threading
from dataclasses import dataclass


SKILL_TIMEOUT = 1200
MCP_LIST_TIMEOUT = 30
SKILL_ERROR_RE = re.compile(
    r"<skill_error>\s*(.*?)\s*</skill_error>",
    re.IGNORECASE | re.DOTALL,
)
CYBERSECURITY_BLOCK_MARKERS = (
    "This chat was flagged for possible cybersecurity risk",
    "flagged this message for a cybersecurity topic",
)
ANSI_ESCAPE_RE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
_MCP_PREFLIGHT_DONE = False
_MCP_PREFLIGHT_FAILED = False
OPENCODE_SKILL_RUNNER_CONFIG = ".opencode/skill_runner.config.json"
DEFAULT_AGENT_MODEL = ""


@dataclass(frozen=True)
class AgentCommand:
    args: list[str]
    input_text: str | None
    retry_target_desc: str


def _detect_agent_kind(agent: str) -> str | None:
    agent_lower = agent.lower()
    if "claude" in agent_lower:
        return "claude"
    if "codex" in agent_lower:
        return "codex"
    if "opencode" in agent_lower:
        return "opencode"
    return None


def _extract_opencode_session_id(output: str) -> str | None:
    for line in (output or "").splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(event, dict):
            continue
        session_id = event.get("sessionID")
        if isinstance(session_id, str) and session_id:
            return session_id
    return None


def _extract_skill_error(*texts: str) -> str | None:
    merged_output = "\n".join(text for text in texts if text)
    match = SKILL_ERROR_RE.search(merged_output)
    if match is None:
        return None
    return match.group(1).strip()


def _extract_cybersecurity_block(*texts: str) -> str | None:
    merged_output = "\n".join(text for text in texts if text).casefold()
    for marker in CYBERSECURITY_BLOCK_MARKERS:
        if marker.casefold() in merged_output:
            return marker
    return None


def _mcp_list_contains_server(output, server_name="ida-pro-mcp"):
    if not output:
        return False
    normalized_output = ANSI_ESCAPE_RE.sub("", output)
    prefix = r"(?:[-*•●|│T—]\s*)*(?:[✓✗]\s*)?"
    pattern = re.compile(
        rf"(?m)^\s*{prefix}{re.escape(server_name)}(?:\s|:|$)"
    )
    return bool(pattern.search(normalized_output))


def _format_mcp_list_output(output, limit=1200):
    text = (output or "").strip()
    if not text:
        return "<empty>"
    if len(text) > limit:
        text = text[:limit] + "... <truncated>"
    return "\n".join(f"      {line}" for line in text.splitlines())


def _agent_process_env(agent_kind: str) -> dict[str, str] | None:
    if agent_kind != "opencode":
        return None
    env = os.environ.copy()
    env.update(
        {
            "OPENCODE_DISABLE_CLAUDE_CODE_PROMPT": "1",
            "OPENCODE_CONFIG": OPENCODE_SKILL_RUNNER_CONFIG,
        }
    )
    return env


def _ensure_agent_mcp_preflight(agent, debug=False, server_name="ida-pro-mcp"):
    global _MCP_PREFLIGHT_DONE, _MCP_PREFLIGHT_FAILED

    if _MCP_PREFLIGHT_DONE:
        return True
    if _MCP_PREFLIGHT_FAILED:
        print("    Error: MCP preflight previously failed; refusing to start agent.")
        return False

    cmd = [agent, "mcp", "list"]
    print(f"    Checking MCP server list: {' '.join(cmd)}")
    try:
        result = _run_process_with_stream_capture(
            cmd,
            debug=debug,
            timeout=MCP_LIST_TIMEOUT,
            env=_agent_process_env(_detect_agent_kind(agent) or ""),
        )
    except subprocess.TimeoutExpired:
        _MCP_PREFLIGHT_FAILED = True
        print(
            "    Error: MCP list preflight timeout "
            f"({MCP_LIST_TIMEOUT} seconds): {' '.join(cmd)}"
        )
        return False
    except FileNotFoundError:
        _MCP_PREFLIGHT_FAILED = True
        print(
            f"    Error: Agent '{agent}' not found while running MCP list preflight."
        )
        return False
    except Exception as error:
        _MCP_PREFLIGHT_FAILED = True
        print(f"    Error executing MCP list preflight: {error}")
        return False

    output = "\n".join(text for text in (result.stdout, result.stderr) if text)
    if _mcp_list_contains_server(output, server_name):
        _MCP_PREFLIGHT_DONE = True
        return True

    _MCP_PREFLIGHT_FAILED = True
    print(
        f"    Error: Required MCP server '{server_name}' is not listed by "
        f"'{agent} mcp list'."
    )
    if result.returncode != 0:
        print(f"    mcp list return code: {result.returncode}")
    print(f"    mcp list output:\n{_format_mcp_list_output(output)}")
    return False


def _drain_text_stream(stream, chunks, forward_stream=None):
    try:
        for chunk in iter(stream.readline, ""):
            chunks.append(chunk)
            if forward_stream is not None:
                forward_stream.write(chunk)
                forward_stream.flush()
    finally:
        try:
            stream.close()
        except Exception:
            pass


def _run_process_with_stream_capture(
    cmd,
    *,
    agent_input=None,
    debug=False,
    timeout=SKILL_TIMEOUT,
    env=None,
):
    process = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE if agent_input is not None else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
    )
    if agent_input is not None and process.stdin is not None:
        process.stdin.write(agent_input)
        process.stdin.flush()
        process.stdin.close()

    stdout_chunks, stderr_chunks = [], []
    stdout_thread = threading.Thread(
        target=_drain_text_stream,
        args=(process.stdout, stdout_chunks, sys.stdout if debug else None),
    )
    stderr_thread = threading.Thread(
        target=_drain_text_stream,
        args=(process.stderr, stderr_chunks, sys.stderr if debug else None),
    )
    stdout_thread.start()
    stderr_thread.start()
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        try:
            process.wait(timeout=1)
        except Exception:
            pass
        stdout_thread.join(timeout=1)
        stderr_thread.join(timeout=1)
        raise

    stdout_thread.join()
    stderr_thread.join()
    return subprocess.CompletedProcess(
        cmd,
        process.returncode,
        "".join(stdout_chunks),
        "".join(stderr_chunks),
    )


def _agent_permission_args(agent_kind: str) -> list[str]:
    if agent_kind == "opencode":
        return ["--auto"]
    return []


def _agent_model_args(
    agent_kind: str,
    agent_model: str = DEFAULT_AGENT_MODEL,
) -> list[str]:
    model = str(agent_model or "").strip()
    if not model:
        return []
    if agent_kind == "opencode" and "/" not in model:
        raise ValueError("OpenCode model must use provider/model format")
    return ["--model" if agent_kind == "claude" else "-m", model]


def _build_opencode_base_args(
    agent: str,
    agent_profile: str,
    is_retry: bool,
    session_id: str | None,
    agent_model: str = DEFAULT_AGENT_MODEL,
) -> list[str]:
    args = [agent, "run", "--format", "json"]
    args.extend(_agent_model_args("opencode", agent_model))
    args.extend(_agent_permission_args("opencode"))
    if is_retry and session_id:
        args.extend(["--session", session_id])
    elif is_retry:
        args.append("--continue")
    args.extend(["--agent", agent_profile])
    return args


def _build_opencode_command(
    agent: str,
    skill_name: str,
    is_retry: bool,
    session_id: str | None,
    agent_model: str = DEFAULT_AGENT_MODEL,
) -> AgentCommand:
    args = _build_opencode_base_args(
        agent,
        "sig-finder",
        is_retry,
        session_id,
        agent_model,
    )
    args.append(f"Run SKILL: .claude/skills/{skill_name}/SKILL.md")
    retry_target = (
        f"OpenCode session {session_id}"
        if session_id
        else "the latest OpenCode session (--continue)"
    )
    return AgentCommand(args, None, retry_target)


def _missing_expected_outputs(expected_yaml_paths) -> list[str]:
    if expected_yaml_paths is None:
        return []
    return [path for path in expected_yaml_paths if not os.path.exists(path)]


def _result_failure_reason(result, expected_yaml_paths):
    if result.returncode != 0:
        return "returncode"
    cybersecurity_block = _extract_cybersecurity_block(
        result.stdout,
        result.stderr,
    )
    if cybersecurity_block is not None:
        return ("cybersecurity_block", cybersecurity_block)
    skill_error = _extract_skill_error(result.stdout, result.stderr)
    if skill_error is not None:
        return ("skill_error", skill_error)
    missing_files = _missing_expected_outputs(expected_yaml_paths)
    if missing_files:
        return missing_files
    return None


def _report_result_failure(reason, result, debug: bool) -> None:
    if reason == "returncode":
        print(f"    Skill failed with return code: {result.returncode}")
        if not debug and result.stderr:
            print(f"    stderr: {result.stderr[:500]}")
    elif isinstance(reason, tuple) and reason[0] == "skill_error":
        print(f"    Error: Skill reported: {reason[1]}")
    elif isinstance(reason, tuple) and reason[0] == "cybersecurity_block":
        print(f"    Error: Skill blocked by cybersecurity filter: {reason[1]}")
    elif reason:
        print(f"    Error: Expected yaml files not generated: {reason}")


def _retry_if_available(
    attempt: int,
    max_retries: int,
    retry_target_desc: str,
) -> None:
    if attempt < max_retries - 1:
        print(f"    Retrying with {retry_target_desc}...")


def _run_opencode_skill_attempts(
    *,
    skill_name: str,
    agent: str,
    debug: bool,
    expected_yaml_paths,
    max_retries: int,
    agent_model: str,
) -> bool:
    opencode_session_id = None
    process_env = _agent_process_env("opencode")
    for attempt in range(max_retries):
        command = _build_opencode_command(
            agent,
            skill_name,
            attempt > 0,
            opencode_session_id,
            agent_model,
        )
        attempt_text = (
            f"(attempt {attempt + 1}/{max_retries})" if max_retries > 1 else ""
        )
        retry_text = "[RETRY] " if attempt else ""
        print(f"    {retry_text}Running {attempt_text}: {' '.join(command.args)}")
        try:
            result = _run_process_with_stream_capture(
                command.args,
                agent_input=command.input_text,
                debug=debug,
                timeout=SKILL_TIMEOUT,
                env=process_env,
            )
            if opencode_session_id is None:
                opencode_session_id = _extract_opencode_session_id(result.stdout)
            reason = _result_failure_reason(result, expected_yaml_paths)
            if reason is None:
                return True
            _report_result_failure(reason, result, debug)
            if isinstance(reason, tuple) and reason[0] == "cybersecurity_block":
                return False
            _retry_if_available(
                attempt,
                max_retries,
                command.retry_target_desc,
            )
        except subprocess.TimeoutExpired:
            print(f"    Error: Skill execution timeout ({SKILL_TIMEOUT} seconds)")
            _retry_if_available(
                attempt,
                max_retries,
                command.retry_target_desc,
            )
        except FileNotFoundError:
            print(
                f"    Error: Agent '{agent}' not found. "
                "Please ensure it is installed and in PATH."
            )
            return False
        except Exception as error:
            print(f"    Error executing skill: {error}")
            _retry_if_available(
                attempt,
                max_retries,
                command.retry_target_desc,
            )

    print(f"    Failed after {max_retries} attempts")
    return False


def run_skill(
    skill_name,
    agent="opencode",
    debug=False,
    expected_yaml_paths=None,
    max_retries=3,
    agent_model=DEFAULT_AGENT_MODEL,
) -> bool:
    """Execute a skill with OpenCode and retry support."""
    agent_kind = _detect_agent_kind(agent)
    if agent_kind != "opencode":
        print(
            f"    Error: Unsupported agent type '{agent}'. "
            "This runner requires opencode or opencode.cmd."
        )
        return False
    try:
        _agent_model_args(agent_kind, agent_model)
    except ValueError as error:
        print(f"    Error: {error}")
        return False

    skill_md_path = os.path.join(
        ".claude",
        "skills",
        skill_name,
        "SKILL.md",
    )
    print(f"    Falling back to: {skill_md_path}")
    if not os.path.exists(skill_md_path):
        print(f"    Error: Skill file not found: {skill_md_path}")
        return False
    if not _ensure_agent_mcp_preflight(agent, debug=debug):
        return False
    return _run_opencode_skill_attempts(
        skill_name=skill_name,
        agent=agent,
        debug=debug,
        expected_yaml_paths=expected_yaml_paths,
        max_retries=max_retries,
        agent_model=agent_model,
    )
