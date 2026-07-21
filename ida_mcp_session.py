from __future__ import annotations

import asyncio
import json
import os
import re
from collections.abc import Mapping, Sequence
from contextlib import AsyncExitStack, asynccontextmanager
from dataclasses import dataclass
from typing import Any

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client


WORKER_TOOL_NAMES = frozenset(
    {
        "py_eval",
        "survey_binary",
        "find_bytes",
        "rename",
        "define_func",
        "set_comments",
        "get_int",
    }
)
MANAGEMENT_TOOL_NAMES = frozenset({"idb_open", "idb_list"})
IDA_DATABASE_SUFFIXES = (".i64", ".idb")
DATABASE_READY_RETRY_INTERVAL = 0.25


class McpContractError(RuntimeError):
    pass


class McpDatabaseSelectionError(RuntimeError):
    pass


class McpDatabaseNotReadyError(McpDatabaseSelectionError):
    pass


class McpConnectionError(RuntimeError):
    pass


class McpToolCallError(RuntimeError):
    pass


def normalize_binary_identity_path(path: str | os.PathLike[str]) -> str:
    if not isinstance(path, (str, os.PathLike)) or not str(path).strip():
        return ""

    value = str(path).strip().replace("\\", "/")
    lowered = value.lower()
    for suffix in IDA_DATABASE_SUFFIXES:
        if lowered.endswith(suffix):
            value = value[: -len(suffix)]
            break

    mount = re.match(r"^/mnt/([A-Za-z])/(.*)$", value)
    if mount:
        value = f"{mount.group(1)}:/{mount.group(2)}"
    if not re.match(r"^[A-Za-z]:/", value) and not value.startswith("/"):
        value = os.path.abspath(os.path.normpath(value)).replace("\\", "/")
    else:
        value = os.path.normpath(value).replace("\\", "/")
    return value.rstrip("/").lower()


def detect_database_requirement(tools: Sequence[Any]) -> bool:
    requirements = {}
    for tool in tools:
        tool_name = getattr(tool, "name", None)
        if tool_name not in WORKER_TOOL_NAMES:
            continue
        schema = getattr(tool, "inputSchema", {})
        schema = schema if isinstance(schema, dict) else {}
        requirements[tool_name] = "database" in schema.get("required", [])

    if not requirements:
        raise McpContractError("MCP tools/list returned no known IDA worker tools")
    if len(set(requirements.values())) != 1:
        raise McpContractError(f"inconsistent database requirement across worker tools: {requirements}")
    return next(iter(requirements.values()))


def _session_summary(sessions: Sequence[Mapping[str, Any]]) -> str:
    return "; ".join(
        "session_id={session_id!r}, input_path={input_path!r}, backend={backend!r}, "
        "owned={owned!r}, is_active={is_active!r}".format(
            session_id=session.get("session_id"),
            input_path=session.get("input_path"),
            backend=session.get("backend"),
            owned=session.get("owned"),
            is_active=session.get("is_active"),
        )
        for session in sessions
    )


def select_database_session(
    sessions: Sequence[Mapping[str, Any]],
    *,
    expected_binary: str | os.PathLike[str] | None = None,
    explicit_database: str | None = None,
) -> Mapping[str, Any]:
    routable = [
        session
        for session in sessions
        if session.get("is_active") is True
        and isinstance(session.get("session_id"), str)
        and session["session_id"].strip()
    ]
    if explicit_database:
        matches = [session for session in routable if session["session_id"] == explicit_database]
        if len(matches) == 1:
            return matches[0]
        discovered = [
            session
            for session in sessions
            if session.get("session_id") == explicit_database
            and session.get("is_active") is not True
        ]
        if discovered:
            raise McpDatabaseNotReadyError(
                f"MCP database {explicit_database!r} exists but is not active yet; "
                f"candidates: {_session_summary(sessions)}"
            )
        raise McpDatabaseSelectionError(
            f"MCP database {explicit_database!r} is not an active routable session; "
            f"candidates: {_session_summary(sessions)}"
        )

    if expected_binary:
        expected = normalize_binary_identity_path(expected_binary)
        matches = [
            session
            for session in routable
            if normalize_binary_identity_path(session.get("input_path", "")) == expected
        ]
        if len(matches) == 1:
            return matches[0]
        discovered = [
            session
            for session in sessions
            if isinstance(session.get("session_id"), str)
            and session["session_id"].strip()
            and normalize_binary_identity_path(session.get("input_path", "")) == expected
            and session.get("is_active") is not True
        ]
        if not matches and discovered:
            raise McpDatabaseNotReadyError(
                f"MCP database for expected binary {expected_binary!r} exists but is not active yet; "
                f"candidates: {_session_summary(sessions)}"
            )
        label = "no" if not matches else "multiple"
        raise McpDatabaseSelectionError(
            f"{label} active MCP database matched expected binary {expected_binary!r}; "
            f"candidates: {_session_summary(sessions)}"
        )

    if len(routable) == 1:
        return routable[0]
    if not routable:
        raise McpDatabaseSelectionError(
            f"no active routable MCP database; candidates: {_session_summary(sessions)}"
        )
    raise McpDatabaseSelectionError(
        "multiple active MCP databases require an expected binary or explicit session id; "
        f"candidates: {_session_summary(sessions)}"
    )


@dataclass(frozen=True)
class McpDatabaseBinding:
    database_required: bool
    session_id: str | None
    input_path: str | None
    backend: str | None
    owned: bool
    auto_started: bool

    @property
    def should_auto_quit(self) -> bool:
        return self.auto_started and self.owned and self.backend == "worker"


class DatabaseBoundSession:
    def __init__(self, raw_session: Any, binding: McpDatabaseBinding) -> None:
        self.raw_session = raw_session
        self.binding = binding

    async def call_tool(
        self,
        name: str,
        arguments: Mapping[str, Any] | None = None,
        **kwargs: Any,
    ) -> Any:
        routed = dict(arguments or {})
        if self.binding.database_required and name not in MANAGEMENT_TOOL_NAMES:
            supplied = routed.get("database")
            if supplied is not None and supplied != self.binding.session_id:
                raise McpDatabaseSelectionError(
                    f"tool {name} database {supplied!r} conflicts with bound database "
                    f"{self.binding.session_id!r}"
                )
            routed["database"] = self.binding.session_id

        result = await self.raw_session.call_tool(name=name, arguments=routed, **kwargs)
        if getattr(result, "isError", False):
            raise McpToolCallError(f"MCP tool {name} failed: {_tool_result_error_text(result)}")
        return result

    def __getattr__(self, name: str) -> Any:
        return getattr(self.raw_session, name)


def _tool_result_payload(result: Any) -> dict[str, Any] | None:
    structured = getattr(result, "structuredContent", None)
    if isinstance(structured, dict):
        return structured

    content = getattr(result, "content", None) or []
    text = getattr(content[0], "text", None) if content else None
    if not isinstance(text, str):
        return None
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _tool_result_error_text(result: Any) -> str:
    payload = _tool_result_payload(result)
    if isinstance(payload, dict) and isinstance(payload.get("error"), str):
        return payload["error"]

    content = getattr(result, "content", None) or []
    text = getattr(content[0], "text", None) if content else None
    return text if isinstance(text, str) and text else "unknown MCP tool error"


def _find_mcp_error(exception: Exception) -> Exception | None:
    known_errors = (
        McpContractError,
        McpDatabaseSelectionError,
        McpConnectionError,
        McpToolCallError,
    )
    if isinstance(exception, known_errors):
        return exception
    for nested in getattr(exception, "exceptions", ()):
        if isinstance(nested, Exception):
            found = _find_mcp_error(nested)
            if found is not None:
                return found
    return None


@asynccontextmanager
async def _open_raw_ida_mcp_session(
    host: str,
    port: int,
    connect_timeout: float,
    read_timeout: float,
):
    server_url = f"http://{host}:{port}/mcp"
    async with AsyncExitStack() as stack:
        http_client = await stack.enter_async_context(
            httpx.AsyncClient(
                follow_redirects=True,
                timeout=httpx.Timeout(connect_timeout, read=read_timeout),
                trust_env=False,
            )
        )
        read_stream, write_stream, _ = await stack.enter_async_context(
            streamable_http_client(
                server_url,
                http_client=http_client,
                terminate_on_close=False,
            )
        )
        raw_session = await stack.enter_async_context(ClientSession(read_stream, write_stream))
        await raw_session.initialize()
        yield raw_session


@asynccontextmanager
async def open_ida_mcp_session(
    host: str,
    port: int,
    *,
    expected_binary: str | os.PathLike[str] | None = None,
    explicit_database: str | None = None,
    auto_started: bool = False,
    connect_timeout: float = 10.0,
    read_timeout: float = 300.0,
    database_ready_timeout: float | None = None,
    database_ready_retry_interval: float = DATABASE_READY_RETRY_INTERVAL,
):
    loop = asyncio.get_running_loop()
    ready_deadline = (
        loop.time() + max(0.0, database_ready_timeout)
        if database_ready_timeout is not None
        else None
    )
    while True:
        session_ready = False
        try:
            async with AsyncExitStack() as stack:
                try:
                    raw_session = await stack.enter_async_context(
                        _open_raw_ida_mcp_session(host, port, connect_timeout, read_timeout)
                    )
                    tools = (await raw_session.list_tools()).tools
                    database_required = detect_database_requirement(tools)
                    if database_required:
                        listed = await raw_session.call_tool(name="idb_list", arguments={})
                        if getattr(listed, "isError", False):
                            raise McpToolCallError(
                                f"MCP tool idb_list failed: {_tool_result_error_text(listed)}"
                            )
                        payload = _tool_result_payload(listed) or {}
                        selected = select_database_session(
                            payload.get("sessions", []),
                            expected_binary=expected_binary,
                            explicit_database=explicit_database,
                        )
                        binding = McpDatabaseBinding(
                            True,
                            selected["session_id"],
                            selected.get("input_path"),
                            selected.get("backend"),
                            bool(selected.get("owned")),
                            auto_started,
                        )
                    else:
                        binding = McpDatabaseBinding(
                            False,
                            None,
                            str(expected_binary) if expected_binary else None,
                            "worker" if auto_started else None,
                            auto_started,
                            auto_started,
                        )
                except (McpContractError, McpDatabaseSelectionError, McpToolCallError):
                    raise
                except Exception as exc:
                    raise McpConnectionError(
                        f"unable to open IDA MCP session at {host}:{port}: {exc}"
                    ) from exc
                session_ready = True
                yield DatabaseBoundSession(raw_session, binding)
                return
        except Exception as exc:
            known_error = _find_mcp_error(exc)
            should_retry = (
                not session_ready
                and isinstance(known_error, McpDatabaseNotReadyError)
                and ready_deadline is not None
                and loop.time() < ready_deadline
            )
            if should_retry:
                retry_delay = min(
                    max(0.0, database_ready_retry_interval),
                    max(0.0, ready_deadline - loop.time()),
                )
                await asyncio.sleep(retry_delay)
                continue
            if known_error is not None and known_error is not exc:
                raise known_error from None
            raise
