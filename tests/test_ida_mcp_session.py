from __future__ import annotations

import ast
from contextlib import asynccontextmanager
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

import ida_mcp_session
from ida_mcp_session import (
    DatabaseBoundSession,
    McpConnectionError,
    McpContractError,
    McpDatabaseBinding,
    McpDatabaseSelectionError,
    McpDatabaseUnavailableError,
    McpToolCallError,
    detect_database_requirement,
    normalize_binary_identity_path,
    open_ida_mcp_session,
    select_database_session,
)


ACTIVE_SERVER = {
    "session_id": "server-db",
    "input_path": r"D:\repo\tests\bin\ida-mcp-smoke.dll.i64",
    "backend": "worker",
    "owned": True,
    "is_active": True,
}
ACTIVE_ENGINE = {
    "session_id": "engine-db",
    "input_path": r"D:\repo\tests\bin\engine2.dll.i64",
    "backend": "worker",
    "owned": False,
    "is_active": True,
}


@asynccontextmanager
async def _async_context(value):
    yield value


def _tool_result(payload: dict) -> SimpleNamespace:
    return SimpleNamespace(isError=False, content=[], structuredContent=payload)


class TestNormalizeBinaryIdentityPath(unittest.TestCase):
    def test_normalizes_database_suffix_and_windows_case(self) -> None:
        self.assertEqual(
            "d:/repo/bin/server/server.dll",
            normalize_binary_identity_path(r"D:\Repo\bin\server\server.dll.i64"),
        )

    def test_normalizes_wsl_mount_path(self) -> None:
        self.assertEqual(
            "d:/repo/bin/server/libserver.so",
            normalize_binary_identity_path("/mnt/d/repo/bin/server/libserver.so.idb"),
        )


class TestDetectDatabaseRequirement(unittest.TestCase):
    def test_legacy_worker_schema_does_not_require_database(self) -> None:
        tools = [SimpleNamespace(name="py_eval", inputSchema={"required": ["code"]})]

        self.assertFalse(detect_database_requirement(tools))

    def test_supervisor_worker_schema_requires_database(self) -> None:
        tools = [
            SimpleNamespace(name="py_eval", inputSchema={"required": ["code", "database"]}),
            SimpleNamespace(name="find_bytes", inputSchema={"required": ["patterns", "database"]}),
        ]

        self.assertTrue(detect_database_requirement(tools))

    def test_mixed_worker_contract_is_rejected(self) -> None:
        tools = [
            SimpleNamespace(name="py_eval", inputSchema={"required": ["code", "database"]}),
            SimpleNamespace(name="find_bytes", inputSchema={"required": ["patterns"]}),
        ]

        with self.assertRaisesRegex(McpContractError, "inconsistent database requirement"):
            detect_database_requirement(tools)


class TestSelectDatabaseSession(unittest.TestCase):
    def test_explicit_database_has_priority(self) -> None:
        selected = select_database_session(
            [ACTIVE_SERVER, ACTIVE_ENGINE],
            expected_binary=r"D:\repo\tests\bin\ida-mcp-smoke.dll",
            explicit_database="engine-db",
        )

        self.assertEqual("engine-db", selected["session_id"])

    def test_expected_binary_matches_ida_database_suffix(self) -> None:
        selected = select_database_session(
            [ACTIVE_SERVER, ACTIVE_ENGINE],
            expected_binary=r"D:\repo\tests\bin\ida-mcp-smoke.dll",
        )

        self.assertEqual("server-db", selected["session_id"])

    def test_matching_inactive_database_is_reported_as_unavailable(self) -> None:
        inactive_server = {
            **ACTIVE_SERVER,
            "is_active": False,
            "pid": 321,
            "worker_pid": 654,
        }

        with self.assertRaisesRegex(
            McpDatabaseUnavailableError,
            r"inactive or unreachable.*pid=321.*worker_pid=654",
        ):
            select_database_session(
                [inactive_server],
                expected_binary=r"D:\repo\tests\bin\ida-mcp-smoke.dll",
            )

    def test_explicit_inactive_database_is_reported_as_unavailable(self) -> None:
        inactive_server = {**ACTIVE_SERVER, "is_active": False}

        with self.assertRaisesRegex(McpDatabaseUnavailableError, "inactive or unreachable"):
            select_database_session(
                [inactive_server],
                explicit_database="server-db",
            )

    def test_single_active_routable_session_is_selected(self) -> None:
        selected = select_database_session([ACTIVE_SERVER])

        self.assertEqual("server-db", selected["session_id"])

    def test_multiple_sessions_without_selector_fail_closed(self) -> None:
        with self.assertRaisesRegex(McpDatabaseSelectionError, "multiple active MCP databases"):
            select_database_session([ACTIVE_SERVER, ACTIVE_ENGINE])

    def test_empty_session_id_is_not_routable(self) -> None:
        discovered = {**ACTIVE_SERVER, "session_id": "", "owned": False}

        with self.assertRaisesRegex(McpDatabaseSelectionError, "no active routable MCP database"):
            select_database_session([discovered])


class TestDatabaseBoundSession(unittest.IsolatedAsyncioTestCase):
    async def test_injects_database_for_worker_tool(self) -> None:
        raw = MagicMock()
        raw.call_tool = AsyncMock(return_value=_tool_result({"ok": True}))
        bound = DatabaseBoundSession(
            raw,
            McpDatabaseBinding(True, "server-db", "server.dll", "worker", True, True),
        )

        result = await bound.call_tool("py_eval", {"code": "1"})

        self.assertEqual({"ok": True}, result.structuredContent)
        raw.call_tool.assert_awaited_once_with(
            name="py_eval",
            arguments={"code": "1", "database": "server-db"},
        )

    async def test_management_tool_is_not_modified(self) -> None:
        raw = MagicMock()
        raw.call_tool = AsyncMock(return_value=_tool_result({}))
        bound = DatabaseBoundSession(
            raw,
            McpDatabaseBinding(True, "server-db", "server.dll", "worker", True, True),
        )

        await bound.call_tool("idb_list", {})

        raw.call_tool.assert_awaited_once_with(name="idb_list", arguments={})

    async def test_conflicting_database_is_rejected(self) -> None:
        raw = MagicMock()
        raw.call_tool = AsyncMock()
        bound = DatabaseBoundSession(
            raw,
            McpDatabaseBinding(True, "server-db", "server.dll", "worker", True, True),
        )

        with self.assertRaisesRegex(McpDatabaseSelectionError, "conflicts with bound database"):
            await bound.call_tool("py_eval", {"code": "1", "database": "engine-db"})

        raw.call_tool.assert_not_awaited()

    async def test_server_is_error_becomes_typed_exception(self) -> None:
        raw = MagicMock()
        raw.call_tool = AsyncMock(
            return_value=SimpleNamespace(
                isError=True,
                structuredContent=None,
                content=[SimpleNamespace(text='{"error":"database is required"}')],
            )
        )
        bound = DatabaseBoundSession(
            raw,
            McpDatabaseBinding(False, None, None, "worker", True, True),
        )

        with self.assertRaisesRegex(McpToolCallError, "py_eval.*database is required"):
            await bound.call_tool("py_eval", {"code": "1"})


class TestOpenIdaMcpSession(unittest.IsolatedAsyncioTestCase):
    async def test_legacy_contract_does_not_list_databases(self) -> None:
        raw = MagicMock()
        raw.initialize = AsyncMock()
        raw.list_tools = AsyncMock(
            return_value=SimpleNamespace(
                tools=[SimpleNamespace(name="py_eval", inputSchema={"required": ["code"]})]
            )
        )
        raw.call_tool = AsyncMock()
        http_client = MagicMock()
        streamable_client = MagicMock(return_value=_async_context(("read", "write", lambda: None)))

        with (
            patch("ida_mcp_session.httpx.AsyncClient", return_value=_async_context(http_client)),
            patch("ida_mcp_session.streamable_http_client", streamable_client),
            patch("ida_mcp_session.ClientSession", return_value=_async_context(raw)),
        ):
            async with open_ida_mcp_session("127.0.0.1", 13337, auto_started=True) as session:
                self.assertFalse(session.binding.database_required)
                self.assertTrue(session.binding.owned)
                self.assertEqual("worker", session.binding.backend)

        raw.call_tool.assert_not_awaited()
        streamable_client.assert_called_once_with(
            "http://127.0.0.1:13337/mcp",
            http_client=http_client,
            terminate_on_close=False,
        )

    async def test_supervisor_contract_selects_expected_database(self) -> None:
        raw = MagicMock()
        raw.initialize = AsyncMock()
        raw.list_tools = AsyncMock(
            return_value=SimpleNamespace(
                tools=[
                    SimpleNamespace(
                        name="py_eval",
                        inputSchema={"required": ["code", "database"]},
                    )
                ]
            )
        )
        raw.call_tool = AsyncMock(return_value=_tool_result({"sessions": [ACTIVE_SERVER]}))

        with (
            patch("ida_mcp_session.httpx.AsyncClient", return_value=_async_context(MagicMock())),
            patch(
                "ida_mcp_session.streamable_http_client",
                return_value=_async_context(("read", "write", lambda: None)),
            ),
            patch("ida_mcp_session.ClientSession", return_value=_async_context(raw)),
        ):
            async with open_ida_mcp_session(
                "127.0.0.1",
                13337,
                expected_binary=r"D:\repo\tests\bin\ida-mcp-smoke.dll",
                auto_started=True,
            ) as session:
                self.assertTrue(session.binding.database_required)
                self.assertEqual("server-db", session.binding.session_id)
                self.assertTrue(session.binding.owned)
                self.assertEqual("worker", session.binding.backend)

        raw.call_tool.assert_awaited_once_with(name="idb_list", arguments={})

    async def test_supervisor_reports_inactive_database_without_retry(self) -> None:
        raw = MagicMock()
        raw.list_tools = AsyncMock(
            return_value=SimpleNamespace(
                tools=[
                    SimpleNamespace(
                        name="py_eval",
                        inputSchema={"required": ["code", "database"]},
                    )
                ]
            )
        )
        inactive_server = {**ACTIVE_SERVER, "is_active": False}
        raw.call_tool = AsyncMock(
            return_value=_tool_result({"sessions": [inactive_server]})
        )

        with patch(
            "ida_mcp_session._open_raw_ida_mcp_session",
            return_value=_async_context(raw),
        ) as open_raw_session:
            with self.assertRaisesRegex(
                McpDatabaseUnavailableError,
                "inactive or unreachable",
            ):
                async with open_ida_mcp_session(
                    "127.0.0.1",
                    13337,
                    expected_binary=r"D:\repo\tests\bin\ida-mcp-smoke.dll",
                ):
                    self.fail("inactive database must fail before yielding a session")

        open_raw_session.assert_called_once()
        raw.call_tool.assert_awaited_once_with(name="idb_list", arguments={})

    async def test_selection_error_is_not_wrapped_by_transport_shutdown(self) -> None:
        raw = MagicMock()
        raw.list_tools = AsyncMock(
            return_value=SimpleNamespace(
                tools=[
                    SimpleNamespace(
                        name="py_eval",
                        inputSchema={"required": ["code", "database"]},
                    )
                ]
            )
        )
        raw.call_tool = AsyncMock(return_value=_tool_result({"sessions": [ACTIVE_SERVER, ACTIVE_ENGINE]}))

        with patch("ida_mcp_session._open_raw_ida_mcp_session", return_value=_async_context(raw)):
            with self.assertRaisesRegex(McpDatabaseSelectionError, "multiple active MCP databases"):
                async with open_ida_mcp_session("127.0.0.1", 13337):
                    self.fail("database selection must fail before yielding a session")

    async def test_transport_errors_are_wrapped(self) -> None:
        with patch("ida_mcp_session.httpx.AsyncClient", side_effect=RuntimeError("offline")):
            with self.assertRaisesRegex(McpConnectionError, "unable to open IDA MCP session.*offline"):
                async with open_ida_mcp_session("127.0.0.1", 13337):
                    self.fail("transport error must fail before yielding a session")

    async def test_session_body_errors_are_not_wrapped_as_connection_errors(self) -> None:
        raw = MagicMock()
        raw.initialize = AsyncMock()
        raw.list_tools = AsyncMock(
            return_value=SimpleNamespace(
                tools=[SimpleNamespace(name="py_eval", inputSchema={"required": ["code"]})]
            )
        )

        with (
            patch("ida_mcp_session.httpx.AsyncClient", return_value=_async_context(MagicMock())),
            patch(
                "ida_mcp_session.streamable_http_client",
                return_value=_async_context(("read", "write", lambda: None)),
            ),
            patch("ida_mcp_session.ClientSession", return_value=_async_context(raw)),
        ):
            with self.assertRaises(RuntimeError) as raised:
                async with open_ida_mcp_session("127.0.0.1", 13337):
                    raise RuntimeError("session body failure")

        self.assertIs(RuntimeError, type(raised.exception))
        self.assertEqual("session body failure", str(raised.exception))


class TestMcpSessionBoundary(unittest.TestCase):
    def test_only_adapter_creates_raw_mcp_sessions(self) -> None:
        violations = []
        repo_root = Path(__file__).resolve().parents[1]
        for path in repo_root.rglob("*.py"):
            if any(part in {"tests", ".venv", "bin", ".git", "thirdparty"} for part in path.parts):
                continue
            if path.name == "ida_mcp_session.py":
                continue
            tree = ast.parse(path.read_text(encoding="utf-8-sig"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.module in {
                    "mcp",
                    "mcp.client.streamable_http",
                }:
                    names = {alias.name for alias in node.names}
                    if names & {"ClientSession", "streamable_http_client"}:
                        violations.append(f"{path}:{node.lineno}")

        self.assertEqual([], violations)
