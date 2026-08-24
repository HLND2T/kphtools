import unittest
from unittest.mock import AsyncMock, patch

import ida_mcp_resolver
from ida_llm_targets import ReferenceResolution, ReferenceResolutionStatus
from ida_mcp_session import McpDatabaseUnavailableError


class TestIdaMcpResolver(unittest.IsolatedAsyncioTestCase):
    async def test_resolve_public_name_via_mcp_returns_rva(self) -> None:
        symbol_name = "PspCreateProcessNotifyRoutine"
        image_base = 0x140000000
        session = AsyncMock()
        session.call_tool.return_value.content = [
            type("Text", (), {"text": '{"result":"{\\"rva\\": \\"0x45678\\"}"}'})()
        ]

        payload = await ida_mcp_resolver.resolve_public_name_via_mcp(
            session,
            symbol_name=symbol_name,
            image_base=image_base,
        )

        session.call_tool.assert_awaited_once()
        tool_name, tool_payload = session.call_tool.await_args.args
        py_code = tool_payload["code"]
        self.assertEqual("py_eval", tool_name)
        self.assertEqual(symbol_name, payload["name"])
        self.assertEqual(0x45678, payload["rva"])
        self.assertIn(repr(symbol_name), py_code)
        self.assertIn(str(image_base), py_code)
        self.assertRegex(py_code, r"get_name_ea_simple|get_name_ea")
        self.assertIn("ea - image_base", py_code)
        self.assertNotIn("0x45678", py_code)

    async def test_resolve_public_name_via_mcp_raises_key_error_on_miss(self) -> None:
        symbol_name = "PspCreateProcessNotifyRoutine"
        session = AsyncMock()
        session.call_tool.return_value.content = [
            type(
                "Text",
                (),
                {
                    "text": '{"result":"{\\"missing\\": '
                    '\\"PspCreateProcessNotifyRoutine\\"}"}'
                },
            )()
        ]

        with self.assertRaises(KeyError) as ctx:
            await ida_mcp_resolver.resolve_public_name_via_mcp(
                session,
                symbol_name=symbol_name,
                image_base=0x140000000,
            )

        self.assertEqual(symbol_name, ctx.exception.args[0])

    async def test_resolve_public_name_via_mcp_raises_on_invalid_result(self) -> None:
        session = AsyncMock()
        session.call_tool.return_value.content = [
            type("Text", (), {"text": '{"result":"{}"}'})()
        ]

        with self.assertRaises(ValueError):
            await ida_mcp_resolver.resolve_public_name_via_mcp(
                session,
                symbol_name="PspCreateProcessNotifyRoutine",
                image_base=0x140000000,
            )

    async def test_function_result_tries_next_candidate_after_no_match(self) -> None:
        result = {
            "found_call": [
                {"insn_va": "0x1000", "func_name": "Target"},
            ],
            "found_funcptr": [
                {"insn_va": "0x1010", "funcptr_name": "Target"},
            ],
        }
        direct_call = AsyncMock(
            return_value=ReferenceResolution(
                status=ReferenceResolutionStatus.NO_MATCH,
            )
        )
        funcptr = AsyncMock(
            return_value=ReferenceResolution(
                status=ReferenceResolutionStatus.SUCCESS,
                address=0x140002000,
                matches=(0x140002000,),
            )
        )

        with (
            patch.object(
                ida_mcp_resolver,
                "_resolve_direct_call_target_via_mcp",
                direct_call,
            ),
            patch.object(
                ida_mcp_resolver,
                "_resolve_funcptr_target_via_mcp",
                funcptr,
            ),
        ):
            payload = await ida_mcp_resolver._consume_function_result(
                AsyncMock(),
                result,
                "Target",
                "Target",
                0x140000000,
                debug=True,
            )

        self.assertEqual(0x2000, payload["func_rva"])
        direct_call.assert_awaited_once()
        funcptr.assert_awaited_once()

    async def test_function_result_reraises_transport_error(self) -> None:
        transport_error = McpDatabaseUnavailableError("worker unavailable")
        resolution = ReferenceResolution(
            status=ReferenceResolutionStatus.TRANSPORT_ERROR,
            error=transport_error,
            detail="MCP call failed",
        )
        result = {
            "found_call": [
                {"insn_va": "0x1000", "func_name": "Target"},
            ],
        }

        with patch.object(
            ida_mcp_resolver,
            "_resolve_direct_call_target_via_mcp",
            AsyncMock(return_value=resolution),
        ):
            with self.assertRaises(McpDatabaseUnavailableError) as context:
                await ida_mcp_resolver._consume_function_result(
                    AsyncMock(),
                    result,
                    "Target",
                    "Target",
                    0x140000000,
                    debug=True,
                )

        self.assertIs(transport_error, context.exception)


if __name__ == "__main__":
    unittest.main()
