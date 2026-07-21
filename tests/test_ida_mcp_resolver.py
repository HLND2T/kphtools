import unittest
from unittest.mock import AsyncMock

import ida_mcp_resolver


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


if __name__ == "__main__":
    unittest.main()
