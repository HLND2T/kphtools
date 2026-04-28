import asyncio
import unittest
from unittest.mock import AsyncMock, patch

import ida_mcp_resolver


class TestIdaMcpResolver(unittest.IsolatedAsyncioTestCase):
    async def test_resolve_public_name_via_mcp_returns_rva(self) -> None:
        session = AsyncMock()
        session.call_tool.return_value.content = [
            type("Text", (), {"text": '{"result":"{\\"rva\\": \\"0x45678\\"}"}'})()
        ]

        payload = await ida_mcp_resolver.resolve_public_name_via_mcp(
            session,
            symbol_name="PspCreateProcessNotifyRoutine",
            image_base=0x140000000,
        )

        self.assertEqual(0x45678, payload["rva"])

    async def test_llm_struct_offset_parser_returns_offset(self) -> None:
        with patch.object(
            ida_mcp_resolver,
            "call_llm_text",
            AsyncMock(return_value="offset: 0x570\n"),
        ):
            payload = await ida_mcp_resolver.resolve_struct_offset_via_llm(
                llm_config={"model": "gpt-4o"},
                reference_blocks=["ref"],
                target_blocks=["target"],
            )

        self.assertEqual(0x570, payload["offset"])
