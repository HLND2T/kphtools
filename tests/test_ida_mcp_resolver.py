import unittest
from unittest.mock import AsyncMock, patch

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
            type("Text", (), {"text": '{"result":"{\\"missing\\": \\"PspCreateProcessNotifyRoutine\\"}"}'})()
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

    def test_parse_llm_decompile_response_normalizes_found_entries(self) -> None:
        payload = ida_mcp_resolver.parse_llm_decompile_response(
            """
```yaml
found_call:
  - insn_va: '0x140010000'
    insn_disasm: call sub_140020000
    func_name: ExReferenceCallBackBlock
found_gv:
  - insn_va: '0x140010008'
    insn_disasm: mov rcx, cs:qword_140030000
    gv_name: PspCreateProcessNotifyRoutine
found_struct_offset:
  - insn_va: '0x140010010'
    insn_disasm: mov rcx, [r9+18h]
    offset: '0x18'
    struct_name: _ALPC_PORT
    member_name: OwnerProcess
```
            """
        )

        self.assertEqual(
            "ExReferenceCallBackBlock",
            payload["found_call"][0]["func_name"],
        )
        self.assertEqual(
            "PspCreateProcessNotifyRoutine",
            payload["found_gv"][0]["gv_name"],
        )
        self.assertEqual("0x18", payload["found_struct_offset"][0]["offset"])

    def test_parse_llm_decompile_response_extracts_fenced_yaml_from_prose(self) -> None:
        payload = ida_mcp_resolver.parse_llm_decompile_response(
            """
Here is the YAML:

```yaml
found_struct_offset:
  - insn_va: '0x140010010'
    insn_disasm: mov rcx, [r9+18h]
    offset: '0x18'
    size: 8
    struct_name: _ALPC_PORT
    member_name: OwnerProcess
```
            """
        )

        self.assertEqual(1, len(payload["found_struct_offset"]))
        self.assertEqual("8", payload["found_struct_offset"][0]["size"])
        self.assertEqual("_ALPC_PORT", payload["found_struct_offset"][0]["struct_name"])

    def test_parse_llm_decompile_response_preserves_struct_bit_offset(self) -> None:
        payload = ida_mcp_resolver.parse_llm_decompile_response(
            """
found_struct_offset:
  - insn_va: '0x140650EB4'
    insn_disasm: 'test    dword ptr [rcx+464h], 2000h'
    offset: '0x464'
    bit_offset: '13'
    struct_name: _EPROCESS
    member_name: BreakOnTerminationfound_struct_offset:
  - insn_va: '0x140650EB4'
    insn_disasm: 'test    dword ptr [rcx+464h], 2000h'
    offset: '0x464'
    bit_offset: '13'
    struct_name: _EPROCESS
    member_name: BreakOnTermination
            """
        )

        self.assertEqual(1, len(payload["found_struct_offset"]))
        self.assertEqual("13", payload["found_struct_offset"][0]["bit_offset"])

    def test_parse_llm_decompile_response_repairs_glued_top_level_header(self) -> None:
        payload = ida_mcp_resolver.parse_llm_decompile_response(
            """
found_struct_offset:
  - insn_va: '0x1406DE4E6'
    insn_disasm: 'and     qword ptr [rax], 0'
    offset: '0x0'
    struct_name: _ALPC_COMMUNICATION_INFO
    member_name: ConnectionPortfound_struct_offset:
  - insn_va: '0x1406DE376'
    insn_disasm: 'test    dword ptr [rcx+100h], 1000h'
    offset: '0x100'
    struct_name: _ALPC_PORT
    member_name: PortAttributes
  - insn_va: '0x1406DE4E6'
    insn_disasm: 'and     qword ptr [rax], 0'
    offset: '0x0'
    struct_name: _ALPC_COMMUNICATION_INFO
    member_name: ConnectionPort
            """
        )

        self.assertEqual(2, len(payload["found_struct_offset"]))
        self.assertEqual(
            "PortAttributes",
            payload["found_struct_offset"][0]["member_name"],
        )
        self.assertEqual(
            "ConnectionPort",
            payload["found_struct_offset"][1]["member_name"],
        )

    def test_llm_decompile_specs_require_four_tuple(self) -> None:
        self.assertIsNone(
            ida_mcp_resolver._build_llm_decompile_specs_map(
                [
                    (
                        "AlpcAttributes",
                        "prompt/call_llm_decompile.md",
                        "references/ntoskrnl/AlpcpOpenPort.amd64.yaml",
                    )
                ]
            )
        )

    async def test_call_llm_decompile_uses_cs2_prompt_template(self) -> None:
        prompt_template = (
            ida_mcp_resolver._get_preprocessor_scripts_dir()
            / "prompt"
            / "call_llm_decompile.md"
        ).read_text(encoding="utf-8")
        with patch.object(
            ida_mcp_resolver,
            "call_llm_text",
            AsyncMock(return_value="found_call: []\n"),
        ) as mock_call:
            await ida_mcp_resolver.call_llm_decompile(
                llm_config={"model": "test-model", "api_key": "test-key"},
                symbol_name_list=["ExReferenceCallBackBlock"],
                reference_items=[
                    {
                        "func_name": "Ref",
                        "disasm_code": "ref disasm",
                        "procedure": "ref proc",
                    }
                ],
                target_items=[
                    {
                        "func_name": "Target",
                        "disasm_code": "target disasm",
                        "procedure": "target proc",
                    }
                ],
                prompt_template=prompt_template,
            )

        prompt = mock_call.await_args.kwargs["prompt"]
        self.assertIn("These are the reference functions:", prompt)
        self.assertIn(
            'collect all references to "ExReferenceCallBackBlock"',
            prompt,
        )
        self.assertIn("ref disasm", prompt)
        self.assertIn("target proc", prompt)

    async def test_call_llm_decompile_debug_prints_prompt_and_raw_response(self) -> None:
        prompt_template = (
            ida_mcp_resolver._get_preprocessor_scripts_dir()
            / "prompt"
            / "call_llm_decompile.md"
        ).read_text(encoding="utf-8")
        with (
            patch.object(
                ida_mcp_resolver,
                "call_llm_text",
                AsyncMock(return_value="found_call: []\n"),
            ),
            patch("builtins.print") as mock_print,
        ):
            await ida_mcp_resolver.call_llm_decompile(
                llm_config={"model": "test-model", "api_key": "test-key"},
                symbol_name_list=["ExReferenceCallBackBlock"],
                reference_items=[
                    {
                        "func_name": "Ref",
                        "disasm_code": "ref disasm",
                        "procedure": "ref proc",
                    }
                ],
                target_items=[
                    {
                        "func_name": "Target",
                        "disasm_code": "target disasm",
                        "procedure": "target proc",
                    }
                ],
                prompt_template=prompt_template,
                debug=True,
            )

        output = "\n".join(
            " ".join(str(arg) for arg in call_args.args)
            for call_args in mock_print.call_args_list
        )
        self.assertIn(
            "BEGIN llm_decompile prompt for ExReferenceCallBackBlock",
            output,
        )
        self.assertIn('collect all references to "ExReferenceCallBackBlock"', output)
        self.assertIn("target disasm", output)
        self.assertIn(
            "BEGIN llm_decompile raw response for ExReferenceCallBackBlock",
            output,
        )
        self.assertIn("found_call: []", output)

    async def test_call_llm_decompile_renders_multiple_symbols(self) -> None:
        prompt_template = (
            ida_mcp_resolver._get_preprocessor_scripts_dir()
            / "prompt"
            / "call_llm_decompile.md"
        ).read_text(encoding="utf-8")
        with patch.object(
            ida_mcp_resolver,
            "call_llm_text",
            AsyncMock(return_value="found_struct_offset: []\n"),
        ) as mock_call:
            await ida_mcp_resolver.call_llm_decompile(
                llm_config={"model": "test-model", "api_key": "test-key"},
                symbol_name_list=[
                    "_ALPC_PORT->PortAttributes",
                    "_ALPC_PORT_ATTRIBUTES->Flags",
                ],
                reference_items=[
                    {
                        "func_name": "Ref",
                        "disasm_code": "ref disasm",
                        "procedure": "ref proc",
                    }
                ],
                target_items=[
                    {
                        "func_name": "Target",
                        "disasm_code": "target disasm",
                        "procedure": "target proc",
                    }
                ],
                prompt_template=prompt_template,
            )

        prompt = mock_call.await_args.kwargs["prompt"]
        self.assertIn(
            'collect all references to "_ALPC_PORT->PortAttributes, '
            '_ALPC_PORT_ATTRIBUTES->Flags"',
            prompt,
        )

    async def test_resolve_symbol_via_llm_decompile_uses_found_call(self) -> None:
        with (
            patch.object(
                ida_mcp_resolver,
                "_prepare_llm_decompile_request",
                return_value={
                    "prepared": True,
                    "llm_symbol_name": "ExReferenceCallBackBlock",
                },
            ),
            patch.object(
                ida_mcp_resolver,
                "call_llm_decompile",
                AsyncMock(
                    return_value={
                        "found_call": [
                            {
                                "insn_va": "0x140001000",
                                "insn_disasm": "call sub_140012340",
                                "func_name": "ExReferenceCallBackBlock",
                            }
                        ],
                        "found_gv": [],
                        "found_struct_offset": [],
                    }
                ),
            ),
            patch.object(
                ida_mcp_resolver,
                "_resolve_direct_call_target_via_mcp",
                AsyncMock(return_value=0x140012340),
            ),
        ):
            payload = await ida_mcp_resolver.resolve_symbol_via_llm_decompile(
                session=AsyncMock(),
                symbol_name="ExReferenceCallBackBlock",
                category="func",
                binary_dir="/tmp",
                image_base=0x140000000,
                llm_decompile_specs=[
                    (
                        "ExReferenceCallBackBlock",
                        "ExReferenceCallBackBlock",
                        "prompt/call_llm_decompile.md",
                        "references/ntoskrnl/Ref.{arch}.yaml",
                    )
                ],
                llm_config={"model": "test-model", "api_key": "test-key"},
            )

        self.assertEqual(
            {
                "func_name": "ExReferenceCallBackBlock",
                "func_va": 0x140012340,
                "func_rva": 0x12340,
            },
            payload,
        )

    async def test_resolve_symbol_via_llm_decompile_uses_found_gv(self) -> None:
        with (
            patch.object(
                ida_mcp_resolver,
                "_prepare_llm_decompile_request",
                return_value={
                    "prepared": True,
                    "llm_symbol_name": "PspCreateProcessNotifyRoutine",
                },
            ),
            patch.object(
                ida_mcp_resolver,
                "call_llm_decompile",
                AsyncMock(
                    return_value={
                        "found_call": [],
                        "found_gv": [
                            {
                                "insn_va": "0x140001008",
                                "insn_disasm": "mov rcx, cs:qword_140045678",
                                "gv_name": "PspCreateProcessNotifyRoutine",
                            }
                        ],
                        "found_struct_offset": [],
                    }
                ),
            ),
            patch.object(
                ida_mcp_resolver,
                "_resolve_direct_gv_target_via_mcp",
                AsyncMock(return_value=0x140045678),
            ),
        ):
            payload = await ida_mcp_resolver.resolve_symbol_via_llm_decompile(
                session=AsyncMock(),
                symbol_name="PspCreateProcessNotifyRoutine",
                category="gv",
                binary_dir="/tmp",
                image_base=0x140000000,
                llm_decompile_specs=[
                    (
                        "PspCreateProcessNotifyRoutine",
                        "PspCreateProcessNotifyRoutine",
                        "prompt/call_llm_decompile.md",
                        "references/ntoskrnl/Ref.{arch}.yaml",
                    )
                ],
                llm_config={"model": "test-model", "api_key": "test-key"},
            )

        self.assertEqual(
            {
                "gv_name": "PspCreateProcessNotifyRoutine",
                "gv_va": 0x140045678,
                "gv_rva": 0x45678,
            },
            payload,
        )

    async def test_resolve_symbol_via_llm_decompile_uses_found_struct_offset(self) -> None:
        with (
            patch.object(
                ida_mcp_resolver,
                "_prepare_llm_decompile_request",
                return_value={
                    "prepared": True,
                    "llm_symbol_name": "_ALPC_PORT->OwnerProcess",
                },
            ),
            patch.object(
                ida_mcp_resolver,
                "call_llm_decompile",
                AsyncMock(
                    return_value={
                        "found_call": [],
                        "found_gv": [],
                        "found_struct_offset": [
                            {
                                "insn_va": "0x140001010",
                                "insn_disasm": "mov rcx, [r9+18h]",
                                "offset": "0x18",
                                "struct_name": "_ALPC_PORT",
                                "member_name": "OwnerProcess",
                            }
                        ],
                    }
                ),
            ),
        ):
            payload = await ida_mcp_resolver.resolve_symbol_via_llm_decompile(
                session=AsyncMock(),
                symbol_name="AlpcOwnerProcess",
                category="struct_offset",
                binary_dir="/tmp",
                image_base=0x140000000,
                llm_decompile_specs=[
                    (
                        "AlpcOwnerProcess",
                        "_ALPC_PORT->OwnerProcess",
                        "prompt/call_llm_decompile.md",
                        "references/ntoskrnl/Ref.{arch}.yaml",
                    )
                ],
                llm_config={"model": "test-model", "api_key": "test-key"},
                struct_metadata={
                    "struct_name": "_ALPC_PORT",
                    "member_name": "OwnerProcess",
                },
            )

        self.assertEqual(
            {
                "struct_name": "_ALPC_PORT",
                "member_name": "OwnerProcess",
                "offset": 0x18,
            },
            payload,
        )

    async def test_resolve_symbol_via_llm_decompile_uses_found_struct_bit_offset(
        self,
    ) -> None:
        with (
            patch.object(
                ida_mcp_resolver,
                "_prepare_llm_decompile_request",
                return_value={
                    "prepared": True,
                    "llm_symbol_name": "_EPROCESS->BreakOnTermination",
                },
            ),
            patch.object(
                ida_mcp_resolver,
                "call_llm_decompile",
                AsyncMock(
                    return_value={
                        "found_call": [],
                        "found_gv": [],
                        "found_struct_offset": [
                            {
                                "insn_va": "0x140650EB4",
                                "insn_disasm": "test dword ptr [rcx+464h], 2000h",
                                "offset": "0x464",
                                "bit_offset": "13",
                                "struct_name": "_EPROCESS",
                                "member_name": "BreakOnTermination",
                            }
                        ],
                    }
                ),
            ),
        ):
            payload = await ida_mcp_resolver.resolve_symbol_via_llm_decompile(
                session=AsyncMock(),
                symbol_name="EpBreakOnTermination",
                category="struct_offset",
                binary_dir="/tmp",
                image_base=0x140000000,
                llm_decompile_specs=[
                    (
                        "EpBreakOnTermination",
                        "_EPROCESS->BreakOnTermination",
                        "prompt/call_llm_decompile.md",
                        "references/ntoskrnl/PspTerminateAllThreads.{arch}.yaml",
                    )
                ],
                llm_config={"model": "test-model", "api_key": "test-key"},
                struct_metadata={
                    "struct_name": "_EPROCESS",
                    "member_name": "BreakOnTermination",
                    "bits": True,
                },
            )

        self.assertEqual(
            {
                "struct_name": "_EPROCESS",
                "member_name": "BreakOnTermination",
                "offset": 0x464,
                "bit_offset": 13,
            },
            payload,
        )

    async def test_resolve_symbol_via_llm_decompile_uses_spec_query_name(self) -> None:
        with (
            patch.object(
                ida_mcp_resolver,
                "_load_llm_decompile_target_details_via_mcp",
                AsyncMock(
                    return_value=[
                        {
                            "func_name": "AlpcpDeletePort",
                            "func_va": "0x1406df5c0",
                            "disasm_code": "target disasm",
                            "procedure": "target proc",
                        }
                    ]
                ),
            ),
            patch.object(
                ida_mcp_resolver,
                "call_llm_decompile",
                AsyncMock(
                    return_value={
                        "found_call": [],
                        "found_gv": [],
                        "found_struct_offset": [
                            {
                                "insn_va": "0x140001010",
                                "insn_disasm": "test dword ptr [r9+100h], 100000h",
                                "offset": "0x100",
                                "struct_name": "_ALPC_PORT",
                                "member_name": "PortAttributes",
                            }
                        ],
                    }
                ),
            ) as mock_call,
        ):
            payload = await ida_mcp_resolver.resolve_symbol_via_llm_decompile(
                session=AsyncMock(),
                symbol_name="AlpcAttributes",
                category="struct_offset",
                binary_dir="/tmp/amd64/ntoskrnl",
                image_base=0x140000000,
                llm_decompile_specs=[
                    (
                        "AlpcAttributes",
                        "_ALPC_PORT->PortAttributes",
                        "prompt/call_llm_decompile.md",
                        "references/ntoskrnl/AlpcpDeletePort.{arch}.yaml",
                    )
                ],
                llm_config={"model": "test-model", "api_key": "test-key"},
                struct_metadata={
                    "struct_name": "_ALPC_PORT",
                    "member_name": "PortAttributes",
                },
            )

        self.assertEqual(
            {
                "struct_name": "_ALPC_PORT",
                "member_name": "PortAttributes",
                "offset": 0x100,
            },
            payload,
        )
        self.assertEqual(
            ["_ALPC_PORT->PortAttributes"],
            mock_call.await_args.kwargs["symbol_name_list"],
        )

    async def test_resolve_symbol_via_llm_decompile_batches_same_request_group(
        self,
    ) -> None:
        ida_mcp_resolver._LLM_DECOMPILE_RESULT_CACHE.clear()
        llm_specs = [
            (
                "AlpcAttributes",
                "_ALPC_PORT->PortAttributes",
                "prompt/call_llm_decompile.md",
                "references/ntoskrnl/AlpcpDeletePort.{arch}.yaml",
            ),
            (
                "AlpcAttributesFlags",
                "_ALPC_PORT_ATTRIBUTES->Flags",
                "prompt/call_llm_decompile.md",
                "references/ntoskrnl/AlpcpDeletePort.{arch}.yaml",
            ),
            (
                "AlpcCommunicationInfo",
                "_ALPC_PORT->CommunicationInfo",
                "prompt/call_llm_decompile.md",
                "references/ntoskrnl/AlpcpDeletePort.{arch}.yaml",
            ),
        ]
        llm_result = {
            "found_call": [],
            "found_gv": [],
            "found_struct_offset": [
                {
                    "insn_va": "0x140001010",
                    "insn_disasm": "test dword ptr [r9+100h], 100000h",
                    "offset": "0x100",
                    "struct_name": "_ALPC_PORT",
                    "member_name": "PortAttributes",
                },
                {
                    "insn_va": "0x140001020",
                    "insn_disasm": "test dword ptr [rax+10h], 1",
                    "offset": "0x10",
                    "struct_name": "_ALPC_PORT_ATTRIBUTES",
                    "member_name": "Flags",
                },
                {
                    "insn_va": "0x140001030",
                    "insn_disasm": "mov rcx, [rdi+10h]",
                    "offset": "0x10",
                    "struct_name": "_ALPC_PORT",
                    "member_name": "CommunicationInfo",
                },
            ],
        }
        with (
            patch.object(
                ida_mcp_resolver,
                "_load_llm_decompile_target_details_via_mcp",
                AsyncMock(
                    return_value=[
                        {
                            "func_name": "AlpcpDeletePort",
                            "func_va": "0x1406df5c0",
                            "disasm_code": "target disasm",
                            "procedure": "target proc",
                        }
                    ]
                ),
            ),
            patch.object(
                ida_mcp_resolver,
                "call_llm_decompile",
                AsyncMock(return_value=llm_result),
            ) as mock_call,
        ):
            attributes_payload = await ida_mcp_resolver.resolve_symbol_via_llm_decompile(
                session=AsyncMock(),
                symbol_name="AlpcAttributes",
                category="struct_offset",
                binary_dir="/tmp/kphtools-test-batch/amd64",
                image_base=0x140000000,
                llm_decompile_specs=llm_specs,
                llm_config={"model": "test-model", "api_key": "test-key"},
                struct_metadata={
                    "struct_name": "_ALPC_PORT",
                    "member_name": "PortAttributes",
                },
            )
            flags_payload = await ida_mcp_resolver.resolve_symbol_via_llm_decompile(
                session=AsyncMock(),
                symbol_name="AlpcAttributesFlags",
                category="struct_offset",
                binary_dir="/tmp/kphtools-test-batch/amd64",
                image_base=0x140000000,
                llm_decompile_specs=llm_specs,
                llm_config={"model": "test-model", "api_key": "test-key"},
                struct_metadata={
                    "struct_name": "_ALPC_PORT_ATTRIBUTES",
                    "member_name": "Flags",
                },
            )
            communication_info_payload = (
                await ida_mcp_resolver.resolve_symbol_via_llm_decompile(
                    session=AsyncMock(),
                    symbol_name="AlpcCommunicationInfo",
                    category="struct_offset",
                    binary_dir="/tmp/kphtools-test-batch/amd64",
                    image_base=0x140000000,
                    llm_decompile_specs=llm_specs,
                    llm_config={"model": "test-model", "api_key": "test-key"},
                    struct_metadata={
                        "struct_name": "_ALPC_PORT",
                        "member_name": "CommunicationInfo",
                    },
                )
            )

        self.assertEqual(
            {
                "struct_name": "_ALPC_PORT",
                "member_name": "PortAttributes",
                "offset": 0x100,
            },
            attributes_payload,
        )
        self.assertEqual(
            {
                "struct_name": "_ALPC_PORT_ATTRIBUTES",
                "member_name": "Flags",
                "offset": 0x10,
            },
            flags_payload,
        )
        self.assertEqual(
            {
                "struct_name": "_ALPC_PORT",
                "member_name": "CommunicationInfo",
                "offset": 0x10,
            },
            communication_info_payload,
        )
        mock_call.assert_awaited_once()
        self.assertEqual(
            [
                "_ALPC_PORT->PortAttributes",
                "_ALPC_PORT_ATTRIBUTES->Flags",
                "_ALPC_PORT->CommunicationInfo",
            ],
            mock_call.await_args.kwargs["symbol_name_list"],
        )
        ida_mcp_resolver._LLM_DECOMPILE_RESULT_CACHE.clear()
