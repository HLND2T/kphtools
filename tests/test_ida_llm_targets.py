import json
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import yaml

import ida_llm_targets


class TestIdaLlmTargets(unittest.IsolatedAsyncioTestCase):
    async def _resolve_funcptr_with_fake_ida(
        self,
        *,
        drefs=(),
        operand_types=(1, 2),
        operand_values=(0, 0x140001000),
        valid_segment_targets=None,
        loaded_targets=None,
        code_targets=None,
        function_starts=None,
    ):
        all_targets = {
            int(target)
            for target in (*drefs, *operand_values)
            if int(target) not in {0, -1}
        }
        if valid_segment_targets is None:
            valid_segment_targets = set(all_targets)
        if loaded_targets is None:
            loaded_targets = set(all_targets)
        if code_targets is None:
            code_targets = set(all_targets)
        if function_starts is None:
            function_starts = {target: target for target in all_targets}

        fake_modules = {
            "ida_bytes": SimpleNamespace(
                get_flags=lambda target_ea: int(target_ea),
                is_code=lambda flags: int(flags) in code_targets,
                is_loaded=lambda target_ea: int(target_ea) in loaded_targets,
            ),
            "ida_funcs": SimpleNamespace(
                get_func=lambda target_ea: (
                    SimpleNamespace(start_ea=function_starts[int(target_ea)])
                    if int(target_ea) in function_starts
                    else None
                ),
            ),
            "ida_segment": SimpleNamespace(
                getseg=lambda target_ea: (
                    SimpleNamespace()
                    if int(target_ea) in valid_segment_targets
                    else None
                ),
            ),
            "ida_ua": SimpleNamespace(
                o_void=0,
                o_reg=1,
                o_mem=2,
                o_phrase=3,
                o_displ=4,
                o_imm=5,
                o_far=6,
                o_near=7,
                insn_t=lambda: SimpleNamespace(
                    ops=[
                        *(SimpleNamespace(type=operand_type) for operand_type in operand_types),
                        SimpleNamespace(type=0),
                    ]
                ),
                decode_insn=lambda _insn, _ea: 7,
            ),
            "idautils": SimpleNamespace(
                DataRefsFrom=lambda _insn_ea: list(drefs),
            ),
            "idc": SimpleNamespace(
                BADADDR=-1,
                get_operand_value=lambda _insn_ea, op_index: operand_values[op_index],
            ),
        }

        async def call_tool(_name, arguments):
            namespace = {}
            with patch.dict(sys.modules, fake_modules):
                exec(arguments["code"], namespace)
            return SimpleNamespace(
                content=[
                    SimpleNamespace(
                        text=json.dumps({"result": namespace["result"]}),
                    )
                ]
            )

        session = AsyncMock()
        session.call_tool.side_effect = call_tool
        resolution = await ida_llm_targets.resolve_funcptr_target_via_mcp(
            session,
            "0x140000100",
        )
        return resolution, session.call_tool.await_args.args[1]["code"]

    async def test_loads_function_target_from_artifact(self) -> None:
        with TemporaryDirectory() as temp_dir:
            Path(temp_dir, "Target.yaml").write_text(
                yaml.safe_dump({"func_rva": "0x1234"}),
                encoding="utf-8",
            )
            with patch.object(
                ida_llm_targets,
                "_export_function_detail_via_mcp",
                AsyncMock(return_value={"func_name": "Target", "func_va": "0x140001234", "disasm_code": "x", "procedure": ""}),
            ) as export:
                result = await ida_llm_targets.load_llm_decompile_target_details_via_mcp(
                    AsyncMock(),
                    ["Target"],
                    binary_dir=temp_dir,
                    image_base=0x140000000,
                )
        self.assertEqual("Target", result[0]["func_name"])
        self.assertEqual(0x140001234, export.await_args.args[2])

    async def test_loads_code_region_target(self) -> None:
        with TemporaryDirectory() as temp_dir:
            Path(temp_dir, "Region.yaml").write_text(
                yaml.safe_dump({"category": "code", "code_rva": "0x2000", "code_size": "0x30"}),
                encoding="utf-8",
            )
            with patch.object(
                ida_llm_targets,
                "_export_code_region_detail_via_mcp",
                AsyncMock(return_value={"func_name": "Region", "func_va": "0x140002000", "disasm_code": "x", "procedure": ""}),
            ) as export:
                result = await ida_llm_targets.load_llm_decompile_target_details_via_mcp(
                    AsyncMock(),
                    ["Region"],
                    binary_dir=temp_dir,
                    image_base=0x140000000,
                )
        self.assertEqual("Region", result[0]["func_name"])
        self.assertEqual((0x140002000, 0x30), export.await_args.args[2:4])

    def test_required_target_check_allows_missing_optional(self) -> None:
        items = [{"func_name": "Required"}]
        self.assertTrue(ida_llm_targets.has_all_required_target_details(items, ["Required"]))
        self.assertFalse(ida_llm_targets.has_all_required_target_details(items, ["Required", "Missing"]))

    async def test_funcptr_requires_unique_function_start(self) -> None:
        session = AsyncMock()
        session.call_tool.return_value.content = [
            type(
                "Text",
                (),
                {"text": '{"result":"{\\"matches\\":[\\"0x140001000\\",\\"0x140002000\\"]}"}'},
            )()
        ]
        result = await ida_llm_targets.resolve_funcptr_target_via_mcp(
            session,
            "0x140000100",
        )
        self.assertEqual(
            ida_llm_targets.ReferenceResolutionStatus.AMBIGUOUS,
            result.status,
        )
        self.assertIsNone(result.address)
        self.assertEqual((0x140001000, 0x140002000), result.matches)
        code = session.call_tool.await_args.args[1]["code"]
        self.assertIn("int(func.start_ea) == int(target_ea)", code)

    async def test_funcptr_uses_valid_direct_operand_when_data_xref_is_missing(
        self,
    ) -> None:
        result, _code = await self._resolve_funcptr_with_fake_ida()

        self.assertEqual(
            ida_llm_targets.ReferenceResolutionStatus.SUCCESS,
            result.status,
        )
        self.assertEqual(0x140001000, result.address)
        self.assertEqual((0x140001000,), result.matches)

    async def test_funcptr_rejects_unsafe_operand_types(self) -> None:
        for operand_type in (3, 4, 5):
            with self.subTest(operand_type=operand_type):
                result, _code = await self._resolve_funcptr_with_fake_ida(
                    operand_types=(1, operand_type),
                )

                self.assertEqual(
                    ida_llm_targets.ReferenceResolutionStatus.NO_MATCH,
                    result.status,
                )

    async def test_funcptr_rejects_invalid_operand_targets(self) -> None:
        target_ea = 0x140001000
        invalid_cases = {
            "no_segment": {"valid_segment_targets": set()},
            "not_loaded": {"loaded_targets": set()},
            "not_code": {"code_targets": set()},
            "not_function_start": {
                "function_starts": {target_ea: target_ea - 0x10},
            },
        }
        for case_name, kwargs in invalid_cases.items():
            with self.subTest(case_name=case_name):
                result, _code = await self._resolve_funcptr_with_fake_ida(**kwargs)

                self.assertEqual(
                    ida_llm_targets.ReferenceResolutionStatus.NO_MATCH,
                    result.status,
                )

    async def test_funcptr_merges_xref_and_operand_candidates_before_uniqueness_check(
        self,
    ) -> None:
        result, _code = await self._resolve_funcptr_with_fake_ida(
            drefs=(0x140002000,),
        )

        self.assertEqual(
            ida_llm_targets.ReferenceResolutionStatus.AMBIGUOUS,
            result.status,
        )
        self.assertEqual((0x140001000, 0x140002000), result.matches)

    async def test_funcptr_deduplicates_matching_xref_and_operand_candidates(
        self,
    ) -> None:
        result, _code = await self._resolve_funcptr_with_fake_ida(
            drefs=(0x140001000,),
        )

        self.assertEqual(
            ida_llm_targets.ReferenceResolutionStatus.SUCCESS,
            result.status,
        )
        self.assertEqual((0x140001000,), result.matches)

    async def test_reference_resolution_returns_success_with_unique_match(self) -> None:
        session = AsyncMock()
        session.call_tool.return_value.content = [
            type(
                "Text",
                (),
                {"text": '{"result":"{\\"matches\\":[\\"0x140001000\\"]}"}'},
            )()
        ]

        result = await ida_llm_targets.resolve_funcptr_target_via_mcp(
            session,
            "0x140000100",
        )

        self.assertEqual(
            ida_llm_targets.ReferenceResolutionStatus.SUCCESS,
            result.status,
        )
        self.assertEqual(0x140001000, result.address)
        self.assertEqual((0x140001000,), result.matches)

    async def test_reference_resolution_distinguishes_no_match(self) -> None:
        session = AsyncMock()
        session.call_tool.return_value.content = [
            type("Text", (), {"text": '{"result":"{\\"matches\\":[]}"}'})()
        ]

        result = await ida_llm_targets.resolve_funcptr_target_via_mcp(
            session,
            "0x140000100",
        )

        self.assertEqual(
            ida_llm_targets.ReferenceResolutionStatus.NO_MATCH,
            result.status,
        )
        self.assertIsNone(result.address)

    async def test_reference_resolution_reports_malformed_response_with_debug_context(
        self,
    ) -> None:
        session = AsyncMock()
        session.call_tool.return_value.content = [
            type("Text", (), {"text": "not-json"})()
        ]

        with patch("builtins.print") as mock_print:
            result = await ida_llm_targets.resolve_funcptr_target_via_mcp(
                session,
                "0x140000100",
                debug=True,
            )

        self.assertEqual(
            ida_llm_targets.ReferenceResolutionStatus.MALFORMED_RESPONSE,
            result.status,
        )
        messages = [
            call.args[0]
            for call in mock_print.call_args_list
            if call.args and isinstance(call.args[0], str)
        ]
        self.assertTrue(
            any(
                "malformed_response" in message
                and "0x140000100" in message
                and "JSONDecodeError" in message
                and "not-json" in message
                for message in messages
            )
        )

    async def test_reference_resolution_classifies_transport_error_and_logs_context(
        self,
    ) -> None:
        session = AsyncMock()
        transport_error = RuntimeError("worker disconnected")
        session.call_tool.side_effect = transport_error

        with patch("builtins.print") as mock_print:
            result = await ida_llm_targets.resolve_funcptr_target_via_mcp(
                session,
                "0x140000100",
                debug=True,
            )

        self.assertEqual(
            ida_llm_targets.ReferenceResolutionStatus.TRANSPORT_ERROR,
            result.status,
        )
        self.assertIs(transport_error, result.error)
        messages = [
            call.args[0]
            for call in mock_print.call_args_list
            if call.args and isinstance(call.args[0], str)
        ]
        self.assertTrue(
            any(
                "transport_error" in message
                and "0x140000100" in message
                and "RuntimeError" in message
                and "response=<unavailable>" in message
                for message in messages
            )
        )

    async def test_reference_resolution_rejects_invalid_instruction_address_without_calling_mcp(
        self,
    ) -> None:
        session = AsyncMock()

        result = await ida_llm_targets.resolve_funcptr_target_via_mcp(
            session,
            "not-an-address",
        )

        self.assertEqual(
            ida_llm_targets.ReferenceResolutionStatus.MALFORMED_RESPONSE,
            result.status,
        )
        session.call_tool.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
