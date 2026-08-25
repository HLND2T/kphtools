import io
import unittest
from contextlib import redirect_stdout
from unittest.mock import AsyncMock, patch

from ida_llm_decompile import call_llm_decompile, is_transient_llm_error
from ida_llm_response import empty_llm_decompile_result


VALID = """\
found_call:
  - insn_va: '0x1000'
    insn_disasm: call sub_2000
    func_name: Target
found_funcptr: []
found_gv: []
found_struct_offset: []
"""

EMPTY = """\
found_call: []
found_funcptr: []
found_gv: []
found_struct_offset: []
"""


class TestIdaLlmDecompile(unittest.IsolatedAsyncioTestCase):
    async def call(self, transport, **kwargs):
        arguments = {
            "max_retries": 3,
            "retry_initial_delay": 0,
            **kwargs,
        }
        return await call_llm_decompile(
            model="test-model",
            symbol_name_list=["Target"],
            expected_result_sections={"Target": ["found_call"]},
            reference_items=[{"func_name": "Ref", "disasm_code": "00001000 nop"}],
            target_items=[{"func_name": "TargetFunc", "disasm_code": "00001000 call sub_2000"}],
            prompt_template="{arch}|{platform}|{module_name}|{symbol_name_list}\n{reference_blocks}\n{target_blocks}",
            arch="amd64",
            platform="amd64",
            binary_path=r"D:\symbols\amd64\ntoskrnl.exe.1.2.3.4\hash",
            call_llm_text_func=transport,
            **arguments,
        )

    async def test_invalid_yaml_then_correction_succeeds(self) -> None:
        transport = AsyncMock(side_effect=["bad: [", VALID])
        result = await self.call(transport)
        self.assertEqual("Target", result["found_call"][0]["func_name"])
        second_messages = transport.call_args_list[1].kwargs["messages"]
        self.assertEqual(["system", "user", "assistant", "user"], [m["role"] for m in second_messages])
        self.assertIn("invalid", second_messages[-1]["content"])
        self.assertIn("Target: found_call", second_messages[-1]["content"])
        self.assertIn("Canonical multi-symbol example", second_messages[-1]["content"])

    async def test_wrapped_mismatch_and_hallucinated_pair_are_corrected(self) -> None:
        invalids = [
            "Other:\n  found_call:\n    - insn_va: '0x1000'\n      insn_disasm: call sub_2000\n      func_name: Other",
            VALID.replace("0x1000", "0x9999"),
        ]
        for invalid in invalids:
            with self.subTest(invalid=invalid):
                transport = AsyncMock(side_effect=[invalid, VALID])
                result = await self.call(transport)
                self.assertTrue(result["found_call"])

    async def test_wrong_section_is_corrected(self) -> None:
        wrong = """\
found_call: []
found_funcptr: []
found_gv:
  - insn_va: '0x1000'
    insn_disasm: call sub_2000
    gv_name: Target
found_struct_offset: []
"""
        transport = AsyncMock(side_effect=[wrong, VALID])
        result = await self.call(transport)
        self.assertTrue(result["found_call"])

    async def test_explicit_empty_batch_is_retried_until_complete(self) -> None:
        complete = """\
found_call:
  - insn_va: '0x1000'
    insn_disasm: call sub_2000
    func_name: First
  - insn_va: '0x1010'
    insn_disasm: call sub_3000
    func_name: Second
found_funcptr: []
found_gv: []
found_struct_offset: []
"""
        transport = AsyncMock(side_effect=[EMPTY, complete])

        result = await call_llm_decompile(
            model="test-model",
            symbol_name_list=["First", "Second"],
            expected_result_sections={
                "First": ["found_call"],
                "Second": ["found_call"],
            },
            reference_items=[
                {"func_name": "Ref", "disasm_code": "00001000 nop"}
            ],
            target_items=[
                {
                    "func_name": "TargetFunc",
                    "disasm_code": (
                        "00001000 call sub_2000\n"
                        "00001010 call sub_3000"
                    ),
                }
            ],
            prompt_template="{symbol_name_list}\n{target_blocks}",
            arch="amd64",
            max_retries=2,
            retry_initial_delay=0,
            call_llm_text_func=transport,
        )

        self.assertEqual(
            ["First", "Second"],
            [entry["func_name"] for entry in result["found_call"]],
        )
        self.assertEqual(2, transport.await_count)

    async def test_optional_batch_symbol_may_be_absent(self) -> None:
        complete_required = """\
found_call:
  - insn_va: '0x1000'
    insn_disasm: call sub_2000
    func_name: Required
found_funcptr: []
found_gv: []
found_struct_offset: []
"""
        transport = AsyncMock(return_value=complete_required)

        result = await call_llm_decompile(
            model="test-model",
            symbol_name_list=["Required", "Optional"],
            required_result_symbols=["Required"],
            expected_result_sections={
                "Required": ["found_call"],
                "Optional": ["found_call"],
            },
            reference_items=[
                {"func_name": "Ref", "disasm_code": "00001000 nop"}
            ],
            target_items=[
                {
                    "func_name": "TargetFunc",
                    "disasm_code": "00001000 call sub_2000",
                }
            ],
            prompt_template="{symbol_name_list}\n{target_blocks}",
            arch="amd64",
            max_retries=2,
            retry_initial_delay=0,
            call_llm_text_func=transport,
        )

        self.assertEqual("Required", result["found_call"][0]["func_name"])
        self.assertEqual(1, transport.await_count)

    async def test_instruction_constraint_mismatch_is_corrected(self) -> None:
        corrected = VALID.replace("0x1000", "0x1010").replace(
            "call sub_2000", "jmp sub_2000"
        )
        transport = AsyncMock(side_effect=[VALID, corrected])

        result = await call_llm_decompile(
            model="test-model",
            symbol_name_list=["Target"],
            expected_result_sections={"Target": ["found_call"]},
            instruction_validations={
                "Target": {
                    "instruction_rules": [
                        {
                            "regex": r"(?i)^jmp\s+.+$",
                            "text": "jmp target",
                        }
                    ]
                }
            },
            reference_items=[{"func_name": "Ref", "disasm_code": "00001000 nop"}],
            target_items=[
                {
                    "func_name": "TargetFunc",
                    "disasm_code": (
                        "00001000 call sub_2000\n"
                        "00001010 jmp sub_2000"
                    ),
                }
            ],
            prompt_template="{symbol_name_list}\n{target_blocks}",
            arch="amd64",
            max_retries=2,
            retry_initial_delay=0,
            call_llm_text_func=transport,
        )

        self.assertEqual("0x1010", result["found_call"][0]["insn_va"])
        correction = transport.call_args_list[1].kwargs["messages"][-1]["content"]
        self.assertIn("instruction must use one of these forms", correction)
        self.assertIn("jmp target", correction)

    async def test_struct_instruction_constraints_are_corrected_and_logged(self) -> None:
        invalid = """\
found_call: []
found_funcptr: []
found_gv: []
found_struct_offset:
  - insn_va: '0x1010'
    insn_disasm: mov eax, [rcx+20h]
    offset: '0x30'
    size: 8
    struct_name: _ITEM
    member_name: Value
"""
        corrected = (
            invalid.replace("0x1010", "0x1020", 1)
            .replace("mov eax, [rcx+20h]", "cmp [rcx+30h], eax")
            .replace("size: 8", "size: 4")
        )
        output = io.StringIO()
        transport = AsyncMock(side_effect=[invalid, corrected])
        kwargs = {
            "model": "test-model",
            "symbol_name_list": ["_ITEM->Value"],
            "expected_result_sections": {"_ITEM->Value": ["found_struct_offset"]},
            "instruction_validations": {
                "_ITEM->Value": {
                    "instruction_rules": [
                        {
                            "regex": r"(?i)^cmp\s+\[[^\]]+\],\s*eax$",
                            "text": "cmp [base+offset], eax",
                        }
                    ],
                    "expected_size": 4,
                }
            },
            "reference_items": [{"func_name": "Ref", "disasm_code": "00001000 nop"}],
            "target_items": [
                {
                    "func_name": "TargetFunc",
                    "disasm_code": (
                        "00001010 mov eax, [rcx+20h]\n"
                        "00001020 cmp [rcx+30h], eax"
                    ),
                }
            ],
            "prompt_template": "{symbol_name_list}\n{target_blocks}",
            "arch": "amd64",
            "max_retries": 2,
            "retry_initial_delay": 0,
            "call_llm_text_func": transport,
        }

        with redirect_stdout(output):
            result = await call_llm_decompile(debug=True, **kwargs)

        self.assertEqual("0x30", result["found_struct_offset"][0]["offset"])
        correction = transport.call_args_list[1].kwargs["messages"][-1]["content"]
        self.assertIn("cmp [base+offset], eax", correction)
        self.assertNotIn(r"(?i)^cmp", correction)
        self.assertIn("required size is 4", correction)
        self.assertIn("contains memory displacement(s) 0x20", correction)

        exhausted = AsyncMock(return_value=invalid)
        kwargs["call_llm_text_func"] = exhausted
        with redirect_stdout(output):
            result = await call_llm_decompile(debug=True, **kwargs)
        self.assertEqual(empty_llm_decompile_result(), result)
        self.assertIn(
            "issue_types=instruction_rule_mismatch,instruction_size_mismatch,"
            "struct_offset_displacement_mismatch",
            output.getvalue(),
        )

    async def test_unsupported_vcall_is_corrected(self) -> None:
        unsupported = """\
found_vcall:
  - insn_va: '0x1000'
    insn_disasm: call [rax+10h]
    vfunc_offset: '0x10'
    func_name: Target
found_call: []
found_funcptr: []
found_gv: []
found_struct_offset: []
"""
        transport = AsyncMock(side_effect=[unsupported, VALID])
        result = await self.call(transport)
        self.assertTrue(result["found_call"])
        correction = transport.call_args_list[1].kwargs["messages"][-1]["content"]
        self.assertIn("found_vcall` is unsupported", correction)

    async def test_validation_exhaustion_returns_empty(self) -> None:
        transport = AsyncMock(return_value="not yaml")
        result = await self.call(transport)
        self.assertEqual(empty_llm_decompile_result(), result)
        self.assertEqual(3, transport.await_count)

    async def test_transient_transport_retries_but_non_transient_does_not(self) -> None:
        transient = AsyncMock(side_effect=[TimeoutError("timed out"), VALID])
        self.assertTrue((await self.call(transient))["found_call"])
        permanent = AsyncMock(side_effect=RuntimeError("authentication failed"))
        self.assertEqual(empty_llm_decompile_result(), await self.call(permanent))
        self.assertEqual(1, permanent.await_count)

    async def test_text_only_transient_statuses_retry_and_log_delay(self) -> None:
        for message in ("read timeout", "status_code=503"):
            with self.subTest(message=message):
                transport = AsyncMock(side_effect=[RuntimeError(message), VALID])
                output = io.StringIO()
                with redirect_stdout(output):
                    result = await self.call(transport, debug=True)

                self.assertTrue(result["found_call"])
                self.assertIn(
                    "transient failure for Target on attempt 1/3",
                    output.getvalue(),
                )
                self.assertIn("retrying in 0.00s", output.getvalue())

    def test_transient_status_code_attributes(self) -> None:
        class StatusError(Exception):
            status_code = 429

        class Response:
            status_code = 502

        class ResponseError(Exception):
            response = Response()

        self.assertTrue(is_transient_llm_error(StatusError()))
        self.assertTrue(is_transient_llm_error(ResponseError()))
        self.assertFalse(is_transient_llm_error(RuntimeError("invalid api key")))

    async def test_validation_exhaustion_logs_schema_and_issue_types(self) -> None:
        transport = AsyncMock(return_value="not yaml")
        output = io.StringIO()

        with redirect_stdout(output):
            result = await self.call(transport, max_retries=2, debug=True)

        self.assertEqual(empty_llm_decompile_result(), result)
        self.assertIn("validation retry exhausted for Target", output.getvalue())
        self.assertIn("schema_kind=invalid", output.getvalue())
        self.assertIn(
            "issue_types=missing_result_symbol,yaml_root_type_mismatch",
            output.getvalue(),
        )

    async def test_transport_and_validation_share_budget(self) -> None:
        transport = AsyncMock(side_effect=[TimeoutError("timeout"), "not yaml", VALID])
        result = await self.call(transport)
        self.assertTrue(result["found_call"])
        self.assertEqual(3, transport.await_count)

    async def test_max_retries_one_disables_all_retries(self) -> None:
        transport = AsyncMock(return_value="not yaml")
        result = await self.call(transport, max_retries=1)
        self.assertEqual(empty_llm_decompile_result(), result)
        self.assertEqual(1, transport.await_count)

    async def test_retry_preserves_existing_message_ids_and_cache_key(self) -> None:
        transport = AsyncMock(side_effect=["not yaml", VALID])
        await self.call(transport)
        first = transport.call_args_list[0].kwargs
        second = transport.call_args_list[1].kwargs
        self.assertEqual(first["prompt_cache_key"], second["prompt_cache_key"])
        self.assertEqual(
            [m["id"] for m in first["messages"]],
            [m["id"] for m in second["messages"][:2]],
        )

    async def test_retry_preserves_added_correction_message_ids(self) -> None:
        transport = AsyncMock(side_effect=["not yaml", "not yaml", VALID])
        await self.call(transport)
        second_messages = transport.call_args_list[1].kwargs["messages"]
        third_messages = transport.call_args_list[2].kwargs["messages"]
        self.assertEqual(
            [message["id"] for message in second_messages],
            [message["id"] for message in third_messages[: len(second_messages)]],
        )

    async def test_prompt_uses_windows_kernel_context(self) -> None:
        transport = AsyncMock(return_value=VALID)
        await self.call(transport)
        messages = transport.call_args.kwargs["messages"]
        self.assertIn("Windows-kernel", messages[0]["content"])
        self.assertIn("amd64|amd64|ntoskrnl|Target", messages[1]["content"])


if __name__ == "__main__":
    unittest.main()
