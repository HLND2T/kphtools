import unittest
from unittest.mock import AsyncMock, patch

from ida_llm_decompile import call_llm_decompile
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

    async def test_prompt_uses_windows_kernel_context(self) -> None:
        transport = AsyncMock(return_value=VALID)
        await self.call(transport)
        messages = transport.call_args.kwargs["messages"]
        self.assertIn("Windows-kernel", messages[0]["content"])
        self.assertIn("amd64|amd64|ntoskrnl|Target", messages[1]["content"])


if __name__ == "__main__":
    unittest.main()
