import unittest

from ida_llm_response import empty_llm_decompile_result
from ida_llm_validation import build_target_disasm_index, validate_llm_decompile_result


def call_entry(va: str = "0x1000", disasm: str = "call sub_2000", name: str = "Target"):
    return {"insn_va": va, "insn_disasm": disasm, "func_name": name}


class TestIdaLlmValidation(unittest.TestCase):
    def setUp(self) -> None:
        self.index = build_target_disasm_index(
            ["00001000  call    sub_2000\n00001010  mov eax, [rcx+20h]"]
        )

    def validate(self, result, requested=("Target",), expected=None):
        return validate_llm_decompile_result(
            result,
            self.index,
            expected or {"Target": ["found_call"]},
            requested_symbol_names=requested,
        )

    def test_rejects_fabricated_or_mismatched_instruction_pairs(self) -> None:
        cases = [
            call_entry("0x9999"),
            call_entry("0x1010", "call sub_2000"),
            call_entry("0x1000", "call sub_9999"),
        ]
        for entry in cases:
            with self.subTest(entry=entry):
                issues = self.validate({**empty_llm_decompile_result(), "found_call": [entry]})
                self.assertEqual("instruction_mismatch", issues[0]["issue_type"])

    def test_instruction_in_another_target_block_reports_candidate_va(self) -> None:
        index = build_target_disasm_index(
            ["00001000  nop", "00002000  call sub_2000"]
        )
        result = {**empty_llm_decompile_result(), "found_call": [call_entry()]}
        issues = validate_llm_decompile_result(
            result,
            index,
            {"Target": ["found_call"]},
            requested_symbol_names=["Target"],
        )
        self.assertEqual([0x2000], issues[0]["candidate_vas"])

    def test_rejects_unknown_symbol_and_wrong_section(self) -> None:
        unknown = {**empty_llm_decompile_result(), "found_call": [call_entry(name="Other")]}
        self.assertIn("unexpected_result_symbol", {i["issue_type"] for i in self.validate(unknown)})
        wrong = {
            **empty_llm_decompile_result(),
            "found_gv": [
                {"insn_va": "0x1000", "insn_disasm": "call sub_2000", "gv_name": "Target"}
            ],
        }
        issues = self.validate(wrong)
        self.assertIn("result_section_mismatch", {i["issue_type"] for i in issues})

    def test_rejects_struct_member_in_wrong_section(self) -> None:
        result = {
            **empty_llm_decompile_result(),
            "found_funcptr": [
                {
                    "insn_va": "0x1010",
                    "insn_disasm": "mov eax, [rcx+20h]",
                    "funcptr_name": "_ITEM->Value",
                }
            ],
        }
        issues = self.validate(
            result,
            requested=("_ITEM->Value",),
            expected={"_ITEM->Value": ["found_struct_offset"]},
        )
        self.assertIn("result_section_mismatch", {i["issue_type"] for i in issues})

    def test_mixed_func_and_struct_batch_passes(self) -> None:
        result = {
            **empty_llm_decompile_result(),
            "found_call": [call_entry()],
            "found_struct_offset": [
                {
                    "insn_va": "0x1010",
                    "insn_disasm": "mov eax, [rcx+20h]",
                    "offset": "0x20",
                    "size": "4",
                    "struct_name": "_ITEM",
                    "member_name": "Value",
                }
            ],
        }
        issues = self.validate(
            result,
            requested=("Target", "_ITEM->Value"),
            expected={"Target": ["found_call"], "_ITEM->Value": ["found_struct_offset"]},
        )
        self.assertEqual([], issues)

    def test_empty_result_passes_without_disassembly_index(self) -> None:
        issues = validate_llm_decompile_result(
            empty_llm_decompile_result(),
            ({}, {}),
            {},
            requested_symbol_names=["Target"],
        )
        self.assertEqual([], issues)


if __name__ == "__main__":
    unittest.main()
