import unittest

from ida_llm_response import (
    empty_llm_decompile_result,
    parse_llm_decompile_response_with_issues,
)


EMPTY_YAML = """\
found_call: []
found_funcptr: []
found_gv: []
found_struct_offset: []
"""


class TestIdaLlmResponse(unittest.TestCase):
    def test_parses_all_four_canonical_sections(self) -> None:
        outcome = parse_llm_decompile_response_with_issues(
            """\
found_call:
  - insn_va: '0x1000'
    insn_disasm: call sub_2000
    func_name: TargetFunc
found_funcptr:
  - insn_va: '0x1010'
    insn_disasm: lea rax, sub_3000
    funcptr_name: TargetPtr
found_gv:
  - insn_va: '0x1020'
    insn_disasm: mov rax, cs:qword_4000
    gv_name: TargetGv
found_struct_offset:
  - insn_va: '0x1030'
    insn_disasm: mov eax, [rcx+20h]
    offset: '0x20'
    size: '4'
    struct_name: _ITEM
    member_name: Value
"""
        )
        self.assertEqual("canonical", outcome["schema_kind"])
        self.assertEqual([], outcome["issues"])

    def test_only_complete_explicit_empty_mapping_is_valid(self) -> None:
        valid = parse_llm_decompile_response_with_issues(EMPTY_YAML)
        self.assertEqual("explicit_empty", valid["schema_kind"])
        self.assertEqual(empty_llm_decompile_result(), valid["result"])
        for invalid_text in ("", "null", "{}", "found_call: []"):
            with self.subTest(invalid_text=invalid_text):
                outcome = parse_llm_decompile_response_with_issues(invalid_text)
                self.assertEqual("invalid", outcome["schema_kind"])
                self.assertTrue(outcome["issues"])

    def test_accepts_fenced_and_symbol_wrapped_yaml(self) -> None:
        fenced = parse_llm_decompile_response_with_issues(f"prose\n```yaml\n{EMPTY_YAML}```")
        self.assertEqual("explicit_empty", fenced["schema_kind"])
        wrapped = parse_llm_decompile_response_with_issues(
            """\
TargetFunc:
  found_call:
    - insn_va: '0x1000'
      insn_disasm: call sub_2000
      func_name: TargetFunc
""",
            ["TargetFunc"],
        )
        self.assertEqual("symbol_wrapped", wrapped["schema_kind"])
        self.assertTrue(wrapped["compatibility_flattened"])

    def test_reports_precise_shape_and_wrapper_issues(self) -> None:
        section = parse_llm_decompile_response_with_issues("found_call: {}")
        self.assertEqual("yaml_section_type_mismatch", section["issues"][0]["issue_type"])
        entry = parse_llm_decompile_response_with_issues("found_call: [bad]")
        self.assertEqual("yaml_entry_shape_mismatch", entry["issues"][0]["issue_type"])
        missing = parse_llm_decompile_response_with_issues(
            "found_call:\n  - insn_va: '0x1'\n    insn_disasm: call sub_2"
        )
        self.assertIn("func_name", missing["issues"][0]["invalid_fields"])
        wrapper = parse_llm_decompile_response_with_issues(
            """\
Expected:
  found_call:
    - insn_va: '0x1'
      insn_disasm: call sub_2
      func_name: Other
""",
            ["Expected"],
        )
        self.assertEqual("wrapped_symbol_mismatch", wrapper["issues"][0]["issue_type"])

    def test_rejects_found_vcall_and_repairs_glued_headers(self) -> None:
        unsupported = parse_llm_decompile_response_with_issues(
            "found_vcall:\n  - insn_va: '0x1'"
        )
        self.assertEqual("invalid", unsupported["schema_kind"])
        self.assertIn("unsupported", unsupported["issues"][0]["message"])
        repaired = parse_llm_decompile_response_with_issues(
            "found_call: []found_funcptr: []found_gv: []found_struct_offset: []"
        )
        self.assertEqual("explicit_empty", repaired["schema_kind"])
        broken = parse_llm_decompile_response_with_issues(
            "found_call: []found_funcptr: [bad]found_gv: []found_struct_offset: []"
        )
        self.assertEqual("invalid", broken["schema_kind"])

    def test_struct_duplicates_keep_the_smallest_numeric_offset(self) -> None:
        outcome = parse_llm_decompile_response_with_issues(
            """\
found_call: []
found_funcptr: []
found_gv: []
found_struct_offset:
  - insn_va: '0x1000'
    insn_disasm: mov eax, [rcx+20h]
    offset: '0x20'
    size: '4'
    struct_name: _ITEM
    member_name: Value
  - insn_va: '0x1010'
    insn_disasm: mov eax, [rcx+10h]
    offset: '10h'
    size: '4'
    struct_name: _ITEM
    member_name: Value
"""
        )
        self.assertEqual("10h", outcome["result"]["found_struct_offset"][0]["offset"])


if __name__ == "__main__":
    unittest.main()
