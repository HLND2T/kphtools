import unittest
from pathlib import Path

from ida_llm_prompt import (
    derive_module_name,
    format_prompt_template,
    render_llm_decompile_blocks,
    strip_c_like_comments,
    strip_disasm_comments,
)


class TestIdaLlmPrompt(unittest.TestCase):
    def test_cleans_only_target_blocks(self) -> None:
        reference, target = render_llm_decompile_blocks(
            [{"func_name": "Ref", "disasm_code": "1000 mov eax, 1 ; keep", "procedure": "x(); // keep"}],
            [{"func_name": "Target", "disasm_code": "seg:140001000\n1000 mov eax, 1 ; remove", "procedure": "x(); // remove"}],
        )
        self.assertIn("; keep", reference)
        self.assertIn("// keep", reference)
        self.assertNotIn("seg:140001000", target)
        self.assertNotIn("; remove", target)
        self.assertNotIn("// remove", target)

    def test_preserves_comment_markers_inside_quotes_and_escapes(self) -> None:
        self.assertEqual('1000 db ";"', strip_disasm_comments('1000 db ";" ; comment'))
        cleaned = strip_c_like_comments('puts("http://x"); // comment\nprintf("\\\"//");')
        self.assertIn('"http://x"', cleaned)
        self.assertIn('"\\\"//"', cleaned)

    def test_renders_multiple_target_names_and_context_placeholders(self) -> None:
        _, targets = render_llm_decompile_blocks(
            [{"func_name": "Ref"}],
            [{"func_name": "One"}, {"func_name": "Two"}],
        )
        self.assertIn("Target Function: One", targets)
        self.assertIn("Target Function: Two", targets)
        rendered = format_prompt_template(
            "{arch}|{platform}|{module_name}|{symbol_name_list}",
            symbol_name_list="One, Two",
            reference_blocks="",
            target_blocks=targets,
            arch="amd64",
            platform="amd64",
            module_name="ntoskrnl",
        )
        self.assertEqual("amd64|amd64|ntoskrnl|One, Two", rendered)

    def test_derives_ntoskrnl_from_binary_dir_or_path(self) -> None:
        self.assertEqual(
            "ntoskrnl",
            derive_module_name(r"D:\symbols\amd64\ntoskrnl.exe.10.0.1.2\hash"),
        )
        self.assertEqual("ntoskrnl", derive_module_name(r"D:\bin\ntoskrnl.exe"))

    def test_repository_prompt_declares_four_sections_and_rejects_vcall(self) -> None:
        prompt = Path(
            "ida_preprocessor_scripts/prompt/call_llm_decompile.md"
        ).read_text(encoding="utf-8")
        for section in (
            "found_call:",
            "found_funcptr:",
            "found_gv:",
            "found_struct_offset:",
        ):
            self.assertIn(section, prompt)
        self.assertIn("found_vcall` is unsupported", prompt)
        self.assertNotIn("found_vcall:", prompt)


if __name__ == "__main__":
    unittest.main()
