from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import AsyncMock

import ida_reference_export


def _make_py_eval_result(result_text: str):
    return type(
        "ToolResult",
        (),
        {
            "content": [
                type(
                    "Text",
                    (),
                    {"text": result_text},
                )()
            ]
        },
    )()


class TestIdaReferenceExport(unittest.IsolatedAsyncioTestCase):
    def test_readable_template_source_lives_in_repo(self) -> None:
        repo_root = Path(__file__).resolve().parent.parent
        helper_source = (repo_root / "ida_reference_export_template.py").read_text(encoding="utf-8")
        module_source = (repo_root / "ida_reference_export.py").read_text(encoding="utf-8")

        self.assertIn("idautils.Chunks(func.start_ea)", helper_source)
        self.assertIn("func_tail_iterator_t", helper_source)
        self.assertIn("CodeRefsFrom(ea, False)", helper_source)
        self.assertNotIn("b85decode", module_source)
        self.assertNotIn("zlib.decompress", module_source)

    def test_build_function_detail_export_py_eval_contains_chunk_and_comment_logic(self) -> None:
        py_code = ida_reference_export.build_function_detail_export_py_eval(0x140001000)

        self.assertIn("idautils.Chunks(func.start_ea)", py_code)
        self.assertIn("func_tail_iterator_t", py_code)
        self.assertIn("CodeRefsFrom(ea, False)", py_code)
        self.assertIn("get_extra_cmt", py_code)
        self.assertIn("collected_eas.update(fallback_eas)", py_code)
        self.assertIn("cfunc.get_pseudocode()", py_code)

    def test_build_reference_yaml_export_py_eval_writes_yaml_and_overrides_func_name(self) -> None:
        py_code = ida_reference_export.build_reference_yaml_export_py_eval(
            0x140001000,
            output_path=Path("/tmp/ref.yaml"),
            func_name="ExReferenceCallBackBlock",
        )

        self.assertIn("payload['func_name'] = \"ExReferenceCallBackBlock\"", py_code)
        self.assertIn("format_name = 'yaml'", py_code)
        self.assertIn("yaml.dump(", py_code)
        self.assertIn("LiteralDumper", py_code)

    def test_validate_reference_yaml_payload_rejects_missing_disasm(self) -> None:
        with self.assertRaisesRegex(
            ida_reference_export.ReferenceGenerationError,
            "invalid reference YAML payload",
        ):
            ida_reference_export.validate_reference_yaml_payload(
                {
                    "func_name": "ExReferenceCallBackBlock",
                    "func_va": "0x140001000",
                    "disasm_code": "",
                    "procedure": "",
                }
            )

    async def test_export_reference_yaml_via_mcp_validates_ack_and_written_yaml(self) -> None:
        session = AsyncMock()
        with TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "ref.yaml"
            output_path.write_text(
                "\n".join(
                    [
                        "func_name: ExReferenceCallBackBlock",
                        "func_va: '0x140001000'",
                        "disasm_code: |-",
                        "  nt:140001000                 mov eax, eax",
                        "procedure: ''",
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            session.call_tool.return_value = _make_py_eval_result(
                (
                    '{"result":"{'
                    '\\"ok\\": true, '
                    f'\\"output_path\\": \\"{output_path}\\", '
                    '\\"bytes_written\\": 120, '
                    '\\"format\\": \\"yaml\\"'
                    '}"}'
                )
            )

            result = await ida_reference_export.export_reference_yaml_via_mcp(
                session,
                func_name="ExReferenceCallBackBlock",
                func_va="0x140001000",
                output_path=output_path,
            )

        self.assertEqual(output_path, result)
        session.call_tool.assert_awaited_once()

    async def test_export_reference_yaml_via_mcp_rejects_invalid_remote_ack(self) -> None:
        session = AsyncMock()
        with TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "ref.yaml"
            session.call_tool.return_value = _make_py_eval_result(
                (
                    '{"result":"{'
                    '\\"ok\\": false, '
                    f'\\"output_path\\": \\"{output_path}\\", '
                    '\\"bytes_written\\": 0, '
                    '\\"format\\": \\"yaml\\"'
                    '}"}'
                )
            )

            with self.assertRaises(ida_reference_export.ReferenceGenerationError):
                await ida_reference_export.export_reference_yaml_via_mcp(
                    session,
                    func_name="ExReferenceCallBackBlock",
                    func_va="0x140001000",
                    output_path=output_path,
                )

    async def test_export_reference_yaml_via_mcp_rejects_invalid_yaml_payload_after_ack(self) -> None:
        session = AsyncMock()
        with TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "ref.yaml"
            output_path.write_text(
                "\n".join(
                    [
                        "func_name: ExReferenceCallBackBlock",
                        "func_va: '0x140001000'",
                        "disasm_code: ''",
                        "procedure: ''",
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            session.call_tool.return_value = _make_py_eval_result(
                (
                    '{"result":"{'
                    '\\"ok\\": true, '
                    f'\\"output_path\\": \\"{output_path}\\", '
                    '\\"bytes_written\\": 96, '
                    '\\"format\\": \\"yaml\\"'
                    '}"}'
                )
            )

            with self.assertRaises(ida_reference_export.ReferenceGenerationError):
                await ida_reference_export.export_reference_yaml_via_mcp(
                    session,
                    func_name="ExReferenceCallBackBlock",
                    func_va="0x140001000",
                    output_path=output_path,
                )
