import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import types
import unittest
from unittest.mock import AsyncMock, patch

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

    def test_build_code_region_yaml_export_py_eval_writes_yaml_without_procedure(
        self,
    ) -> None:
        py_code = ida_reference_export.build_code_region_yaml_export_py_eval(
            0x140A20B1A,
            0x647,
            output_path=Path("/tmp/ref.yaml"),
            code_name="PgInitContext",
        )

        self.assertIn("'func_name': \"PgInitContext\"", py_code)
        self.assertIn("code_start = 0x140a20b1a", py_code.lower())
        self.assertIn("'func_va': hex(code_start)", py_code)
        self.assertIn("get_code_region_disasm", py_code)
        self.assertIn("format_name = 'yaml'", py_code)
        self.assertNotIn("'procedure'", py_code)

    def test_code_region_detail_export_runs_with_separate_exec_namespaces(
        self,
    ) -> None:
        ida_bytes = types.ModuleType("ida_bytes")
        ida_bytes.get_flags = lambda ea: 1
        ida_bytes.is_code = lambda flags: True

        ida_lines = types.ModuleType("ida_lines")
        ida_lines.tag_remove = lambda text: text

        ida_segment = types.ModuleType("ida_segment")
        ida_segment.getseg = lambda ea: None
        ida_segment.get_segm_name = lambda seg: ""

        idc = types.ModuleType("idc")
        idc.BADADDR = -1
        idc.generate_disasm_line = lambda ea, flags: "nop"
        idc.get_cmt = lambda ea, repeatable: None
        idc.next_head = lambda ea, end_ea: idc.BADADDR

        py_code = ida_reference_export.build_code_region_detail_export_py_eval(
            0x1000,
            1,
            code_name="PgInitContext",
        )
        namespace: dict[str, object] = {}

        with patch.dict(
            sys.modules,
            {
                "ida_bytes": ida_bytes,
                "ida_lines": ida_lines,
                "ida_segment": ida_segment,
                "idc": idc,
            },
        ):
            exec(py_code, {}, namespace)

        payload = json.loads(str(namespace["result"]))
        self.assertEqual("PgInitContext", payload["func_name"])
        self.assertIn("0000000000001000                 nop", payload["disasm_code"])

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

    def test_validate_reference_yaml_payload_allows_missing_procedure(self) -> None:
        payload = ida_reference_export.validate_reference_yaml_payload(
            {
                "func_name": "PgInitContext",
                "func_va": "0x140a20b1a",
                "disasm_code": "sti",
            }
        )

        self.assertEqual("PgInitContext", payload["func_name"])
        self.assertEqual("", payload["procedure"])

    def test_validate_reference_yaml_payload_preserves_optional_funcs(self) -> None:
        payload = ida_reference_export.validate_reference_yaml_payload(
            {
                "func_name": "ObpEnumFindHandleProcedure",
                "func_va": "0x1406c6cd0",
                "disasm_code": "mov rax, rcx",
                "procedure": "",
                "optional_funcs": ["ExGetHandlePointer"],
            }
        )

        self.assertEqual("ObpEnumFindHandleProcedure", payload["func_name"])
        self.assertEqual(["ExGetHandlePointer"], payload["optional_funcs"])

    def test_validate_reference_yaml_payload_omits_empty_optional_funcs(self) -> None:
        payload = ida_reference_export.validate_reference_yaml_payload(
            {
                "func_name": "ObpEnumFindHandleProcedure",
                "func_va": "0x1406c6cd0",
                "disasm_code": "mov rax, rcx",
                "procedure": "",
                "optional_funcs": [],
            }
        )

        self.assertEqual("ObpEnumFindHandleProcedure", payload["func_name"])
        self.assertNotIn("optional_funcs", payload)

    def test_validate_reference_yaml_payload_rejects_invalid_optional_funcs(self) -> None:
        invalid_values = [
            "ExGetHandlePointer",
            ["ExGetHandlePointer", ""],
            ["ExGetHandlePointer", 123],
            [""],
        ]

        for optional_funcs in invalid_values:
            with self.subTest(optional_funcs=optional_funcs):
                with self.assertRaisesRegex(
                    ida_reference_export.ReferenceGenerationError,
                    "invalid reference YAML payload",
                ):
                    ida_reference_export.validate_reference_yaml_payload(
                        {
                            "func_name": "ObpEnumFindHandleProcedure",
                            "func_va": "0x1406c6cd0",
                            "disasm_code": "mov rax, rcx",
                            "procedure": "",
                            "optional_funcs": optional_funcs,
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
                json.dumps(
                    {
                        "result": json.dumps(
                            {
                                "ok": True,
                                "output_path": str(output_path),
                                "bytes_written": 120,
                                "format": "yaml",
                            }
                        )
                    }
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

    async def test_export_code_region_yaml_via_mcp_allows_missing_procedure(
        self,
    ) -> None:
        session = AsyncMock()
        with TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "ref.yaml"
            output_path.write_text(
                "\n".join(
                    [
                        "func_name: PgInitContext",
                        "func_va: '0x140a20b1a'",
                        "disasm_code: |-",
                        "  INIT:0000000140A20B1A                 sti",
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            session.call_tool.return_value = _make_py_eval_result(
                json.dumps(
                    {
                        "result": json.dumps(
                            {
                                "ok": True,
                                "output_path": str(output_path),
                                "bytes_written": 120,
                                "format": "yaml",
                            }
                        )
                    }
                )
            )

            result = await ida_reference_export.export_code_region_yaml_via_mcp(
                session,
                code_name="PgInitContext",
                code_va="0x140a20b1a",
                code_size=0x647,
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
