import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import AsyncMock, patch

import yaml

import ida_llm_targets


class TestIdaLlmTargets(unittest.IsolatedAsyncioTestCase):
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
        self.assertIsNone(result)
        code = session.call_tool.await_args.args[1]["code"]
        self.assertIn("int(func.start_ea) == int(target_ea)", code)


if __name__ == "__main__":
    unittest.main()
