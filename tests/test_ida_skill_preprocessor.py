from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import AsyncMock, patch

import ida_skill_preprocessor
from symbol_config import SkillSpec, SymbolSpec


class TestIdaSkillPreprocessor(unittest.IsolatedAsyncioTestCase):
    async def test_generic_struct_preprocessor_writes_yaml_on_pdb_hit(self) -> None:
        with TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "EpObjectTable.yaml"

            with (
                patch(
                    "ida_preprocessor_scripts.generic_struct_offset.resolve_struct_symbol",
                    return_value={
                        "struct_name": "_EPROCESS",
                        "member_name": "ObjectTable",
                        "offset": 0x570,
                    },
                ),
                patch(
                    "ida_preprocessor_scripts.generic_struct_offset.resolve_struct_offset_via_llm",
                    new=AsyncMock(),
                ),
            ):
                status = await ida_skill_preprocessor.preprocess_single_skill_via_mcp(
                    session=AsyncMock(),
                    skill=SkillSpec(
                        name="find-EpObjectTable",
                        symbol="EpObjectTable",
                        expected_output=["EpObjectTable.yaml"],
                        expected_input=[],
                        agent_skill="find-kph-struct-offset",
                    ),
                    symbol=SymbolSpec(
                        name="EpObjectTable",
                        category="struct_offset",
                        data_type="uint16",
                        symbol_expr="_EPROCESS->ObjectTable",
                        struct_name="_EPROCESS",
                        member_name="ObjectTable",
                    ),
                    binary_dir=Path(temp_dir),
                    pdb_path=Path(temp_dir) / "ntkrnlmp.pdb",
                    debug=False,
                    llm_config=None,
                )

            self.assertEqual(ida_skill_preprocessor.PREPROCESS_STATUS_SUCCESS, status)
            self.assertTrue(output_path.exists())

    async def test_generic_gv_preprocessor_returns_failed_when_all_fallbacks_miss(
        self,
    ) -> None:
        with (
            patch(
                "ida_preprocessor_scripts.generic_gv.resolve_public_symbol",
                side_effect=KeyError("PspCreateProcessNotifyRoutine"),
            ),
            patch(
                "ida_preprocessor_scripts.generic_gv.resolve_public_name_via_mcp",
                new=AsyncMock(side_effect=KeyError("PspCreateProcessNotifyRoutine")),
            ),
        ):
            status = await ida_skill_preprocessor.preprocess_single_skill_via_mcp(
                session=AsyncMock(),
                skill=SkillSpec(
                    name="find-PspCreateProcessNotifyRoutine",
                    symbol="PspCreateProcessNotifyRoutine",
                    expected_output=["PspCreateProcessNotifyRoutine.yaml"],
                    expected_input=[],
                    agent_skill="find-kph-gv",
                ),
                symbol=SymbolSpec(
                    name="PspCreateProcessNotifyRoutine",
                    category="gv",
                    data_type="uint32",
                    alias=["PspCreateProcessNotifyRoutine"],
                ),
                binary_dir=Path("/tmp"),
                pdb_path=Path("/tmp/ntkrnlmp.pdb"),
                debug=False,
                llm_config=None,
            )

        self.assertEqual(ida_skill_preprocessor.PREPROCESS_STATUS_FAILED, status)
