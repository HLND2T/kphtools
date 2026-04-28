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

    async def test_generic_struct_preprocessor_returns_failed_for_bitfield_llm_fallback(
        self,
    ) -> None:
        with TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "PspPicoProviderRoutines.yaml"

            with (
                patch(
                    "ida_preprocessor_scripts.generic_struct_offset.resolve_struct_symbol",
                    side_effect=KeyError("_PSP_PICO_PROVIDER_ROUTINES->Flags"),
                ),
                patch(
                    "ida_preprocessor_scripts.generic_struct_offset.resolve_struct_offset_via_llm",
                    new=AsyncMock(return_value={"offset": 0x18}),
                ),
            ):
                status = await ida_skill_preprocessor.preprocess_single_skill_via_mcp(
                    session=AsyncMock(),
                    skill=SkillSpec(
                        name="find-PspPicoProviderRoutines",
                        symbol="PspPicoProviderRoutines",
                        expected_output=["PspPicoProviderRoutines.yaml"],
                        expected_input=[],
                        agent_skill="find-kph-struct-offset",
                    ),
                    symbol=SymbolSpec(
                        name="PspPicoProviderRoutines",
                        category="struct_offset",
                        data_type="uint32",
                        struct_name="_PSP_PICO_PROVIDER_ROUTINES",
                        member_name="Flags",
                        bits=True,
                    ),
                    binary_dir=Path(temp_dir),
                    pdb_path=Path(temp_dir) / "ntkrnlmp.pdb",
                    debug=False,
                    llm_config={"model": "test-model"},
                )

            self.assertEqual(ida_skill_preprocessor.PREPROCESS_STATUS_FAILED, status)
            self.assertFalse(output_path.exists())

    async def test_generic_struct_preprocessor_returns_failed_on_missing_offset_payload(
        self,
    ) -> None:
        with TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "PspHostSiloGlobals.yaml"

            with (
                patch(
                    "ida_preprocessor_scripts.generic_struct_offset.resolve_struct_symbol",
                    side_effect=KeyError("_ESERVERSILO_GLOBALS->PspHostSiloGlobals"),
                ),
                patch(
                    "ida_preprocessor_scripts.generic_struct_offset.resolve_struct_offset_via_llm",
                    new=AsyncMock(side_effect=KeyError("offset")),
                ),
            ):
                status = await ida_skill_preprocessor.preprocess_single_skill_via_mcp(
                    session=AsyncMock(),
                    skill=SkillSpec(
                        name="find-PspHostSiloGlobals",
                        symbol="PspHostSiloGlobals",
                        expected_output=["PspHostSiloGlobals.yaml"],
                        expected_input=[],
                        agent_skill="find-kph-struct-offset",
                    ),
                    symbol=SymbolSpec(
                        name="PspHostSiloGlobals",
                        category="struct_offset",
                        data_type="uint64",
                        struct_name="_ESERVERSILO_GLOBALS",
                        member_name="PspHostSiloGlobals",
                    ),
                    binary_dir=Path(temp_dir),
                    pdb_path=Path(temp_dir) / "ntkrnlmp.pdb",
                    debug=False,
                    llm_config={"model": "test-model"},
                )

            self.assertEqual(ida_skill_preprocessor.PREPROCESS_STATUS_FAILED, status)
            self.assertFalse(output_path.exists())

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

    async def test_generic_func_preprocessor_returns_failed_on_invalid_mcp_payload(
        self,
    ) -> None:
        with (
            patch(
                "ida_preprocessor_scripts.generic_func.resolve_public_symbol",
                side_effect=KeyError("PspSetCreateProcessNotifyRoutine"),
            ),
            patch(
                "ida_preprocessor_scripts.generic_func.resolve_public_name_via_mcp",
                new=AsyncMock(side_effect=ValueError("invalid payload")),
            ),
        ):
            status = await ida_skill_preprocessor.preprocess_single_skill_via_mcp(
                session=AsyncMock(),
                skill=SkillSpec(
                    name="find-PspSetCreateProcessNotifyRoutine",
                    symbol="PspSetCreateProcessNotifyRoutine",
                    expected_output=["PspSetCreateProcessNotifyRoutine.yaml"],
                    expected_input=[],
                    agent_skill="find-kph-func",
                ),
                symbol=SymbolSpec(
                    name="PspSetCreateProcessNotifyRoutine",
                    category="func",
                    data_type="uint32",
                    alias=["PspSetCreateProcessNotifyRoutine"],
                ),
                binary_dir=Path("/tmp"),
                pdb_path=Path("/tmp/ntkrnlmp.pdb"),
                debug=False,
                llm_config=None,
            )

        self.assertEqual(ida_skill_preprocessor.PREPROCESS_STATUS_FAILED, status)
