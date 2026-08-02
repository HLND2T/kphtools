from pathlib import Path
import unittest
from unittest.mock import AsyncMock, patch

import ida_skill_preprocessor
from symbol_config import SkillSpec, SymbolSpec, load_config


class TestIdaSkillPreprocessor(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        ida_skill_preprocessor._SCRIPT_ENTRY_CACHE.clear()

    def test_repository_config_skills_have_matching_script(self) -> None:
        config = load_config("config.yaml")

        for module in config.modules:
            for skill in module.skills:
                script_path = Path("ida_preprocessor_scripts") / f"{skill.name}.py"
                self.assertTrue(script_path.is_file(), script_path)

    def test_repository_config_skills_export_loadable_preprocess_entries(self) -> None:
        config = load_config("config.yaml")

        ida_skill_preprocessor._SCRIPT_ENTRY_CACHE.clear()
        for module in config.modules:
            for skill in module.skills:
                entry = ida_skill_preprocessor._get_preprocess_entry(skill.name)
                self.assertTrue(callable(entry), skill.name)

    async def test_injects_current_arch_inputs_without_mutating_llm_config(self) -> None:
        preprocess_func = AsyncMock(
            return_value=ida_skill_preprocessor.PREPROCESS_STATUS_SUCCESS
        )
        original_llm_config = {"model": "test-model"}
        skill = SkillSpec(
            name="find-Test",
            expected_output=["Output.yaml"],
            expected_input=["Common.yaml"],
            expected_input_amd64=["Amd64.yaml"],
            expected_input_arm64=["Arm64.yaml"],
            optional_input=["OptionalCommon.yaml"],
            optional_input_amd64=["OptionalAmd64.yaml"],
            optional_input_arm64=["OptionalArm64.yaml"],
        )

        with patch.object(
            ida_skill_preprocessor,
            "_get_preprocess_entry",
            return_value=preprocess_func,
        ):
            status = await ida_skill_preprocessor.preprocess_single_skill_via_mcp(
                session=AsyncMock(),
                skill=skill,
                symbol=SymbolSpec(name="Output", category="func", data_type="uint32"),
                binary_dir=Path("/symbols/ntoskrnl/amd64/.10.0.26100.1"),
                pdb_path=None,
                debug=False,
                llm_config=original_llm_config,
            )

        self.assertEqual(ida_skill_preprocessor.PREPROCESS_STATUS_SUCCESS, status)
        effective_config = preprocess_func.await_args.kwargs["llm_config"]
        self.assertEqual(
            ["Common.yaml", "Amd64.yaml"], effective_config["_expected_inputs"]
        )
        self.assertEqual(
            ["OptionalCommon.yaml", "OptionalAmd64.yaml"],
            effective_config["_optional_inputs"],
        )
        self.assertEqual({"model": "test-model"}, original_llm_config)

    async def test_missing_script_returns_failed(self) -> None:
        status = await ida_skill_preprocessor.preprocess_single_skill_via_mcp(
            session=AsyncMock(),
            skill=SkillSpec(
                name="find-DoesNotExist",
                expected_output=["DoesNotExist.yaml"],
                expected_input=[],
            ),
            symbol=SymbolSpec(
                name="DoesNotExist",
                category="struct_offset",
                data_type="uint16",
            ),
            binary_dir=Path("/tmp"),
            pdb_path=Path("/tmp/ntkrnlmp.pdb"),
            debug=False,
            llm_config=None,
        )

        self.assertEqual(ida_skill_preprocessor.PREPROCESS_STATUS_FAILED, status)
