import unittest
from types import SimpleNamespace

import dump_symbols


class TestLlmDecompileDumpIntegration(unittest.TestCase):
    def test_explicit_and_default_retry_attempts(self) -> None:
        explicit = SimpleNamespace(
            max_retries=4,
            expected_input=[],
            optional_input=[],
            expected_input_amd64=[],
            optional_input_amd64=[],
        )
        default = SimpleNamespace(
            max_retries=None,
            expected_input=[],
            optional_input=[],
            expected_input_amd64=[],
            optional_input_amd64=[],
        )
        explicit_config = dump_symbols._build_effective_llm_config_for_skill(
            {}, explicit, "x/amd64/y"
        )
        default_config = dump_symbols._build_effective_llm_config_for_skill(
            {}, default, "x/amd64/y"
        )
        self.assertEqual(4, explicit_config["max_retries"])
        self.assertEqual(3, default_config["max_retries"])

    def test_arch_inputs_are_merged_in_an_isolated_copy(self) -> None:
        original = {"model": "test", "max_retries": 99}
        skill = SimpleNamespace(
            max_retries=2,
            expected_input=["Base.yaml"],
            expected_input_amd64=["Arch.yaml", "Base.yaml"],
            optional_input=["Optional.yaml"],
            optional_input_amd64=["ArchOptional.yaml"],
        )
        first = dump_symbols._build_effective_llm_config_for_skill(
            original,
            skill,
            "symbols/amd64/module/hash",
        )
        second = dump_symbols._build_effective_llm_config_for_skill(
            original,
            SimpleNamespace(
                max_retries=None,
                expected_input=["Other.yaml"],
                expected_input_amd64=[],
                optional_input=[],
                optional_input_amd64=[],
            ),
            "symbols/amd64/module/hash",
        )
        self.assertEqual(["Base.yaml", "Arch.yaml"], first["_expected_inputs"])
        self.assertEqual(["Optional.yaml", "ArchOptional.yaml"], first["_optional_inputs"])
        self.assertEqual(["Other.yaml"], second["_expected_inputs"])
        self.assertEqual({"model": "test", "max_retries": 99}, original)


if __name__ == "__main__":
    unittest.main()
