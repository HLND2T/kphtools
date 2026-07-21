import ast
import importlib.util
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

import yaml

import ida_llm_specs


REQUIRED_KEYS = {
    "symbol_name",
    "prompt_path",
    "reference_yaml_paths",
    "expected_result_sections",
    "dependency_policy",
}


class TestIdaLlmSpecs(unittest.TestCase):
    @staticmethod
    def _spec(**overrides):
        spec = {
            "symbol_name": "EpCookie",
            "prompt_path": "prompt/call_llm_decompile.md",
            "reference_yaml_paths": [
                "references/ntoskrnl/PspAllocateProcess.{arch}.yaml"
            ],
            "expected_result_sections": ["found_struct_offset"],
            "dependency_policy": {"PspAllocateProcess.yaml": "required"},
        }
        spec.update(overrides)
        return spec

    def test_normalizes_complete_strict_dict(self) -> None:
        spec = self._spec()

        self.assertEqual(
            spec,
            ida_llm_specs.normalize_llm_decompile_spec(spec),
        )

    def test_rejects_legacy_tuple_missing_unknown_and_duplicate_symbol(self) -> None:
        self.assertIsNone(
            ida_llm_specs.build_llm_decompile_specs_map(
                [
                    (
                        "EpCookie",
                        "_EPROCESS->Cookie",
                        "prompt/call_llm_decompile.md",
                        "references/ntoskrnl/PspAllocateProcess.{arch}.yaml",
                    )
                ]
            )
        )
        self.assertIsNone(
            ida_llm_specs.normalize_llm_decompile_spec(
                {
                    key: value
                    for key, value in self._spec().items()
                    if key != "dependency_policy"
                }
            )
        )
        self.assertIsNone(
            ida_llm_specs.normalize_llm_decompile_spec(
                {**self._spec(), "legacy_query_name": "_EPROCESS->Cookie"}
            )
        )
        self.assertIsNone(
            ida_llm_specs.build_llm_decompile_specs_map(
                [self._spec(), self._spec()]
            )
        )

    def test_rejects_invalid_reference_section_and_policy_schema(self) -> None:
        invalid_specs = [
            self._spec(reference_yaml_paths=[]),
            self._spec(reference_yaml_paths=[1]),
            self._spec(expected_result_sections=["found_unknown"]),
            self._spec(expected_result_sections=["found_vcall"]),
            self._spec(dependency_policy={}),
            self._spec(dependency_policy={"dir/PspAllocateProcess.yaml": "required"}),
            self._spec(dependency_policy={"PspAllocateProcess.yaml": "runtime"}),
            self._spec(dependency_policy={"PspAllocateProcess.yaml": []}),
        ]

        for spec in invalid_specs:
            with self.subTest(spec=spec):
                self.assertIsNone(
                    ida_llm_specs.normalize_llm_decompile_spec(spec)
                )

    def test_multiple_references_are_ordered_and_deduplicated(self) -> None:
        spec = self._spec(
            reference_yaml_paths=[
                "references/a.{arch}.yaml",
                "references/b.{arch}.yaml",
                "references/a.{arch}.yaml",
            ],
            dependency_policy={
                "TargetA.yaml": "required",
                "TargetB.yaml": "optional",
            },
        )

        normalized = ida_llm_specs.normalize_llm_decompile_spec(spec)

        self.assertEqual(
            ["references/a.{arch}.yaml", "references/b.{arch}.yaml"],
            normalized["reference_yaml_paths"],
        )
        self.assertEqual(spec["dependency_policy"], normalized["dependency_policy"])

    def test_reference_func_name_maps_to_current_artifact_basename(self) -> None:
        with TemporaryDirectory() as temp_dir:
            scripts_dir = Path(temp_dir)
            reference_path = (
                scripts_dir
                / "references"
                / "ntoskrnl"
                / "PspAllocateProcess.amd64.yaml"
            )
            reference_path.parent.mkdir(parents=True)
            reference_path.write_text(
                yaml.safe_dump({"func_name": "PspAllocateProcess"}),
                encoding="utf-8",
            )
            specs = ida_llm_specs.build_llm_decompile_specs_map([self._spec()])

            valid = ida_llm_specs.validate_llm_decompile_specs(
                specs,
                expected_inputs=["PspAllocateProcess.yaml"],
                optional_inputs=[],
                category_by_symbol={"EpCookie": "struct_offset"},
                scripts_dir=scripts_dir,
                arch="amd64",
            )

        self.assertTrue(valid)

    def test_policy_reference_config_and_category_mismatches_fail(self) -> None:
        with TemporaryDirectory() as temp_dir:
            scripts_dir = Path(temp_dir)
            reference_path = scripts_dir / "references" / "target.amd64.yaml"
            reference_path.parent.mkdir(parents=True)
            reference_path.write_text(
                yaml.safe_dump({"func_name": "Target"}),
                encoding="utf-8",
            )
            base = self._spec(
                reference_yaml_paths=["references/target.{arch}.yaml"],
                dependency_policy={"Target.yaml": "required"},
            )
            cases = [
                (
                    base,
                    ["Target.yaml"],
                    ["Target.yaml"],
                    {"EpCookie": "struct_offset"},
                ),
                (
                    {**base, "dependency_policy": {"Extra.yaml": "required"}},
                    ["Extra.yaml"],
                    [],
                    {"EpCookie": "struct_offset"},
                ),
                (
                    base,
                    [],
                    ["Target.yaml"],
                    {"EpCookie": "struct_offset"},
                ),
                (
                    base,
                    ["Target.yaml"],
                    [],
                    {"EpCookie": "func"},
                ),
            ]
            for spec, required, optional, categories in cases:
                with self.subTest(spec=spec, categories=categories):
                    specs = ida_llm_specs.build_llm_decompile_specs_map([spec])
                    self.assertFalse(
                        ida_llm_specs.validate_llm_decompile_specs(
                            specs,
                            expected_inputs=required,
                            optional_inputs=optional,
                            category_by_symbol=categories,
                            scripts_dir=scripts_dir,
                            arch="amd64",
                        )
                    )

    def test_semantic_query_names_preserve_struct_expression(self) -> None:
        specs = ida_llm_specs.build_llm_decompile_specs_map(
            [
                self._spec(),
                self._spec(
                    symbol_name="MmCreateProcessAddressSpace",
                    expected_result_sections=["found_call", "found_funcptr"],
                ),
            ]
        )

        queries = ida_llm_specs.build_semantic_query_names(
            specs,
            category_by_symbol={
                "EpCookie": "struct_offset",
                "MmCreateProcessAddressSpace": "func",
            },
            struct_metadata={
                "EpCookie": {
                    "symbol_expr": "_EPROCESS->Cookie",
                    "struct_name": "_EPROCESS",
                    "member_name": "Cookie",
                }
            },
        )

        self.assertEqual(
            {
                "EpCookie": "_EPROCESS->Cookie",
                "MmCreateProcessAddressSpace": "MmCreateProcessAddressSpace",
            },
            queries,
        )

    def test_all_finders_use_strict_dict_entries(self) -> None:
        finder_paths = sorted(Path("ida_preprocessor_scripts").glob("find-*.py"))
        static_files = 0
        static_entries = 0
        for path in finder_paths:
            tree = ast.parse(path.read_text(encoding="utf-8"))
            file_entries = 0
            for node in tree.body:
                if not isinstance(node, ast.Assign):
                    continue
                names = {
                    target.id
                    for target in node.targets
                    if isinstance(target, ast.Name)
                }
                if "LLM_DECOMPILE" in names:
                    self.assertIsInstance(node.value, ast.List, path)
                    entries = node.value.elts
                elif "LLM_DECOMPILE_BY_FUNCTION" in names:
                    self.assertIsInstance(node.value, ast.Dict, path)
                    entries = [
                        entry
                        for value in node.value.values
                        for entry in value.elts
                    ]
                else:
                    continue
                for entry in entries:
                    self.assertIsInstance(entry, ast.Dict, path)
                    keys = {key.value for key in entry.keys}
                    self.assertEqual(REQUIRED_KEYS, keys, path)
                file_entries += len(entries)
            if file_entries:
                static_files += 1
                static_entries += file_entries

        dynamic_path = Path(
            "ida_preprocessor_scripts/find-KtInitialStack-AND-KtStackBase-"
            "AND-KtStackLimit.py"
        )
        module_spec = importlib.util.spec_from_file_location(
            "test_dynamic_kthread_llm_specs", dynamic_path
        )
        module = importlib.util.module_from_spec(module_spec)
        module_spec.loader.exec_module(module)
        dynamic_entries = module._llm_decompile_specs(
            Path("/symbols/ntoskrnl/amd64/.10.0.18305.1")
        )
        self.assertEqual(3, len(dynamic_entries))
        for entry in dynamic_entries:
            self.assertEqual(REQUIRED_KEYS, set(entry))

        self.assertEqual(38, static_files)
        self.assertEqual(66, static_entries)
        self.assertEqual(39, static_files + 1)
        self.assertEqual(69, static_entries + len(dynamic_entries))


if __name__ == "__main__":
    unittest.main()
