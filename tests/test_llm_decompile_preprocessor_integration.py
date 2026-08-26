import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import AsyncMock, patch

import yaml

import ida_mcp_resolver
from ida_llm_response import empty_llm_decompile_result


class TestLlmDecompileRequestIntegration(unittest.TestCase):
    def test_conflicting_artifacts_cannot_share_a_semantic_query(self) -> None:
        specs_map = {
            "One": {
                "prompt_path": "prompt.md",
                "reference_yaml_paths": ["ref.yaml"],
                "expected_result_sections": ["found_call"],
                "dependency_policy": {"Ref.yaml": "required"},
            },
            "Two": {
                "prompt_path": "prompt.md",
                "reference_yaml_paths": ["ref.yaml"],
                "expected_result_sections": ["found_call"],
                "dependency_policy": {"Ref.yaml": "required"},
            },
        }
        self.assertIsNone(
            ida_mcp_resolver._collect_batch_context(
                specs_map,
                specs_map["One"],
                {"One": "Same", "Two": "Same"},
            )
        )

    def test_strict_specs_build_semantic_batch_and_dependency_targets(self) -> None:
        with TemporaryDirectory() as temp_dir:
            scripts_dir = Path(temp_dir)
            (scripts_dir / "prompt").mkdir()
            (scripts_dir / "references").mkdir()
            (scripts_dir / "prompt" / "call.md").write_text(
                "{symbol_name_list}\n{reference_blocks}\n{target_blocks}",
                encoding="utf-8",
            )
            (scripts_dir / "references" / "Ref.amd64.yaml").write_text(
                yaml.safe_dump(
                    {
                        "func_name": "Ref",
                        "func_va": "0x140001000",
                        "disasm_code": "00001000 nop",
                        "procedure": "",
                        "optional_funcs": ["Optional", "Optional"],
                    }
                ),
                encoding="utf-8",
            )
            specs = [
                {
                    "symbol_name": "ArtifactFunc",
                    "prompt_path": "prompt/call.md",
                    "reference_yaml_paths": ["references/Ref.{arch}.yaml"],
                    "expected_result_sections": ["found_call"],
                    "dependency_policy": {"Ref.yaml": "required"},
                },
                {
                    "symbol_name": "ArtifactMember",
                    "prompt_path": "prompt/call.md",
                    "reference_yaml_paths": ["references/Ref.{arch}.yaml"],
                    "expected_result_sections": ["found_struct_offset"],
                    "instruction_rules": [
                        {
                            "regex": r"(?i)^mov\s+.+$",
                            "text": "mov operands",
                        }
                    ],
                    "expected_size": 4,
                    "dependency_policy": {"Ref.yaml": "required"},
                },
            ]
            config = {
                "model": "test-model",
                "api_key": "test-key",
                "_required_output_symbols": ["ArtifactFunc"],
                "_semantic_query_names": {
                    "ArtifactFunc": "ArtifactFunc",
                    "ArtifactMember": "_ITEM->Member",
                },
            }
            with patch.object(
                ida_mcp_resolver,
                "_get_preprocessor_scripts_dir",
                return_value=scripts_dir,
            ):
                request = ida_mcp_resolver._prepare_llm_decompile_request(
                    symbol_name="ArtifactMember",
                    llm_decompile_specs=specs,
                    llm_config=config,
                    binary_dir=scripts_dir / "amd64" / "module",
                )
        self.assertEqual(["ArtifactFunc", "_ITEM->Member"], request["llm_symbol_names"])
        self.assertEqual(["ArtifactFunc"], request["required_result_symbols"])
        self.assertEqual(["Ref", "Optional"], request["target_func_names"])
        self.assertEqual(["Ref"], request["required_target_func_names"])
        self.assertEqual(
            {
                "ArtifactFunc": ["found_call"],
                "_ITEM->Member": ["found_struct_offset"],
            },
            request["expected_result_sections"],
        )
        self.assertEqual(
            {
                "_ITEM->Member": {
                    "instruction_rules": [
                        {
                            "regex": r"(?i)^mov\s+.+$",
                            "text": "mov operands",
                        }
                    ],
                    "expected_size": 4,
                }
            },
            request["instruction_validations"],
        )

    def test_request_paths_expand_module_name(self) -> None:
        with TemporaryDirectory() as temp_dir:
            scripts_dir = Path(temp_dir)
            prompt_path = scripts_dir / "prompt" / "ntoskrnl" / "call.md"
            reference_path = (
                scripts_dir / "references" / "ntoskrnl" / "Ref.amd64.yaml"
            )
            prompt_path.parent.mkdir(parents=True)
            reference_path.parent.mkdir(parents=True)
            prompt_path.write_text("{symbol_name_list}", encoding="utf-8")
            reference_path.write_text(
                yaml.safe_dump(
                    {
                        "func_name": "Ref",
                        "func_va": "0x140001000",
                        "disasm_code": "00001000 nop",
                        "procedure": "",
                    }
                ),
                encoding="utf-8",
            )
            specs = [
                {
                    "symbol_name": "Target",
                    "prompt_path": "prompt/{module_name}/call.md",
                    "reference_yaml_paths": [
                        "references/{module_name}/Ref.{arch}.yaml"
                    ],
                    "expected_result_sections": ["found_call"],
                    "dependency_policy": {"Ref.yaml": "required"},
                }
            ]
            config = {
                "model": "test-model",
                "api_key": "test-key",
                "_semantic_query_names": {"Target": "Target"},
            }
            binary_dir = (
                scripts_dir
                / "amd64"
                / "ntoskrnl.exe.10.0.26100.1"
                / "hash"
            )
            with patch.object(
                ida_mcp_resolver,
                "_get_preprocessor_scripts_dir",
                return_value=scripts_dir,
            ):
                request = ida_mcp_resolver._prepare_llm_decompile_request(
                    symbol_name="Target",
                    llm_decompile_specs=specs,
                    llm_config=config,
                    binary_dir=binary_dir,
                )

        self.assertEqual(str(prompt_path.resolve()), request["prompt_path"])
        self.assertEqual([str(reference_path.resolve())], request["reference_paths"])


class TestLlmDecompileResolverIntegration(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        ida_mcp_resolver._LLM_DECOMPILE_RESULT_CACHE.clear()
        self.request = {
            "llm_symbol_name": "_ITEM->First",
            "llm_symbol_names": ["_ITEM->First", "_ITEM->Second"],
            "expected_result_sections": {
                "_ITEM->First": ["found_struct_offset"],
                "_ITEM->Second": ["found_struct_offset"],
            },
            "instruction_validations": {
                "_ITEM->First": {"expected_size": 4},
                "_ITEM->Second": {"expected_size": 8},
            },
            "target_func_names": ["Ref"],
            "required_target_func_names": ["Ref"],
            "reference_items": [{"func_name": "Ref"}],
            "prompt_template": "{symbol_name_list}",
            "prompt_path": "prompt.md",
            "reference_paths": ["ref.yaml"],
            "arch": "amd64",
        }
        self.target_items = [
            {
                "func_name": "Ref",
                "func_va": "0x140001000",
                "disasm_code": "00001000 mov eax, [rcx+10h]",
                "procedure": "",
            }
        ]

    async def test_configured_client_is_forwarded_to_validated_decompiler(self) -> None:
        client = object()
        with patch.object(
            ida_mcp_resolver,
            "_validated_call_llm_decompile",
            AsyncMock(return_value=empty_llm_decompile_result()),
        ) as call:
            await ida_mcp_resolver.call_llm_decompile(
                llm_config={
                    "client": client,
                    "model": "test-model",
                    "api_key": "test-key",
                },
                symbol_name_list=["Target"],
                reference_items=[],
                target_items=[],
                prompt_template="{symbol_name_list}",
            )

        self.assertIs(client, call.await_args.kwargs["client"])

    async def test_batched_result_is_called_once_and_consumed_by_two_artifacts(self) -> None:
        result = {
            **empty_llm_decompile_result(),
            "found_struct_offset": [
                {
                    "insn_va": "0x1000",
                    "insn_disasm": "mov eax, [rcx+10h]",
                    "offset": "0x10",
                    "size": "4",
                    "struct_name": "_ITEM",
                    "member_name": "First",
                },
                {
                    "insn_va": "0x1000",
                    "insn_disasm": "mov eax, [rcx+10h]",
                    "offset": "0x18",
                    "size": "8",
                    "struct_name": "_ITEM",
                    "member_name": "Second",
                },
            ],
        }
        with (
            patch.object(ida_mcp_resolver, "_prepare_llm_decompile_request", return_value=self.request),
            patch.object(
                ida_mcp_resolver,
                "_load_llm_decompile_target_details_via_mcp",
                AsyncMock(return_value=self.target_items),
            ),
            patch.object(ida_mcp_resolver, "call_llm_decompile", AsyncMock(return_value=result)) as call,
        ):
            first = await self._resolve("First")
            second = await self._resolve("Second")
        self.assertEqual(0x10, first["offset"])
        self.assertEqual(0x18, second["offset"])
        call.assert_awaited_once()
        self.assertEqual(
            self.request["expected_result_sections"],
            call.await_args.kwargs["llm_config"]["_expected_result_sections"],
        )
        self.assertEqual(
            self.request["instruction_validations"],
            call.await_args.kwargs["llm_config"]["_instruction_validations"],
        )

    async def test_empty_result_is_cached_as_terminal_batch_result(self) -> None:
        with (
            patch.object(ida_mcp_resolver, "_prepare_llm_decompile_request", return_value=self.request),
            patch.object(
                ida_mcp_resolver,
                "_load_llm_decompile_target_details_via_mcp",
                AsyncMock(return_value=self.target_items),
            ),
            patch.object(
                ida_mcp_resolver,
                "call_llm_decompile",
                AsyncMock(return_value=empty_llm_decompile_result()),
            ) as call,
        ):
            self.assertIsNone(await self._resolve("First"))
            self.assertIsNone(await self._resolve("First"))
        self.assertEqual(1, call.await_count)

    def test_instruction_validations_are_part_of_cache_key(self) -> None:
        llm_config = {"model": "test-model"}
        first = ida_mcp_resolver._build_llm_decompile_result_cache_key(
            request=self.request,
            llm_config=llm_config,
            binary_dir=Path("binary"),
            image_base=0x140000000,
        )
        changed_request = {
            **self.request,
            "instruction_validations": {
                **self.request["instruction_validations"],
                "_ITEM->First": {"expected_size": 8},
            },
        }
        second = ida_mcp_resolver._build_llm_decompile_result_cache_key(
            request=changed_request,
            llm_config=llm_config,
            binary_dir=Path("binary"),
            image_base=0x140000000,
        )

        self.assertNotEqual(first, second)
        self.assertEqual("kphtools-atomic-batch-v3", ida_mcp_resolver._LLM_RESULT_CONTRACT_VERSION)

    async def test_found_call_precedes_function_pointer_resolution(self) -> None:
        request = {**self.request, "llm_symbol_name": "Target", "llm_symbol_names": ["Target"]}
        result = {
            **empty_llm_decompile_result(),
            "found_call": [{"insn_va": "0x1000", "insn_disasm": "jmp sub_2000", "func_name": "Target"}],
            "found_funcptr": [{"insn_va": "0x1010", "insn_disasm": "lea rax, sub_2000", "funcptr_name": "Target"}],
        }
        with (
            patch.object(ida_mcp_resolver, "_prepare_llm_decompile_request", return_value=request),
            patch.object(
                ida_mcp_resolver,
                "_load_llm_decompile_target_details_via_mcp",
                AsyncMock(return_value=self.target_items),
            ),
            patch.object(ida_mcp_resolver, "call_llm_decompile", AsyncMock(return_value=result)),
            patch.object(
                ida_mcp_resolver,
                "_resolve_direct_call_target_via_mcp",
                AsyncMock(return_value=0x140002000),
            ),
            patch.object(
                ida_mcp_resolver,
                "_resolve_funcptr_target_via_mcp",
                AsyncMock(),
            ) as funcptr,
        ):
            payload = await ida_mcp_resolver.resolve_symbol_via_llm_decompile(
                session=AsyncMock(),
                symbol_name="Target",
                category="func",
                binary_dir="symbols/amd64/module/hash",
                image_base=0x140000000,
                llm_decompile_specs=[],
                llm_config={"model": "test", "api_key": "key"},
            )
        self.assertEqual(0x2000, payload["func_rva"])
        funcptr.assert_not_awaited()

    async def _resolve(self, member_name: str):
        return await ida_mcp_resolver.resolve_symbol_via_llm_decompile(
            session=AsyncMock(),
            symbol_name=f"Artifact{member_name}",
            category="struct_offset",
            binary_dir="symbols/amd64/module/hash",
            image_base=0x140000000,
            llm_decompile_specs=[],
            llm_config={"model": "test", "api_key": "key"},
            struct_metadata={"struct_name": "_ITEM", "member_name": member_name},
        )


if __name__ == "__main__":
    unittest.main()
