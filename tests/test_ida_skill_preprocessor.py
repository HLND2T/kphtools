from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import AsyncMock, patch

import ida_skill_preprocessor
from symbol_config import SkillSpec, SymbolSpec, load_config


COMBINED_ALPC_SKILL_NAME = (
    "find-AlpcAttributes-AND-AlpcAttributesFlags-AND-AlpcCommunicationInfo-"
    "AND-AlpcOwnerProcess-AND-AlpcConnectionPort-"
    "AND-AlpcServerCommunicationPort-AND-AlpcClientCommunicationPort"
)


class TestIdaSkillPreprocessor(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        ida_skill_preprocessor._SCRIPT_ENTRY_CACHE.clear()

    def test_repository_config_skills_have_matching_script_and_skill_doc(self) -> None:
        config = load_config("config.yaml")

        for module in config.modules:
            for skill in module.skills:
                script_path = (
                    Path("ida_preprocessor_scripts") / f"{skill.name}.py"
                )
                skill_doc_path = Path(".claude") / "skills" / skill.name / "SKILL.md"
                self.assertTrue(script_path.is_file(), script_path)
                self.assertTrue(skill_doc_path.is_file(), skill_doc_path)

    def test_repository_config_skills_export_loadable_preprocess_entries(self) -> None:
        config = load_config("config.yaml")

        ida_skill_preprocessor._SCRIPT_ENTRY_CACHE.clear()
        for module in config.modules:
            for skill in module.skills:
                entry = ida_skill_preprocessor._get_preprocess_entry(skill.name)
                self.assertTrue(callable(entry), skill.name)

    async def test_struct_script_dispatches_through_preprocess_common_skill(self) -> None:
        with patch(
            "ida_preprocessor_common.preprocess_common_skill",
            new=AsyncMock(return_value=ida_skill_preprocessor.PREPROCESS_STATUS_SUCCESS),
        ) as mock_common:
            status = await ida_skill_preprocessor.preprocess_single_skill_via_mcp(
                session=AsyncMock(),
                skill=SkillSpec(
                    name="find-EpObjectTable",
                    expected_output=["EpObjectTable.yaml"],
                    expected_input=[],
                ),
                symbol=SymbolSpec(
                    name="EpObjectTable",
                    category="struct_offset",
                    data_type="uint16",
                ),
                binary_dir=Path("/tmp"),
                pdb_path=Path("/tmp/ntkrnlmp.pdb"),
                debug=False,
                llm_config=None,
            )

        self.assertEqual(ida_skill_preprocessor.PREPROCESS_STATUS_SUCCESS, status)
        self.assertEqual(
            ["EpObjectTable"],
            mock_common.await_args.kwargs["struct_member_names"],
        )
        self.assertEqual(
            {
                "EpObjectTable": {
                    "symbol_expr": "_EPROCESS->ObjectTable",
                    "struct_name": "_EPROCESS",
                    "member_name": "ObjectTable",
                    "bits": False,
                }
            },
            mock_common.await_args.kwargs["struct_metadata"],
        )
        self.assertEqual(
            {"EpObjectTable": ["struct_name", "member_name", "offset"]},
            mock_common.await_args.kwargs["generate_yaml_desired_fields"],
        )

    async def test_combined_alpc_attributes_script_dispatches_owner_process(self) -> None:
        with patch(
            "ida_preprocessor_common.preprocess_common_skill",
            new=AsyncMock(return_value=ida_skill_preprocessor.PREPROCESS_STATUS_SUCCESS),
        ) as mock_common:
            status = await ida_skill_preprocessor.preprocess_single_skill_via_mcp(
                session=AsyncMock(),
                skill=SkillSpec(
                    name=COMBINED_ALPC_SKILL_NAME,
                    expected_output=[
                        "AlpcAttributes.yaml",
                        "AlpcAttributesFlags.yaml",
                        "AlpcCommunicationInfo.yaml",
                        "AlpcOwnerProcess.yaml",
                        "AlpcConnectionPort.yaml",
                        "AlpcServerCommunicationPort.yaml",
                        "AlpcClientCommunicationPort.yaml",
                    ],
                    expected_input=[],
                ),
                symbol=SymbolSpec(
                    name="AlpcOwnerProcess",
                    category="struct_offset",
                    data_type="uint16",
                ),
                binary_dir=Path("/tmp"),
                pdb_path=Path("/tmp/ntkrnlmp.pdb"),
                debug=False,
                llm_config={"model": "test-model", "api_key": "test-key"},
            )

        self.assertEqual(ida_skill_preprocessor.PREPROCESS_STATUS_SUCCESS, status)
        self.assertIn(
            (
                "AlpcOwnerProcess",
                "_ALPC_PORT->OwnerProcess",
                "prompt/call_llm_decompile.md",
                "references/ntoskrnl/AlpcpDeletePort.{arch}.yaml",
            ),
            mock_common.await_args.kwargs["llm_decompile_specs"],
        )
        self.assertEqual(
            {
                "symbol_expr": "_ALPC_PORT->OwnerProcess",
                "struct_name": "_ALPC_PORT",
                "member_name": "OwnerProcess",
                "bits": False,
            },
            mock_common.await_args.kwargs["struct_metadata"]["AlpcOwnerProcess"],
        )

    async def test_combined_alpc_attributes_script_dispatches_alpc_attributes(self) -> None:
        with patch(
            "ida_preprocessor_common.preprocess_common_skill",
            new=AsyncMock(return_value=ida_skill_preprocessor.PREPROCESS_STATUS_SUCCESS),
        ) as mock_common:
            status = await ida_skill_preprocessor.preprocess_single_skill_via_mcp(
                session=AsyncMock(),
                skill=SkillSpec(
                    name=COMBINED_ALPC_SKILL_NAME,
                    expected_output=[
                        "AlpcAttributes.yaml",
                        "AlpcAttributesFlags.yaml",
                        "AlpcCommunicationInfo.yaml",
                        "AlpcOwnerProcess.yaml",
                        "AlpcConnectionPort.yaml",
                        "AlpcServerCommunicationPort.yaml",
                        "AlpcClientCommunicationPort.yaml",
                    ],
                    expected_input=[],
                ),
                symbol=SymbolSpec(
                    name="AlpcAttributes",
                    category="struct_offset",
                    data_type="uint16",
                ),
                binary_dir=Path("/tmp"),
                pdb_path=Path("/tmp/ntkrnlmp.pdb"),
                debug=False,
                llm_config={"model": "test-model", "api_key": "test-key"},
            )

        self.assertEqual(ida_skill_preprocessor.PREPROCESS_STATUS_SUCCESS, status)
        self.assertEqual(
            [
                (
                    "AlpcAttributes",
                    "_ALPC_PORT->PortAttributes",
                    "prompt/call_llm_decompile.md",
                    "references/ntoskrnl/AlpcpDeletePort.{arch}.yaml",
                ),
                (
                    "AlpcAttributesFlags",
                    "_ALPC_PORT_ATTRIBUTES->Flags",
                    "prompt/call_llm_decompile.md",
                    "references/ntoskrnl/AlpcpDeletePort.{arch}.yaml",
                ),
                (
                    "AlpcCommunicationInfo",
                    "_ALPC_PORT->CommunicationInfo",
                    "prompt/call_llm_decompile.md",
                    "references/ntoskrnl/AlpcpDeletePort.{arch}.yaml",
                ),
                (
                    "AlpcOwnerProcess",
                    "_ALPC_PORT->OwnerProcess",
                    "prompt/call_llm_decompile.md",
                    "references/ntoskrnl/AlpcpDeletePort.{arch}.yaml",
                ),
                (
                    "AlpcConnectionPort",
                    "_ALPC_COMMUNICATION_INFO->ConnectionPort",
                    "prompt/call_llm_decompile.md",
                    "references/ntoskrnl/AlpcpDeletePort.{arch}.yaml",
                ),
                (
                    "AlpcServerCommunicationPort",
                    "_ALPC_COMMUNICATION_INFO->ServerCommunicationPort",
                    "prompt/call_llm_decompile.md",
                    "references/ntoskrnl/AlpcpDeletePort.{arch}.yaml",
                ),
                (
                    "AlpcClientCommunicationPort",
                    "_ALPC_COMMUNICATION_INFO->ClientCommunicationPort",
                    "prompt/call_llm_decompile.md",
                    "references/ntoskrnl/AlpcpDeletePort.{arch}.yaml",
                ),
            ],
            mock_common.await_args.kwargs["llm_decompile_specs"],
        )

    async def test_combined_alpc_attributes_script_dispatches_alpc_attributes_flags(self) -> None:
        with patch(
            "ida_preprocessor_common.preprocess_common_skill",
            new=AsyncMock(return_value=ida_skill_preprocessor.PREPROCESS_STATUS_SUCCESS),
        ) as mock_common:
            status = await ida_skill_preprocessor.preprocess_single_skill_via_mcp(
                session=AsyncMock(),
                skill=SkillSpec(
                    name=COMBINED_ALPC_SKILL_NAME,
                    expected_output=[
                        "AlpcAttributes.yaml",
                        "AlpcAttributesFlags.yaml",
                        "AlpcCommunicationInfo.yaml",
                        "AlpcOwnerProcess.yaml",
                        "AlpcConnectionPort.yaml",
                        "AlpcServerCommunicationPort.yaml",
                        "AlpcClientCommunicationPort.yaml",
                    ],
                    expected_input=[],
                ),
                symbol=SymbolSpec(
                    name="AlpcAttributesFlags",
                    category="struct_offset",
                    data_type="uint16",
                ),
                binary_dir=Path("/tmp"),
                pdb_path=Path("/tmp/ntkrnlmp.pdb"),
                debug=False,
                llm_config={"model": "test-model", "api_key": "test-key"},
            )

        self.assertEqual(ida_skill_preprocessor.PREPROCESS_STATUS_SUCCESS, status)
        self.assertEqual(
            [
                "AlpcAttributes",
                "AlpcAttributesFlags",
                "AlpcCommunicationInfo",
                "AlpcOwnerProcess",
                "AlpcConnectionPort",
                "AlpcServerCommunicationPort",
                "AlpcClientCommunicationPort",
            ],
            mock_common.await_args.kwargs["struct_member_names"],
        )
        self.assertEqual(
            {
                "AlpcAttributesFlags": {
                    "symbol_expr": "_ALPC_PORT_ATTRIBUTES->Flags",
                    "struct_name": "_ALPC_PORT_ATTRIBUTES",
                    "member_name": "Flags",
                    "bits": False,
                }
            },
            {
                "AlpcAttributesFlags": mock_common.await_args.kwargs[
                    "struct_metadata"
                ]["AlpcAttributesFlags"]
            },
        )

    async def test_combined_alpc_attributes_script_dispatches_alpc_communication_info(
        self,
    ) -> None:
        with patch(
            "ida_preprocessor_common.preprocess_common_skill",
            new=AsyncMock(return_value=ida_skill_preprocessor.PREPROCESS_STATUS_SUCCESS),
        ) as mock_common:
            status = await ida_skill_preprocessor.preprocess_single_skill_via_mcp(
                session=AsyncMock(),
                skill=SkillSpec(
                    name=COMBINED_ALPC_SKILL_NAME,
                    expected_output=[
                        "AlpcAttributes.yaml",
                        "AlpcAttributesFlags.yaml",
                        "AlpcCommunicationInfo.yaml",
                        "AlpcOwnerProcess.yaml",
                        "AlpcConnectionPort.yaml",
                        "AlpcServerCommunicationPort.yaml",
                        "AlpcClientCommunicationPort.yaml",
                    ],
                    expected_input=[],
                ),
                symbol=SymbolSpec(
                    name="AlpcCommunicationInfo",
                    category="struct_offset",
                    data_type="uint16",
                ),
                binary_dir=Path("/tmp"),
                pdb_path=Path("/tmp/ntkrnlmp.pdb"),
                debug=False,
                llm_config={"model": "test-model", "api_key": "test-key"},
            )

        self.assertEqual(ida_skill_preprocessor.PREPROCESS_STATUS_SUCCESS, status)
        self.assertEqual(
            {
                "symbol_expr": "_ALPC_PORT->CommunicationInfo",
                "struct_name": "_ALPC_PORT",
                "member_name": "CommunicationInfo",
                "bits": False,
            },
            mock_common.await_args.kwargs["struct_metadata"]["AlpcCommunicationInfo"],
        )
        self.assertEqual(
            ["struct_name", "member_name", "offset"],
            mock_common.await_args.kwargs["generate_yaml_desired_fields"][
                "AlpcCommunicationInfo"
            ],
        )

    async def test_combined_alpc_attributes_script_dispatches_merged_alpc_members(
        self,
    ) -> None:
        cases = [
            (
                "AlpcOwnerProcess",
                {
                    "symbol_expr": "_ALPC_PORT->OwnerProcess",
                    "struct_name": "_ALPC_PORT",
                    "member_name": "OwnerProcess",
                    "bits": False,
                },
            ),
            (
                "AlpcConnectionPort",
                {
                    "symbol_expr": "_ALPC_COMMUNICATION_INFO->ConnectionPort",
                    "struct_name": "_ALPC_COMMUNICATION_INFO",
                    "member_name": "ConnectionPort",
                    "bits": False,
                },
            ),
            (
                "AlpcServerCommunicationPort",
                {
                    "symbol_expr": "_ALPC_COMMUNICATION_INFO->ServerCommunicationPort",
                    "struct_name": "_ALPC_COMMUNICATION_INFO",
                    "member_name": "ServerCommunicationPort",
                    "bits": False,
                },
            ),
            (
                "AlpcClientCommunicationPort",
                {
                    "symbol_expr": "_ALPC_COMMUNICATION_INFO->ClientCommunicationPort",
                    "struct_name": "_ALPC_COMMUNICATION_INFO",
                    "member_name": "ClientCommunicationPort",
                    "bits": False,
                },
            ),
        ]
        for symbol_name, expected_metadata in cases:
            with self.subTest(symbol_name=symbol_name):
                with patch(
                    "ida_preprocessor_common.preprocess_common_skill",
                    new=AsyncMock(
                        return_value=ida_skill_preprocessor.PREPROCESS_STATUS_SUCCESS
                    ),
                ) as mock_common:
                    status = await ida_skill_preprocessor.preprocess_single_skill_via_mcp(
                        session=AsyncMock(),
                        skill=SkillSpec(
                            name=COMBINED_ALPC_SKILL_NAME,
                            expected_output=[
                                "AlpcAttributes.yaml",
                                "AlpcAttributesFlags.yaml",
                                "AlpcCommunicationInfo.yaml",
                                "AlpcOwnerProcess.yaml",
                                "AlpcConnectionPort.yaml",
                                "AlpcServerCommunicationPort.yaml",
                                "AlpcClientCommunicationPort.yaml",
                            ],
                            expected_input=[],
                        ),
                        symbol=SymbolSpec(
                            name=symbol_name,
                            category="struct_offset",
                            data_type="uint16",
                        ),
                        binary_dir=Path("/tmp"),
                        pdb_path=Path("/tmp/ntkrnlmp.pdb"),
                        debug=False,
                        llm_config={"model": "test-model", "api_key": "test-key"},
                    )

                self.assertEqual(
                    ida_skill_preprocessor.PREPROCESS_STATUS_SUCCESS,
                    status,
                )
                self.assertEqual(
                    expected_metadata,
                    mock_common.await_args.kwargs["struct_metadata"][symbol_name],
                )
                self.assertEqual(
                    ["struct_name", "member_name", "offset"],
                    mock_common.await_args.kwargs["generate_yaml_desired_fields"][
                        symbol_name
                    ],
                )

    async def test_bitfield_struct_script_dispatches_bitfield_metadata(
        self,
    ) -> None:
        with patch(
            "ida_preprocessor_common.preprocess_common_skill",
            new=AsyncMock(return_value=ida_skill_preprocessor.PREPROCESS_STATUS_SUCCESS),
        ) as mock_common:
            status = await ida_skill_preprocessor.preprocess_single_skill_via_mcp(
                session=AsyncMock(),
                skill=SkillSpec(
                    name="find-ObDecodeShift",
                    expected_output=["ObDecodeShift.yaml"],
                    expected_input=[],
                ),
                symbol=SymbolSpec(
                    name="ObDecodeShift",
                    category="struct_offset",
                    data_type="uint16",
                ),
                binary_dir=Path("/tmp"),
                pdb_path=Path("/tmp/ntkrnlmp.pdb"),
                debug=False,
                llm_config={"model": "test-model"},
            )

        self.assertEqual(ida_skill_preprocessor.PREPROCESS_STATUS_SUCCESS, status)
        self.assertEqual(
            {
                "ObDecodeShift": {
                    "symbol_expr": "_HANDLE_TABLE_ENTRY->ObjectPointerBits",
                    "struct_name": "_HANDLE_TABLE_ENTRY",
                    "member_name": "ObjectPointerBits",
                    "bits": True,
                }
            },
            mock_common.await_args.kwargs["struct_metadata"],
        )
        self.assertEqual(
            {
                "ObDecodeShift": [
                    "struct_name",
                    "member_name",
                    "offset",
                    "bit_offset",
                ]
            },
            mock_common.await_args.kwargs["generate_yaml_desired_fields"],
        )

    async def test_gv_script_dispatches_alias_metadata(
        self,
    ) -> None:
        with patch(
            "ida_preprocessor_common.preprocess_common_skill",
            new=AsyncMock(return_value=ida_skill_preprocessor.PREPROCESS_STATUS_SUCCESS),
        ) as mock_common:
            status = await ida_skill_preprocessor.preprocess_single_skill_via_mcp(
                session=AsyncMock(),
                skill=SkillSpec(
                    name="find-PspCreateProcessNotifyRoutine",
                    expected_output=["PspCreateProcessNotifyRoutine.yaml"],
                    expected_input=[],
                ),
                symbol=SymbolSpec(
                    name="PspCreateProcessNotifyRoutine",
                    category="gv",
                    data_type="uint32",
                ),
                binary_dir=Path("/tmp"),
                pdb_path=Path("/tmp/ntkrnlmp.pdb"),
                debug=False,
                llm_config=None,
            )

        self.assertEqual(ida_skill_preprocessor.PREPROCESS_STATUS_SUCCESS, status)
        self.assertEqual(
            ["PspCreateProcessNotifyRoutine"],
            mock_common.await_args.kwargs["gv_names"],
        )
        self.assertEqual(
            {
                "PspCreateProcessNotifyRoutine": {
                    "alias": ["PspCreateProcessNotifyRoutine"]
                }
            },
            mock_common.await_args.kwargs["gv_metadata"],
        )

    async def test_func_script_dispatches_alias_metadata(
        self,
    ) -> None:
        with patch(
            "ida_preprocessor_common.preprocess_common_skill",
            new=AsyncMock(return_value=ida_skill_preprocessor.PREPROCESS_STATUS_SUCCESS),
        ) as mock_common:
            status = await ida_skill_preprocessor.preprocess_single_skill_via_mcp(
                session=AsyncMock(),
                skill=SkillSpec(
                    name="find-ExReferenceCallBackBlock",
                    expected_output=["ExReferenceCallBackBlock.yaml"],
                    expected_input=[],
                ),
                symbol=SymbolSpec(
                    name="ExReferenceCallBackBlock",
                    category="func",
                    data_type="uint32",
                ),
                binary_dir=Path("/tmp"),
                pdb_path=Path("/tmp/ntkrnlmp.pdb"),
                debug=False,
                llm_config=None,
            )

        self.assertEqual(ida_skill_preprocessor.PREPROCESS_STATUS_SUCCESS, status)
        self.assertEqual(
            ["ExReferenceCallBackBlock"],
            mock_common.await_args.kwargs["func_names"],
        )
        self.assertEqual(
            {
                "ExReferenceCallBackBlock": {
                    "alias": ["ExReferenceCallBackBlock"]
                }
            },
            mock_common.await_args.kwargs["func_metadata"],
        )

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
