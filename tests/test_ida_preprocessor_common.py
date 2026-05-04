from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

import ida_preprocessor_common
import ida_preprocessor_scripts.generic_struct_offset as generic_struct_offset
from symbol_artifacts import load_artifact


class TestIdaPreprocessorCommon(unittest.IsolatedAsyncioTestCase):
    async def test_preprocess_common_skill_writes_struct_yaml_from_script_metadata(
        self,
    ) -> None:
        with TemporaryDirectory() as temp_dir:
            with patch.object(
                ida_preprocessor_common,
                "preprocess_struct_symbol",
                new=AsyncMock(
                    return_value={
                        "struct_name": "_ETW_GUID_ENTRY",
                        "member_name": "Guid",
                        "offset": 0x10,
                    }
                ),
            ):
                status = await ida_preprocessor_common.preprocess_common_skill(
                    session=AsyncMock(),
                    skill=SimpleNamespace(name="find-EgeGuid"),
                    symbol=SimpleNamespace(
                        name="EgeGuid",
                        category="struct_offset",
                        data_type="uint16",
                    ),
                    binary_dir=Path(temp_dir),
                    pdb_path=Path(temp_dir) / "ntkrnlmp.pdb",
                    debug=False,
                    llm_config=None,
                    struct_member_names=["EgeGuid"],
                    struct_metadata={
                        "EgeGuid": {
                            "symbol_expr": "_ETW_GUID_ENTRY->Guid",
                            "struct_name": "_ETW_GUID_ENTRY",
                            "member_name": "Guid",
                            "bits": False,
                        }
                    },
                    generate_yaml_desired_fields={
                        "EgeGuid": ["struct_name", "member_name", "offset"]
                    },
                )

            self.assertEqual(ida_preprocessor_common.PREPROCESS_STATUS_SUCCESS, status)
            payload = load_artifact(Path(temp_dir) / "EgeGuid.yaml")
            self.assertEqual(
                {
                    "category": "struct_offset",
                    "struct_name": "_ETW_GUID_ENTRY",
                    "member_name": "Guid",
                    "offset": 0x10,
                },
                payload,
            )

    async def test_preprocess_common_skill_fails_when_requested_field_is_missing(
        self,
    ) -> None:
        with TemporaryDirectory() as temp_dir, patch.object(
            ida_preprocessor_common,
            "preprocess_struct_symbol",
            new=AsyncMock(
                return_value={
                    "struct_name": "_HANDLE_TABLE_ENTRY",
                    "member_name": "ObjectPointerBits",
                    "offset": 0x8,
                }
            ),
        ):
            status = await ida_preprocessor_common.preprocess_common_skill(
                session=AsyncMock(),
                skill=SimpleNamespace(
                    name="find-ObDecodeShift",
                ),
                symbol=SimpleNamespace(
                    name="ObDecodeShift",
                    category="struct_offset",
                    data_type="uint16",
                ),
                binary_dir=Path(temp_dir),
                pdb_path=Path(temp_dir) / "ntkrnlmp.pdb",
                debug=False,
                llm_config={"model": "test-model"},
                struct_member_names=["ObDecodeShift"],
                struct_metadata={
                    "ObDecodeShift": {
                        "symbol_expr": "_HANDLE_TABLE_ENTRY->ObjectPointerBits",
                        "struct_name": "_HANDLE_TABLE_ENTRY",
                        "member_name": "ObjectPointerBits",
                        "bits": True,
                    }
                },
                generate_yaml_desired_fields={
                    "ObDecodeShift": [
                        "struct_name",
                        "member_name",
                        "offset",
                        "bit_offset",
                    ]
                },
            )

        self.assertEqual(ida_preprocessor_common.PREPROCESS_STATUS_FAILED, status)
        self.assertFalse((Path(temp_dir) / "ObDecodeShift.yaml").exists())

    async def test_preprocess_common_skill_filters_gv_fields(self) -> None:
        with TemporaryDirectory() as temp_dir:
            with patch.object(
                ida_preprocessor_common,
                "preprocess_gv_symbol",
                new=AsyncMock(
                    return_value={
                        "gv_name": "PspCreateProcessNotifyRoutine",
                        "gv_rva": 0x45678,
                        "unused": 1,
                    }
                ),
            ):
                status = await ida_preprocessor_common.preprocess_common_skill(
                    session=AsyncMock(),
                    skill=SimpleNamespace(
                        name="find-PspCreateProcessNotifyRoutine",
                    ),
                    symbol=SimpleNamespace(
                        name="PspCreateProcessNotifyRoutine",
                        category="gv",
                        data_type="uint32",
                    ),
                    binary_dir=Path(temp_dir),
                    pdb_path=Path(temp_dir) / "ntkrnlmp.pdb",
                    debug=False,
                    llm_config=None,
                    gv_names=["PspCreateProcessNotifyRoutine"],
                    gv_metadata={
                        "PspCreateProcessNotifyRoutine": {
                            "alias": ["PspCreateProcessNotifyRoutine"]
                        }
                    },
                    generate_yaml_desired_fields={
                        "PspCreateProcessNotifyRoutine": ["gv_name", "gv_rva"]
                    },
                )

            self.assertEqual(ida_preprocessor_common.PREPROCESS_STATUS_SUCCESS, status)
            payload = load_artifact(
                Path(temp_dir) / "PspCreateProcessNotifyRoutine.yaml"
            )
            self.assertEqual(
                {
                    "category": "gv",
                    "gv_name": "PspCreateProcessNotifyRoutine",
                    "gv_rva": 0x45678,
                },
                payload,
            )

    async def test_preprocess_common_skill_falls_back_to_llm_decompile(
        self,
    ) -> None:
        with TemporaryDirectory() as temp_dir:
            with (
                patch.object(
                    ida_preprocessor_common,
                    "preprocess_func_symbol",
                    new=AsyncMock(return_value=None),
                ),
                patch.object(
                    ida_preprocessor_common,
                    "resolve_symbol_via_llm_decompile",
                    new=AsyncMock(
                        return_value={
                            "func_name": "ExReferenceCallBackBlock",
                            "func_va": 0x140012340,
                            "func_rva": 0x12340,
                        }
                    ),
                ) as mock_llm,
            ):
                status = await ida_preprocessor_common.preprocess_common_skill(
                    session=AsyncMock(),
                    skill=SimpleNamespace(name="find-ExReferenceCallBackBlock"),
                    symbol=SimpleNamespace(
                        name="ExReferenceCallBackBlock",
                        category="func",
                        data_type="uint32",
                    ),
                    binary_dir=Path(temp_dir),
                    pdb_path=Path(temp_dir) / "ntkrnlmp.pdb",
                    debug=False,
                    llm_config={"model": "test-model", "api_key": "test-key"},
                    func_names=["ExReferenceCallBackBlock"],
                    func_metadata={
                        "ExReferenceCallBackBlock": {
                            "alias": ["ExReferenceCallBackBlock"]
                        }
                    },
                    llm_decompile_specs=[
                        (
                            "ExReferenceCallBackBlock",
                            "ExReferenceCallBackBlock",
                            "prompt/call_llm_decompile.md",
                            "references/ntoskrnl/Ref.{arch}.yaml",
                        )
                    ],
                    generate_yaml_desired_fields={
                        "ExReferenceCallBackBlock": ["func_name", "func_rva"]
                    },
                )

            self.assertEqual(ida_preprocessor_common.PREPROCESS_STATUS_SUCCESS, status)
            mock_llm.assert_awaited_once()
            payload = load_artifact(Path(temp_dir) / "ExReferenceCallBackBlock.yaml")
            self.assertEqual(
                {
                    "category": "func",
                    "func_name": "ExReferenceCallBackBlock",
                    "func_rva": 0x12340,
                },
                payload,
            )

    async def test_preprocess_common_skill_skips_pdb_preprocess_when_pdb_missing(
        self,
    ) -> None:
        with TemporaryDirectory() as temp_dir:
            with (
                patch.object(
                    ida_preprocessor_common,
                    "preprocess_func_symbol",
                    new=AsyncMock(return_value=None),
                ) as mock_pdb_preprocess,
                patch.object(
                    ida_preprocessor_common,
                    "resolve_symbol_via_llm_decompile",
                    new=AsyncMock(
                        return_value={
                            "func_name": "ExReferenceCallBackBlock",
                            "func_rva": 0x12340,
                        }
                    ),
                ) as mock_llm,
            ):
                status = await ida_preprocessor_common.preprocess_common_skill(
                    session=AsyncMock(),
                    skill=SimpleNamespace(name="find-ExReferenceCallBackBlock"),
                    symbol=SimpleNamespace(
                        name="ExReferenceCallBackBlock",
                        category="func",
                        data_type="uint32",
                    ),
                    binary_dir=Path(temp_dir),
                    pdb_path=None,
                    debug=False,
                    llm_config={"model": "test-model", "api_key": "test-key"},
                    func_names=["ExReferenceCallBackBlock"],
                    func_metadata={
                        "ExReferenceCallBackBlock": {
                            "alias": ["ExReferenceCallBackBlock"]
                        }
                    },
                    llm_decompile_specs=[
                        (
                            "ExReferenceCallBackBlock",
                            "ExReferenceCallBackBlock",
                            "prompt/call_llm_decompile.md",
                            "references/ntoskrnl/Ref.{arch}.yaml",
                        )
                    ],
                    generate_yaml_desired_fields={
                        "ExReferenceCallBackBlock": ["func_name", "func_rva"]
                    },
                )

            self.assertEqual(ida_preprocessor_common.PREPROCESS_STATUS_SUCCESS, status)
            mock_pdb_preprocess.assert_not_awaited()
            mock_llm.assert_awaited_once()
            payload = load_artifact(Path(temp_dir) / "ExReferenceCallBackBlock.yaml")
            self.assertEqual(
                {
                    "category": "func",
                    "func_name": "ExReferenceCallBackBlock",
                    "func_rva": 0x12340,
                },
                payload,
            )

    def test_normalize_func_xrefs_accepts_none(self) -> None:
        self.assertEqual({}, ida_preprocessor_common._normalize_func_xrefs(None))

    def test_normalize_func_xrefs_fills_missing_fields_and_converts_tuples(
        self,
    ) -> None:
        normalized = ida_preprocessor_common._normalize_func_xrefs(
            [
                {
                    "func_name": "AlpcpInitSystem",
                    "xref_unicode_strings": ("FULLMATCH:ALPC Port",),
                    "exclude_funcs": ("KeBugCheckEx",),
                }
            ]
        )

        self.assertEqual(
            {
                "AlpcpInitSystem": {
                    "xref_strings": [],
                    "xref_unicode_strings": ["FULLMATCH:ALPC Port"],
                    "xref_gvs": [],
                    "xref_signatures": [],
                    "xref_funcs": [],
                    "exclude_funcs": ["KeBugCheckEx"],
                    "exclude_strings": [],
                    "exclude_unicode_strings": [],
                    "exclude_gvs": [],
                    "exclude_signatures": [],
                }
            },
            normalized,
        )

    def test_normalize_func_xrefs_rejects_invalid_shapes(self) -> None:
        invalid_cases = {
            "top_level_non_iterable": 123,
            "top_level_string": "AlpcpInitSystem",
            "non_mapping_item": [123],
            "duplicate_func_name": [
                {
                    "func_name": "AlpcpInitSystem",
                    "xref_unicode_strings": ["FULLMATCH:ALPC Port"],
                },
                {
                    "func_name": "AlpcpInitSystem",
                    "xref_strings": ["ALPC Port"],
                },
            ],
            "scalar_list_field": [
                {
                    "func_name": "AlpcpInitSystem",
                    "xref_unicode_strings": "FULLMATCH:ALPC Port",
                }
            ],
            "empty_positive_sources": [
                {
                    "func_name": "AlpcpInitSystem",
                    "exclude_funcs": ["KeBugCheckEx"],
                }
            ],
        }

        for case_name, func_xrefs in invalid_cases.items():
            with self.subTest(case_name=case_name):
                self.assertIsNone(
                    ida_preprocessor_common._normalize_func_xrefs(func_xrefs)
                )

    async def test_preprocess_common_skill_rejects_unknown_func_xrefs_key(
        self,
    ) -> None:
        with TemporaryDirectory() as temp_dir:
            with (
                patch.object(
                    ida_preprocessor_common,
                    "preprocess_func_symbol",
                    new=AsyncMock(return_value=None),
                ) as mock_pdb_preprocess,
                patch.object(
                    ida_preprocessor_common,
                    "resolve_symbol_via_llm_decompile",
                    new=AsyncMock(return_value=None),
                ) as mock_llm,
            ):
                status = await ida_preprocessor_common.preprocess_common_skill(
                    session=AsyncMock(),
                    skill=SimpleNamespace(name="find-AlpcpInitSystem"),
                    symbol=SimpleNamespace(
                        name="AlpcpInitSystem",
                        category="func",
                        data_type="uint32",
                    ),
                    binary_dir=Path(temp_dir),
                    pdb_path=None,
                    debug=True,
                    llm_config=None,
                    func_names=["AlpcpInitSystem"],
                    func_xrefs=[
                        {
                            "func_name": "AlpcpInitSystem",
                            "xref_unicode_strings": ["FULLMATCH:ALPC Port"],
                            "unknown": [],
                        }
                    ],
                    generate_yaml_desired_fields={
                        "AlpcpInitSystem": ["func_name", "func_rva"]
                    },
                )

        self.assertEqual(ida_preprocessor_common.PREPROCESS_STATUS_FAILED, status)
        mock_pdb_preprocess.assert_not_awaited()
        mock_llm.assert_not_awaited()

    async def test_preprocess_common_skill_rejects_empty_func_xrefs_sources(
        self,
    ) -> None:
        with TemporaryDirectory() as temp_dir:
            with (
                patch.object(
                    ida_preprocessor_common,
                    "preprocess_func_symbol",
                    new=AsyncMock(return_value=None),
                ) as mock_pdb_preprocess,
                patch.object(
                    ida_preprocessor_common,
                    "resolve_symbol_via_llm_decompile",
                    new=AsyncMock(return_value=None),
                ) as mock_llm,
            ):
                status = await ida_preprocessor_common.preprocess_common_skill(
                    session=AsyncMock(),
                    skill=SimpleNamespace(name="find-AlpcpInitSystem"),
                    symbol=SimpleNamespace(
                        name="AlpcpInitSystem",
                        category="func",
                        data_type="uint32",
                    ),
                    binary_dir=Path(temp_dir),
                    pdb_path=None,
                    debug=True,
                    llm_config=None,
                    func_names=["AlpcpInitSystem"],
                    func_xrefs=[
                        {
                            "func_name": "AlpcpInitSystem",
                            "xref_strings": [],
                            "xref_unicode_strings": [],
                            "xref_gvs": [],
                            "xref_signatures": [],
                            "xref_funcs": [],
                            "exclude_funcs": [],
                            "exclude_strings": [],
                            "exclude_unicode_strings": [],
                            "exclude_gvs": [],
                            "exclude_signatures": [],
                        }
                    ],
                    generate_yaml_desired_fields={
                        "AlpcpInitSystem": ["func_name", "func_rva"]
                    },
                )

        self.assertEqual(ida_preprocessor_common.PREPROCESS_STATUS_FAILED, status)
        mock_pdb_preprocess.assert_not_awaited()
        mock_llm.assert_not_awaited()

    async def test_preprocess_common_skill_routes_func_xrefs_without_pdb(
        self,
    ) -> None:
        with TemporaryDirectory() as temp_dir:
            with (
                patch.object(
                    ida_preprocessor_common,
                    "preprocess_func_symbol",
                    new=AsyncMock(
                        return_value={
                            "func_name": "AlpcpInitSystem",
                            "func_va": 0x140123000,
                            "func_rva": 0x123000,
                        }
                    ),
                ) as mock_func,
                patch.object(
                    ida_preprocessor_common,
                    "resolve_symbol_via_llm_decompile",
                    new=AsyncMock(return_value=None),
                ) as mock_llm,
            ):
                status = await ida_preprocessor_common.preprocess_common_skill(
                    session=AsyncMock(),
                    skill=SimpleNamespace(name="find-AlpcpInitSystem"),
                    symbol=SimpleNamespace(
                        name="AlpcpInitSystem",
                        category="func",
                        data_type="uint32",
                    ),
                    binary_dir=Path(temp_dir),
                    pdb_path=None,
                    debug=True,
                    llm_config=None,
                    func_names=["AlpcpInitSystem"],
                    func_xrefs=[
                        {
                            "func_name": "AlpcpInitSystem",
                            "xref_strings": [],
                            "xref_unicode_strings": ["FULLMATCH:ALPC Port"],
                            "xref_gvs": [],
                            "xref_signatures": ["41 B8 41 6C 49 6E"],
                            "xref_funcs": [],
                            "exclude_funcs": [],
                            "exclude_strings": [],
                            "exclude_unicode_strings": [],
                            "exclude_gvs": [],
                            "exclude_signatures": [],
                        }
                    ],
                    generate_yaml_desired_fields={
                        "AlpcpInitSystem": ["func_name", "func_rva"]
                    },
                )

                self.assertEqual(
                    ida_preprocessor_common.PREPROCESS_STATUS_SUCCESS,
                    status,
                )
                mock_func.assert_awaited_once()
                mock_llm.assert_not_awaited()
                self.assertEqual(
                    ["FULLMATCH:ALPC Port"],
                    mock_func.await_args.kwargs["func_xref"]["xref_unicode_strings"],
                )
                self.assertEqual(
                    Path(temp_dir),
                    mock_func.await_args.kwargs["binary_dir"],
                )
                payload = load_artifact(Path(temp_dir) / "AlpcpInitSystem.yaml")
                self.assertEqual(
                    {
                        "category": "func",
                        "func_name": "AlpcpInitSystem",
                        "func_rva": 0x123000,
                    },
                    payload,
                )

    async def test_preprocess_common_skill_allows_xref_only_function_target(
        self,
    ) -> None:
        with TemporaryDirectory() as temp_dir, patch.object(
            ida_preprocessor_common,
            "preprocess_func_symbol",
            new=AsyncMock(
                return_value={
                    "func_name": "AlpcpInitSystem",
                    "func_rva": 0x123000,
                }
            ),
        ):
            status = await ida_preprocessor_common.preprocess_common_skill(
                session=AsyncMock(),
                skill=SimpleNamespace(name="find-AlpcpInitSystem"),
                symbol=SimpleNamespace(
                    name="AlpcpInitSystem",
                    category="func",
                    data_type="uint32",
                ),
                binary_dir=Path(temp_dir),
                pdb_path=None,
                debug=False,
                llm_config=None,
                func_names=[],
                func_xrefs=[
                    {
                        "func_name": "AlpcpInitSystem",
                        "xref_unicode_strings": ["FULLMATCH:ALPC Port"],
                    }
                ],
                generate_yaml_desired_fields={
                    "AlpcpInitSystem": ["func_name", "func_rva"]
                },
            )

        self.assertEqual(ida_preprocessor_common.PREPROCESS_STATUS_SUCCESS, status)

    async def test_preprocess_common_skill_infers_func_category_for_mapping_symbol(
        self,
    ) -> None:
        with TemporaryDirectory() as temp_dir, patch.object(
            ida_preprocessor_common,
            "preprocess_func_symbol",
            new=AsyncMock(
                return_value={
                    "func_name": "AlpcpCreateClientPort",
                    "func_rva": 0x5E8D70,
                }
            ),
        ):
            status = await ida_preprocessor_common.preprocess_common_skill(
                session=AsyncMock(),
                skill=SimpleNamespace(name="find-AlpcpCreateClientPort"),
                symbol={"name": "AlpcpCreateClientPort"},
                binary_dir=Path(temp_dir),
                pdb_path=Path(temp_dir) / "ntkrnlmp.pdb",
                debug=False,
                llm_config=None,
                func_names=["AlpcpCreateClientPort"],
                func_metadata={
                    "AlpcpCreateClientPort": {
                        "alias": ["AlpcpCreateClientPort"],
                    }
                },
                generate_yaml_desired_fields={
                    "AlpcpCreateClientPort": ["func_name", "func_rva"]
                },
            )

            self.assertEqual(ida_preprocessor_common.PREPROCESS_STATUS_SUCCESS, status)
            payload = load_artifact(Path(temp_dir) / "AlpcpCreateClientPort.yaml")
            self.assertEqual(
                {
                    "category": "func",
                    "func_name": "AlpcpCreateClientPort",
                    "func_rva": 0x5E8D70,
                },
                payload,
            )

    async def test_preprocess_common_skill_falls_back_to_llm_decompile_for_struct_specs(
        self,
    ) -> None:
        with TemporaryDirectory() as temp_dir:
            llm_specs = [
                (
                    "AlpcAttributes",
                    "_ALPC_PORT->PortAttributes",
                    "prompt/call_llm_decompile.md",
                    "references/ntoskrnl/AlpcpDeletePort.{arch}.yaml",
                )
            ]
            with (
                patch.object(
                    generic_struct_offset,
                    "resolve_struct_symbol",
                    side_effect=KeyError("AlpcAttributes"),
                ),
                patch.object(
                    ida_preprocessor_common,
                    "resolve_symbol_via_llm_decompile",
                    new=AsyncMock(
                        return_value={
                            "struct_name": "_ALPC_PORT",
                            "member_name": "PortAttributes",
                            "offset": 0x100,
                        }
                    ),
                ) as mock_llm_decompile,
            ):
                status = await ida_preprocessor_common.preprocess_common_skill(
                    session=AsyncMock(),
                    skill=SimpleNamespace(
                        name="find-AlpcAttributes-AND-AlpcAttributesFlags-AND-AlpcCommunicationInfo-AND-AlpcOwnerProcess-AND-AlpcConnectionPort-AND-AlpcServerCommunicationPort-AND-AlpcClientCommunicationPort"
                    ),
                    symbol=SimpleNamespace(
                        name="AlpcAttributes",
                        category="struct_offset",
                        data_type="uint16",
                    ),
                    binary_dir=Path(temp_dir),
                    pdb_path=Path(temp_dir) / "ntkrnlmp.pdb",
                    debug=True,
                    llm_config={"model": "test-model", "api_key": "test-key"},
                    struct_member_names=["AlpcAttributes"],
                    struct_metadata={
                        "AlpcAttributes": {
                            "symbol_expr": "_ALPC_PORT->PortAttributes",
                            "struct_name": "_ALPC_PORT",
                            "member_name": "PortAttributes",
                            "bits": False,
                        }
                    },
                    llm_decompile_specs=llm_specs,
                    generate_yaml_desired_fields={
                        "AlpcAttributes": ["struct_name", "member_name", "offset"]
                    },
                )

            self.assertEqual(ida_preprocessor_common.PREPROCESS_STATUS_SUCCESS, status)
            mock_llm_decompile.assert_awaited_once()
            self.assertEqual(
                llm_specs,
                mock_llm_decompile.await_args.kwargs["llm_decompile_specs"],
            )
            payload = load_artifact(Path(temp_dir) / "AlpcAttributes.yaml")
            self.assertEqual(
                {
                    "category": "struct_offset",
                    "struct_name": "_ALPC_PORT",
                    "member_name": "PortAttributes",
                    "offset": 0x100,
                },
                payload,
            )

    async def test_preprocess_struct_symbol_returns_none_after_pdb_miss(
        self,
    ) -> None:
        with patch.object(
            generic_struct_offset,
            "resolve_struct_symbol",
            side_effect=KeyError("AlpcAttributes"),
        ):
            payload = await generic_struct_offset.preprocess_struct_symbol(
                session=AsyncMock(),
                symbol_name="AlpcAttributes",
                metadata={
                    "symbol_expr": "_ALPC_PORT->PortAttributes",
                    "struct_name": "_ALPC_PORT",
                    "member_name": "PortAttributes",
                    "bits": False,
                },
                pdb_path="ntkrnlmp.pdb",
                debug=True,
                llm_config={"model": "test-model", "api_key": "test-key"},
                binary_dir="/tmp/amd64/ntoskrnl",
                llm_decompile_specs=[
                    (
                        "AlpcAttributes",
                        "_ALPC_PORT->PortAttributes",
                        "prompt/call_llm_decompile.md",
                        "references/ntoskrnl/AlpcpDeletePort.{arch}.yaml",
                    )
                ],
            )

        self.assertIsNone(payload)
