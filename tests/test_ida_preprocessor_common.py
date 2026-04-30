from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

import ida_preprocessor_common
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
                    skill=SimpleNamespace(name="find-EgeGuid", symbol="EgeGuid"),
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
                    symbol="ObDecodeShift",
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
                        symbol="PspCreateProcessNotifyRoutine",
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
