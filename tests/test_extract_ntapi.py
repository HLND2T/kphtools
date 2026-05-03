from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

from ida_preprocessor_scripts import _extract_ntapi
from symbol_artifacts import load_artifact


def _tool_result(payload):
    return SimpleNamespace(
        content=[
            SimpleNamespace(
                text=json.dumps({"result": json.dumps(payload)})
            )
        ]
    )


def _base_kwargs(temp_dir, session, pdb_path=None):
    return {
        "session": session,
        "skill": SimpleNamespace(name="find-NtSecureConnectPort"),
        "symbol": {"name": "NtSecureConnectPort"},
        "binary_dir": Path(temp_dir),
        "pdb_path": pdb_path,
        "debug": True,
        "target_function_names": ["NtSecureConnectPort"],
        "ntapi_signatures": {
            "NtSecureConnectPort": ["5D 53 26 88 09 00 00 00"],
        },
        "generate_yaml_desired_fields": {
            "NtSecureConnectPort": ["func_name", "func_rva"],
        },
    }


class TestExtractNtApi(unittest.IsolatedAsyncioTestCase):
    async def test_pdb_success_writes_artifact_without_signature_search(self) -> None:
        session = AsyncMock()
        with TemporaryDirectory() as temp_dir:
            with patch.object(
                _extract_ntapi,
                "resolve_public_symbol",
                return_value={"rva": 0x12340},
            ) as mock_resolve:
                status = await _extract_ntapi.preprocess_ntapi_symbols(
                    **_base_kwargs(
                        temp_dir,
                        session,
                        pdb_path=Path(temp_dir) / "ntkrnlmp.pdb",
                    )
                )

            self.assertEqual(_extract_ntapi.PREPROCESS_STATUS_SUCCESS, status)
            mock_resolve.assert_called_once_with(
                Path(temp_dir) / "ntkrnlmp.pdb",
                "NtSecureConnectPort",
            )
            session.call_tool.assert_not_awaited()
            self.assertEqual(
                {
                    "category": "func",
                    "func_name": "NtSecureConnectPort",
                    "func_rva": 0x12340,
                },
                load_artifact(Path(temp_dir) / "NtSecureConnectPort.yaml"),
            )

    async def test_pdb_miss_uses_signature_fallback(self) -> None:
        session = AsyncMock()
        session.call_tool.side_effect = [
            _tool_result(
                [
                    {
                        "pattern": "5D 53 26 88 09 00 00 00",
                        "matches": ["0x140989840"],
                    }
                ]
            ),
            _tool_result(
                {
                    "candidates": [
                        {
                            "match_ea": "0x140989840",
                            "ptr_ea": "0x140989848",
                            "func_va": "0x1405e8d70",
                            "func_rva": "0x5e8d70",
                            "segment": "PAGE",
                        }
                    ]
                }
            ),
        ]

        with TemporaryDirectory() as temp_dir:
            with patch.object(
                _extract_ntapi,
                "resolve_public_symbol",
                side_effect=KeyError("NtSecureConnectPort"),
            ):
                status = await _extract_ntapi.preprocess_ntapi_symbols(
                    **_base_kwargs(
                        temp_dir,
                        session,
                        pdb_path=Path(temp_dir) / "ntkrnlmp.pdb",
                    )
                )

            self.assertEqual(_extract_ntapi.PREPROCESS_STATUS_SUCCESS, status)
            self.assertEqual(
                "find_bytes",
                session.call_tool.await_args_list[0].kwargs["name"],
            )
            self.assertEqual(
                {"patterns": ["5D 53 26 88 09 00 00 00"]},
                session.call_tool.await_args_list[0].kwargs["arguments"],
            )
            py_eval_code = session.call_tool.await_args_list[1].kwargs["arguments"]["code"]
            self.assertIn("+ 8", py_eval_code)
            self.assertIn("ida_bytes.get_qword", py_eval_code)
            self.assertIn("PAGE", py_eval_code)
            self.assertIn(".text", py_eval_code)
            self.assertEqual(
                {
                    "category": "func",
                    "func_name": "NtSecureConnectPort",
                    "func_rva": 0x5E8D70,
                },
                load_artifact(Path(temp_dir) / "NtSecureConnectPort.yaml"),
            )

    async def test_accepts_single_candidate_in_page_segment(self) -> None:
        session = AsyncMock()
        session.call_tool.side_effect = [
            _tool_result(
                [
                    {
                        "pattern": "5D 53 26 88 09 00 00 00",
                        "matches": ["0x140989840"],
                    }
                ]
            ),
            _tool_result(
                {
                    "candidates": [
                        {
                            "match_ea": "0x140989840",
                            "ptr_ea": "0x140989848",
                            "func_va": "0x1405e8d70",
                            "func_rva": "0x5e8d70",
                            "segment": "PAGE",
                        }
                    ]
                }
            ),
        ]

        with TemporaryDirectory() as temp_dir:
            status = await _extract_ntapi.preprocess_ntapi_symbols(
                **_base_kwargs(temp_dir, session, pdb_path=None)
            )

            self.assertEqual(_extract_ntapi.PREPROCESS_STATUS_SUCCESS, status)
            self.assertEqual(
                {
                    "category": "func",
                    "func_name": "NtSecureConnectPort",
                    "func_rva": 0x5E8D70,
                },
                load_artifact(Path(temp_dir) / "NtSecureConnectPort.yaml"),
            )

    async def test_accepts_single_candidate_in_text_segment(self) -> None:
        session = AsyncMock()
        session.call_tool.side_effect = [
            _tool_result(
                [
                    {
                        "pattern": "5D 53 26 88 09 00 00 00",
                        "matches": ["0x140989840"],
                    }
                ]
            ),
            _tool_result(
                {
                    "candidates": [
                        {
                            "match_ea": "0x140989840",
                            "ptr_ea": "0x140989848",
                            "func_va": "0x1405e8d70",
                            "func_rva": "0x5e8d70",
                            "segment": ".text",
                        }
                    ]
                }
            ),
        ]

        with TemporaryDirectory() as temp_dir:
            status = await _extract_ntapi.preprocess_ntapi_symbols(
                **_base_kwargs(temp_dir, session, pdb_path=None)
            )

            self.assertEqual(_extract_ntapi.PREPROCESS_STATUS_SUCCESS, status)
            self.assertEqual(
                {
                    "category": "func",
                    "func_name": "NtSecureConnectPort",
                    "func_rva": 0x5E8D70,
                },
                load_artifact(Path(temp_dir) / "NtSecureConnectPort.yaml"),
            )

    async def test_rejects_candidates_outside_allowed_segments(self) -> None:
        session = AsyncMock()
        session.call_tool.side_effect = [
            _tool_result(
                [
                    {
                        "pattern": "5D 53 26 88 09 00 00 00",
                        "matches": ["0x140989840"],
                    }
                ]
            ),
            _tool_result(
                {
                    "candidates": [
                        {
                            "match_ea": "0x140989840",
                            "ptr_ea": "0x140989848",
                            "func_va": "0x1405e8d70",
                            "func_rva": "0x5e8d70",
                            "segment": "INIT",
                        }
                    ]
                }
            ),
        ]

        with TemporaryDirectory() as temp_dir:
            status = await _extract_ntapi.preprocess_ntapi_symbols(
                **_base_kwargs(temp_dir, session, pdb_path=None)
            )

            self.assertEqual(_extract_ntapi.PREPROCESS_STATUS_FAILED, status)
            self.assertFalse((Path(temp_dir) / "NtSecureConnectPort.yaml").exists())

    async def test_rejects_non_unique_candidates(self) -> None:
        session = AsyncMock()
        session.call_tool.side_effect = [
            _tool_result(
                [
                    {
                        "pattern": "5D 53 26 88 09 00 00 00",
                        "matches": ["0x140989840", "0x140999000"],
                    }
                ]
            ),
            _tool_result(
                {
                    "candidates": [
                        {
                            "match_ea": "0x140989840",
                            "ptr_ea": "0x140989848",
                            "func_va": "0x1405e8d70",
                            "func_rva": "0x5e8d70",
                            "segment": "PAGE",
                        },
                        {
                            "match_ea": "0x140999000",
                            "ptr_ea": "0x140999008",
                            "func_va": "0x140600000",
                            "func_rva": "0x600000",
                            "segment": ".text",
                        },
                    ]
                }
            ),
        ]

        with TemporaryDirectory() as temp_dir:
            status = await _extract_ntapi.preprocess_ntapi_symbols(
                **_base_kwargs(temp_dir, session, pdb_path=None)
            )

            self.assertEqual(_extract_ntapi.PREPROCESS_STATUS_FAILED, status)
            self.assertFalse((Path(temp_dir) / "NtSecureConnectPort.yaml").exists())
