from __future__ import annotations

import json
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

from ida_preprocessor_scripts import generic_func


def _tool_result(payload):
    return SimpleNamespace(
        content=[
            SimpleNamespace(
                text=json.dumps({"result": json.dumps(payload)})
            )
        ]
    )


class TestGenericFuncXrefs(unittest.IsolatedAsyncioTestCase):
    async def test_preprocess_func_symbol_uses_xref_after_pdb_miss(self) -> None:
        with (
            patch.object(
                generic_func,
                "resolve_public_symbol",
                side_effect=KeyError("AlpcpInitSystem"),
            ) as mock_resolve_public,
            patch.object(
                generic_func,
                "preprocess_func_xrefs_symbol",
                new=AsyncMock(
                    return_value={
                        "func_name": "AlpcpInitSystem",
                        "func_va": 0x140123000,
                        "func_rva": 0x123000,
                    }
                ),
            ) as mock_xrefs,
        ):
            payload = await generic_func.preprocess_func_symbol(
                session=AsyncMock(),
                symbol_name="AlpcpInitSystem",
                metadata={"alias": ["AlpcpInitSystem"]},
                pdb_path="/tmp/ntkrnlmp.pdb",
                debug=True,
                llm_config=None,
                binary_dir="/tmp/bin",
                image_base=0x140000000,
                func_xref={"xref_unicode_strings": ["FULLMATCH:ALPC Port"]},
            )

        self.assertEqual(
            {
                "func_name": "AlpcpInitSystem",
                "func_va": 0x140123000,
                "func_rva": 0x123000,
            },
            payload,
        )
        mock_resolve_public.assert_called_once_with(
            "/tmp/ntkrnlmp.pdb",
            "AlpcpInitSystem",
        )
        mock_xrefs.assert_awaited_once()
        self.assertEqual(
            {"xref_unicode_strings": ["FULLMATCH:ALPC Port"]},
            mock_xrefs.await_args.kwargs["func_xref"],
        )

    async def test_collect_unicode_string_xrefs_generates_fullmatch_filter(self) -> None:
        session = AsyncMock()
        session.call_tool.return_value = _tool_result(
            {"func_starts": ["0x140010000"]}
        )

        addrs = await generic_func._collect_xref_func_starts_for_string(
            session=session,
            xref_string="FULLMATCH:ALPC Port",
            unicode_only=True,
            debug=True,
        )

        self.assertEqual({0x140010000}, addrs)
        session.call_tool.assert_awaited_once()
        kwargs = session.call_tool.await_args.kwargs
        self.assertEqual("py_eval", kwargs["name"])
        code = kwargs["arguments"]["code"]
        self.assertIn("unicode_only = True", code)
        self.assertIn("current_str == search_str", code)
        self.assertIn("ALPC Port", code)
        self.assertIn("STRTYPE_C_16", code)

    async def test_signature_xrefs_parse_find_bytes_matches(self) -> None:
        session = AsyncMock()
        session.call_tool.side_effect = [
            _tool_result(
                [
                    {
                        "pattern": "41 B8 41 6C 49 6E",
                        "matches": ["0x140020123", "0x140020456"],
                    }
                ]
            ),
            _tool_result({"func_starts": ["0x140020000"]}),
        ]

        addrs = await generic_func._collect_xref_func_starts_for_signature(
            session=session,
            xref_signature="41 B8 41 6C 49 6E",
            debug=True,
        )

        self.assertEqual({0x140020000}, addrs)
        self.assertEqual("find_bytes", session.call_tool.await_args_list[0].kwargs["name"])
        self.assertEqual(
            {"patterns": ["41 B8 41 6C 49 6E"]},
            session.call_tool.await_args_list[0].kwargs["arguments"],
        )

    async def test_func_xrefs_intersects_positive_sources_and_excludes(self) -> None:
        session = AsyncMock()
        with (
            patch.object(
                generic_func,
                "_collect_xref_func_starts_for_string",
                new=AsyncMock(
                    side_effect=[
                        {0x140010000, 0x140020000},
                        {0x140020000},
                        {0x140030000},
                    ]
                ),
            ) as mock_string,
            patch.object(
                generic_func,
                "_collect_xref_func_starts_for_signature",
                new=AsyncMock(return_value={0x140020000, 0x140030000}),
            ) as mock_signature,
        ):
            payload = await generic_func.preprocess_func_xrefs_symbol(
                session=session,
                symbol_name="AlpcpInitSystem",
                func_xref={
                    "xref_strings": ["ALPC"],
                    "xref_unicode_strings": ["FULLMATCH:ALPC Port"],
                    "xref_signatures": ["41 B8 41 6C 49 6E"],
                    "xref_gvs": [],
                    "xref_funcs": [],
                    "exclude_strings": ["not this function"],
                    "exclude_unicode_strings": [],
                    "exclude_gvs": [],
                    "exclude_funcs": [],
                    "exclude_signatures": [],
                },
                binary_dir="/tmp/bin",
                image_base=0x140000000,
                debug=True,
            )

        self.assertEqual(
            {
                "func_name": "AlpcpInitSystem",
                "func_va": 0x140020000,
                "func_rva": 0x20000,
            },
            payload,
        )
        self.assertEqual(3, mock_string.await_count)
        mock_signature.assert_awaited_once()

    async def test_func_xrefs_returns_none_for_non_unique_candidates(self) -> None:
        with patch.object(
            generic_func,
            "_collect_xref_func_starts_for_signature",
            new=AsyncMock(return_value={0x140020000, 0x140030000}),
        ):
            payload = await generic_func.preprocess_func_xrefs_symbol(
                session=AsyncMock(),
                symbol_name="AlpcpInitSystem",
                func_xref={
                    "xref_strings": [],
                    "xref_unicode_strings": [],
                    "xref_signatures": ["41 6C 4D 73"],
                    "xref_gvs": [],
                    "xref_funcs": [],
                    "exclude_strings": [],
                    "exclude_unicode_strings": [],
                    "exclude_gvs": [],
                    "exclude_funcs": [],
                    "exclude_signatures": [],
                },
                binary_dir="/tmp/bin",
                image_base=0x140000000,
                debug=True,
            )

        self.assertIsNone(payload)
