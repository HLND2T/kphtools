from pathlib import Path
from tempfile import TemporaryDirectory
import asyncio
import unittest
from unittest.mock import AsyncMock, patch

import dump_symbols


class TestDumpSymbols(unittest.TestCase):
    def test_topological_sort_uses_expected_input_output(self) -> None:
        skills = [
            {"name": "find-B", "expected_output": ["B.yaml"], "expected_input": ["A.yaml"]},
            {"name": "find-A", "expected_output": ["A.yaml"], "expected_input": []},
        ]

        self.assertEqual(["find-A", "find-B"], dump_symbols.topological_sort_skills(skills))

    def test_parse_args_reads_arch_and_force(self) -> None:
        args = dump_symbols.parse_args(
            [
                "-symboldir",
                "symbols",
                "-arch",
                "amd64",
                "-configyaml",
                "config.yaml",
                "-force",
            ]
        )

        self.assertEqual("amd64", args.arch)
        self.assertTrue(args.force)

    def test_process_binary_falls_back_to_agent_after_preprocess_failure(self) -> None:
        with TemporaryDirectory() as temp_dir:
            binary_dir = Path(temp_dir)
            config = {
                "skills": [
                    {
                        "name": "find-EpObjectTable",
                        "symbol": "EpObjectTable",
                        "expected_output": ["EpObjectTable.yaml"],
                        "agent_skill": "find-kph-struct-offset",
                    }
                ],
                "symbols": [
                    {
                        "name": "EpObjectTable",
                        "category": "struct_offset",
                        "data_type": "uint16",
                        "symbol_expr": "_EPROCESS->ObjectTable",
                        "struct_name": "_EPROCESS",
                        "member_name": "ObjectTable",
                    }
                ],
            }
            with (
                patch.object(
                    dump_symbols,
                    "preprocess_single_skill_via_mcp",
                    new=AsyncMock(return_value="failed"),
                ),
                patch.object(dump_symbols, "run_skill", return_value=True) as mock_run_skill,
            ):
                ok = asyncio.run(
                    dump_symbols.process_binary_dir(
                        binary_dir=binary_dir,
                        pdb_path=binary_dir / "ntkrnlmp.pdb",
                        skills=config["skills"],
                        symbols=config["symbols"],
                        agent="codex",
                        debug=False,
                        force=False,
                        llm_config=None,
                    )
                )

        self.assertTrue(ok)
        mock_run_skill.assert_called_once_with(
            "find-EpObjectTable",
            agent="codex",
            debug=False,
            expected_yaml_paths=[str(binary_dir / "EpObjectTable.yaml")],
            max_retries=3,
            agent_skill_name="find-kph-struct-offset",
        )
