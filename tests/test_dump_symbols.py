from pathlib import Path
from tempfile import TemporaryDirectory
import asyncio
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

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

    def test_process_binary_absent_ok_still_falls_back_to_agent(self) -> None:
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
                    new=AsyncMock(return_value="absent_ok"),
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
        mock_run_skill.assert_called_once()

    def test_process_binary_success_does_not_require_output_files(self) -> None:
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
                    new=AsyncMock(return_value=dump_symbols.PREPROCESS_STATUS_SUCCESS),
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
        mock_run_skill.assert_not_called()

    def test_process_binary_returns_false_immediately_when_run_skill_fails(self) -> None:
        with TemporaryDirectory() as temp_dir:
            binary_dir = Path(temp_dir)
            skills = [
                {
                    "name": "find-A",
                    "symbol": "SymbolA",
                    "expected_output": ["A.yaml"],
                    "agent_skill": "find-kph-struct-offset",
                },
                {
                    "name": "find-B",
                    "symbol": "SymbolB",
                    "expected_output": ["B.yaml"],
                    "agent_skill": "find-kph-struct-offset",
                },
            ]
            symbols = [
                {
                    "name": "SymbolA",
                    "category": "struct_offset",
                    "data_type": "uint16",
                    "symbol_expr": "_EPROCESS->ObjectTable",
                    "struct_name": "_EPROCESS",
                    "member_name": "ObjectTable",
                },
                {
                    "name": "SymbolB",
                    "category": "struct_offset",
                    "data_type": "uint16",
                    "symbol_expr": "_EPROCESS->ObjectTable",
                    "struct_name": "_EPROCESS",
                    "member_name": "ObjectTable",
                },
            ]
            preprocess_mock = AsyncMock(return_value="failed")
            with (
                patch.object(
                    dump_symbols,
                    "preprocess_single_skill_via_mcp",
                    new=preprocess_mock,
                ),
                patch.object(dump_symbols, "run_skill", return_value=False) as mock_run_skill,
            ):
                ok = asyncio.run(
                    dump_symbols.process_binary_dir(
                        binary_dir=binary_dir,
                        pdb_path=binary_dir / "ntkrnlmp.pdb",
                        skills=skills,
                        symbols=symbols,
                        agent="codex",
                        debug=False,
                        force=False,
                        llm_config=None,
                    )
                )

        self.assertFalse(ok)
        self.assertEqual(1, mock_run_skill.call_count)
        self.assertEqual(1, preprocess_mock.await_count)

    def test_run_skill_calls_subprocess_once_even_with_higher_retry_limit(self) -> None:
        completed = subprocess.CompletedProcess(args=["codex"], returncode=1)
        with (
            patch("pathlib.Path.exists", return_value=True),
            patch("pathlib.Path.read_text", return_value="developer prompt"),
            patch.object(dump_symbols.subprocess, "run", return_value=completed) as mock_run,
        ):
            ok = dump_symbols.run_skill(
                "find-test",
                agent="codex",
                debug=False,
                expected_yaml_paths=[],
                max_retries=5,
                agent_skill_name="find-kph-struct-offset",
            )

        self.assertFalse(ok)
        mock_run.assert_called_once()

    def test_process_module_binary_uses_same_dynamic_port_for_mcp_start_and_session(
        self,
    ) -> None:
        with TemporaryDirectory() as temp_dir:
            binary_dir = Path(temp_dir)
            binary_path = binary_dir / "ntoskrnl.exe"
            binary_path.write_text("", encoding="utf-8")
            pdb_path = binary_dir / "ntkrnlmp.pdb"
            pdb_path.write_text("", encoding="utf-8")

            module = SimpleNamespace(path=["ntoskrnl.exe"], skills=[], symbols=[])
            args = SimpleNamespace(agent="codex", debug=False, force=False)
            fake_process = MagicMock()
            fake_streams = AsyncMock()
            fake_session = AsyncMock()

            with (
                patch.object(
                    dump_symbols,
                    "_allocate_local_port",
                    return_value=24567,
                    create=True,
                ) as mock_allocate_port,
                patch.object(
                    dump_symbols, "start_idalib_mcp", return_value=fake_process
                ) as mock_start,
                patch.object(
                    dump_symbols,
                    "_open_session",
                    new=AsyncMock(return_value=(fake_streams, fake_session)),
                ) as mock_open_session,
                patch.object(
                    dump_symbols,
                    "_session_matches_binary",
                    new=AsyncMock(return_value=True),
                    create=True,
                ) as mock_session_matches_binary,
                patch.object(
                    dump_symbols,
                    "process_binary_dir",
                    new=AsyncMock(return_value=True),
                ) as mock_process_binary,
            ):
                ok = asyncio.run(
                    dump_symbols._process_module_binary(module, binary_dir, pdb_path, args)
                )

        self.assertTrue(ok)
        mock_allocate_port.assert_called_once_with("127.0.0.1")
        mock_start.assert_called_once_with(binary_path, host="127.0.0.1", port=24567)
        mock_open_session.assert_awaited_once_with("http://127.0.0.1:24567/mcp")
        mock_session_matches_binary.assert_awaited_once_with(fake_session, binary_path)
        mock_process_binary.assert_awaited_once()

    def test_process_module_binary_fails_when_session_path_mismatches(self) -> None:
        with TemporaryDirectory() as temp_dir:
            binary_dir = Path(temp_dir)
            binary_path = binary_dir / "ntoskrnl.exe"
            binary_path.write_text("", encoding="utf-8")
            pdb_path = binary_dir / "ntkrnlmp.pdb"
            pdb_path.write_text("", encoding="utf-8")

            module = SimpleNamespace(path=["ntoskrnl.exe"], skills=[], symbols=[])
            args = SimpleNamespace(agent="codex", debug=False, force=False)
            fake_process = MagicMock()
            fake_streams = AsyncMock()
            fake_session = AsyncMock()

            with (
                patch.object(
                    dump_symbols,
                    "_allocate_local_port",
                    return_value=24567,
                    create=True,
                ),
                patch.object(
                    dump_symbols, "start_idalib_mcp", return_value=fake_process
                ),
                patch.object(
                    dump_symbols,
                    "_open_session",
                    new=AsyncMock(return_value=(fake_streams, fake_session)),
                ),
                patch.object(
                    dump_symbols,
                    "_session_matches_binary",
                    new=AsyncMock(return_value=False),
                    create=True,
                ) as mock_session_matches_binary,
                patch.object(
                    dump_symbols,
                    "process_binary_dir",
                    new=AsyncMock(return_value=True),
                ) as mock_process_binary,
            ):
                with self.assertRaisesRegex(RuntimeError, "MCP session target mismatch"):
                    asyncio.run(
                        dump_symbols._process_module_binary(
                            module, binary_dir, pdb_path, args
                        )
                    )

        mock_session_matches_binary.assert_awaited_once_with(fake_session, binary_path)
        mock_process_binary.assert_not_awaited()

    def test_start_idalib_mcp_uses_devnull_streams(self) -> None:
        fake_process = MagicMock()
        binary_path = Path("/tmp/ntoskrnl.exe")

        with (
            patch.object(
                dump_symbols.subprocess, "Popen", return_value=fake_process
            ) as mock_popen,
            patch.object(dump_symbols, "_wait_for_port", return_value=True),
        ):
            process = dump_symbols.start_idalib_mcp(binary_path, host="127.0.0.1", port=13337)

        self.assertIs(process, fake_process)
        mock_popen.assert_called_once_with(
            [
                "uv",
                "run",
                "idalib-mcp",
                "--unsafe",
                "--host",
                "127.0.0.1",
                "--port",
                "13337",
                str(binary_path),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
        )

    def test_start_idalib_mcp_waits_after_timeout_failure(self) -> None:
        fake_process = MagicMock()
        binary_path = Path("/tmp/ntoskrnl.exe")

        with (
            patch.object(dump_symbols.subprocess, "Popen", return_value=fake_process),
            patch.object(dump_symbols, "_wait_for_port", return_value=False),
        ):
            with self.assertRaisesRegex(RuntimeError, "failed to start"):
                dump_symbols.start_idalib_mcp(binary_path, host="127.0.0.1", port=13337)

        fake_process.kill.assert_called_once_with()
        fake_process.wait.assert_called_once_with()
