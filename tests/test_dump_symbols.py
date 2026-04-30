from pathlib import Path
from tempfile import TemporaryDirectory
import asyncio
import subprocess
import sys
from types import SimpleNamespace
import types
import unittest
from unittest.mock import AsyncMock, MagicMock, call, patch

import dump_symbols


class TestDumpSymbols(unittest.TestCase):
    def test_open_session_cleans_up_streams_when_session_enter_fails(self) -> None:
        fake_streams = AsyncMock()
        read_stream = object()
        write_stream = object()
        fake_streams.__aenter__ = AsyncMock(return_value=(read_stream, write_stream, object()))
        fake_streams.__aexit__ = AsyncMock()

        fake_session = AsyncMock()
        fake_session.__aenter__ = AsyncMock(side_effect=RuntimeError("session enter failed"))
        fake_session.__aexit__ = AsyncMock()
        fake_session.initialize = AsyncMock()

        fake_mcp_module = types.ModuleType("mcp")
        fake_mcp_module.ClientSession = MagicMock(return_value=fake_session)
        fake_mcp_client_module = types.ModuleType("mcp.client")
        fake_streamable_http_module = types.ModuleType("mcp.client.streamable_http")
        fake_streamable_http_module.streamable_http_client = MagicMock(return_value=fake_streams)

        with patch.dict(
            sys.modules,
            {
                "mcp": fake_mcp_module,
                "mcp.client": fake_mcp_client_module,
                "mcp.client.streamable_http": fake_streamable_http_module,
            },
        ):
            with self.assertRaisesRegex(RuntimeError, "session enter failed"):
                asyncio.run(dump_symbols._open_session("http://127.0.0.1:13337/mcp"))

        fake_streams.__aexit__.assert_awaited_once_with(None, None, None)
        fake_session.__aexit__.assert_not_awaited()

    def test_open_session_cleans_up_session_and_streams_when_initialize_fails(self) -> None:
        fake_streams = AsyncMock()
        read_stream = object()
        write_stream = object()
        fake_streams.__aenter__ = AsyncMock(return_value=(read_stream, write_stream, object()))
        fake_streams.__aexit__ = AsyncMock()

        fake_session = AsyncMock()
        fake_session.__aenter__ = AsyncMock(return_value=fake_session)
        fake_session.__aexit__ = AsyncMock()
        fake_session.initialize = AsyncMock(side_effect=RuntimeError("initialize failed"))

        fake_mcp_module = types.ModuleType("mcp")
        fake_mcp_module.ClientSession = MagicMock(return_value=fake_session)
        fake_mcp_client_module = types.ModuleType("mcp.client")
        fake_streamable_http_module = types.ModuleType("mcp.client.streamable_http")
        fake_streamable_http_module.streamable_http_client = MagicMock(return_value=fake_streams)

        with patch.dict(
            sys.modules,
            {
                "mcp": fake_mcp_module,
                "mcp.client": fake_mcp_client_module,
                "mcp.client.streamable_http": fake_streamable_http_module,
            },
        ):
            with self.assertRaisesRegex(RuntimeError, "initialize failed"):
                asyncio.run(dump_symbols._open_session("http://127.0.0.1:13337/mcp"))

        fake_session.__aexit__.assert_awaited_once_with(None, None, None)
        fake_streams.__aexit__.assert_awaited_once_with(None, None, None)

    def test_open_session_cleans_up_session_and_streams_when_initialize_cancelled(self) -> None:
        fake_streams = AsyncMock()
        read_stream = object()
        write_stream = object()
        fake_streams.__aenter__ = AsyncMock(return_value=(read_stream, write_stream, object()))
        fake_streams.__aexit__ = AsyncMock()

        fake_session = AsyncMock()
        fake_session.__aenter__ = AsyncMock(return_value=fake_session)
        fake_session.__aexit__ = AsyncMock()
        fake_session.initialize = AsyncMock(side_effect=asyncio.CancelledError())

        fake_mcp_module = types.ModuleType("mcp")
        fake_mcp_module.ClientSession = MagicMock(return_value=fake_session)
        fake_mcp_client_module = types.ModuleType("mcp.client")
        fake_streamable_http_module = types.ModuleType("mcp.client.streamable_http")
        fake_streamable_http_module.streamable_http_client = MagicMock(return_value=fake_streams)

        with patch.dict(
            sys.modules,
            {
                "mcp": fake_mcp_module,
                "mcp.client": fake_mcp_client_module,
                "mcp.client.streamable_http": fake_streamable_http_module,
            },
        ):
            with self.assertRaises(asyncio.CancelledError):
                asyncio.run(dump_symbols._open_session("http://127.0.0.1:13337/mcp"))

        fake_session.__aexit__.assert_awaited_once_with(None, None, None)
        fake_streams.__aexit__.assert_awaited_once_with(None, None, None)

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
                    }
                ],
                "symbols": [
                    {
                        "name": "EpObjectTable",
                        "category": "struct_offset",
                        "data_type": "uint16",
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
                    }
                ],
                "symbols": [
                    {
                        "name": "EpObjectTable",
                        "category": "struct_offset",
                        "data_type": "uint16",
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
                    }
                ],
                "symbols": [
                    {
                        "name": "EpObjectTable",
                        "category": "struct_offset",
                        "data_type": "uint16",
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
                },
                {
                    "name": "find-B",
                    "symbol": "SymbolB",
                    "expected_output": ["B.yaml"],
                },
            ]
            symbols = [
                {
                    "name": "SymbolA",
                    "category": "struct_offset",
                    "data_type": "uint16",
                },
                {
                    "name": "SymbolB",
                    "category": "struct_offset",
                    "data_type": "uint16",
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

    def test_process_binary_dir_debug_logs_preprocess_failure_and_fallback(self) -> None:
        with TemporaryDirectory() as temp_dir:
            binary_dir = Path(temp_dir)
            config = {
                "skills": [
                    {
                        "name": "find-EpObjectTable",
                        "symbol": "EpObjectTable",
                        "expected_output": ["EpObjectTable.yaml"],
                    }
                ],
                "symbols": [
                    {
                        "name": "EpObjectTable",
                        "category": "struct_offset",
                        "data_type": "uint16",
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
                patch("builtins.print") as mock_print,
            ):
                ok = asyncio.run(
                    dump_symbols.process_binary_dir(
                        binary_dir=binary_dir,
                        pdb_path=binary_dir / "ntkrnlmp.pdb",
                        skills=config["skills"],
                        symbols=config["symbols"],
                        agent="codex",
                        debug=True,
                        force=False,
                        llm_config=None,
                    )
                )

        self.assertTrue(ok)
        mock_run_skill.assert_called_once_with(
            "find-EpObjectTable",
            agent="codex",
            debug=True,
            expected_yaml_paths=[str(binary_dir / "EpObjectTable.yaml")],
            max_retries=3,
        )
        printed_messages = [
            c.args[0]
            for c in mock_print.call_args_list
            if c.args and isinstance(c.args[0], str)
        ]
        self.assertIn("[debug] skill find-EpObjectTable started", printed_messages)
        self.assertIn(
            "[debug] preprocess status for find-EpObjectTable: failed",
            printed_messages,
        )
        self.assertIn(
            "[debug] falling back to run_skill for find-EpObjectTable",
            printed_messages,
        )

    def test_process_binary_dir_debug_false_does_not_print_debug_logs(self) -> None:
        with TemporaryDirectory() as temp_dir:
            binary_dir = Path(temp_dir)
            config = {
                "skills": [
                    {
                        "name": "find-EpObjectTable",
                        "symbol": "EpObjectTable",
                        "expected_output": ["EpObjectTable.yaml"],
                    }
                ],
                "symbols": [
                    {
                        "name": "EpObjectTable",
                        "category": "struct_offset",
                        "data_type": "uint16",
                    }
                ],
            }
            with (
                patch.object(
                    dump_symbols,
                    "preprocess_single_skill_via_mcp",
                    new=AsyncMock(return_value="failed"),
                ),
                patch.object(dump_symbols, "run_skill", return_value=True),
                patch("builtins.print") as mock_print,
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
        printed_messages = [
            c.args[0]
            for c in mock_print.call_args_list
            if c.args and isinstance(c.args[0], str)
        ]
        self.assertFalse(any(message.startswith("[debug]") for message in printed_messages))

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
            )

        self.assertFalse(ok)
        mock_run.assert_called_once()

    def test_process_module_binary_passes_lazy_session_without_eager_start(self) -> None:
        with TemporaryDirectory() as temp_dir:
            binary_dir = Path(temp_dir)
            binary_path = binary_dir / "ntoskrnl.exe"
            binary_path.write_text("", encoding="utf-8")
            pdb_path = binary_dir / "ntkrnlmp.pdb"
            pdb_path.write_text("", encoding="utf-8")

            module = SimpleNamespace(path=["ntoskrnl.exe"], skills=[], symbols=[])
            args = SimpleNamespace(agent="codex", debug=False, force=False)
            fake_lazy_session = MagicMock()
            fake_lazy_session.close = AsyncMock()

            with (
                patch.object(
                    dump_symbols,
                    "LazyIdalibSession",
                    return_value=fake_lazy_session,
                ) as mock_lazy_session_cls,
                patch.object(
                    dump_symbols,
                    "start_idalib_mcp",
                ) as mock_start,
                patch.object(dump_symbols, "_open_session", new=AsyncMock()) as mock_open_session,
                patch.object(
                    dump_symbols,
                    "_session_matches_binary",
                    new=AsyncMock(),
                    create=True,
                ) as mock_session_matches_binary,
                patch.object(
                    dump_symbols,
                    "process_binary_dir",
                    new=AsyncMock(return_value=True),
                ) as mock_process_binary,
            ):
                ok, did_work = asyncio.run(
                    dump_symbols._process_module_binary(module, binary_dir, pdb_path, args)
                )

        self.assertTrue(ok)
        self.assertFalse(did_work)
        mock_lazy_session_cls.assert_called_once_with(
            binary_path,
            host="127.0.0.1",
            debug=False,
        )
        self.assertIs(mock_process_binary.await_args.kwargs["session"], fake_lazy_session)
        mock_start.assert_not_called()
        mock_open_session.assert_not_awaited()
        mock_session_matches_binary.assert_not_awaited()
        mock_process_binary.assert_awaited_once()
        fake_lazy_session.close.assert_awaited_once()

    def test_process_module_binary_real_empty_pipeline_does_not_eager_start(self) -> None:
        with TemporaryDirectory() as temp_dir:
            binary_dir = Path(temp_dir)
            binary_path = binary_dir / "ntoskrnl.exe"
            binary_path.write_text("", encoding="utf-8")
            pdb_path = binary_dir / "ntkrnlmp.pdb"
            pdb_path.write_text("", encoding="utf-8")

            module = SimpleNamespace(path=["ntoskrnl.exe"], skills=[], symbols=[])
            args = SimpleNamespace(agent="codex", debug=False, force=False)

            with (
                patch.object(dump_symbols, "start_idalib_mcp") as mock_start,
                patch.object(dump_symbols, "_open_session", new=AsyncMock()) as mock_open_session,
                patch.object(
                    dump_symbols,
                    "_session_matches_binary",
                    new=AsyncMock(),
                    create=True,
                ) as mock_session_matches_binary,
            ):
                ok, did_work = asyncio.run(
                    dump_symbols._process_module_binary(module, binary_dir, pdb_path, args)
                )

        self.assertTrue(ok)
        self.assertFalse(did_work)
        mock_start.assert_not_called()
        mock_open_session.assert_not_awaited()
        mock_session_matches_binary.assert_not_awaited()

    def test_process_binary_dir_marks_activity_when_work_is_required(self) -> None:
        with TemporaryDirectory() as temp_dir:
            binary_dir = Path(temp_dir)
            skills = [
                {
                    "name": "find-A",
                    "symbol": "SymbolA",
                    "expected_output": ["A.yaml"],
                }
            ]
            symbols = [
                {
                    "name": "SymbolA",
                    "category": "struct_offset",
                    "data_type": "uint16",
                }
            ]
            activity = {"did_work": False}
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
                        skills=skills,
                        symbols=symbols,
                        agent="codex",
                        debug=False,
                        force=False,
                        llm_config=None,
                        activity=activity,
                    )
                )

        self.assertTrue(ok)
        self.assertTrue(activity["did_work"])
        mock_run_skill.assert_not_called()

    def test_process_module_binary_sets_did_work_true_without_eager_start(self) -> None:
        with TemporaryDirectory() as temp_dir:
            binary_dir = Path(temp_dir)
            binary_path = binary_dir / "ntoskrnl.exe"
            binary_path.write_text("", encoding="utf-8")
            pdb_path = binary_dir / "ntkrnlmp.pdb"
            pdb_path.write_text("", encoding="utf-8")

            module = SimpleNamespace(
                path=["ntoskrnl.exe"],
                skills=[
                    {
                        "name": "find-EpObjectTable",
                        "symbol": "EpObjectTable",
                        "expected_output": ["EpObjectTable.yaml"],
                    }
                ],
                symbols=[
                    {
                        "name": "EpObjectTable",
                        "category": "struct_offset",
                        "data_type": "uint16",
                    }
                ],
            )
            args = SimpleNamespace(agent="codex", debug=False, force=False)

            with (
                patch.object(dump_symbols, "start_idalib_mcp") as mock_start,
                patch.object(dump_symbols, "_open_session", new=AsyncMock()) as mock_open_session,
                patch.object(
                    dump_symbols,
                    "_session_matches_binary",
                    new=AsyncMock(),
                    create=True,
                ) as mock_session_matches_binary,
                patch.object(
                    dump_symbols,
                    "preprocess_single_skill_via_mcp",
                    new=AsyncMock(return_value=dump_symbols.PREPROCESS_STATUS_SUCCESS),
                ) as mock_preprocess,
                patch.object(dump_symbols, "run_skill", return_value=True) as mock_run_skill,
            ):
                ok, did_work = asyncio.run(
                    dump_symbols._process_module_binary(module, binary_dir, pdb_path, args)
                )

        self.assertTrue(ok)
        self.assertTrue(did_work)
        mock_preprocess.assert_awaited_once()
        mock_run_skill.assert_not_called()
        mock_start.assert_not_called()
        mock_open_session.assert_not_awaited()
        mock_session_matches_binary.assert_not_awaited()

    def test_lazy_idalib_session_starts_on_first_call_and_reuses_session(self) -> None:
        with TemporaryDirectory() as temp_dir:
            binary_dir = Path(temp_dir)
            binary_path = binary_dir / "ntoskrnl.exe"
            binary_path.write_text("", encoding="utf-8")
            fake_process = MagicMock()
            fake_process.poll.return_value = None
            fake_streams = AsyncMock()
            fake_session = AsyncMock()
            first_result = object()
            second_result = object()
            fake_session.call_tool = AsyncMock(side_effect=[first_result, second_result])

            with (
                patch.object(
                    dump_symbols,
                    "_allocate_local_port",
                    return_value=24567,
                    create=True,
                ),
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
            ):
                session = dump_symbols.LazyIdalibSession(binary_path=binary_path)
                self.assertIsNone(session.session)
                mock_start.assert_not_called()
                mock_open_session.assert_not_awaited()
                mock_session_matches_binary.assert_not_awaited()

                async def run_sequence():
                    call_one = await session.call_tool("py_eval", {"code": "1"})
                    call_two = await session.call_tool("py_eval", {"code": "2"})
                    await session.close()
                    return call_one, call_two

                call_one, call_two = asyncio.run(run_sequence())

        self.assertIs(call_one, first_result)
        self.assertIs(call_two, second_result)
        mock_start.assert_called_once_with(
            binary_path,
            host="127.0.0.1",
            port=24567,
            debug=False,
        )
        mock_open_session.assert_awaited_once_with(
            "http://127.0.0.1:24567/mcp",
            debug=False,
        )
        mock_session_matches_binary.assert_awaited_once_with(fake_session, binary_path)
        fake_session.call_tool.assert_has_awaits(
            [
                call(name="py_eval", arguments={"code": "1"}),
                call(name="py_eval", arguments={"code": "2"}),
                call(
                    name="py_eval",
                    arguments={"code": "import idc; idc.qexit(0)"},
                ),
            ]
        )
        fake_session.__aexit__.assert_awaited_once_with(None, None, None)
        fake_streams.__aexit__.assert_awaited_once_with(None, None, None)
        fake_process.kill.assert_not_called()
        fake_process.wait.assert_called_once_with(timeout=10)

    def test_lazy_idalib_session_debug_logs_startup(self) -> None:
        with TemporaryDirectory() as temp_dir:
            binary_dir = Path(temp_dir)
            binary_path = binary_dir / "ntoskrnl.exe"
            binary_path.write_text("", encoding="utf-8")
            fake_process = MagicMock()
            fake_process.poll.return_value = None
            fake_streams = AsyncMock()
            fake_session = AsyncMock()
            fake_session.call_tool = AsyncMock()

            with (
                patch.object(
                    dump_symbols,
                    "_allocate_local_port",
                    return_value=24567,
                    create=True,
                ),
                patch.object(
                    dump_symbols,
                    "start_idalib_mcp",
                    return_value=fake_process,
                ),
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
                ),
                patch("builtins.print") as mock_print,
            ):
                lazy_session = dump_symbols.LazyIdalibSession(
                    binary_path=binary_path,
                    debug=True,
                )

                async def run_sequence():
                    await lazy_session.ensure_started()
                    await lazy_session.close()

                asyncio.run(run_sequence())

        mock_open_session.assert_awaited_once_with(
            "http://127.0.0.1:24567/mcp",
            debug=True,
        )
        printed_messages = [
            c.args[0]
            for c in mock_print.call_args_list
            if c.args and isinstance(c.args[0], str)
        ]
        self.assertIn(
            f"[debug] allocating lazy MCP session for {binary_path}",
            printed_messages,
        )
        self.assertIn(
            f"[debug] closing lazy MCP session for {binary_path}",
            printed_messages,
        )

    def test_lazy_idalib_session_close_without_startup_does_not_log_closing(self) -> None:
        session = dump_symbols.LazyIdalibSession(
            binary_path=Path("/tmp/ntoskrnl.exe"),
            debug=True,
        )

        with patch("builtins.print") as mock_print:
            asyncio.run(session.close())

        printed_messages = [
            c.args[0]
            for c in mock_print.call_args_list
            if c.args and isinstance(c.args[0], str)
        ]
        self.assertNotIn(
            "[debug] closing lazy MCP session for /tmp/ntoskrnl.exe",
            printed_messages,
        )

    def test_lazy_idalib_session_cleans_up_after_binary_mismatch(self) -> None:
        with TemporaryDirectory() as temp_dir:
            binary_dir = Path(temp_dir)
            binary_path = binary_dir / "ntoskrnl.exe"
            binary_path.write_text("", encoding="utf-8")

            fake_process = MagicMock()
            fake_process.poll.return_value = None
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
                    dump_symbols,
                    "start_idalib_mcp",
                    return_value=fake_process,
                ) as mock_start,
                patch.object(
                    dump_symbols,
                    "_open_session",
                    new=AsyncMock(return_value=(fake_streams, fake_session)),
                ) as mock_open_session,
                patch.object(
                    dump_symbols,
                    "_session_matches_binary",
                    new=AsyncMock(return_value=False),
                    create=True,
                ) as mock_session_matches_binary,
            ):
                lazy_session = dump_symbols.LazyIdalibSession(binary_path=binary_path)

                with self.assertRaisesRegex(RuntimeError, "MCP session target mismatch"):
                    asyncio.run(lazy_session.call_tool("py_eval", {"code": "1"}))

        mock_start.assert_called_once_with(
            binary_path,
            host="127.0.0.1",
            port=24567,
            debug=False,
        )
        mock_open_session.assert_awaited_once_with(
            "http://127.0.0.1:24567/mcp",
            debug=False,
        )
        mock_session_matches_binary.assert_awaited_once_with(fake_session, binary_path)
        fake_session.__aexit__.assert_awaited_once_with(None, None, None)
        fake_streams.__aexit__.assert_awaited_once_with(None, None, None)
        fake_process.kill.assert_called_once_with()
        fake_process.wait.assert_called_once_with(timeout=1)
        self.assertIsNone(lazy_session.process)
        self.assertIsNone(lazy_session.streams)
        self.assertIsNone(lazy_session.session)

    def test_lazy_idalib_session_startup_cleanup_wait_failure_keeps_mismatch_error(self) -> None:
        with TemporaryDirectory() as temp_dir:
            binary_dir = Path(temp_dir)
            binary_path = binary_dir / "ntoskrnl.exe"
            binary_path.write_text("", encoding="utf-8")

            fake_process = MagicMock()
            fake_process.poll.return_value = None
            fake_process.wait.side_effect = subprocess.TimeoutExpired(cmd="wait", timeout=1)
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
                    dump_symbols,
                    "start_idalib_mcp",
                    return_value=fake_process,
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
                ),
            ):
                lazy_session = dump_symbols.LazyIdalibSession(binary_path=binary_path)
                with self.assertRaisesRegex(RuntimeError, "MCP session target mismatch"):
                    asyncio.run(lazy_session.call_tool("py_eval", {"code": "1"}))

        fake_session.__aexit__.assert_awaited_once_with(None, None, None)
        fake_streams.__aexit__.assert_awaited_once_with(None, None, None)
        fake_process.kill.assert_called_once_with()
        fake_process.wait.assert_called_once_with(timeout=1)
        self.assertIsNone(lazy_session.process)
        self.assertIsNone(lazy_session.streams)
        self.assertIsNone(lazy_session.session)

    def test_lazy_idalib_session_startup_failure_after_process_start_cleans_up_process(self) -> None:
        with TemporaryDirectory() as temp_dir:
            binary_dir = Path(temp_dir)
            binary_path = binary_dir / "ntoskrnl.exe"
            binary_path.write_text("", encoding="utf-8")

            fake_process = MagicMock()
            fake_process.poll.return_value = None

            with (
                patch.object(
                    dump_symbols,
                    "_allocate_local_port",
                    return_value=24567,
                    create=True,
                ),
                patch.object(
                    dump_symbols,
                    "start_idalib_mcp",
                    return_value=fake_process,
                ) as mock_start,
                patch.object(
                    dump_symbols,
                    "_open_session",
                    new=AsyncMock(side_effect=RuntimeError("open session failed")),
                ) as mock_open_session,
            ):
                lazy_session = dump_symbols.LazyIdalibSession(binary_path=binary_path)

                with self.assertRaisesRegex(RuntimeError, "open session failed"):
                    asyncio.run(lazy_session.ensure_started())

        mock_start.assert_called_once_with(
            binary_path,
            host="127.0.0.1",
            port=24567,
            debug=False,
        )
        mock_open_session.assert_awaited_once_with(
            "http://127.0.0.1:24567/mcp",
            debug=False,
        )
        fake_process.kill.assert_called_once_with()
        fake_process.wait.assert_called_once_with(timeout=1)
        self.assertIsNone(lazy_session.process)
        self.assertIsNone(lazy_session.streams)
        self.assertIsNone(lazy_session.session)

    def test_lazy_idalib_session_close_uses_qexit_before_wait(self) -> None:
        session = dump_symbols.LazyIdalibSession(binary_path=Path("/tmp/ntoskrnl.exe"))
        events: list[str] = []

        fake_process = MagicMock()
        fake_process.poll.return_value = None
        fake_process.wait.side_effect = lambda timeout: events.append(f"wait:{timeout}")
        fake_process.kill.side_effect = lambda: events.append("kill")

        fake_session = AsyncMock()
        fake_session.call_tool = AsyncMock(
            side_effect=lambda **kwargs: events.append("qexit")
        )
        fake_session.__aexit__ = AsyncMock(side_effect=lambda *_: events.append("session_exit"))

        fake_streams = AsyncMock()
        fake_streams.__aexit__ = AsyncMock(side_effect=lambda *_: events.append("streams_exit"))

        session.process = fake_process
        session.session = fake_session
        session.streams = fake_streams

        asyncio.run(session.close())

        fake_session.call_tool.assert_awaited_once_with(
            name="py_eval",
            arguments={"code": "import idc; idc.qexit(0)"},
        )
        self.assertEqual(["qexit", "session_exit", "streams_exit", "wait:10"], events)
        fake_process.kill.assert_not_called()

    def test_lazy_idalib_session_close_kills_after_wait_timeout(self) -> None:
        session = dump_symbols.LazyIdalibSession(binary_path=Path("/tmp/ntoskrnl.exe"))

        fake_process = MagicMock()
        fake_process.poll.return_value = None
        fake_process.wait.side_effect = [
            subprocess.TimeoutExpired(cmd="wait", timeout=10),
            None,
        ]

        fake_session = AsyncMock()
        fake_streams = AsyncMock()
        session.process = fake_process
        session.session = fake_session
        session.streams = fake_streams

        asyncio.run(session.close())

        fake_session.call_tool.assert_awaited_once_with(
            name="py_eval",
            arguments={"code": "import idc; idc.qexit(0)"},
        )
        fake_process.wait.assert_has_calls([call(timeout=10), call(timeout=1)])
        fake_process.kill.assert_called_once_with()

    def test_lazy_idalib_session_close_without_session_waits_before_kill(self) -> None:
        session = dump_symbols.LazyIdalibSession(binary_path=Path("/tmp/ntoskrnl.exe"))

        fake_process = MagicMock()
        fake_process.poll.return_value = None
        fake_streams = AsyncMock()

        session.process = fake_process
        session.session = None
        session.streams = fake_streams

        asyncio.run(session.close())

        fake_streams.__aexit__.assert_awaited_once_with(None, None, None)
        fake_process.wait.assert_called_once_with(timeout=10)
        fake_process.kill.assert_not_called()

    def test_lazy_idalib_session_close_qexit_timeout_still_runs_cleanup_and_fallback(self) -> None:
        session = dump_symbols.LazyIdalibSession(binary_path=Path("/tmp/ntoskrnl.exe"))

        fake_process = MagicMock()
        fake_process.poll.return_value = None
        fake_process.wait.side_effect = [
            subprocess.TimeoutExpired(cmd="wait", timeout=10),
            None,
        ]

        fake_session = AsyncMock()
        fake_streams = AsyncMock()
        session.process = fake_process
        session.session = fake_session
        session.streams = fake_streams

        async def fake_wait_for(awaitable, timeout):
            awaitable.close()
            raise asyncio.TimeoutError()

        with patch.object(dump_symbols.asyncio, "wait_for", new=AsyncMock(side_effect=fake_wait_for)) as mock_wait_for:
            asyncio.run(session.close())

        self.assertEqual(1, mock_wait_for.await_count)
        fake_session.__aexit__.assert_awaited_once_with(None, None, None)
        fake_streams.__aexit__.assert_awaited_once_with(None, None, None)
        fake_process.wait.assert_has_calls([call(timeout=10), call(timeout=1)])
        fake_process.kill.assert_called_once_with()

    def test_lazy_idalib_session_close_re_raises_cancel_after_cleanup(self) -> None:
        session = dump_symbols.LazyIdalibSession(binary_path=Path("/tmp/ntoskrnl.exe"))

        fake_process = MagicMock()
        fake_process.poll.return_value = None

        fake_session = AsyncMock()
        fake_session.call_tool = AsyncMock(side_effect=asyncio.CancelledError())
        fake_streams = AsyncMock()

        session.process = fake_process
        session.session = fake_session
        session.streams = fake_streams

        with self.assertRaises(asyncio.CancelledError):
            asyncio.run(session.close())

        fake_session.__aexit__.assert_awaited_once_with(None, None, None)
        fake_streams.__aexit__.assert_awaited_once_with(None, None, None)
        fake_process.kill.assert_called_once_with()
        fake_process.wait.assert_called_once_with(timeout=1)
        self.assertIsNone(session.process)
        self.assertIsNone(session.session)
        self.assertIsNone(session.streams)

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

    def test_start_idalib_mcp_uses_reference_startup_timeout(self) -> None:
        fake_process = MagicMock()
        binary_path = Path("/tmp/ntoskrnl.exe")

        with (
            patch.object(
                dump_symbols.subprocess,
                "Popen",
                return_value=fake_process,
            ),
            patch.object(dump_symbols, "_wait_for_port", return_value=True) as mock_wait,
        ):
            process = dump_symbols.start_idalib_mcp(
                binary_path,
                host="127.0.0.1",
                port=13337,
            )

        self.assertIs(process, fake_process)
        mock_wait.assert_called_once_with(
            "127.0.0.1",
            13337,
            timeout=dump_symbols.MCP_STARTUP_TIMEOUT,
        )

    def test_main_reports_when_no_binary_dirs_match(self) -> None:
        args = SimpleNamespace(
            symboldir="symbols",
            arch="amd64",
            configyaml="config.yaml",
            agent="codex",
            debug=False,
            force=False,
        )

        with (
            patch.object(dump_symbols, "parse_args", return_value=args),
            patch.object(dump_symbols, "load_config", return_value=SimpleNamespace()),
            patch.object(dump_symbols, "_iter_binary_dirs", return_value=[]),
            patch("builtins.print") as mock_print,
        ):
            exit_code = dump_symbols.main([])

        self.assertEqual(0, exit_code)
        mock_print.assert_has_calls(
            [
                call("Scanning symbols/amd64"),
                call("Found 0 candidate binary directories"),
                call("No processable binary directories found"),
            ]
        )
        self.assertEqual(3, mock_print.call_count)

    def test_main_reports_single_binary_success_summary(self) -> None:
        args = SimpleNamespace(
            symboldir="symbols",
            arch="amd64",
            configyaml="config.yaml",
            agent="codex",
            debug=False,
            force=False,
        )
        module = SimpleNamespace()
        binary_dir = Path("symbols/amd64/ntoskrnl.10.0.1/abc123")
        pdb_path = binary_dir / "ntkrnlmp.pdb"

        with (
            patch.object(dump_symbols, "parse_args", return_value=args),
            patch.object(dump_symbols, "load_config", return_value=SimpleNamespace()),
            patch.object(
                dump_symbols,
                "_iter_binary_dirs",
                return_value=[(module, binary_dir, pdb_path)],
            ),
            patch.object(
                dump_symbols,
                "_process_module_binary",
                new=AsyncMock(return_value=(True, True)),
            ),
            patch("builtins.print") as mock_print,
        ):
            exit_code = dump_symbols.main([])

        self.assertEqual(0, exit_code)
        mock_print.assert_has_calls(
            [
                call("Scanning symbols/amd64"),
                call("Found 1 candidate binary directories"),
                call(f"Processing {binary_dir}"),
                call(f"Processed {binary_dir} successfully"),
                call("Summary: 1 succeeded, 0 failed, 0 skipped"),
            ]
        )
        self.assertEqual(5, mock_print.call_count)

    def test_main_reports_single_binary_skip_summary_when_outputs_exist(self) -> None:
        args = SimpleNamespace(
            symboldir="symbols",
            arch="amd64",
            configyaml="config.yaml",
            agent="codex",
            debug=False,
            force=False,
        )
        with TemporaryDirectory() as temp_dir:
            binary_dir = Path(temp_dir)
            binary_path = binary_dir / "ntoskrnl.exe"
            binary_path.write_text("", encoding="utf-8")
            pdb_path = binary_dir / "ntkrnlmp.pdb"
            pdb_path.write_text("", encoding="utf-8")
            output_path = binary_dir / "EpObjectTable.yaml"
            output_path.write_text("ready", encoding="utf-8")

            module = SimpleNamespace(
                path=["ntoskrnl.exe"],
                skills=[
                    {
                        "name": "find-EpObjectTable",
                        "symbol": "EpObjectTable",
                        "expected_output": ["EpObjectTable.yaml"],
                    }
                ],
                symbols=[
                    {
                        "name": "EpObjectTable",
                        "category": "struct_offset",
                        "data_type": "uint16",
                    }
                ],
            )

            with (
                patch.object(dump_symbols, "parse_args", return_value=args),
                patch.object(dump_symbols, "load_config", return_value=SimpleNamespace()),
                patch.object(
                    dump_symbols,
                    "_iter_binary_dirs",
                    return_value=[(module, binary_dir, pdb_path)],
                ),
                patch.object(dump_symbols, "start_idalib_mcp") as mock_start,
                patch("builtins.print") as mock_print,
            ):
                exit_code = dump_symbols.main([])

        self.assertEqual(0, exit_code)
        mock_start.assert_not_called()
        mock_print.assert_has_calls(
            [
                call("Scanning symbols/amd64"),
                call("Found 1 candidate binary directories"),
                call(f"Processing {binary_dir}"),
                call(f"Skipped {binary_dir} (no work required)"),
                call("Summary: 0 succeeded, 0 failed, 1 skipped"),
            ]
        )
        self.assertEqual(5, mock_print.call_count)

    def test_main_reports_failure_summary_before_reraising_exception(self) -> None:
        args = SimpleNamespace(
            symboldir="symbols",
            arch="amd64",
            configyaml="config.yaml",
            agent="codex",
            debug=False,
            force=False,
        )
        module = SimpleNamespace()
        binary_dir = Path("symbols/amd64/ntoskrnl.10.0.1/abc123")
        pdb_path = binary_dir / "ntkrnlmp.pdb"

        with (
            patch.object(dump_symbols, "parse_args", return_value=args),
            patch.object(dump_symbols, "load_config", return_value=SimpleNamespace()),
            patch.object(
                dump_symbols,
                "_iter_binary_dirs",
                return_value=[(module, binary_dir, pdb_path)],
            ),
            patch.object(
                dump_symbols,
                "_process_module_binary",
                new=AsyncMock(side_effect=RuntimeError("boom")),
            ),
            patch("builtins.print") as mock_print,
        ):
            with self.assertRaisesRegex(RuntimeError, "boom"):
                dump_symbols.main([])

        mock_print.assert_has_calls(
            [
                call("Scanning symbols/amd64"),
                call("Found 1 candidate binary directories"),
                call(f"Processing {binary_dir}"),
                call(f"Processing {binary_dir} failed"),
                call("Summary: 0 succeeded, 1 failed, 0 skipped"),
            ]
        )
        self.assertEqual(5, mock_print.call_count)
