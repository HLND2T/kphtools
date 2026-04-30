from pathlib import Path
from tempfile import TemporaryDirectory
import asyncio
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, MagicMock, call, patch

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
                ok = asyncio.run(
                    dump_symbols._process_module_binary(module, binary_dir, pdb_path, args)
                )

        self.assertTrue(ok)
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
                ok = asyncio.run(
                    dump_symbols._process_module_binary(module, binary_dir, pdb_path, args)
                )

        self.assertTrue(ok)
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
        mock_open_session.assert_awaited_once_with("http://127.0.0.1:24567/mcp")
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

    def test_lazy_idalib_session_close_without_session_uses_fast_kill_path(self) -> None:
        session = dump_symbols.LazyIdalibSession(binary_path=Path("/tmp/ntoskrnl.exe"))

        fake_process = MagicMock()
        fake_process.poll.return_value = None
        fake_streams = AsyncMock()

        session.process = fake_process
        session.session = None
        session.streams = fake_streams

        asyncio.run(session.close())

        fake_streams.__aexit__.assert_awaited_once_with(None, None, None)
        fake_process.kill.assert_called_once_with()
        fake_process.wait.assert_called_once_with(timeout=1)

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

    def test_lazy_idalib_session_close_preserves_process_handle_on_wait_error(self) -> None:
        session = dump_symbols.LazyIdalibSession(binary_path=Path("/tmp/ntoskrnl.exe"))

        fake_process = MagicMock()
        fake_process.poll.return_value = None
        fake_process.wait.side_effect = RuntimeError("wait failed")
        fake_session = AsyncMock()
        fake_streams = AsyncMock()

        session.process = fake_process
        session.session = fake_session
        session.streams = fake_streams

        with self.assertRaises(RuntimeError):
            asyncio.run(session.close())

        self.assertIs(session.process, fake_process)

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
