import asyncio
import os
from pathlib import Path
import signal
import subprocess
import sys
import unittest
from unittest.mock import AsyncMock, Mock, patch

import dump_symbols


@unittest.skipUnless(os.name == "posix", "POSIX process groups")
class TestPosixMcpCleanup(unittest.TestCase):
    def run_tree(self, *, ignore_term=False, parent_exits=False):
        port = dump_symbols._allocate_local_port()
        child = (
            "import signal,socket,time; "
            + ("signal.signal(signal.SIGTERM, signal.SIG_IGN); " if ignore_term else "")
            + "s=socket.socket(); "
            + f"s.bind(('127.0.0.1',{port})); s.listen(); time.sleep(60)"
        )
        parent = (
            "import subprocess,sys,time; "
            + f"subprocess.Popen([sys.executable,'-c',{child!r}]); "
            + ("sys.exit(0)" if parent_exits else "time.sleep(60)")
        )
        real_popen = subprocess.Popen
        def launch(_command, **kwargs):
            return real_popen([sys.executable, "-c", parent], **kwargs)
        process = None
        try:
            with patch.object(dump_symbols.subprocess, "Popen", side_effect=launch):
                process = dump_symbols.start_idalib_mcp(Path("dummy.exe"), port=port)
            if parent_exits:
                process.wait(timeout=5)
            self.assertTrue(dump_symbols.stop_idalib_mcp_process(process, timeout=0.3))
            self.assertTrue(dump_symbols._wait_for_port_release("127.0.0.1", port, timeout=3))
            self.assertIsNotNone(process.poll())
            self.assertTrue(dump_symbols.stop_idalib_mcp_process(process, timeout=0.3))
        finally:
            if process is not None:
                # Only signal the session created by this test, never our own group.
                try:
                    if os.getpgid(process.pid) == process.pid:
                        os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    # An exited leader may still have a live child in its owned group.
                    if getattr(process, "_kphtools_pgid", None) == process.pid:
                        try:
                            os.killpg(process.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                process.wait(timeout=5)

    def test_releases_descendant_listener(self):
        self.run_tree()

    def test_escalates_when_worker_ignores_sigterm(self):
        self.run_tree(ignore_term=True)

    def test_reclaims_worker_after_parent_exits(self):
        self.run_tree(parent_exits=True, ignore_term=True)

    def test_missing_group_is_already_stopped(self):
        process = Mock(pid=12345, _kphtools_pgid=12345)
        process.poll.return_value = 0
        with patch.object(os, "killpg", side_effect=ProcessLookupError):
            self.assertTrue(dump_symbols.stop_idalib_mcp_process(process))
        process.wait.assert_called_once()
        self.assertIsNone(process._kphtools_pgid)

    def test_permission_error_reports_failed_cleanup(self):
        process = Mock(pid=12345, _kphtools_pgid=12345)
        with (
            patch.object(os, "killpg", side_effect=PermissionError("denied")),
            patch("builtins.print") as output,
        ):
            self.assertFalse(dump_symbols.stop_idalib_mcp_process(process))
        self.assertIn("denied", output.call_args.args[0])

    def test_does_not_infer_group_from_unregistered_process(self):
        process = Mock(pid=12345, _kphtools_pgid=None)
        process.poll.return_value = 0
        with patch.object(os, "killpg") as killpg:
            self.assertTrue(dump_symbols.stop_idalib_mcp_process(process))
        killpg.assert_not_called()


class TestMcpCleanupLifecycle(unittest.TestCase):
    def test_close_and_recovery_clean_exited_parent(self):
        for method in ("close", "_stop_for_recovery", "_cleanup_failed_start"):
            with self.subTest(method=method):
                session = dump_symbols.LazyIdalibSession(Path("dummy.exe"))
                process = Mock()
                process.poll.return_value = 0
                session.process = process
                session._wait_for_port_release = AsyncMock(return_value=True)
                with patch.object(dump_symbols, "stop_idalib_mcp_process", return_value=True) as stop:
                    asyncio.run(getattr(session, method)())
                stop.assert_called_once_with(process, debug=False)

    def test_cancellation_during_handle_close_still_stops_tree(self):
        for method in ("close", "_stop_for_recovery"):
            with self.subTest(method=method):
                session = dump_symbols.LazyIdalibSession(Path("dummy.exe"))
                process = Mock()
                process.poll.return_value = 0
                session.process = process
                session._close_handles = AsyncMock(side_effect=asyncio.CancelledError)
                session._wait_for_port_release = AsyncMock(return_value=True)
                with patch.object(dump_symbols, "stop_idalib_mcp_process", return_value=True) as stop:
                    with self.assertRaises(asyncio.CancelledError):
                        asyncio.run(getattr(session, method)())
                stop.assert_called_once_with(process, debug=False)
                session._wait_for_port_release.assert_awaited_once()

    def test_port_release_does_not_hide_tree_cleanup_failure(self):
        for method in ("close", "_stop_for_recovery"):
            with self.subTest(method=method):
                session = dump_symbols.LazyIdalibSession(Path("dummy.exe"))
                session.process = Mock()
                session.process.poll.return_value = 0
                session._wait_for_port_release = AsyncMock(return_value=True)
                with patch.object(dump_symbols, "stop_idalib_mcp_process", return_value=False):
                    self.assertFalse(asyncio.run(getattr(session, method)()))
