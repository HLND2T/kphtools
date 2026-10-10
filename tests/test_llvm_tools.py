import asyncio
import os
from pathlib import Path
import stat
import subprocess
import sys
import textwrap
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import llvm_tools
import pdb_resolver
import pe_resolver
from ida_preprocessor_scripts.generic_func import preprocess_func_symbol


class TestLlvmTools(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        environment = {
            name: os.environ[name]
            for name in ("SystemRoot", "WINDIR", "TEMP", "TMP")
            if name in os.environ
        }
        environment["PATH"] = str(self.root)
        self.env = patch.dict(os.environ, environment, clear=True)
        self.env.start()
        self.addCleanup(self.env.stop)
        pdb_resolver._LLVM_PDBUTIL_CACHE.clear()

    def executable(self, name):
        path = self.root / (name + (".exe" if os.name == "nt" else ""))
        path.touch()
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
        return str(path)

    def test_prefers_bare_name_then_highest_numeric_version(self):
        self.executable("llvm-pdbutil-9")
        newest = self.executable("llvm-pdbutil-18")
        self.executable("llvm-pdbutil-99-extra")
        self.assertEqual(newest, llvm_tools.resolve_llvm_tool("llvm-pdbutil"))
        bare = self.executable("llvm-pdbutil")
        self.assertEqual(os.path.normcase(bare), os.path.normcase(llvm_tools.resolve_llvm_tool("llvm-pdbutil")))

    def test_explicit_argument_precedes_environment_and_path(self):
        bare = self.executable("llvm-pdbutil")
        override = self.executable("custom tool")
        os.environ["KPHTOOLS_LLVM_PDBUTIL"] = override
        self.assertEqual(override, llvm_tools.resolve_llvm_tool("llvm-pdbutil"))
        self.assertEqual(bare, llvm_tools.resolve_llvm_tool("llvm-pdbutil", bare))

    def test_invalid_override_does_not_fall_back(self):
        self.executable("llvm-readobj")
        os.environ["KPHTOOLS_LLVM_READOBJ"] = "missing-tool"
        with self.assertRaisesRegex(llvm_tools.LlvmToolNotFoundError, "KPHTOOLS_LLVM_READOBJ"):
            llvm_tools.resolve_llvm_tool("llvm-readobj")
        with self.assertRaises(llvm_tools.LlvmToolNotFoundError):
            llvm_tools.resolve_llvm_tool("llvm-readobj", "missing-explicit")

    def test_missing_tools_are_not_symbol_misses(self):
        for resolve, args in (
            (pdb_resolver.resolve_public_symbol, ("dummy.pdb", "Symbol")),
            (pdb_resolver.resolve_struct_symbol, ("dummy.pdb", "_TYPE->Field")),
            (pe_resolver.resolve_export_symbol, ("dummy.exe", "Symbol")),
        ):
            with self.subTest(resolve=resolve.__name__):
                with self.assertRaisesRegex(llvm_tools.LlvmToolNotFoundError, "LLVM.*PATH"):
                    resolve(*args)

    def test_missing_tool_propagates_past_preprocessor_fallback(self):
        with self.assertRaises(llvm_tools.LlvmToolNotFoundError):
            asyncio.run(preprocess_func_symbol(
                session=None, symbol_name="Symbol", metadata={},
                pdb_path="dummy.pdb", debug=False, llm_config=None,
            ))

    def test_missing_tool_exits_nonzero_with_diagnostic(self):
        binary_dir = self.root / "amd64/dummy.exe.1.0.0.0/hash"
        binary_dir.mkdir(parents=True)
        (binary_dir / "dummy.exe").touch()
        (binary_dir / "dummy.pdb").touch()
        # Keep the real CLI scan, analysis lifecycle, resolver, and error propagation.
        # Substitute only configuration, the preprocessor entry, and external services.
        code = textwrap.dedent("""
            import sys
            from types import SimpleNamespace
            from unittest.mock import patch
            import dump_symbols
            from ida_preprocessor_scripts.generic_func import preprocess_func_symbol

            async def preprocess(**kwargs):
                return await preprocess_func_symbol(
                    session=kwargs['session'], symbol_name='Symbol', metadata={},
                    pdb_path=kwargs['pdb_path'], debug=False, llm_config=None,
                )

            module = SimpleNamespace(
                path=['dummy.exe'],
                skills=[{'name': 'find-Symbol', 'expected_output': ['Symbol.yaml']}],
                symbols=[{'name': 'Symbol', 'category': 'func'}],
            )
            with (
                patch.object(dump_symbols, 'load_dotenv'),
                patch.object(dump_symbols, 'load_config', return_value=SimpleNamespace(modules=[module])),
                patch.object(dump_symbols, '_build_llm_config', return_value=None),
                patch.object(dump_symbols, 'preprocess_single_skill_via_mcp', side_effect=preprocess),
                patch.object(dump_symbols, 'run_skill', side_effect=AssertionError('AGENT_FALLBACK_REACHED')),
                patch.object(dump_symbols, 'start_idalib_mcp', side_effect=AssertionError('IDA_START_REACHED')),
            ):
                sys.exit(dump_symbols.main(['-symboldir', sys.argv[1], '-arch', 'amd64', '-force']))
        """)
        result = subprocess.run(
            [sys.executable, "-c", code, str(self.root)],
            capture_output=True, text=True,
            cwd=Path(__file__).resolve().parents[1],
        )
        self.assertNotEqual(0, result.returncode)
        self.assertIn("KPHTOOLS_LLVM_PDBUTIL", result.stderr)
        self.assertNotIn("AGENT_FALLBACK_REACHED", result.stderr)
        self.assertNotIn("IDA_START_REACHED", result.stderr)
        self.assertFalse((binary_dir / "artifacts.yaml").exists())

    def test_tool_disappearing_before_launch_is_not_a_symbol_miss(self):
        self.executable("llvm-pdbutil")
        self.executable("llvm-readobj")
        with patch("subprocess.run", side_effect=FileNotFoundError):
            for resolve, path in (
                (pdb_resolver.resolve_public_symbol, "dummy.pdb"),
                (pe_resolver.resolve_export_symbol, "dummy.exe"),
            ):
                with self.subTest(resolve=resolve.__name__):
                    with self.assertRaises(llvm_tools.LlvmToolNotFoundError):
                        resolve(path, "Symbol")

    def test_cache_isolated_by_resolved_executable(self):
        first = self.executable("first")
        second = self.executable("second")
        with patch("pdb_resolver.subprocess.run", side_effect=[
            subprocess.CompletedProcess([], 0, stdout="one"),
            subprocess.CompletedProcess([], 0, stdout="two"),
        ]) as run:
            os.environ["KPHTOOLS_LLVM_PDBUTIL"] = first
            self.assertEqual("one", pdb_resolver.run_llvm_pdbutil("dummy.pdb", "-types"))
            os.environ["KPHTOOLS_LLVM_PDBUTIL"] = second
            self.assertEqual("two", pdb_resolver.run_llvm_pdbutil("dummy.pdb", "-types"))
            self.assertEqual("two", pdb_resolver.run_llvm_pdbutil("dummy.pdb", "-types"))
        self.assertEqual(2, run.call_count)
