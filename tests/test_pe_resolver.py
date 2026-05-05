from __future__ import annotations

import subprocess
import unittest
from unittest import mock

import pe_resolver


COFF_EXPORTS_OUTPUT = """
File: ntoskrnl.exe
Format: COFF-x86-64
Arch: x86_64
Export {
  Ordinal: 949
  Name: IoGetStackLimits
  RVA: 0x2494F0
}
"""


class TestPeResolver(unittest.TestCase):
    def test_resolve_export_symbol_from_text_returns_rva(self) -> None:
        result = pe_resolver.resolve_export_symbol_from_text(
            COFF_EXPORTS_OUTPUT,
            "IoGetStackLimits",
        )

        self.assertEqual("IoGetStackLimits", result["name"])
        self.assertEqual(0x2494F0, result["rva"])

    def test_resolve_export_symbol_invokes_llvm_readobj_exports(self) -> None:
        completed_process = subprocess.CompletedProcess(
            args=["llvm-readobj", "--coff-exports", "ntoskrnl.exe"],
            returncode=0,
            stdout=COFF_EXPORTS_OUTPUT,
            stderr="",
        )

        with mock.patch(
            "pe_resolver.subprocess.run",
            return_value=completed_process,
        ) as run_mock:
            result = pe_resolver.resolve_export_symbol(
                "ntoskrnl.exe",
                "IoGetStackLimits",
            )

        self.assertEqual(0x2494F0, result["rva"])
        run_mock.assert_called_once_with(
            ["llvm-readobj", "--coff-exports", "ntoskrnl.exe"],
            capture_output=True,
            text=True,
            check=True,
            timeout=300,
        )
