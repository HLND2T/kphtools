from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import textwrap
import unittest

import symbol_config


class TestSymbolConfig(unittest.TestCase):
    def test_load_config_reads_modules_skills_symbols(self) -> None:
        with TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "config.yaml"
            config_path.write_text(
                textwrap.dedent(
                    """
                    modules:
                      - name: ntoskrnl
                        path:
                          - ntoskrnl.exe
                          - ntkrla57.exe
                        skills:
                          - name: find-EpObjectTable
                            symbol: EpObjectTable
                            expected_output:
                              - EpObjectTable.yaml
                            agent_skill: find-kph-struct-offset
                        symbols:
                          - name: EpObjectTable
                            category: struct_offset
                            struct_name: _EPROCESS
                            member_name: ObjectTable
                            data_type: uint16
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )

            config = symbol_config.load_config(config_path)

        self.assertEqual(["ntoskrnl.exe", "ntkrla57.exe"], config.modules[0].path)
        self.assertEqual("EpObjectTable", config.modules[0].skills[0].symbol)
        self.assertEqual(
            "find-kph-struct-offset", config.modules[0].skills[0].agent_skill
        )
        self.assertEqual("struct_offset", config.modules[0].symbols[0].category)
        self.assertEqual(
            "_EPROCESS->ObjectTable", config.modules[0].symbols[0].symbol_expr
        )

    def test_load_config_rejects_arch_suffix_in_expected_output(self) -> None:
        with TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "config.yaml"
            config_path.write_text(
                textwrap.dedent(
                    """
                    modules:
                      - name: ntoskrnl
                        path: [ntoskrnl.exe]
                        skills:
                          - name: find-EpObjectTable
                            symbol: EpObjectTable
                            expected_output:
                              - EpObjectTable.amd64.yaml
                        symbols:
                          - name: EpObjectTable
                            category: struct_offset
                            struct_name: _EPROCESS
                            member_name: ObjectTable
                            data_type: uint16
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(
                ValueError, "must not encode arch in filename"
            ):
                symbol_config.load_config(config_path)
