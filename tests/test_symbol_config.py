from pathlib import Path
from tempfile import TemporaryDirectory
import textwrap
import unittest

import symbol_config


class TestSymbolConfig(unittest.TestCase):
    def test_load_config_rejects_non_mapping_top_level(self) -> None:
        with TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "config.yaml"
            config_path.write_text("- not-a-mapping\n", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "top-level config must be a mapping"):
                symbol_config.load_config(config_path)

    def test_load_config_reads_minimal_symbol_inventory(self) -> None:
        with TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "config.yaml"
            config_path.write_text(
                textwrap.dedent(
                    """
                    modules:
                      - name: ntoskrnl
                        path: [ntoskrnl.exe]
                        skills:
                          - name: find-EgeGuid
                            symbol: EgeGuid
                            expected_output: [EgeGuid.yaml]
                        symbols:
                          - name: EgeGuid
                            category: struct_offset
                            data_type: uint16
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )

            config = symbol_config.load_config(config_path)

        self.assertEqual("EgeGuid", config.modules[0].skills[0].symbol)
        self.assertEqual("struct_offset", config.modules[0].symbols[0].category)
        self.assertFalse(hasattr(config.modules[0].symbols[0], "symbol_expr"))

    def test_load_config_rejects_agent_skill_override(self) -> None:
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
                            expected_output: [EpObjectTable.yaml]
                            agent_skill: find-kph-struct-offset
                        symbols:
                          - name: EpObjectTable
                            category: struct_offset
                            data_type: uint16
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "skill.agent_skill"):
                symbol_config.load_config(config_path)

    def test_load_config_rejects_symbol_locating_fields(self) -> None:
        with TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "config.yaml"
            config_path.write_text(
                textwrap.dedent(
                    """
                    modules:
                      - name: ntoskrnl
                        path: [ntoskrnl.exe]
                        skills:
                          - name: find-EgeGuid
                            symbol: EgeGuid
                            expected_output: [EgeGuid.yaml]
                        symbols:
                          - name: EgeGuid
                            category: struct_offset
                            symbol_expr: _ETW_GUID_ENTRY->Guid
                            data_type: uint16
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "symbol.symbol_expr"):
                symbol_config.load_config(config_path)

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

    def test_load_config_rejects_scalar_for_list_field(self) -> None:
        with TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "config.yaml"
            config_path.write_text(
                textwrap.dedent(
                    """
                    modules:
                      - name: ntoskrnl
                        path: ntoskrnl.exe
                        skills:
                          - name: find-EpObjectTable
                            symbol: EpObjectTable
                            expected_output: [EpObjectTable.yaml]
                        symbols:
                          - name: EpObjectTable
                            category: struct_offset
                            data_type: uint16
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "must be a list"):
                symbol_config.load_config(config_path)

    def test_load_config_rejects_scalar_expected_output(self) -> None:
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
                            expected_output: EpObjectTable.yaml
                        symbols:
                          - name: EpObjectTable
                            category: struct_offset
                            data_type: uint16
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "must be a list"):
                symbol_config.load_config(config_path)

    def test_load_config_rejects_unknown_skill_symbol(self) -> None:
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
                            symbol: MissingSymbol
                            expected_output: [EpObjectTable.yaml]
                        symbols:
                          - name: EpObjectTable
                            category: struct_offset
                            data_type: uint16
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "unknown symbol"):
                symbol_config.load_config(config_path)

    def test_load_config_rejects_empty_module_sections(self) -> None:
        with TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "config.yaml"
            config_path.write_text(
                textwrap.dedent(
                    """
                    modules:
                      - name: ntoskrnl
                        path: []
                        skills: []
                        symbols: []
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "must be a non-empty list"):
                symbol_config.load_config(config_path)

    def test_load_config_rejects_missing_required_fields(self) -> None:
        cases = [
            (
                "module.name",
                """
                modules:
                  - path: [ntoskrnl.exe]
                    skills:
                      - name: find-EpObjectTable
                        symbol: EpObjectTable
                        expected_output: [EpObjectTable.yaml]
                    symbols:
                      - name: EpObjectTable
                        category: struct_offset
                        data_type: uint16
                """,
            ),
            (
                "skill.name",
                """
                modules:
                  - name: ntoskrnl
                    path: [ntoskrnl.exe]
                    skills:
                      - symbol: EpObjectTable
                        expected_output: [EpObjectTable.yaml]
                    symbols:
                      - name: EpObjectTable
                        category: struct_offset
                        data_type: uint16
                """,
            ),
            (
                "skill.symbol",
                """
                modules:
                  - name: ntoskrnl
                    path: [ntoskrnl.exe]
                    skills:
                      - name: find-EpObjectTable
                        expected_output: [EpObjectTable.yaml]
                    symbols:
                      - name: EpObjectTable
                        category: struct_offset
                        data_type: uint16
                """,
            ),
            (
                "symbol.name",
                """
                modules:
                  - name: ntoskrnl
                    path: [ntoskrnl.exe]
                    skills:
                      - name: find-EpObjectTable
                        symbol: EpObjectTable
                        expected_output: [EpObjectTable.yaml]
                    symbols:
                      - category: struct_offset
                        data_type: uint16
                """,
            ),
            (
                "symbol.category",
                """
                modules:
                  - name: ntoskrnl
                    path: [ntoskrnl.exe]
                    skills:
                      - name: find-EpObjectTable
                        symbol: EpObjectTable
                        expected_output: [EpObjectTable.yaml]
                    symbols:
                      - name: EpObjectTable
                        data_type: uint16
                """,
            ),
            (
                "symbol.data_type",
                """
                modules:
                  - name: ntoskrnl
                    path: [ntoskrnl.exe]
                    skills:
                      - name: find-EpObjectTable
                        symbol: EpObjectTable
                        expected_output: [EpObjectTable.yaml]
                    symbols:
                      - name: EpObjectTable
                        category: struct_offset
                """,
            ),
        ]

        for field_name, content in cases:
            with self.subTest(field_name=field_name):
                with TemporaryDirectory() as temp_dir:
                    config_path = Path(temp_dir) / "config.yaml"
                    config_path.write_text(
                        textwrap.dedent(content).strip() + "\n",
                        encoding="utf-8",
                    )

                    with self.assertRaisesRegex(ValueError, field_name):
                        symbol_config.load_config(config_path)

    def test_load_config_rejects_null_required_string_fields(self) -> None:
        cases = [
            (
                "module.name",
                """
                modules:
                  - name: null
                    path: [ntoskrnl.exe]
                    skills:
                      - name: find-EpObjectTable
                        symbol: EpObjectTable
                        expected_output: [EpObjectTable.yaml]
                    symbols:
                      - name: EpObjectTable
                        category: struct_offset
                        data_type: uint16
                """,
            ),
            (
                "symbol.data_type",
                """
                modules:
                  - name: ntoskrnl
                    path: [ntoskrnl.exe]
                    skills:
                      - name: find-EpObjectTable
                        symbol: EpObjectTable
                        expected_output: [EpObjectTable.yaml]
                    symbols:
                      - name: EpObjectTable
                        category: struct_offset
                        data_type: null
                """,
            ),
        ]

        for field_name, content in cases:
            with self.subTest(field_name=field_name):
                with TemporaryDirectory() as temp_dir:
                    config_path = Path(temp_dir) / "config.yaml"
                    config_path.write_text(
                        textwrap.dedent(content).strip() + "\n",
                        encoding="utf-8",
                    )

                    with self.assertRaisesRegex(ValueError, field_name):
                        symbol_config.load_config(config_path)

    def test_load_config_rejects_non_string_required_field(self) -> None:
        with TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "config.yaml"
            config_path.write_text(
                textwrap.dedent(
                    """
                    modules:
                      - name: ntoskrnl
                        path: [ntoskrnl.exe]
                        skills:
                          - name: 123
                            symbol: EpObjectTable
                            expected_output: [EpObjectTable.yaml]
                        symbols:
                          - name: EpObjectTable
                            category: struct_offset
                            data_type: uint16
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "skill.name"):
                symbol_config.load_config(config_path)

    def test_load_config_reads_repository_baseline(self) -> None:
        config = symbol_config.load_config(Path("config.yaml"))

        self.assertEqual(1, len(config.modules))
        self.assertEqual("ntoskrnl", config.modules[0].name)
        self.assertEqual(len(config.modules[0].symbols), len(config.modules[0].skills))
        self.assertGreater(len(config.modules[0].symbols), 0)
