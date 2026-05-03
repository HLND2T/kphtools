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

        self.assertEqual(
            ["EgeGuid"], config.modules[0].skills[0].produced_symbols
        )
        self.assertEqual("struct_offset", config.modules[0].symbols[0].category)
        self.assertFalse(hasattr(config.modules[0].symbols[0], "symbol_expr"))

    def test_load_config_reads_multiple_symbols_from_expected_output(self) -> None:
        with TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "config.yaml"
            config_path.write_text(
                textwrap.dedent(
                    """
                    modules:
                      - name: ntoskrnl
                        path: [ntoskrnl.exe]
                        skills:
                          - name: find-Callbacks
                            expected_output:
                              - ExReferenceCallBackBlock.yaml
                              - ExDereferenceCallBackBlock.yaml
                        symbols:
                          - name: ExReferenceCallBackBlock
                            category: func
                            data_type: uint32
                          - name: ExDereferenceCallBackBlock
                            category: func
                            data_type: uint32
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )

            config = symbol_config.load_config(config_path)

        self.assertEqual(
            ["ExReferenceCallBackBlock", "ExDereferenceCallBackBlock"],
            config.modules[0].skills[0].produced_symbols,
        )

    def test_load_config_reads_optional_and_arch_specific_skill_fields(self) -> None:
        with TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "config.yaml"
            config_path.write_text(
                textwrap.dedent(
                    """
                    modules:
                      - name: ntoskrnl
                        path: [ntoskrnl.exe]
                        skills:
                          - name: find-Required
                            expected_output: [Required.yaml]
                            optional_output: [Optional.yaml]
                            skip_if_exists: [Substitute.yaml]
                            expected_input_amd64: [InputAmd64.yaml]
                            expected_input_arm64: [InputArm64.yaml]
                        symbols:
                          - name: Required
                            category: func
                            data_type: uint32
                          - name: Optional
                            category: func
                            data_type: uint32
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )

            config = symbol_config.load_config(config_path)

        skill = config.modules[0].skills[0]
        self.assertEqual(["Required.yaml"], skill.expected_output)
        self.assertEqual(["Optional.yaml"], skill.optional_output)
        self.assertEqual(["Substitute.yaml"], skill.skip_if_exists)
        self.assertEqual(["InputAmd64.yaml"], skill.expected_input_amd64)
        self.assertEqual(["InputArm64.yaml"], skill.expected_input_arm64)
        self.assertEqual(["Required", "Optional"], skill.produced_symbols)

    def test_load_config_accepts_optional_only_skill(self) -> None:
        with TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "config.yaml"
            config_path.write_text(
                textwrap.dedent(
                    """
                    modules:
                      - name: ntoskrnl
                        path: [ntoskrnl.exe]
                        skills:
                          - name: find-Optional
                            optional_output: [Optional.yaml]
                        symbols:
                          - name: Optional
                            category: func
                            data_type: uint32
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )

            config = symbol_config.load_config(config_path)

        skill = config.modules[0].skills[0]
        self.assertEqual([], skill.expected_output)
        self.assertEqual(["Optional.yaml"], skill.optional_output)
        self.assertEqual(["Optional"], skill.produced_symbols)

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

    def test_load_config_rejects_legacy_skill_symbol_field(self) -> None:
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
                        symbols:
                          - name: EpObjectTable
                            category: struct_offset
                            data_type: uint16
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "skill.symbol"):
                symbol_config.load_config(config_path)

    def test_load_config_rejects_symbol_locating_fields(self) -> None:
        cases = [
            ("symbol.symbol_expr", "symbol_expr: _ETW_GUID_ENTRY->Guid"),
            ("symbol.struct_name", "struct_name: _ETW_GUID_ENTRY"),
            ("symbol.member_name", "member_name: Guid"),
            ("symbol.bits", "bits: true"),
            ("symbol.alias", "alias: [GuidAlias]"),
        ]

        for field_name, extra_field in cases:
            with self.subTest(field_name=field_name):
                with TemporaryDirectory() as temp_dir:
                    config_path = Path(temp_dir) / "config.yaml"
                    config_path.write_text(
                        textwrap.dedent(
                            f"""
                            modules:
                              - name: ntoskrnl
                                path: [ntoskrnl.exe]
                                skills:
                                  - name: find-EgeGuid
                                    expected_output: [EgeGuid.yaml]
                                symbols:
                                  - name: EgeGuid
                                    category: struct_offset
                                    data_type: uint16
                                    {extra_field}
                            """
                        ).strip()
                        + "\n",
                        encoding="utf-8",
                    )

                    with self.assertRaisesRegex(ValueError, field_name):
                        symbol_config.load_config(config_path)

    def test_load_config_rejects_unknown_skill_field(self) -> None:
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
                            expected_output: [EgeGuid.yaml]
                            unexpected_skill_field: true
                        symbols:
                          - name: EgeGuid
                            category: struct_offset
                            data_type: uint16
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "skill.unexpected_skill_field"):
                symbol_config.load_config(config_path)

    def test_load_config_rejects_unknown_symbol_field(self) -> None:
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
                            expected_output: [EgeGuid.yaml]
                        symbols:
                          - name: EgeGuid
                            category: struct_offset
                            data_type: uint16
                            unexpected_symbol_field: true
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "symbol.unexpected_symbol_field"):
                symbol_config.load_config(config_path)

    def test_load_config_rejects_non_integer_max_retries(self) -> None:
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
                            expected_output: [EgeGuid.yaml]
                            max_retries: not-an-int
                        symbols:
                          - name: EgeGuid
                            category: struct_offset
                            data_type: uint16
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "skill.max_retries"):
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

    def test_load_config_rejects_unknown_skill_output_symbol(self) -> None:
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
                            expected_output: [MissingSymbol.yaml]
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
                      - expected_output: [EpObjectTable.yaml]
                    symbols:
                      - name: EpObjectTable
                        category: struct_offset
                        data_type: uint16
                """,
            ),
            (
                "expected_output or optional_output must be a non-empty list",
                """
                modules:
                  - name: ntoskrnl
                    path: [ntoskrnl.exe]
                    skills:
                      - name: find-EpObjectTable
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
        self.assertGreater(len(config.modules[0].symbols), 0)
        symbol_names = {symbol.name for symbol in config.modules[0].symbols}
        for skill in config.modules[0].skills:
            self.assertTrue(skill.produced_symbols)
            self.assertTrue(set(skill.produced_symbols).issubset(symbol_names))
