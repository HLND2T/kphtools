from pathlib import Path
import tempfile
import textwrap
import unittest

import generate_reference_yaml
from ida_reference_export import ReferenceGenerationError


class TestGenerateReferenceYaml(unittest.TestCase):
    def test_parse_args_rejects_auto_start_mcp_without_binary(self) -> None:
        with self.assertRaises(SystemExit):
            generate_reference_yaml.parse_args(
                [
                    "-func_name",
                    "ExReferenceCallBackBlock",
                    "-auto_start_mcp",
                ]
            )

    def test_parse_args_rejects_binary_without_auto_start_mcp(self) -> None:
        with self.assertRaises(SystemExit):
            generate_reference_yaml.parse_args(
                [
                    "-func_name",
                    "ExReferenceCallBackBlock",
                    "-binary",
                    "/tmp/ntoskrnl.exe",
                ]
            )

    def test_build_reference_output_path(self) -> None:
        output_path = generate_reference_yaml.build_reference_output_path(
            Path("/repo"),
            module="ntoskrnl",
            func_name="ExReferenceCallBackBlock",
            arch="amd64",
        )
        self.assertEqual(
            Path("/repo")
            / "ida_preprocessor_scripts"
            / "references"
            / "ntoskrnl"
            / "ExReferenceCallBackBlock.amd64.yaml",
            output_path,
        )

    def test_build_reference_output_path_rejects_invalid_target(self) -> None:
        with self.assertRaisesRegex(
            ReferenceGenerationError,
            r"^invalid reference output target$",
        ):
            generate_reference_yaml.build_reference_output_path(
                Path("/repo"),
                module='nto:skrnl',
                func_name="ExReferenceCallBackBlock",
                arch="amd64",
            )


class TestGenerateReferenceYamlContext(unittest.TestCase):
    def _write_config(self, config_path: Path) -> None:
        config_path.write_text(
            textwrap.dedent(
                """
                modules:
                  - name: ntoskrnl
                    path:
                      - ntoskrnl.exe
                      - ntkrla57.exe
                    skills:
                      - name: sample-skill
                        symbol: ExReferenceCallBackBlock
                        expected_output:
                          - summary.yaml
                        expected_input:
                          - context
                    symbols:
                      - name: ExReferenceCallBackBlock
                        category: function
                        data_type: void
                """
            ).strip()
            + "\n",
            encoding="utf-8",
        )

    def test_infer_context_from_binary_path(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_root = Path(temp_dir)
            binary_dir = (
                repo_root
                / "symbols"
                / "amd64"
                / "ntoskrnl.exe.10.0.26100.1"
                / "deadbeef"
            )
            binary_dir.mkdir(parents=True)
            (binary_dir / "ntoskrnl.exe").write_text("", encoding="utf-8")
            config_path = repo_root / "config.yaml"
            self._write_config(config_path)

            context = generate_reference_yaml.infer_context_from_binary_path(
                binary_dir / "ntoskrnl.exe.i64",
                config_path=config_path,
            )

            self.assertEqual("amd64", context["arch"])
            self.assertEqual("ntoskrnl", context["module"])
            self.assertEqual(binary_dir, context["binary_dir"])
            self.assertEqual(binary_dir / "ntoskrnl.exe", context["binary_path"])

    def test_infer_context_from_binary_path_rejects_unknown_arch(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_root = Path(temp_dir)
            binary_dir = (
                repo_root
                / "symbols"
                / "mips64"
                / "ntoskrnl.exe.10.0.26100.1"
                / "deadbeef"
            )
            binary_dir.mkdir(parents=True)
            (binary_dir / "ntoskrnl.exe").write_text("", encoding="utf-8")
            config_path = repo_root / "config.yaml"
            self._write_config(config_path)

            with self.assertRaisesRegex(
                ReferenceGenerationError,
                r"unable to infer arch",
            ):
                generate_reference_yaml.infer_context_from_binary_path(
                    binary_dir / "ntoskrnl.exe.i64",
                    config_path=config_path,
                )
