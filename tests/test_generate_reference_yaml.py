from pathlib import Path
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
