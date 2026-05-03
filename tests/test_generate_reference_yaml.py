from contextlib import asynccontextmanager
from io import StringIO
import json
from pathlib import Path
import tempfile
import textwrap
import unittest
from unittest.mock import AsyncMock, patch

import generate_reference_yaml
from ida_reference_export import ReferenceGenerationError


def _make_py_eval_result(payload: dict) -> object:
    return type(
        "ToolResult",
        (),
        {
            "content": [
                type(
                    "Text",
                    (),
                    {"text": json.dumps({"result": json.dumps(payload)})},
                )()
            ]
        },
    )()


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
                        expected_output:
                          - ExReferenceCallBackBlock.yaml
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

    def test_match_module_spec_falls_back_to_version_dir_name(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            from symbol_config import load_config

            repo_root = Path(temp_dir)
            binary_dir = (
                repo_root
                / "symbols"
                / "amd64"
                / "ntoskrnl.exe.10.0.26100.1"
                / "deadbeef"
            )
            binary_dir.mkdir(parents=True)
            config_path = repo_root / "config.yaml"
            self._write_config(config_path)

            module_spec = generate_reference_yaml._match_module_spec(
                load_config(config_path),
                binary_dir,
                binary_dir.parent.name,
            )

            self.assertEqual("ntoskrnl", module_spec.name)

    def test_infer_context_from_binary_path_normalizes_explicit_overrides(self) -> None:
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
                module=" ntoskrnl ",
                arch=" AMD64 ",
            )

            self.assertEqual("amd64", context["arch"])
            self.assertEqual("ntoskrnl", context["module"])

    def test_infer_context_from_binary_path_rejects_module_override_mismatch(
        self,
    ) -> None:
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

            with self.assertRaisesRegex(
                ReferenceGenerationError,
                r"^module override does not match current binary directory$",
            ):
                generate_reference_yaml.infer_context_from_binary_path(
                    binary_dir / "ntoskrnl.exe.i64",
                    config_path=config_path,
                    module=" hal ",
                )

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


class TestGenerateReferenceYamlResolution(unittest.IsolatedAsyncioTestCase):
    async def test_resolve_func_va_prefers_existing_func_va(self) -> None:
        session = AsyncMock()
        with tempfile.TemporaryDirectory() as temp_dir:
            binary_dir = Path(temp_dir)
            (binary_dir / "ExReferenceCallBackBlock.yaml").write_text(
                "func_va: '0x140001234'\n",
                encoding="utf-8",
            )

            func_va = await generate_reference_yaml.resolve_func_va(
                session=session,
                binary_dir=binary_dir,
                func_name="ExReferenceCallBackBlock",
            )

        self.assertEqual("0x140001234", func_va)
        session.call_tool.assert_not_awaited()

    async def test_resolve_func_va_builds_from_func_rva_and_image_base(self) -> None:
        session = AsyncMock()
        session.call_tool.return_value = _make_py_eval_result(
            {"image_base": "0x140000000"}
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            binary_dir = Path(temp_dir)
            (binary_dir / "ExReferenceCallBackBlock.yaml").write_text(
                "func_rva: '0x1234'\n",
                encoding="utf-8",
            )

            func_va = await generate_reference_yaml.resolve_func_va(
                session=session,
                binary_dir=binary_dir,
                func_name="ExReferenceCallBackBlock",
            )

        self.assertEqual("0x140001234", func_va)
        session.call_tool.assert_awaited_once()

    async def test_resolve_func_va_falls_back_to_exact_name_lookup(self) -> None:
        session = AsyncMock()
        session.call_tool.return_value = _make_py_eval_result(
            {"matches": {"0x140004321": ["ExReferenceCallBackBlock"]}}
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            func_va = await generate_reference_yaml.resolve_func_va(
                session=session,
                binary_dir=Path(temp_dir),
                func_name="ExReferenceCallBackBlock",
            )

        self.assertEqual("0x140004321", func_va)
        session.call_tool.assert_awaited_once()

    async def test_resolve_func_va_rejects_multiple_unique_matches(self) -> None:
        session = AsyncMock()
        session.call_tool.return_value = _make_py_eval_result(
            {
                "matches": {
                    "0x140004321": ["ExReferenceCallBackBlock"],
                    "0x140004555": ["ExReferenceCallBackBlock"],
                }
            }
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            with self.assertRaisesRegex(
                ReferenceGenerationError,
                r"multiple function addresses",
            ):
                await generate_reference_yaml.resolve_func_va(
                    session=session,
                    binary_dir=Path(temp_dir),
                    func_name="ExReferenceCallBackBlock",
                )

    async def test_resolve_func_va_rejects_missing_matches(self) -> None:
        session = AsyncMock()
        session.call_tool.return_value = _make_py_eval_result({"matches": {}})

        with tempfile.TemporaryDirectory() as temp_dir:
            with self.assertRaisesRegex(
                ReferenceGenerationError,
                r"unable to resolve function address",
            ):
                await generate_reference_yaml.resolve_func_va(
                    session=session,
                    binary_dir=Path(temp_dir),
                    func_name="ExReferenceCallBackBlock",
                )


class TestGenerateReferenceYamlWorkflow(unittest.IsolatedAsyncioTestCase):
    async def test_run_reference_generation_attach_mode_exports_yaml(self) -> None:
        fake_session = AsyncMock()

        @asynccontextmanager
        async def fake_attach_existing_mcp_session(host: str, port: int, debug: bool):
            self.assertEqual("127.0.0.1", host)
            self.assertEqual(13337, port)
            self.assertFalse(debug)
            yield fake_session

        args = generate_reference_yaml.parse_args(
            ["-func_name", "ExReferenceCallBackBlock"]
        )

        with (
            patch.object(
                generate_reference_yaml,
                "attach_existing_mcp_session",
                fake_attach_existing_mcp_session,
            ),
            patch.object(
                generate_reference_yaml,
                "survey_current_binary_path",
                AsyncMock(
                    return_value=Path(
                        "/repo/symbols/amd64/ntoskrnl.exe.10.0.1/hash/ntoskrnl.exe.i64"
                    )
                ),
            ),
            patch.object(
                generate_reference_yaml,
                "infer_context_from_binary_path",
                return_value={
                    "module": "ntoskrnl",
                    "arch": "amd64",
                    "binary_dir": Path("/repo/symbols/amd64/ntoskrnl.exe.10.0.1/hash"),
                    "binary_path": Path(
                        "/repo/symbols/amd64/ntoskrnl.exe.10.0.1/hash/ntoskrnl.exe"
                    ),
                    "module_spec": object(),
                },
            ),
            patch.object(
                generate_reference_yaml,
                "resolve_func_va",
                AsyncMock(return_value="0x140001234"),
            ),
            patch.object(
                generate_reference_yaml,
                "export_reference_yaml_via_mcp",
                AsyncMock(
                    return_value=Path(
                        "/repo/ida_preprocessor_scripts/references/ntoskrnl/ExReferenceCallBackBlock.amd64.yaml"
                    )
                ),
            ) as mock_export,
        ):
            output_path = await generate_reference_yaml.run_reference_generation(
                args,
                repo_root="/repo",
            )

        self.assertEqual(
            Path(
                "/repo/ida_preprocessor_scripts/references/ntoskrnl/ExReferenceCallBackBlock.amd64.yaml"
            ),
            output_path,
        )
        mock_export.assert_awaited_once_with(
            fake_session,
            func_name="ExReferenceCallBackBlock",
            func_va="0x140001234",
            output_path=Path(
                "/repo/ida_preprocessor_scripts/references/ntoskrnl/ExReferenceCallBackBlock.amd64.yaml"
            ),
            debug=False,
        )

    def test_main_prints_generated_path(self) -> None:
        stdout = StringIO()
        with (
            patch.object(
                generate_reference_yaml,
                "run_reference_generation",
                AsyncMock(return_value=Path("/repo/out.yaml")),
            ),
            patch("sys.stdout", stdout),
        ):
            exit_code = generate_reference_yaml.main(
                ["-func_name", "ExReferenceCallBackBlock"]
            )

        self.assertEqual(0, exit_code)
        self.assertIn("/repo/out.yaml", stdout.getvalue())
