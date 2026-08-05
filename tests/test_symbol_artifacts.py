from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import symbol_artifacts


class TestSymbolArtifacts(unittest.TestCase):
    def test_artifact_path_uses_symbol_name_only(self) -> None:
        binary_dir = Path("/tmp/symbols/amd64/ntoskrnl.exe.10.0.1/hash")
        self.assertEqual(
            binary_dir / "EpObjectTable.yaml",
            symbol_artifacts.artifact_path(binary_dir, "EpObjectTable"),
        )

    def test_write_and_load_struct_yaml_round_trip(self) -> None:
        with TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "EpObjectTable.yaml"
            symbol_artifacts.write_struct_yaml(
                path,
                {
                    "category": "gv",
                    "struct_name": "_EPROCESS",
                    "member_name": "ObjectTable",
                    "offset": 0x570,
                },
            )
            loaded = symbol_artifacts.load_artifact(path)

        self.assertEqual("struct_offset", loaded["category"])
        self.assertEqual(0x570, loaded["offset"])

    def test_write_and_load_gv_yaml_round_trip(self) -> None:
        with TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "PspCreateProcessNotifyRoutine.yaml"
            symbol_artifacts.write_gv_yaml(
                path,
                {
                    "category": "func",
                    "gv_name": "PspCreateProcessNotifyRoutine",
                    "gv_rva": 0x45678,
                },
            )
            loaded = symbol_artifacts.load_artifact(path)

        self.assertEqual("gv", loaded["category"])
        self.assertEqual(0x45678, loaded["gv_rva"])

    def test_write_and_load_func_yaml_round_trip(self) -> None:
        with TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "PspInsertProcess.yaml"
            symbol_artifacts.write_func_yaml(
                path,
                {
                    "category": "gv",
                    "func_name": "PspInsertProcess",
                    "func_rva": 0x1234,
                    "func_size": 0x80,
                },
            )
            loaded = symbol_artifacts.load_artifact(path)

        self.assertEqual("func", loaded["category"])
        self.assertEqual(0x1234, loaded["func_rva"])
        self.assertEqual(0x80, loaded["func_size"])

    def test_load_artifact_prefers_c_safe_loader(self) -> None:
        expected_loader = getattr(
            symbol_artifacts.yaml,
            "CSafeLoader",
            symbol_artifacts.yaml.SafeLoader,
        )

        with TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "EpObjectTable.yaml"
            path.write_text("offset: '0x570'\n", encoding="utf-8")
            with patch.object(
                symbol_artifacts.yaml,
                "load",
                return_value={"offset": "0x570"},
            ) as load_mock:
                loaded = symbol_artifacts.load_artifact(path)

        load_mock.assert_called_once_with(
            "offset: '0x570'\n",
            Loader=expected_loader,
        )
        self.assertEqual(0x570, loaded["offset"])

    def test_write_artifacts_manifest_includes_all_symbols_and_skips_unchanged(
        self,
    ) -> None:
        artifacts = {
            "EpObjectTable": {
                "category": "struct_offset",
                "offset": 0x570,
            },
            "MissingSymbol": None,
        }

        with TemporaryDirectory() as temp_dir:
            self.assertTrue(
                symbol_artifacts.write_artifacts_manifest(temp_dir, artifacts)
            )
            manifest_path = Path(temp_dir) / "artifacts.yaml"
            loaded = symbol_artifacts.yaml.safe_load(
                manifest_path.read_text(encoding="utf-8")
            )
            with patch.object(Path, "touch") as touch_mock:
                self.assertFalse(
                    symbol_artifacts.write_artifacts_manifest(temp_dir, artifacts)
                )
            touch_mock.assert_called_once_with()

        self.assertEqual(
            {
                "EpObjectTable": {
                    "category": "struct_offset",
                    "offset": "0x570",
                },
                "MissingSymbol": None,
            },
            loaded,
        )

    def test_load_artifacts_manifest_normalizes_hex_fields_and_nulls(self) -> None:
        with TemporaryDirectory() as temp_dir:
            manifest_path = Path(temp_dir) / "artifacts.yaml"
            manifest_path.write_text(
                "EpObjectTable:\n"
                "  category: struct_offset\n"
                "  offset: '0x570'\n"
                "MissingSymbol: null\n",
                encoding="utf-8",
            )

            loaded = symbol_artifacts.load_artifacts_manifest(temp_dir)

        self.assertEqual(
            {
                "EpObjectTable": {
                    "category": "struct_offset",
                    "offset": 0x570,
                },
                "MissingSymbol": None,
            },
            loaded,
        )

    def test_load_artifacts_manifest_rejects_non_mapping_payload(self) -> None:
        with TemporaryDirectory() as temp_dir:
            manifest_path = Path(temp_dir) / "artifacts.yaml"
            manifest_path.write_text("EpObjectTable: invalid\n", encoding="utf-8")

            with self.assertRaisesRegex(
                ValueError,
                "artifact payload for EpObjectTable must be a mapping or null",
            ):
                symbol_artifacts.load_artifacts_manifest(temp_dir)
