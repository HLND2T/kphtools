from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

import yaml

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
                    "struct_name": "_EPROCESS",
                    "member_name": "ObjectTable",
                    "offset": 0x570,
                },
            )
            loaded = yaml.safe_load(path.read_text(encoding="utf-8"))

        self.assertEqual("0x570", loaded["offset"])

    def test_write_and_load_gv_yaml_round_trip(self) -> None:
        with TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "PspCreateProcessNotifyRoutine.yaml"
            symbol_artifacts.write_gv_yaml(
                path,
                {
                    "gv_name": "PspCreateProcessNotifyRoutine",
                    "gv_rva": 0x45678,
                },
            )
            loaded = symbol_artifacts.load_artifact(path)

        self.assertEqual("gv", loaded["category"])
        self.assertEqual(0x45678, loaded["gv_rva"])
