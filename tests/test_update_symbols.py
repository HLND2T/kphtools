import os
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import update_symbols


XML_TEXT = """
<kphdyn>
  <data id="1" arch="amd64" file="ntoskrnl.exe" version="10.0.1" timestamp="0" size="0" sha256="abc" fields="0" />
  <fields id="1" EpObjectTable="0x570" />
</kphdyn>
"""

HASH_XML_TEXT = """
<kphdyn>
  <data id="1" arch="amd64" file="ntoskrnl.exe" version="10.0.1" timestamp="0x10" size="0x20" hash="abc" fields="0" />
  <fields id="1" EpObjectTable="0x570" />
</kphdyn>
"""


class TestUpdateSymbols(unittest.TestCase):
    @staticmethod
    def _build_config() -> SimpleNamespace:
        return SimpleNamespace(
            modules=[
                SimpleNamespace(
                    name="ntoskrnl",
                    path=["ntoskrnl.exe"],
                    symbols=[
                        SimpleNamespace(
                            name="EpObjectTable",
                            category="struct_offset",
                            data_type="uint16",
                        )
                    ],
                )
            ]
        )

    def test_parse_args_uses_default_xml_and_symboldir(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            args = update_symbols.parse_args(["-syncfile"])

        self.assertEqual("kphdyn.xml", args.xml)
        self.assertEqual("symbols", args.symboldir)
        self.assertTrue(args.syncfile)

    def test_parse_args_prefers_environment_xml_and_symboldir(self) -> None:
        with patch.dict(
            os.environ,
            {
                "KPHTOOLS_XML": "env.xml",
                "KPHTOOLS_SYMBOLDIR": "env-symbols",
            },
            clear=True,
        ):
            args = update_symbols.parse_args(
                [
                    "-xml",
                    "cli.xml",
                    "-symboldir",
                    "cli-symbols",
                    "-syncfile",
                ]
            )

        self.assertEqual("env.xml", args.xml)
        self.assertEqual("env-symbols", args.symboldir)

    def test_collect_yaml_values_uses_real_and_fallback_values(self) -> None:
        symbol_specs = [
            {"name": "EpObjectTable", "category": "struct_offset", "data_type": "uint16"},
            {"name": "PspCreateProcessNotifyRoutine", "category": "gv", "data_type": "uint32"},
        ]
        yaml_payloads = {
            "EpObjectTable": {"offset": 0x570},
        }

        values = update_symbols.collect_symbol_values(symbol_specs, yaml_payloads)

        self.assertEqual(0x570, values["EpObjectTable"])
        self.assertEqual(0xFFFFFFFF, values["PspCreateProcessNotifyRoutine"])

    def test_collect_symbol_values_applies_bitfield_formula(self) -> None:
        symbol_specs = [
            {
                "name": "ObDecodeShift",
                "category": "struct_offset",
                "data_type": "uint16",
            },
        ]
        yaml_payloads = {
            "ObDecodeShift": {"offset": 0x8, "bit_offset": 20},
        }

        values = update_symbols.collect_symbol_values(symbol_specs, yaml_payloads)

        self.assertEqual(84, values["ObDecodeShift"])

    def test_collect_symbol_values_uses_offset_when_bit_offset_is_absent(self) -> None:
        symbol_specs = [
            {
                "name": "ObDecodeShift",
                "category": "struct_offset",
                "data_type": "uint16",
            },
        ]
        yaml_payloads = {
            "ObDecodeShift": {"offset": 0x8},
        }

        values = update_symbols.collect_symbol_values(symbol_specs, yaml_payloads)

        self.assertEqual(0x8, values["ObDecodeShift"])

    def test_export_xml_reuses_existing_fields_id(self) -> None:
        tree = update_symbols.ET.ElementTree(update_symbols.ET.fromstring(XML_TEXT))
        config = self._build_config()

        with TemporaryDirectory() as temp_dir:
            sha_dir = Path(temp_dir) / "amd64" / "ntoskrnl.exe.10.0.1" / "abc"
            sha_dir.mkdir(parents=True, exist_ok=True)
            (sha_dir / "EpObjectTable.yaml").write_text(
                "category: struct_offset\noffset: 0x570\n",
                encoding="utf-8",
            )
            with patch.object(
                update_symbols,
                "_load_binary_metadata",
                return_value={"timestamp": "0x0", "size": "0x0"},
            ):
                update_symbols.export_xml(tree, config, Path(temp_dir))

        data_elem = tree.getroot().find("data")
        self.assertEqual("1", data_elem.get("fields"))

    def test_export_xml_reuses_existing_data_entry_with_hash_attribute(self) -> None:
        tree = update_symbols.ET.ElementTree(update_symbols.ET.fromstring(HASH_XML_TEXT))
        config = self._build_config()

        with TemporaryDirectory() as temp_dir:
            sha_dir = Path(temp_dir) / "amd64" / "ntoskrnl.exe.10.0.1" / "abc"
            sha_dir.mkdir(parents=True, exist_ok=True)
            (sha_dir / "EpObjectTable.yaml").write_text(
                "category: struct_offset\noffset: 0x570\n",
                encoding="utf-8",
            )
            with patch.object(
                update_symbols,
                "_load_binary_metadata",
                return_value={"timestamp": "0x10", "size": "0x20"},
                create=True,
            ):
                update_symbols.export_xml(tree, config, Path(temp_dir))

        data_elems = tree.getroot().findall("data")
        self.assertEqual(1, len(data_elems))
        self.assertEqual("abc", data_elems[0].get("hash"))
        self.assertEqual("1", data_elems[0].get("fields"))

    def test_export_xml_creates_data_entry_with_required_metadata(self) -> None:
        tree = update_symbols.ET.ElementTree(update_symbols.ET.fromstring("<kphdyn />"))
        config = self._build_config()

        with TemporaryDirectory() as temp_dir:
            sha_dir = Path(temp_dir) / "amd64" / "ntoskrnl.exe.10.0.1" / "abc"
            sha_dir.mkdir(parents=True, exist_ok=True)
            (sha_dir / "ntoskrnl.exe").write_bytes(b"")
            (sha_dir / "EpObjectTable.yaml").write_text(
                "category: struct_offset\noffset: 0x570\n",
                encoding="utf-8",
            )
            with patch.object(
                update_symbols,
                "_load_binary_metadata",
                return_value={"timestamp": "0x123", "size": "0x456"},
                create=True,
            ):
                update_symbols.export_xml(tree, config, Path(temp_dir))

        data_elem = tree.getroot().find("data")
        self.assertEqual("abc", data_elem.get("hash"))
        self.assertEqual("0x123", data_elem.get("timestamp"))
        self.assertEqual("0x456", data_elem.get("size"))
        self.assertEqual("1", data_elem.get("fields"))
