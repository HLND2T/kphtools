from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest

import update_symbols


XML_TEXT = """
<kphdyn>
  <data id="1" arch="amd64" file="ntoskrnl.exe" version="10.0.1" timestamp="0" size="0" sha256="abc" fields="0" />
  <fields id="1" EpObjectTable="0x570" />
</kphdyn>
"""


class TestUpdateSymbols(unittest.TestCase):
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
                "bits": True,
            },
        ]
        yaml_payloads = {
            "ObDecodeShift": {"offset": 0x8, "bit_offset": 20},
        }

        values = update_symbols.collect_symbol_values(symbol_specs, yaml_payloads)

        self.assertEqual(84, values["ObDecodeShift"])

    def test_export_xml_reuses_existing_fields_id(self) -> None:
        tree = update_symbols.ET.ElementTree(update_symbols.ET.fromstring(XML_TEXT))
        config = SimpleNamespace(
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

        with TemporaryDirectory() as temp_dir:
            sha_dir = Path(temp_dir) / "amd64" / "ntoskrnl.exe.10.0.1" / "abc"
            sha_dir.mkdir(parents=True, exist_ok=True)
            (sha_dir / "EpObjectTable.yaml").write_text(
                "category: struct_offset\noffset: 0x570\n",
                encoding="utf-8",
            )
            update_symbols.export_xml(tree, config, Path(temp_dir))

        data_elem = tree.getroot().find("data")
        self.assertEqual("1", data_elem.get("fields"))
