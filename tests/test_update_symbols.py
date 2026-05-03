import io
import os
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

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
        self.assertFalse(args.debug)

    def test_parse_args_accepts_debug_flag(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            args = update_symbols.parse_args(["-syncfile", "-debug"])

        self.assertTrue(args.debug)

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

    def test_parse_args_rejects_empty_environment_xml(self) -> None:
        with patch.dict(os.environ, {"KPHTOOLS_XML": ""}, clear=True):
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                with self.assertRaises(SystemExit):
                    update_symbols.parse_args(["-syncfile"])
        self.assertIn("-xml cannot be empty", stderr.getvalue())

    def test_parse_args_rejects_empty_environment_symboldir(self) -> None:
        with patch.dict(os.environ, {"KPHTOOLS_SYMBOLDIR": ""}, clear=True):
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                with self.assertRaises(SystemExit):
                    update_symbols.parse_args(["-syncfile"])
        self.assertIn("-symboldir cannot be empty", stderr.getvalue())

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

    def test_parse_file_path_info_parses_symbol_directory_layout(self) -> None:
        sha256 = "a" * 64

        with TemporaryDirectory() as temp_dir:
            binary_path = (
                Path(temp_dir)
                / "amd64"
                / "ntoskrnl.exe.10.0.1"
                / sha256
                / "ntoskrnl.exe"
            )
            binary_path.parent.mkdir(parents=True)
            binary_path.write_bytes(b"binary")

            info = update_symbols.parse_file_path_info(Path(temp_dir), binary_path)

        self.assertEqual("amd64", info.arch)
        self.assertEqual("ntoskrnl.exe", info.file)
        self.assertEqual("10.0.1", info.version)
        self.assertEqual(sha256, info.sha256)
        self.assertEqual(binary_path.resolve(), info.binary_path)

    def test_scan_symbol_directory_returns_matching_candidates_without_validation(self) -> None:
        valid_sha = "d" * 64
        invalid_sha = "not-a-sha256"

        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            valid_binary = (
                root / "amd64" / "ntoskrnl.exe.10.0.1" / valid_sha / "ntoskrnl.exe"
            )
            invalid_sha_binary = (
                root / "amd64" / "ntoskrnl.exe.10.0.2" / invalid_sha / "ntoskrnl.exe"
            )
            empty_version_binary = (
                root / "amd64" / "ntoskrnl.exe." / valid_sha / "ntoskrnl.exe"
            )
            nonmatching_file = (
                root / "amd64" / "ntoskrnl.exe.10.0.3" / valid_sha / "other.exe"
            )

            for path in (
                valid_binary,
                invalid_sha_binary,
                empty_version_binary,
                nonmatching_file,
            ):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"binary")

            binaries = update_symbols.scan_symbol_directory(root)

        self.assertEqual(
            [empty_version_binary, valid_binary, invalid_sha_binary],
            binaries,
        )

    def test_parse_file_path_info_rejects_invalid_sha_directory(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            binary_path = (
                root / "amd64" / "ntoskrnl.exe.10.0.1" / "not-a-sha256" / "ntoskrnl.exe"
            )
            binary_path.parent.mkdir(parents=True)
            binary_path.write_bytes(b"binary")

            with self.assertRaises(ValueError):
                update_symbols.parse_file_path_info(root, binary_path)

    def test_parse_file_path_info_rejects_missing_version(self) -> None:
        sha256 = "e" * 64
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            binary_path = root / "amd64" / "ntoskrnl.exe." / sha256 / "ntoskrnl.exe"
            binary_path.parent.mkdir(parents=True)
            binary_path.write_bytes(b"binary")

            with self.assertRaises(ValueError):
                update_symbols.parse_file_path_info(root, binary_path)

    def test_parse_file_path_info_rejects_version_file_mismatch(self) -> None:
        sha256 = "f" * 64
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            binary_path = root / "amd64" / "ntoskrnl.exe.10.0.1" / sha256 / "other.exe"
            binary_path.parent.mkdir(parents=True)
            binary_path.write_bytes(b"binary")

            with self.assertRaises(ValueError):
                update_symbols.parse_file_path_info(root, binary_path)

    def test_parse_file_path_info_rejects_path_outside_symboldir(self) -> None:
        with TemporaryDirectory() as symboldir, TemporaryDirectory() as outside_dir:
            root = Path(symboldir)
            binary_path = (
                Path(outside_dir)
                / "amd64"
                / "ntoskrnl.exe.10.0.1"
                / ("1" * 64)
                / "ntoskrnl.exe"
            )
            binary_path.parent.mkdir(parents=True)
            binary_path.write_bytes(b"binary")

            with self.assertRaises(ValueError):
                update_symbols.parse_file_path_info(root, binary_path)

    def test_find_data_entry_matches_hash_attribute(self) -> None:
        sha256 = "b" * 64
        root = update_symbols.ET.fromstring(
            f'<kphdyn><data arch="amd64" file="ntoskrnl.exe" '
            f'version="10.0.1" hash="{sha256}">1</data></kphdyn>'
        )
        info = update_symbols.FilePathInfo(
            arch="amd64",
            file="ntoskrnl.exe",
            version="10.0.1",
            sha256=sha256,
            binary_path=Path("ntoskrnl.exe"),
        )

        data_elem = update_symbols.find_data_entry(root, info)

        self.assertIsNotNone(data_elem)
        self.assertEqual("1", data_elem.text)

    def test_find_data_entry_matches_legacy_sha256_attribute(self) -> None:
        sha256 = "c" * 64
        root = update_symbols.ET.fromstring(
            f'<kphdyn><data arch="amd64" file="ntoskrnl.exe" '
            f'version="10.0.1" sha256="{sha256}" fields="0" /></kphdyn>'
        )
        info = update_symbols.FilePathInfo(
            arch="amd64",
            file="ntoskrnl.exe",
            version="10.0.1",
            sha256=sha256,
            binary_path=Path("ntoskrnl.exe"),
        )

        data_elem = update_symbols.find_data_entry(root, info)

        self.assertIsNotNone(data_elem)
        self.assertEqual("0", data_elem.get("fields"))

    def test_find_data_entry_matches_sha256_when_hash_mismatches(self) -> None:
        sha256 = "d" * 64
        root = update_symbols.ET.fromstring(
            f'<kphdyn><data arch="amd64" file="ntoskrnl.exe" '
            f'version="10.0.1" hash="deadbeef" sha256="{sha256}" /></kphdyn>'
        )
        info = update_symbols.FilePathInfo(
            arch="amd64",
            file="ntoskrnl.exe",
            version="10.0.1",
            sha256=sha256,
            binary_path=Path("ntoskrnl.exe"),
        )

        data_elem = update_symbols.find_data_entry(root, info)

        self.assertIsNotNone(data_elem)

    def test_create_data_entry_uses_text_fields_id_zero(self) -> None:
        info = update_symbols.FilePathInfo(
            arch="amd64",
            file="ntoskrnl.exe",
            version="10.0.1",
            sha256="d" * 64,
            binary_path=Path("ntoskrnl.exe"),
        )

        data_elem = update_symbols.create_data_entry(
            info,
            {"timestamp": "0x10", "size": "0x20", "sha256": "d" * 64},
        )

        self.assertEqual("data", data_elem.tag)
        self.assertEqual("amd64", data_elem.get("arch"))
        self.assertEqual("10.0.1", data_elem.get("version"))
        self.assertEqual("ntoskrnl.exe", data_elem.get("file"))
        self.assertEqual("d" * 64, data_elem.get("hash"))
        self.assertEqual("0x10", data_elem.get("timestamp"))
        self.assertEqual("0x20", data_elem.get("size"))
        self.assertEqual("0", data_elem.text)
        self.assertIsNone(data_elem.get("fields"))
        self.assertIsNone(data_elem.get("sha256"))
        self.assertIsNone(data_elem.get("added"))

    def test_find_insert_position_keeps_data_before_fields(self) -> None:
        root = update_symbols.ET.fromstring(
            '<kphdyn>'
            '<data arch="amd64" file="ntoskrnl.exe" version="10.0.1" hash="a">1</data>'
            '<fields id="1" />'
            '</kphdyn>'
        )
        info = update_symbols.FilePathInfo(
            arch="amd64",
            file="ntoskrnl.exe",
            version="10.0.2",
            sha256="e" * 64,
            binary_path=Path("ntoskrnl.exe"),
        )

        insert_index = update_symbols.find_insert_position(root, info)

        self.assertEqual(1, insert_index)

    def test_find_insert_position_orders_versions_within_same_group(self) -> None:
        root = update_symbols.ET.fromstring(
            '<kphdyn>'
            '<data arch="amd64" file="ntoskrnl.exe" version="10.0.1" hash="a">1</data>'
            '<data arch="amd64" file="ntoskrnl.exe" version="10.0.3" hash="b">1</data>'
            '<fields id="1" />'
            '</kphdyn>'
        )
        info = update_symbols.FilePathInfo(
            arch="amd64",
            file="ntoskrnl.exe",
            version="10.0.2",
            sha256="f" * 64,
            binary_path=Path("ntoskrnl.exe"),
        )

        insert_index = update_symbols.find_insert_position(root, info)

        self.assertEqual(1, insert_index)

    def test_find_insert_position_orders_across_files_by_arch_and_version(self) -> None:
        root = update_symbols.ET.fromstring(
            '<kphdyn>'
            '<data arch="amd64" file="ntoskrnl.exe" version="10.0.14393.0" hash="a">1</data>'
            '<data arch="amd64" file="lxcore.sys" version="10.0.14393.0" hash="b">14</data>'
            '<data arch="amd64" file="lxcore.sys" version="10.0.14393.51" hash="c">14</data>'
            '<data arch="amd64" file="ntoskrnl.exe" version="10.0.14393.82" hash="d">2</data>'
            '<data arch="amd64" file="ntoskrnl.exe" version="10.0.14393.206" hash="e">2</data>'
            '<data arch="amd64" file="lxcore.sys" version="10.0.14393.206" hash="f">14</data>'
            '<fields id="1" />'
            '</kphdyn>'
        )
        info = update_symbols.FilePathInfo(
            arch="amd64",
            file="lxcore.sys",
            version="10.0.14393.100",
            sha256="1" * 64,
            binary_path=Path("lxcore.sys"),
        )

        self.assertEqual(4, update_symbols.find_insert_position(root, info))

    def test_syncfile_main_adds_missing_entries_and_skips_existing(self) -> None:
        existing_sha = "1" * 64
        missing_sha = "2" * 64

        with TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            xml_path = temp_path / "kphdyn.xml"
            symboldir = temp_path / "symbols"

            xml_path.write_text(
                f'<kphdyn>'
                f'<data arch="amd64" file="ntoskrnl.exe" version="10.0.1" '
                f'hash="{existing_sha}" timestamp="0x1" size="0x2">1</data>'
                f'<fields id="1" />'
                f'</kphdyn>',
                encoding="utf-8",
            )

            existing_binary = (
                symboldir
                / "amd64"
                / "ntoskrnl.exe.10.0.1"
                / existing_sha
                / "ntoskrnl.exe"
            )
            missing_binary = (
                symboldir
                / "amd64"
                / "ntoskrnl.exe.10.0.2"
                / missing_sha
                / "ntoskrnl.exe"
            )
            existing_binary.parent.mkdir(parents=True)
            missing_binary.parent.mkdir(parents=True)
            existing_binary.write_bytes(b"existing")
            missing_binary.write_bytes(b"missing")

            def fake_parse_pe_info(binary_path: Path, expected_sha256: str) -> dict[str, str]:
                self.assertEqual(missing_binary.resolve(), binary_path)
                self.assertEqual(missing_sha, expected_sha256)
                return {
                    "timestamp": "0x10",
                    "size": "0x20",
                    "sha256": expected_sha256,
                }

            output = io.StringIO()
            args = SimpleNamespace(
                xml=str(xml_path),
                symboldir=str(symboldir),
                outxml=None,
                debug=False,
            )
            with (
                patch.object(update_symbols, "parse_pe_info", side_effect=fake_parse_pe_info) as pe_mock,
                redirect_stdout(output),
            ):
                exit_code = update_symbols.syncfile_main(args)

            self.assertEqual(0, exit_code)
            self.assertEqual(1, pe_mock.call_count)
            self.assertIn("added=1", output.getvalue())
            self.assertIn("existing=1", output.getvalue())

            root = update_symbols.ET.parse(xml_path).getroot()
            data_elems = root.findall("data")
            self.assertEqual(2, len(data_elems))
            self.assertEqual("fields", list(root)[2].tag)

            info = update_symbols.FilePathInfo(
                arch="amd64",
                file="ntoskrnl.exe",
                version="10.0.2",
                sha256=missing_sha,
                binary_path=missing_binary.resolve(),
            )
            new_elem = update_symbols.find_data_entry(root, info)
            self.assertIsNotNone(new_elem)
            self.assertEqual("0", new_elem.text)
            self.assertIsNone(new_elem.get("fields"))

    def test_syncfile_main_debug_prints_added_file_entries(self) -> None:
        missing_sha = "2" * 64

        with TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            xml_path = temp_path / "kphdyn.xml"
            symboldir = temp_path / "symbols"

            xml_path.write_text("<kphdyn />", encoding="utf-8")

            missing_binary = (
                symboldir
                / "amd64"
                / "ntoskrnl.exe.10.0.2"
                / missing_sha
                / "ntoskrnl.exe"
            )
            missing_binary.parent.mkdir(parents=True)
            missing_binary.write_bytes(b"missing")

            output = io.StringIO()
            args = SimpleNamespace(
                xml=str(xml_path),
                symboldir=str(symboldir),
                outxml=None,
                debug=True,
            )
            with (
                patch.object(
                    update_symbols,
                    "parse_pe_info",
                    return_value={
                        "timestamp": "0x10",
                        "size": "0x20",
                        "sha256": missing_sha,
                    },
                ),
                redirect_stdout(output),
            ):
                exit_code = update_symbols.syncfile_main(args)

        self.assertEqual(0, exit_code)
        self.assertIn("syncfile: added file entry: <data", output.getvalue())
        self.assertIn('arch="amd64"', output.getvalue())
        self.assertIn('version="10.0.2"', output.getvalue())
        self.assertIn('file="ntoskrnl.exe"', output.getvalue())
        self.assertIn(f'hash="{missing_sha}"', output.getvalue())
        self.assertIn(">0</data>", output.getvalue())

    def test_main_syncfile_dispatch_does_not_load_configyaml(self) -> None:
        with (
            patch.object(update_symbols, "syncfile_main", return_value=0) as sync_mock,
            patch.object(update_symbols, "load_config") as load_config_mock,
        ):
            exit_code = update_symbols.main(["-syncfile"])

        self.assertEqual(0, exit_code)
        sync_mock.assert_called_once()
        load_config_mock.assert_not_called()

    def test_main_without_syncfile_keeps_export_flow(self) -> None:
        with TemporaryDirectory() as temp_dir:
            xml_path = Path(temp_dir) / "kphdyn.xml"
            xml_path.write_text("<kphdyn />", encoding="utf-8")

            config = self._build_config()
            with (
                patch.object(update_symbols, "load_config", return_value=config) as load_mock,
                patch.object(update_symbols, "export_xml") as export_mock,
            ):
                exit_code = update_symbols.main(
                    [
                        "-xml",
                        str(xml_path),
                        "-symboldir",
                        str(Path(temp_dir) / "symbols"),
                    ]
                )

        self.assertEqual(0, exit_code)
        load_mock.assert_called_once()
        export_mock.assert_called_once()

    def test_calculate_sha256_returns_lowercase_digest(self) -> None:
        with TemporaryDirectory() as temp_dir:
            binary_path = Path(temp_dir) / "binary.bin"
            binary_path.write_bytes(b"abc")

            digest = update_symbols._calculate_sha256(binary_path)

        self.assertEqual(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            digest,
        )

    def test_parse_pe_info_raises_hash_mismatch_without_loading_pe(self) -> None:
        with patch.object(
            update_symbols, "_calculate_sha256", return_value="a" * 64
        ) as calc_mock, patch("update_symbols.pefile.PE") as pe_ctor:
            with self.assertRaises(update_symbols.HashMismatchError):
                update_symbols.parse_pe_info(Path("ntoskrnl.exe"), "b" * 64)

        calc_mock.assert_called_once_with(Path("ntoskrnl.exe"))
        pe_ctor.assert_not_called()

    def test_parse_pe_info_returns_metadata_and_closes_pe(self) -> None:
        mock_pe = Mock()
        mock_pe.FILE_HEADER = SimpleNamespace(TimeDateStamp=0x10)
        mock_pe.OPTIONAL_HEADER = SimpleNamespace(SizeOfImage=0x20)
        mock_pe.close = Mock()

        with patch.object(
            update_symbols, "_calculate_sha256", return_value="c" * 64
        ) as calc_mock, patch("update_symbols.pefile.PE", return_value=mock_pe) as pe_ctor:
            result = update_symbols.parse_pe_info(Path("ntoskrnl.exe"), "C" * 64)

        self.assertEqual(
            {"timestamp": "0x10", "size": "0x20", "sha256": "c" * 64},
            result,
        )
        calc_mock.assert_called_once_with(Path("ntoskrnl.exe"))
        pe_ctor.assert_called_once_with("ntoskrnl.exe", fast_load=True)
        mock_pe.close.assert_called_once_with()

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
