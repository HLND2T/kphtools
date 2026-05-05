import os
import tempfile
import unittest
from unittest.mock import Mock, patch

import download_symbols


class TestDownloadSymbolsParseArgs(unittest.TestCase):
    def test_parse_args_uses_default_xml_and_symboldir(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            args = download_symbols.parse_args(["-fast"])

        self.assertEqual("kphdyn.xml", args.xml)
        self.assertEqual("symbols", args.symboldir)
        self.assertTrue(args.fast)

    def test_parse_args_prefers_environment_variables(self) -> None:
        with patch.dict(
            os.environ,
            {
                "KPHTOOLS_XML": "env.xml",
                "KPHTOOLS_SYMBOLDIR": "env-symbols",
            },
            clear=True,
        ):
            args = download_symbols.parse_args(
                [
                    "-xml",
                    "cli.xml",
                    "-symboldir",
                    "cli-symbols",
                ]
            )

        self.assertEqual("env.xml", args.xml)
        self.assertEqual("env-symbols", args.symboldir)


class TestDownloadSymbolsDownloadFile(unittest.TestCase):
    def test_download_file_returns_not_found_for_http_404(self) -> None:
        response = Mock()
        error = download_symbols.requests.exceptions.HTTPError(
            "404 Client Error: Not Found for url"
        )
        error.response = Mock(status_code=404)
        response.raise_for_status.side_effect = error

        with (
            patch.object(download_symbols.requests, "get", return_value=response),
            patch("builtins.print") as print_mock,
        ):
            status = download_symbols.download_file(
                "https://example.invalid/missing.pdb",
                "missing.pdb",
            )

        self.assertEqual(download_symbols.DownloadStatus.NOT_FOUND, status)
        printed_lines = "\n".join(
            str(call.args[0]) for call in print_mock.call_args_list
        )
        self.assertIn("Download not found (404)", printed_lines)
        self.assertNotIn("Download failed", printed_lines)


class TestDownloadSymbolsMain(unittest.TestCase):
    def test_main_does_not_count_not_found_as_failed(self) -> None:
        entry = {
            "file": "missing.exe",
            "version": "10.0.1",
            "arch": "amd64",
            "hash": "abc",
            "timestamp": "1",
            "size": "2",
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            xml_path = os.path.join(temp_dir, "kphdyn.xml")
            symbol_dir = os.path.join(temp_dir, "symbols")
            with open(xml_path, "w", encoding="utf-8") as f:
                f.write("<root />")

            with (
                patch(
                    "sys.argv",
                    [
                        "download_symbols.py",
                        "-xml",
                        xml_path,
                        "-symboldir",
                        symbol_dir,
                    ],
                ),
                patch.object(download_symbols, "parse_xml", return_value=[entry]),
                patch.object(
                    download_symbols,
                    "process_entry",
                    return_value=download_symbols.DownloadStatus.NOT_FOUND,
                ),
                patch("builtins.print") as print_mock,
            ):
                download_symbols.main()

        printed_lines = "\n".join(
            str(call.args[0]) for call in print_mock.call_args_list
        )
        self.assertIn("0 successful, 0 skipped, 1 not found, 0 failed", printed_lines)

    def test_main_counts_skipped_separately_from_successful(self) -> None:
        entry = {
            "file": "existing.exe",
            "version": "10.0.1",
            "arch": "amd64",
            "hash": "abc",
            "timestamp": "1",
            "size": "2",
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            xml_path = os.path.join(temp_dir, "kphdyn.xml")
            symbol_dir = os.path.join(temp_dir, "symbols")
            with open(xml_path, "w", encoding="utf-8") as f:
                f.write("<root />")

            with (
                patch(
                    "sys.argv",
                    [
                        "download_symbols.py",
                        "-xml",
                        xml_path,
                        "-symboldir",
                        symbol_dir,
                    ],
                ),
                patch.object(download_symbols, "parse_xml", return_value=[entry]),
                patch.object(
                    download_symbols,
                    "process_entry",
                    return_value=download_symbols.DownloadStatus.SKIPPED,
                ),
                patch("builtins.print") as print_mock,
            ):
                download_symbols.main()

        printed_lines = "\n".join(
            str(call.args[0]) for call in print_mock.call_args_list
        )
        self.assertIn("0 successful, 1 skipped, 0 not found, 0 failed", printed_lines)
