import os
import unittest
from unittest.mock import patch

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
