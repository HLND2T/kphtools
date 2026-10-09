from contextlib import redirect_stderr, redirect_stdout
import io
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, patch
import xml.etree.ElementTree as ET

import requests

import check_nightly_release


XML = (
    b'<dyn><data arch="amd64" version="1">7</data>'
    b'<fields id="7"><field name="Offset" value="0x10" /></fields></dyn>'
)
FORMATTED_XML = (
    b'<?xml version="1.0" encoding="utf-8"?>\r\n<dyn>\r\n'
    b'  <!-- formatting only -->\r\n'
    b'  <data version="1" arch="amd64"> 7 </data>\r\n'
    b'  <fields id="7">\r\n'
    b'    <field value="0x10" name="Offset"/>\r\n'
    b'  </fields>\r\n</dyn>\r\n'
)
ASSET = {
    "name": "kphdyn.xml",
    "url": "https://api.github.com/repos/owner/repo/releases/assets/42",
}


def response(status: int = 200, *, assets=None, content: bytes = XML) -> Mock:
    result = Mock(spec=requests.Response)
    result.status_code = status
    result.content = content
    result.json.return_value = {"assets": [ASSET] if assets is None else assets}
    if status >= 400:
        result.raise_for_status.side_effect = requests.HTTPError(
            f"HTTP {status}", response=result
        )
    return result


class TestCanonicalizeXml(unittest.TestCase):
    def test_ignores_formatting_comments_and_attribute_order(self) -> None:
        self.assertEqual(
            check_nightly_release.canonicalize_xml(XML),
            check_nightly_release.canonicalize_xml(FORMATTED_XML),
        )

    def test_retains_data_changes(self) -> None:
        variants = {
            "field value": XML.replace(b"0x10", b"0x20"),
            "data attribute": XML.replace(b'version="1"', b'version="2"'),
            "fields id": XML.replace(b'id="7"', b'id="8"'),
            "data reference": XML.replace(b">7</data>", b">8</data>"),
            "element added": XML.replace(b"</dyn>", b'<fields id="8" /></dyn>'),
            "element removed": XML.replace(
                b'<field name="Offset" value="0x10" />', b""
            ),
            "element order": (
                b'<dyn><fields id="7"><field name="Offset" value="0x10" />'
                b'</fields><data arch="amd64" version="1">7</data></dyn>'
            ),
        }
        original = check_nightly_release.canonicalize_xml(XML)
        for name, variant in variants.items():
            with self.subTest(change=name):
                self.assertNotEqual(
                    original, check_nightly_release.canonicalize_xml(variant)
                )

    def test_rejects_empty_and_invalid_xml(self) -> None:
        for content in (b"", b"<dyn>", b"not XML"):
            with self.subTest(content=content), self.assertRaises(ET.ParseError):
                check_nightly_release.canonicalize_xml(content)


class TestReleaseXmlChanged(unittest.TestCase):
    def setUp(self) -> None:
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.xml_path = Path(directory.name) / "candidate.xml"
        self.xml_path.write_bytes(XML)
        get_patch = patch.object(check_nightly_release.requests, "get")
        self.get = get_patch.start()
        self.addCleanup(get_patch.stop)
        self.stdout = io.StringIO()
        stdout_redirect = redirect_stdout(self.stdout)
        stdout_redirect.__enter__()
        self.addCleanup(stdout_redirect.__exit__, None, None, None)

    def check(self, tag: str = "nightly", token: str | None = None) -> bool:
        return check_nightly_release.release_xml_changed(
            "owner/repo", self.xml_path, tag=tag, token=token
        )

    def test_missing_release_requires_publication(self) -> None:
        self.get.return_value = response(404)

        self.assertTrue(self.check())
        self.assertEqual(1, self.get.call_count)

    def test_missing_xml_asset_requires_publication(self) -> None:
        for assets in ([], [{"name": "other.xml"}]):
            with self.subTest(assets=assets):
                self.get.reset_mock()
                self.get.return_value = response(assets=assets)

                self.assertTrue(self.check())
                self.assertEqual(1, self.get.call_count)

    def test_identical_xml_skips_publication(self) -> None:
        self.get.side_effect = [response(), response(content=XML)]

        self.assertFalse(self.check())

    def test_equivalent_xml_skips_publication(self) -> None:
        self.get.side_effect = [response(), response(content=FORMATTED_XML)]

        self.assertFalse(self.check())

    def test_changed_xml_requires_publication(self) -> None:
        self.get.side_effect = [
            response(), response(content=XML.replace(b"0x10", b"0x20"))
        ]

        self.assertTrue(self.check())

    def test_downloads_the_named_asset_with_authentication(self) -> None:
        self.get.side_effect = [response(), response(content=XML)]

        self.assertFalse(self.check(token="test-token"))
        self.assertEqual(2, self.get.call_count)
        metadata_call, download_call = self.get.call_args_list
        self.assertEqual(
            "https://api.github.com/repos/owner/repo/releases/tags/nightly",
            metadata_call.args[0],
        )
        self.assertEqual(ASSET["url"], download_call.args[0])
        for call in (metadata_call, download_call):
            self.assertEqual(
                "Bearer test-token", call.kwargs["headers"]["Authorization"]
            )
            self.assertGreater(call.kwargs["timeout"], 0)
        self.assertEqual(
            "application/octet-stream", download_call.kwargs["headers"]["Accept"]
        )
        self.assertNotIn("test-token", self.stdout.getvalue())

    def test_encodes_the_release_tag_in_the_url(self) -> None:
        self.get.return_value = response(404)

        self.assertTrue(self.check(tag="nightly/test"))
        self.assertEqual(
            "https://api.github.com/repos/owner/repo/releases/tags/nightly%2Ftest",
            self.get.call_args.args[0],
        )

    def test_release_errors_stop_the_check(self) -> None:
        for status in (401, 403, 500):
            with self.subTest(status=status):
                self.get.reset_mock()
                self.get.return_value = response(status)

                with self.assertRaises(requests.HTTPError):
                    self.check()
                self.assertEqual(1, self.get.call_count)

    def test_download_errors_are_not_treated_as_missing_baselines(self) -> None:
        for status in (404, 403, 500):
            with self.subTest(status=status):
                self.get.side_effect = [response(), response(status)]
                with self.assertRaises(requests.HTTPError):
                    self.check()

    def test_network_errors_stop_the_check(self) -> None:
        for error in (requests.Timeout("timeout"), requests.ConnectionError("offline")):
            for during_download in (False, True):
                with self.subTest(error=error, during_download=during_download):
                    self.get.side_effect = (
                        [response(), error] if during_download else error
                    )
                    with self.assertRaises(requests.RequestException):
                        self.check()

    def test_invalid_published_xml_stops_the_check(self) -> None:
        self.get.side_effect = [response(), response(content=b"<dyn>")]

        with self.assertRaises(ET.ParseError):
            self.check()

    def test_invalid_candidate_is_rejected_before_requesting_baseline(self) -> None:
        self.xml_path.write_bytes(b"<dyn>")

        with self.assertRaises(ET.ParseError):
            self.check()
        self.get.assert_not_called()

    def test_missing_candidate_is_rejected_before_requesting_baseline(self) -> None:
        with self.assertRaises(OSError):
            check_nightly_release.release_xml_changed(
                "owner/repo", self.xml_path.with_name("missing.xml")
            )
        self.get.assert_not_called()


class TestMain(unittest.TestCase):
    def test_success_appends_the_decision_to_github_output(self) -> None:
        cases = (
            (XML, "false"),
            (FORMATTED_XML, "false"),
            (XML.replace(b"0x10", b"0x20"), "true"),
            (None, "true"),
        )
        for published_xml, decision in cases:
            with self.subTest(published_xml=published_xml), TemporaryDirectory() as directory:
                xml_path = Path(directory) / "candidate.xml"
                xml_path.write_bytes(XML)
                output_path = Path(directory) / "github-output"
                output_path.write_text("previous=value\n", encoding="utf-8")
                stdout = io.StringIO()
                replies = (
                    [response(404)] if published_xml is None
                    else [response(), response(content=published_xml)]
                )
                with (
                    patch.dict(
                        os.environ,
                        {"GITHUB_OUTPUT": str(output_path), "GITHUB_TOKEN": "test-token"},
                        clear=True,
                    ),
                    patch.object(check_nightly_release.requests, "get", side_effect=replies),
                    redirect_stdout(stdout),
                ):
                    result = check_nightly_release.main(
                        ["--repository", "owner/repo", "--xml", str(xml_path)]
                    )

                self.assertEqual(0, result)
                self.assertEqual(
                    f"previous=value\nchanged={decision}\n",
                    output_path.read_text(encoding="utf-8"),
                )
                self.assertIn(f"changed={decision}", stdout.getvalue())

    def test_errors_return_nonzero_without_emitting_a_publish_decision(self) -> None:
        errors = {
            "authentication": [response(401)],
            "timeout": requests.Timeout("timeout"),
            "download": [response(), response(404)],
            "invalid baseline": [response(), response(content=b"<dyn>")],
        }
        for name, replies in errors.items():
            with self.subTest(error=name), TemporaryDirectory() as directory:
                xml_path = Path(directory) / "candidate.xml"
                xml_path.write_bytes(XML)
                output_path = Path(directory) / "github-output"
                stdout, stderr = io.StringIO(), io.StringIO()
                with (
                    patch.dict(os.environ, {"GITHUB_OUTPUT": str(output_path)}, clear=True),
                    patch.object(check_nightly_release.requests, "get", side_effect=replies),
                    redirect_stdout(stdout), redirect_stderr(stderr),
                ):
                    result = check_nightly_release.main(
                        ["--repository", "owner/repo", "--xml", str(xml_path)]
                    )

                self.assertEqual(1, result)
                self.assertFalse(output_path.exists())
                self.assertNotIn("changed=", stdout.getvalue())
                self.assertIn("Error:", stderr.getvalue())

    def test_can_run_without_github_output(self) -> None:
        with TemporaryDirectory() as directory:
            xml_path = Path(directory) / "candidate.xml"
            xml_path.write_bytes(XML)
            stdout = io.StringIO()
            with (
                patch.dict(os.environ, {}, clear=True),
                patch.object(check_nightly_release.requests, "get", return_value=response(404)),
                redirect_stdout(stdout),
            ):
                result = check_nightly_release.main(
                    ["--repository", "owner/repo", "--xml", str(xml_path), "--tag", "custom"]
                )

            self.assertEqual(0, result)
            self.assertIn("changed=true", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
