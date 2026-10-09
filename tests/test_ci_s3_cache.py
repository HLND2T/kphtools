import os
import subprocess
import tarfile
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest.mock import patch

from ci_s3_cache import (
    CACHE_DIRECTORY,
    PR_DIRECTORY,
    cleanup,
    isolate_pr_inputs,
    main,
    parse_endpoint,
    prepare,
    verify_pr_inputs,
)


class TestEndpoint(unittest.TestCase):
    def test_http_and_https_origins(self):
        self.assertEqual(
            {"endpoint": "HZVM", "port": "8333", "insecure": "true"},
            parse_endpoint("http://HZVM:8333"),
        )
        self.assertEqual(
            {"endpoint": "cache.local", "port": "443", "insecure": "false"},
            parse_endpoint("https://cache.local/"),
        )
        self.assertEqual("80", parse_endpoint("http://cache.local")["port"])
        self.assertEqual("8443", parse_endpoint("https://cache.local:8443")["port"])

    def test_invalid_origins(self):
        for value in (
            "", "HZVM:8333", "ftp://host", "http://u:p@host",
            "http://host/path", "http://host?", "http://host#",
            "http://host:0", "http://host:65536", "http://host:",
            "http://host:abc", "http://host\n",
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                parse_endpoint(value)


class WorkspaceTestCase(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.workspace = Path(self.temporary.name) / "checkout"
        self.workspace.mkdir()

    def layout(self, repository="HLND2T/kphtools", run_id="123", attempt="1"):
        return prepare(self.workspace, repository, "Windows", run_id, attempt)

    def make_link(self, link, target):
        try:
            link.symlink_to(target, target_is_directory=target.is_dir())
        except OSError as error:
            self.skipTest(f"Symlinks unavailable: {error}")


class TestCacheLayout(WorkspaceTestCase):
    def test_fresh_staging_preserves_checkout_and_repository_namespace(self):
        sentinel = self.workspace / "keep"
        sentinel.write_text("keep")
        first = self.layout()
        staging = Path(first["cache-root"])
        (staging / "stale").write_text("stale")
        second = self.layout("hlnd2t/KPHTOOLS", attempt="2")
        self.assertEqual(first["cache-path"], second["cache-path"])
        self.assertEqual(staging, self.workspace / second["cache-path"])
        self.assertFalse((staging / "stale").exists())
        self.assertEqual("keep", sentinel.read_text())
        self.assertEqual(first["namespace"], second["namespace"])
        self.assertNotEqual(first["namespace"], self.layout("Owner/Other")["namespace"])

    def test_invalid_identity_does_not_remove_existing_staging(self):
        staging = Path(self.layout()["cache-root"])
        sentinel = staging / "keep"
        sentinel.write_text("keep")
        for repository, run_id, attempt in (
            ("../other", "123", "1"), ("owner/repo\n", "123", "1"),
            ("owner/repo", "../123", "1"), ("owner/repo", "123", "0"),
        ):
            with self.subTest(repository=repository, run_id=run_id, attempt=attempt):
                with self.assertRaises(ValueError):
                    self.layout(repository, run_id, attempt)
                self.assertEqual("keep", sentinel.read_text())

    def test_prepare_rejects_link_without_touching_target(self):
        target = Path(self.temporary.name) / "outside"
        target.mkdir()
        sentinel = target / "keep"
        sentinel.write_text("keep")
        self.make_link(self.workspace / CACHE_DIRECTORY, target)
        with self.assertRaises(ValueError):
            self.layout()
        self.assertEqual("keep", sentinel.read_text())

    def test_snapshot_restores_on_a_different_work_root(self):
        first = self.layout()
        binary = Path(first["symbols-path"]) / "amd64/kernel/hash/ntoskrnl.exe"
        binary.parent.mkdir(parents=True)
        binary.write_bytes(b"cached PE")
        archive_path = Path(self.temporary.name) / "snapshot.tar"
        with tarfile.open(archive_path, "w") as archive:
            archive.add(first["cache-root"], arcname=first["cache-path"])
        other_workspace = Path(self.temporary.name) / "other-runner/work/repo"
        other_workspace.mkdir(parents=True)
        second = prepare(other_workspace, "HLND2T/kphtools", "Windows", "456", "1")
        with tarfile.open(archive_path) as archive:
            # This archive was created above from this test's own temporary tree.
            options = {"filter": "data"} if hasattr(tarfile, "data_filter") else {}
            archive.extractall(other_workspace, **options)
        self.assertEqual(first["namespace"], second["namespace"])
        self.assertEqual(
            b"cached PE",
            (Path(second["symbols-path"]) / "amd64/kernel/hash/ntoskrnl.exe").read_bytes(),
        )
        cleanup(other_workspace)
        self.assertEqual(b"cached PE", binary.read_bytes())

    @unittest.skipUnless(os.name == "nt", "Windows junction protection")
    def test_cleanup_rejects_windows_junction_without_touching_target(self):
        staging = Path(self.layout()["cache-root"])
        target = Path(self.temporary.name) / "outside"
        target.mkdir()
        sentinel = target / "keep"
        sentinel.write_text("keep")
        junction = staging / "symbols/junction"
        result = subprocess.run(
            ["cmd", "/d", "/c", "mklink", "/J", str(junction), str(target)],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        with self.assertRaises(ValueError):
            cleanup(self.workspace)
        self.assertEqual("keep", sentinel.read_text())
        junction.rmdir()

    def test_cleanup_is_idempotent_and_preserves_checkout_and_uv_files(self):
        self.layout()
        for name in ("pyproject.toml", "uv.lock", ".venv/keep"):
            path = self.workspace / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("keep")
        cleanup(self.workspace)
        cleanup(self.workspace)
        self.assertFalse((self.workspace / CACHE_DIRECTORY).exists())
        self.assertFalse((self.workspace / PR_DIRECTORY).exists())
        self.assertEqual("keep", (self.workspace / ".venv/keep").read_text())
        self.assertEqual("keep", (self.workspace / "uv.lock").read_text())

    def test_cleanup_rejects_nested_link_before_removing_any_tree(self):
        staging = Path(self.layout()["cache-root"])
        target = Path(self.temporary.name) / "outside"
        target.mkdir()
        sentinel = target / "keep"
        sentinel.write_text("keep")
        self.make_link(staging / "symbols/link", target)
        with self.assertRaises(ValueError):
            cleanup(self.workspace)
        self.assertTrue((self.workspace / PR_DIRECTORY).exists())
        self.assertEqual("keep", sentinel.read_text())


class TestPrInputs(WorkspaceTestCase):
    version = "10.0.22621.3668"

    def make_xml(self):
        xml = self.workspace / "official.xml"
        xml.write_text(
            '<root><data arch="amd64" file="ntoskrnl.exe" version="10.0.22621.3668" hash="abc"/>'
            '<data arch="arm64" file="ntoskrnl.exe" version="10.0.22621.3668"/>'
            '<data arch="amd64" file="ntkrla57.exe" version="10.0.22621.3668"/>'
            '<data arch="amd64" file="ntoskrnl.exe" version="10.0.26100.1"/></root>',
            encoding="utf-8",
        )
        return xml

    def test_copies_selected_inputs_and_excludes_all_yaml(self):
        cache = Path(self.layout()["cache-root"])
        source = cache / "symbols/amd64" / f"ntoskrnl.exe.{self.version}" / "abc"
        source.mkdir(parents=True)
        for name in ("ntoskrnl.exe", "ntkrnlmp.pdb", "ntoskrnl.exe.i64", "Offset.yaml", "artifacts.yaml", "OTHER.YAML"):
            (source / name).write_text("input")
        other = cache / "symbols/arm64/other.exe"
        other.parent.mkdir(parents=True)
        other.write_text("other")

        result = isolate_pr_inputs(self.workspace, self.make_xml(), "amd64", self.version)
        symbols = Path(result["symbols-path"])
        binaries = verify_pr_inputs(self.workspace, "amd64", self.version)
        self.assertEqual(1, binaries)
        self.assertEqual(
            ["ntkrnlmp.pdb", "ntoskrnl.exe", "ntoskrnl.exe.i64"],
            sorted(path.name for path in symbols.rglob("*") if path.is_file()),
        )
        self.assertFalse((symbols / "arm64").exists())
        self.assertTrue((source / "Offset.yaml").exists())
        entries = ET.parse(result["download-xml"]).getroot().findall("data")
        self.assertEqual(1, len(entries))
        self.assertEqual("abc", entries[0].get("hash"))
        (symbols / "amd64" / f"ntoskrnl.exe.{self.version}" / "abc/ntoskrnl.exe").write_text("changed")
        self.assertEqual("input", (source / "ntoskrnl.exe").read_text())

    def test_empty_cache_can_bootstrap_then_verification_requires_pe_and_pdb(self):
        self.layout()
        result = isolate_pr_inputs(self.workspace, self.make_xml(), "amd64", self.version)
        with self.assertRaisesRegex(ValueError, "ntoskrnl.exe"):
            verify_pr_inputs(self.workspace, "amd64", self.version)
        binary = Path(result["symbols-path"]) / "amd64" / f"ntoskrnl.exe.{self.version}" / "abc/ntoskrnl.exe"
        binary.parent.mkdir(parents=True)
        binary.write_text("PE")
        with self.assertRaisesRegex(ValueError, "PDB"):
            verify_pr_inputs(self.workspace, "amd64", self.version)
        binary.with_name("ntkrnlmp.pdb").write_text("PDB")
        self.assertEqual(1, verify_pr_inputs(self.workspace, "amd64", self.version))
        binary.with_name("Offset.yaml").write_text("stale")
        with self.assertRaisesRegex(ValueError, "YAML"):
            verify_pr_inputs(self.workspace, "amd64", self.version)

    def test_invalid_version_cannot_escape_symbol_root(self):
        self.layout()
        with self.assertRaises(ValueError):
            isolate_pr_inputs(self.workspace, self.make_xml(), "amd64", "../../outside")

    def test_pruned_upstream_uses_retained_download_metadata(self):
        self.layout()
        xml = self.workspace / "official.xml"
        xml.write_text('<root><data arch="amd64" version="10.0.26100.1" file="ntoskrnl.exe"/></root>')
        baseline = self.workspace / "baseline.xml"
        baseline.write_text(
            '<root><data arch="amd64" version="10.0.22621.3668" file="ntoskrnl.exe" '
            'hash="retained" timestamp="0x123" size="0x456">0</data></root>'
        )
        result = isolate_pr_inputs(self.workspace, xml, "amd64", self.version, baseline)
        entries = ET.parse(result["download-xml"]).getroot().findall("data")
        self.assertEqual(1, len(entries))
        self.assertEqual("retained", entries[0].get("hash"))
        self.assertEqual("0x123", entries[0].get("timestamp"))
        self.assertEqual("0x456", entries[0].get("size"))

    def test_current_upstream_selection_takes_priority_over_baseline(self):
        self.layout()
        baseline = self.workspace / "baseline.xml"
        baseline.write_text(
            '<root><data arch="amd64" version="10.0.22621.3668" file="ntoskrnl.exe" hash="old"/></root>'
        )
        result = isolate_pr_inputs(self.workspace, self.make_xml(), "amd64", self.version, baseline)
        entries = ET.parse(result["download-xml"]).getroot().findall("data")
        self.assertEqual(1, len(entries))
        self.assertEqual("abc", entries[0].get("hash"))

    def test_rejects_linked_cached_inputs(self):
        cache = Path(self.layout()["cache-root"])
        source = cache / "symbols/amd64" / f"ntoskrnl.exe.{self.version}"
        source.parent.mkdir(parents=True)
        target = Path(self.temporary.name) / "outside"
        target.mkdir()
        self.make_link(source, target)
        with self.assertRaises(ValueError):
            isolate_pr_inputs(self.workspace, self.make_xml(), "amd64", self.version)


class TestCli(unittest.TestCase):
    def test_prepare_exports_local_paths_and_cache_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            checkout = root / "checkout"
            checkout.mkdir()
            output = root / "output"
            environment = root / "environment"
            with patch.dict(os.environ, {
                "GITHUB_WORKSPACE": str(checkout), "GITHUB_REPOSITORY": "owner/repo",
                "RUNNER_OS": "Windows", "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1",
                "GITHUB_OUTPUT": str(output), "GITHUB_ENV": str(environment),
            }, clear=True):
                self.assertEqual(0, main(["prepare"]))
            self.assertIn("namespace=", output.read_text())
            self.assertIn(f"KPHTOOLS_SYMBOLDIR={checkout / CACHE_DIRECTORY / 'symbols'}", environment.read_text())

    def test_endpoint_requires_both_credentials(self):
        with patch.dict(os.environ, {"S3_ENDPOINT_URL": "http://host"}, clear=True):
            with self.assertRaisesRegex(ValueError, "S3_ACCESS_KEY_ID"):
                main(["endpoint"])


if __name__ == "__main__":
    unittest.main()
