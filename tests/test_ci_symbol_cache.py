import hashlib
import io
import json
import tarfile
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import dump_symbols
import update_symbols

from ci_symbol_cache import (
    CatalogConflict,
    cache_namespace,
    ensure_binary_inputs,
    publish,
    restore,
    S3Store,
)
from symbol_cache_metadata import ENTRY_NAME, cached_binary_exists, cached_pe_metadata


class MemoryStore:
    def __init__(self):
        self.objects = {}
        self.metadata = {}
        self.reads = []
        self.writes = []
        self.revision = 0
        self.fail_upload = False
        self.conflict = False

    def get_catalog(self, key):
        self.reads.append(key)
        if key not in self.objects:
            return None, None
        return json.loads(self.objects[key]), str(self.revision)

    def put_catalog(self, key, value, etag):
        if self.conflict or (str(self.revision) if key in self.objects else None) != etag:
            raise CatalogConflict("Catalog changed")
        self.revision += 1
        self.objects[key] = json.dumps(value).encode()
        self.writes.append(key)

    def head(self, key):
        if key not in self.objects:
            return None
        return {"size": len(self.objects[key]), "sha256": self.metadata[key]}

    def upload(self, key, path, sha256):
        if self.fail_upload:
            raise OSError("Upload failed")
        self.objects[key] = path.read_bytes()
        self.metadata[key] = sha256
        self.writes.append(key)

    def download(self, key, path):
        self.reads.append(key)
        path.write_bytes(self.objects[key])


class TestShardedSymbolCache(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        self.source.mkdir()
        self.store = MemoryStore()
        self.namespace = cache_namespace("HLND2T/kphtools", "Windows")
        self.first = self.make_binary("10.0.1.1", b"first PE")
        self.second = self.make_binary("10.0.2.2", b"second PE")

    def make_binary(self, version, pe):
        digest = hashlib.sha256(pe).hexdigest()
        path = self.source / "amd64" / f"ntoskrnl.exe.{version}" / digest
        path.mkdir(parents=True)
        (path / "ntoskrnl.exe").write_bytes(pe)
        (path / "ntkrnlmp.pdb").write_bytes(b"PDB data")
        (path / "ntoskrnl.exe.i64").write_bytes(b"IDA data")
        (path / "ntoskrnl.exe.idb").write_bytes(b"IDA 32-bit data")
        (path / "Offset.yaml").write_text("offset: 4\n", encoding="utf-8")
        return path

    def publish(self, source=None, base=None):
        return publish(
            source or self.source, self.store, self.namespace, base=base,
            metadata_reader=lambda _path: {"timestamp": "0x1234", "size": "0x1000"},
        )

    def legacy_namespace(self, platform):
        return self.namespace.rsplit("/", 1)[0] + "/" + platform.lower()

    def publish_legacy(self, platform, source=None):
        return publish(
            source or self.source, self.store, self.legacy_namespace(platform),
            metadata_reader=lambda _path: {"timestamp": "0x1234", "size": "0x1000"},
        )

    def test_symbol_namespace_is_shared_by_runner_platforms_and_isolates_repositories(self):
        for platform in ("Windows", "Linux", "macOS"):
            with self.subTest(platform=platform):
                self.assertEqual(self.namespace, cache_namespace("hlnd2t/KPHTOOLS", platform))
        self.assertNotEqual(self.namespace, cache_namespace("Owner/Other", "Linux"))
        for repository, platform in (("../other", "Linux"), ("Owner/Other", "unknown")):
            with self.subTest(repository=repository, platform=platform), self.assertRaises(ValueError):
                cache_namespace(repository, platform)

    def test_windows_publication_restores_all_components_on_linux_and_macos(self):
        self.publish()
        writes = list(self.store.writes)
        for platform in ("Linux", "macOS"):
            with self.subTest(platform=platform):
                namespace = cache_namespace("HLND2T/kphtools", platform)
                destination = self.root / platform
                base = restore(destination, self.store, namespace, mode="build")
                restored = destination / self.first.relative_to(self.source)
                self.assertEqual("offset: 4\n", (restored / "Offset.yaml").read_text())
                self.assertTrue(ensure_binary_inputs(restored, store=self.store))
                for name in ("ntoskrnl.exe", "ntkrnlmp.pdb", "ntoskrnl.exe.idb", "ntoskrnl.exe.i64"):
                    self.assertEqual((self.first / name).read_bytes(), (restored / name).read_bytes())
                publish(destination, self.store, namespace, base=base,
                        metadata_reader=lambda _path: {"timestamp": "0x1234", "size": "0x1000"})
                self.assertEqual(writes, self.store.writes)

    def test_linux_result_update_is_restored_by_windows(self):
        self.publish()
        linux_namespace = cache_namespace("HLND2T/kphtools", "Linux")
        linux = self.root / "linux"
        base = restore(linux, self.store, linux_namespace, mode="build")
        (linux / self.first.relative_to(self.source) / "Offset.yaml").write_text("offset: 99\n")
        publish(linux, self.store, linux_namespace, base=base)
        windows = self.root / "windows"
        restore(windows, self.store, self.namespace, mode="build")
        self.assertEqual("offset: 99\n", (windows / self.first.relative_to(self.source) / "Offset.yaml").read_text())

    def test_legacy_windows_cache_restores_on_linux_without_writing_or_reuploading(self):
        self.publish_legacy("Windows")
        old_objects = dict(self.store.objects)
        old_writes = list(self.store.writes)
        destination = self.root / "linux"
        namespace = cache_namespace("HLND2T/kphtools", "Linux")
        base = restore(destination, self.store, namespace, mode="build")
        restored = destination / self.first.relative_to(self.source)
        self.assertTrue((restored / "Offset.yaml").is_file())
        self.assertTrue(ensure_binary_inputs(restored, store=self.store))
        self.assertEqual(b"IDA data", (restored / "ntoskrnl.exe.i64").read_bytes())
        self.assertEqual(old_objects, self.store.objects)
        self.assertEqual(old_writes, self.store.writes)
        self.publish(destination, base)
        self.assertEqual([self.namespace + "/catalog.json"], self.store.writes[len(old_writes):])
        self.assertTrue(all(self.store.objects[key] == value for key, value in old_objects.items()))
        before = list(self.store.writes)
        self.publish(destination)
        self.assertEqual(before, self.store.writes)

    def test_pr_restores_legacy_inputs_from_another_platform_without_results(self):
        self.publish_legacy("Windows")
        destination = self.root / "linux-pr"
        restore(destination, self.store, cache_namespace("HLND2T/kphtools", "Linux"),
                mode="pr", arch="amd64", version="10.0.1.1")
        restored = destination / self.first.relative_to(self.source)
        for name in ("ntoskrnl.exe", "ntkrnlmp.pdb", "ntoskrnl.exe.idb", "ntoskrnl.exe.i64"):
            self.assertEqual((self.first / name).read_bytes(), (restored / name).read_bytes())
        self.assertFalse((restored / "Offset.yaml").exists())
        self.assertFalse((restored / ENTRY_NAME).exists())

    def test_legacy_catalog_union_prefers_windows_and_keeps_other_platform_only_shards(self):
        self.publish_legacy("Windows")
        (self.first / "Offset.yaml").write_text("offset: 8\n")
        third = self.make_binary("10.0.3.3", b"Linux-only PE")
        self.publish_legacy("Linux")
        destination = self.root / "merged"
        base = restore(destination, self.store, self.namespace, mode="build")
        self.assertEqual(3, len(base["catalog"]["shards"]))
        self.assertEqual("offset: 4\n", (destination / self.first.relative_to(self.source) / "Offset.yaml").read_text())
        self.assertTrue((destination / third.relative_to(self.source) / "Offset.yaml").is_file())
        self.publish(destination, base)
        shared = json.loads(self.store.objects[self.namespace + "/catalog.json"])
        self.assertEqual(base["catalog"], shared)

    def test_shared_results_take_precedence_over_legacy_results(self):
        self.publish_legacy("Windows")
        (self.first / "Offset.yaml").write_text("offset: 99\n")
        self.publish()
        destination = self.root / "shared"
        restore(destination, self.store, self.namespace, mode="build")
        self.assertEqual("offset: 99\n", (destination / self.first.relative_to(self.source) / "Offset.yaml").read_text())

    def test_late_legacy_shards_are_imported_without_reverting_shared_results(self):
        self.publish()
        (self.first / "Offset.yaml").write_text("offset: 8\n")
        third = self.make_binary("10.0.3.3", b"late legacy PE")
        self.publish_legacy("Linux")
        destination = self.root / "merged"
        base = restore(destination, self.store, self.namespace, mode="build")
        self.assertEqual("offset: 4\n", (destination / self.first.relative_to(self.source) / "Offset.yaml").read_text())
        self.assertTrue((destination / third.relative_to(self.source) / "Offset.yaml").is_file())
        before = len(self.store.writes)
        self.publish(destination, base)
        self.assertEqual([self.namespace + "/catalog.json"], self.store.writes[before:])

    def test_shared_catalog_rejects_cross_repository_legacy_references(self):
        catalog = self.publish()
        catalog_key = self.namespace + "/catalog.json"
        shard = next(iter(catalog["shards"].values()))
        foreign = cache_namespace("Owner/Other", "Windows").rsplit("/", 1)[0] + "/windows"
        shard["inputs"]["key"] = shard["inputs"]["key"].replace(self.namespace, foreign)
        self.store.objects[catalog_key] = json.dumps(catalog).encode()
        with self.assertRaisesRegex(ValueError, "namespace"):
            restore(self.root / "unsafe", self.store, self.namespace, mode="build")

    def test_concurrent_migration_does_not_overwrite_shared_catalog(self):
        self.publish_legacy("Windows")
        first = self.root / "first"
        second = self.root / "second"
        first_base = restore(first, self.store, self.namespace, mode="build")
        second_base = restore(second, self.store, self.namespace, mode="build")
        self.publish(first, first_base)
        previous = self.store.objects[self.namespace + "/catalog.json"]
        with self.assertRaises(CatalogConflict):
            self.publish(second, second_base)
        self.assertEqual(previous, self.store.objects[self.namespace + "/catalog.json"])

    def test_publication_is_content_addressed_and_timestamp_changes_do_not_upload(self):
        self.publish()
        initial_writes = list(self.store.writes)
        self.assertEqual(5, len(initial_writes))
        (self.first / "Offset.yaml").touch()
        self.publish()
        self.assertEqual(initial_writes, self.store.writes)
        (self.first / "Offset.yaml").write_text("offset: 8\n", encoding="utf-8")
        self.publish()
        self.assertEqual(2, len(self.store.writes) - len(initial_writes))
        self.assertIn("/results/", self.store.writes[-2])
        self.assertTrue(self.store.writes[-1].endswith("/catalog.json"))

    def test_build_restores_results_and_metadata_without_heavy_inputs(self):
        self.publish()
        destination = self.root / "build"
        base = restore(destination, self.store, self.namespace, mode="build")
        restored = destination / self.first.relative_to(self.source)
        self.assertTrue((restored / "Offset.yaml").exists())
        self.assertFalse((restored / "ntoskrnl.exe").exists())
        self.assertFalse((restored / "ntkrnlmp.pdb").exists())
        self.assertTrue(cached_binary_exists(restored, "ntoskrnl.exe"))
        self.assertEqual({"timestamp": "0x1234", "size": "0x1000", "sha256": self.first.name}, cached_pe_metadata(restored / "ntoskrnl.exe"))
        self.assertFalse(any("/inputs/" in key for key in self.store.reads))
        before = len(self.store.writes)
        self.publish(destination, base)
        self.assertEqual(before, len(self.store.writes))

    def test_inputs_are_hydrated_only_once_and_keep_current_results(self):
        self.publish()
        destination = self.root / "build"
        restore(destination, self.store, self.namespace, mode="build")
        restored = destination / self.first.relative_to(self.source)
        (restored / "Offset.yaml").write_text("offset: 99\n", encoding="utf-8")
        self.assertTrue(ensure_binary_inputs(restored, store=self.store))
        self.assertEqual(b"first PE", (restored / "ntoskrnl.exe").read_bytes())
        self.assertEqual("offset: 99\n", (restored / "Offset.yaml").read_text())
        before = len(self.store.reads)
        self.assertFalse(ensure_binary_inputs(restored, store=self.store))
        self.assertEqual(before, len(self.store.reads))

    def test_pr_restores_only_selected_version_inputs_and_no_yaml_or_marker(self):
        self.publish()
        destination = self.root / "pr"
        restore(destination, self.store, self.namespace, mode="pr", arch="amd64", version="10.0.1.1")
        restored = destination / self.first.relative_to(self.source)
        self.assertTrue((restored / "ntoskrnl.exe").exists())
        self.assertTrue((restored / "ntkrnlmp.pdb").exists())
        self.assertFalse((restored / "Offset.yaml").exists())
        self.assertFalse((restored / ENTRY_NAME).exists())
        self.assertFalse((destination / self.second.relative_to(self.source)).exists())
        self.assertEqual(1, sum("/inputs/" in key for key in self.store.reads))
        self.assertFalse(any("/results/" in key for key in self.store.reads))

    def test_failed_upload_does_not_publish_a_catalog(self):
        self.store.fail_upload = True
        with self.assertRaisesRegex(OSError, "Upload failed"):
            self.publish()
        self.assertFalse(any(key.endswith("/catalog.json") for key in self.store.objects))

    def test_interrupted_seed_reuses_uploaded_components_without_repacking(self):
        import ci_symbol_cache

        original_upload = self.store.upload
        attempts = 0

        def interrupted_upload(key, path, sha256):
            nonlocal attempts
            attempts += 1
            if attempts == 2:
                raise OSError("Interrupted upload")
            original_upload(key, path, sha256)

        with patch.object(self.store, "upload", side_effect=interrupted_upload):
            with self.assertRaisesRegex(OSError, "Interrupted upload"):
                self.publish()
        self.assertEqual(1, len(self.store.objects))
        uploaded_key = next(iter(self.store.objects))
        with patch.object(ci_symbol_cache, "_write_archive", wraps=ci_symbol_cache._write_archive) as archive_writer:
            self.publish()
            self.assertEqual(3, archive_writer.call_count)
        self.assertEqual(1, self.store.writes.count(uploaded_key))
        self.assertEqual(5, len(self.store.objects))

    def test_corrupt_shard_is_rejected_before_destination_is_changed(self):
        self.publish()
        key = next(key for key in self.store.objects if "/results/" in key)
        self.store.objects[key] = b"corrupt"
        destination = self.root / "build"
        with self.assertRaisesRegex(ValueError, "checksum|size"):
            restore(destination, self.store, self.namespace, mode="build")
        self.assertFalse((destination / self.first.relative_to(self.source) / "Offset.yaml").exists())

    def test_catalog_concurrent_update_is_not_overwritten(self):
        self.publish()
        catalog_key = self.namespace + "/catalog.json"
        previous = self.store.objects[catalog_key]
        self.store.conflict = True
        (self.first / "Offset.yaml").write_text("offset: 8\n", encoding="utf-8")
        with self.assertRaises(CatalogConflict):
            self.publish()
        self.assertEqual(previous, self.store.objects[catalog_key])

    def test_catalog_cannot_escape_the_symbol_root_or_object_namespace(self):
        self.publish()
        catalog_key = self.namespace + "/catalog.json"
        catalog = json.loads(self.store.objects[catalog_key])
        shard = catalog["shards"].pop(next(iter(catalog["shards"])))
        catalog["shards"]["../outside"] = shard
        self.store.objects[catalog_key] = json.dumps(catalog).encode()
        with self.assertRaises(ValueError):
            restore(self.root / "build", self.store, self.namespace, mode="build")

    def test_cached_metadata_is_bound_to_the_binary_directory(self):
        self.publish()
        destination = self.root / "build"
        restore(destination, self.store, self.namespace, mode="build")
        restored = destination / self.first.relative_to(self.source)
        data = json.loads((restored / ENTRY_NAME).read_text())
        data["shard"]["metadata"]["sha256"] = self.second.name
        (restored / ENTRY_NAME).write_text(json.dumps(data))
        with self.assertRaises(ValueError):
            cached_pe_metadata(restored / "ntoskrnl.exe")

    def test_dump_discovers_results_only_and_skips_complete_artifacts(self):
        self.publish()
        destination = self.root / "build"
        restore(destination, self.store, self.namespace, mode="build")
        module = SimpleNamespace(
            path=["ntoskrnl.exe"], symbols=[],
            skills=[{"name": "sample", "expected_output": ["Offset.yaml"]}],
        )
        candidates = list(dump_symbols._iter_binary_dirs(destination, "amd64", SimpleNamespace(modules=[module])))
        self.assertEqual(2, len(candidates))
        for _, directory, pdb, snapshot in candidates:
            self.assertIsNone(pdb)
            self.assertFalse((directory / "ntoskrnl.exe").exists())
            self.assertTrue(dump_symbols._module_skills_are_satisfied(
                module=module, arch="amd64", selected_skill_name=None,
                force=False, debug=False, snapshot=snapshot,
            ))

    def test_dump_hydrates_only_unsatisfied_binary_and_refreshes_pdb_snapshot(self):
        self.publish()
        destination = self.root / "build"
        restore(destination, self.store, self.namespace, mode="build")
        first = destination / self.first.relative_to(self.source)
        (first / "Offset.yaml").unlink()
        module = SimpleNamespace(
            path=["ntoskrnl.exe"], symbols=[],
            skills=[{"name": "sample", "expected_output": ["Offset.yaml"]}],
        )
        configuration = self.root / "configuration.yaml"
        configuration.write_text("", encoding="utf-8")
        args = SimpleNamespace(
            symboldir=str(destination), arch="amd64", arches=["amd64"],
            version=None, configyaml=str(configuration), force=False, debug=False, skill=None,
        )
        processor = AsyncMock(return_value=(True, True))
        with (
            patch.object(dump_symbols, "parse_args", return_value=args),
            patch.object(dump_symbols, "load_config", return_value=SimpleNamespace(modules=[module])),
            patch.object(dump_symbols, "_process_module_binary", processor),
            patch.object(dump_symbols, "ensure_cached_binary_inputs", side_effect=lambda directory: ensure_binary_inputs(directory, store=self.store)),
        ):
            self.assertEqual(0, dump_symbols.main([]))
        processor.assert_awaited_once()
        self.assertEqual(first / "ntkrnlmp.pdb", processor.await_args.args[2])
        self.assertTrue(processor.await_args.kwargs["snapshot"].name_is_file("ntoskrnl.exe"))
        self.assertEqual(1, sum("/inputs/" in key for key in self.store.reads))

    def test_xml_sync_and_metadata_export_do_not_download_or_open_cached_pe(self):
        self.publish()
        destination = self.root / "build"
        restore(destination, self.store, self.namespace, mode="build")
        binary = destination / self.first.relative_to(self.source) / "ntoskrnl.exe"
        xml = self.root / "input.xml"
        xml.write_text("<dyn/>", encoding="utf-8")
        args = SimpleNamespace(xml=str(xml), outxml=None, symboldir=str(destination), debug=False)
        with patch.object(update_symbols.pefile, "PE") as pe_loader:
            self.assertEqual(2, len(update_symbols.scan_symbol_directory(destination)))
            self.assertEqual({"timestamp": "0x1234", "size": "0x1000"}, update_symbols._load_binary_metadata(binary))
            self.assertEqual(0, update_symbols.syncfile_main(args))
            pe_loader.assert_not_called()
        entries = ET.parse(xml).getroot().findall("data")
        self.assertEqual(2, len(entries))
        self.assertEqual({self.first.name, self.second.name}, {entry.get("hash") for entry in entries})
        self.assertFalse(any("/inputs/" in key for key in self.store.reads))

    def test_source_change_during_archive_does_not_publish_a_catalog(self):
        import ci_symbol_cache

        original = ci_symbol_cache._write_archive

        def racing_archive(root, files, output):
            files[0].write_bytes(b"changed during upload preparation")
            original(root, files, output)

        with patch.object(ci_symbol_cache, "_write_archive", side_effect=racing_archive):
            with self.assertRaisesRegex(ValueError, "changed while"):
                self.publish()
        self.assertFalse(any(key.endswith("/catalog.json") for key in self.store.objects))

    def test_file_added_during_archive_does_not_publish_a_catalog(self):
        import ci_symbol_cache

        original = ci_symbol_cache._write_archive

        def racing_archive(root, files, output):
            original(root, files, output)
            (root / "NewOffset.yaml").write_text("offset: 12\n", encoding="utf-8")

        with patch.object(ci_symbol_cache, "_write_archive", side_effect=racing_archive):
            with self.assertRaisesRegex(ValueError, "changed while"):
                self.publish()
        self.assertEqual({}, self.store.objects)

    def test_unsafe_archive_member_is_rejected_without_writing_outside(self):
        import zstandard

        self.publish()
        catalog_key = self.namespace + "/catalog.json"
        catalog = json.loads(self.store.objects[catalog_key])
        ref = next(iter(catalog["shards"].values()))["results"]
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w") as archive:
            info = tarfile.TarInfo("../escape.yaml")
            info.size = 3
            archive.addfile(info, io.BytesIO(b"bad"))
        payload = zstandard.ZstdCompressor().compress(buffer.getvalue())
        self.store.objects[ref["key"]] = payload
        ref["archive_size"] = len(payload)
        ref["archive_sha256"] = hashlib.sha256(payload).hexdigest()
        self.store.objects[catalog_key] = json.dumps(catalog).encode()
        with self.assertRaisesRegex(ValueError, "Unsafe"):
            restore(self.root / "build", self.store, self.namespace, mode="build")
        self.assertEqual([], list(self.root.rglob("escape.yaml")))

    def test_download_skips_cached_binaries_and_fetches_only_new_entries(self):
        import download_symbols
        from ci_symbol_cache import download_missing_binaries

        self.publish()
        destination = self.root / "build"
        restore(destination, self.store, self.namespace, mode="build")
        entries = [
            {"arch": "amd64", "file": "ntoskrnl.exe", "version": "10.0.1.1", "hash": self.first.name},
            {"arch": "amd64", "file": "ntoskrnl.exe", "version": "10.0.3.3", "hash": "a" * 64},
        ]
        with (
            patch.object(download_symbols, "parse_xml", side_effect=[entries, []]),
            patch.object(download_symbols, "process_entry", return_value=download_symbols.DownloadStatus.SUCCESS) as downloader,
        ):
            download_missing_binaries(self.root / "input.xml", destination)
        downloader.assert_called_once_with(entries[1], str(destination), fast_mode=True)

    def test_oss_pull_keeps_catalog_backed_pe_virtual_and_fetches_new_pe(self):
        from ci_symbol_cache import sync_oss
        import oss_sync

        self.publish()
        destination = self.root / "build"
        restore(destination, self.store, self.namespace, mode="build")
        known = (self.first.relative_to(self.source) / "ntoskrnl.exe").as_posix()
        new = "amd64/ntoskrnl.exe.10.0.3.3/" + "a" * 64 + "/ntoskrnl.exe"
        client = SimpleNamespace(
            _iter_oss_objects=lambda: [SimpleNamespace(key=known), SimpleNamespace(key=new)],
            _relative_object_path=lambda key: key,
            _should_ignore=lambda _key: False,
            _download_file=unittest.mock.Mock(return_value=True),
        )
        with (
            patch.object(oss_sync, "load_config_from_environment", return_value={}),
            patch.object(oss_sync, "OSSSync", return_value=client),
        ):
            sync_oss(destination, "oss2local")
        client._download_file.assert_called_once_with(new)
        self.assertFalse((destination / known).exists())

    def test_oss_push_uploads_only_materialized_nonexcluded_files(self):
        from ci_symbol_cache import sync_oss
        import oss_sync

        self.publish()
        destination = self.root / "build"
        restore(destination, self.store, self.namespace, mode="build")
        first = destination / self.first.relative_to(self.source)
        (first / "ntoskrnl.exe").write_bytes(b"first PE")
        client = SimpleNamespace(
            _should_ignore=lambda key: Path(key).suffix.lower() in (".yaml", ".pdb", ".i64"),
            _upload_file_if_changed=unittest.mock.Mock(return_value=True),
        )
        with (
            patch.object(oss_sync, "load_config_from_environment", return_value={}),
            patch.object(oss_sync, "OSSSync", return_value=client),
        ):
            sync_oss(destination, "local2oss")
        client._upload_file_if_changed.assert_called_once_with(
            (self.first.relative_to(self.source) / "ntoskrnl.exe").as_posix()
        )


class TestS3CatalogRequests(unittest.TestCase):
    def setUp(self):
        import boto3
        from botocore.config import Config
        from botocore.stub import Stubber

        client = boto3.client(
            "s3", endpoint_url="http://s3.invalid", region_name="us-east-1",
            aws_access_key_id="test-only", aws_secret_access_key="test-only",
            config=Config(request_checksum_calculation="when_required"),
        )
        self.store = S3Store(client)
        self.stub = Stubber(client)
        self.stub.activate()
        self.addCleanup(self.stub.deactivate)

    def test_missing_catalog_is_a_cold_cache_but_access_denied_is_an_error(self):
        from botocore.exceptions import ClientError

        parameters = {"Bucket": "actions-cache-kphtools", "Key": "catalog"}
        self.stub.add_client_error("get_object", service_error_code="NoSuchKey", http_status_code=404, expected_params=parameters)
        self.assertEqual((None, None), self.store.get_catalog("catalog"))
        self.stub.add_client_error("get_object", service_error_code="AccessDenied", http_status_code=403, expected_params=parameters)
        with self.assertRaises(ClientError):
            self.store.get_catalog("catalog")
        self.stub.assert_no_pending_responses()

    def test_catalog_create_and_update_use_conditional_writes(self):
        from ci_symbol_cache import _json_bytes

        value = {"schema": 1}
        parameters = {
            "Bucket": "actions-cache-kphtools", "Key": "catalog", "Body": _json_bytes(value),
            "ContentType": "application/json",
        }
        self.stub.add_response("put_object", {}, {**parameters, "IfNoneMatch": "*"})
        self.store.put_catalog("catalog", value, None)
        self.stub.add_client_error("put_object", service_error_code="PreconditionFailed", http_status_code=412, expected_params={**parameters, "IfMatch": '"previous"'})
        with self.assertRaises(CatalogConflict):
            self.store.put_catalog("catalog", value, '"previous"')
        self.stub.assert_no_pending_responses()


if __name__ == "__main__":
    unittest.main()
