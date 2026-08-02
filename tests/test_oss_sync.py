import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock, patch

import oss_sync as oss_sync_module


class TestInitialSyncProgress(unittest.TestCase):
    @staticmethod
    def _make_sync_client(local_path, direction="local2oss"):
        sync_client = oss_sync_module.OSSSync.__new__(oss_sync_module.OSSSync)
        sync_client.config = {
            "local_path": local_path,
            "oss_path": "symbols",
            "exclude": set(),
            "exclude_extension": set(),
            "sync_direction": direction,
        }
        sync_client.client = Mock()
        sync_client.bucket_name = "test-bucket"
        return sync_client

    def test_logs_local_scan_progress_and_summary(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            local_path = Path(temp_dir)
            (local_path / "first.bin").write_bytes(b"first")
            (local_path / "second.bin").write_bytes(b"second")

            sync_client = self._make_sync_client(local_path)
            sync_client._iter_oss_objects = Mock(return_value=[])
            sync_client._upload_file = Mock()

            with (
                patch.object(
                    oss_sync_module.time,
                    "monotonic",
                    side_effect=[100.0, 111.0, 112.0, 113.0],
                ),
                self.assertLogs("aliyun_oss_sync", level="INFO") as captured_logs,
            ):
                sync_client.initial_sync()

        log_output = "\n".join(captured_logs.output)
        self.assertIn("Local scan progress: 1 files scanned", log_output)
        self.assertIn("Local files scanned: 2 files", log_output)

    def test_does_not_hash_when_remote_key_is_missing(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            local_path = Path(temp_dir)
            (local_path / "new.bin").write_bytes(b"new file")

            sync_client = self._make_sync_client(local_path)
            sync_client._iter_oss_objects = Mock(return_value=[])
            sync_client._calculate_file_hash = Mock()
            sync_client._upload_file = Mock()

            sync_client.initial_sync()

        sync_client._calculate_file_hash.assert_not_called()
        sync_client._upload_file.assert_called_once_with("new.bin")

    def test_hashes_common_key_when_metadata_cannot_determine_change(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            local_path = Path(temp_dir)
            local_file = local_path / "existing.bin"
            local_file.write_bytes(b"local content")
            local_stat = local_file.stat()

            sync_client = self._make_sync_client(local_path)
            sync_client._calculate_file_hash = Mock(return_value="local-hash")
            sync_client._upload_file = Mock()
            remote_object = Mock(
                key="symbols/existing.bin",
                last_modified=datetime.fromtimestamp(
                    local_stat.st_mtime + 1,
                    tz=timezone.utc,
                ),
                size=local_stat.st_size,
                etag='"remote-hash"',
            )
            sync_client._iter_oss_objects = Mock(return_value=[remote_object])

            sync_client.initial_sync()

        sync_client._calculate_file_hash.assert_called_once_with(local_file)
        sync_client._upload_file.assert_called_once_with("existing.bin")

    def test_skips_hash_when_common_key_size_differs(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            local_path = Path(temp_dir)
            local_file = local_path / "changed.bin"
            local_file.write_bytes(b"local content")
            local_stat = local_file.stat()

            sync_client = self._make_sync_client(local_path)
            sync_client._calculate_file_hash = Mock()
            sync_client._upload_file = Mock()
            remote_object = Mock(
                key="symbols/changed.bin",
                last_modified=datetime.fromtimestamp(
                    local_stat.st_mtime + 1,
                    tz=timezone.utc,
                ),
                size=local_stat.st_size + 1,
                etag='"remote-hash"',
            )
            sync_client._iter_oss_objects = Mock(return_value=[remote_object])

            sync_client.initial_sync()

        sync_client._calculate_file_hash.assert_not_called()
        sync_client._upload_file.assert_called_once_with("changed.bin")

    def test_reports_synchronized_when_file_sets_and_contents_match(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            local_path = Path(temp_dir)
            local_file = local_path / "matching.bin"
            local_file.write_bytes(b"matching content")

            sync_client = self._make_sync_client(local_path)
            sync_client._iter_oss_objects = Mock(return_value=[Mock(
                key="symbols/matching.bin",
                size=local_file.stat().st_size,
                etag=f'"{oss_sync_module.hashlib.md5(local_file.read_bytes()).hexdigest()}"',
            )])

            self.assertTrue(sync_client.is_synchronized())

    def test_reports_unsynchronized_when_an_oss_only_file_exists(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            local_path = Path(temp_dir)
            sync_client = self._make_sync_client(local_path)
            sync_client._iter_oss_objects = Mock(return_value=[Mock(
                key="symbols/remote-only.bin",
                size=1,
                etag='"9dd4e461268c8034f5c8564e155c67a6"',
            )])

            self.assertFalse(sync_client.is_synchronized())


class TestOneShotSync(unittest.TestCase):
    def test_parse_args_accepts_once(self):
        args = oss_sync_module.parse_args(["--once"])

        self.assertTrue(args.once)

    def test_main_exits_zero_without_starting_watchers_when_synchronized(self):
        args = Mock(direction="local2oss", once=True)
        with (
            patch.object(oss_sync_module, "setup_logging"),
            patch.object(oss_sync_module, "parse_args", return_value=args),
            patch.object(
                oss_sync_module,
                "load_config_from_environment",
                return_value={},
            ),
            patch.object(oss_sync_module, "OSSSync") as sync_type,
            patch.object(oss_sync_module, "Observer") as observer_type,
        ):
            sync_client = sync_type.return_value
            sync_client.is_synchronized.return_value = True

            exit_code = oss_sync_module.main()

        self.assertEqual(0, exit_code)
        sync_client.initial_sync.assert_called_once_with()
        sync_client.is_synchronized.assert_called_once_with()
        sync_client.start_continuous_sync.assert_not_called()
        observer_type.assert_not_called()

    def test_main_exits_one_when_synchronization_does_not_converge(self):
        args = Mock(direction="local2oss", once=True)
        with (
            patch.object(oss_sync_module, "setup_logging"),
            patch.object(oss_sync_module, "parse_args", return_value=args),
            patch.object(
                oss_sync_module,
                "load_config_from_environment",
                return_value={},
            ),
            patch.object(oss_sync_module, "OSSSync") as sync_type,
            patch.object(oss_sync_module, "Observer") as observer_type,
        ):
            sync_client = sync_type.return_value
            sync_client.is_synchronized.return_value = False

            exit_code = oss_sync_module.main()

        self.assertEqual(1, exit_code)
        sync_client.initial_sync.assert_called_once_with()
        sync_client.is_synchronized.assert_called_once_with()
        sync_client.start_continuous_sync.assert_not_called()
        observer_type.assert_not_called()


class TestOssV2Migration(unittest.TestCase):
    def test_loads_region_and_optional_session_token_from_environment(self):
        environment = {
            "OSS_ACCESS_KEY_ID": "access-key-id",
            "OSS_ACCESS_KEY_SECRET": "access-key-secret",
            "OSS_SESSION_TOKEN": "security-token",
            "KPHTOOLS_SERVER_OSS_REGION": "cn-hangzhou",
            "KPHTOOLS_SERVER_OSS_ENDPOINT": "oss-cn-hangzhou.aliyuncs.com",
            "KPHTOOLS_SERVER_OSS_BUCKET": "test-bucket",
        }

        with patch.dict(oss_sync_module.os.environ, environment, clear=True):
            config = oss_sync_module.load_config_from_environment("local2oss")

        self.assertEqual("cn-hangzhou", config["region"])
        self.assertEqual("security-token", config["security_token"])

    def test_initializes_v2_client_with_region_and_static_credentials(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            sdk_config = Mock()
            credentials_provider = Mock()
            client = Mock()
            config = {
                "access_key_id": "access-key-id",
                "access_key_secret": "access-key-secret",
                "security_token": "security-token",
                "region": "cn-hangzhou",
                "endpoint": "oss-cn-hangzhou.aliyuncs.com",
                "bucket_name": "test-bucket",
                "local_path": temp_dir,
                "oss_path": "symbols",
            }

            with (
                patch.object(
                    oss_sync_module.oss.credentials,
                    "StaticCredentialsProvider",
                    return_value=credentials_provider,
                ) as provider_type,
                patch.object(
                    oss_sync_module.oss.config,
                    "load_default",
                    return_value=sdk_config,
                ),
                patch.object(
                    oss_sync_module.oss,
                    "Client",
                    return_value=client,
                ) as client_type,
            ):
                sync_client = oss_sync_module.OSSSync(config)

        provider_type.assert_called_once_with(
            "access-key-id",
            "access-key-secret",
            "security-token",
        )
        self.assertIs(sdk_config.credentials_provider, credentials_provider)
        self.assertEqual("cn-hangzhou", sdk_config.region)
        self.assertEqual("oss-cn-hangzhou.aliyuncs.com", sdk_config.endpoint)
        client_type.assert_called_once_with(sdk_config)
        self.assertIs(sync_client.client, client)
        self.assertEqual("test-bucket", sync_client.bucket_name)

    def test_real_v2_sdk_initializes_without_network_access(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            sync_client = oss_sync_module.OSSSync(
                {
                    "access_key_id": "access-key-id",
                    "access_key_secret": "access-key-secret",
                    "region": "cn-hangzhou",
                    "endpoint": "oss-cn-hangzhou.aliyuncs.com",
                    "bucket_name": "test-bucket",
                    "local_path": temp_dir,
                    "oss_path": "symbols",
                }
            )

        self.assertIsInstance(sync_client.client, oss_sync_module.oss.Client)

    def test_iterates_v2_pages_and_uses_directory_prefix(self):
        sync_client = oss_sync_module.OSSSync.__new__(oss_sync_module.OSSSync)
        sync_client.config = {"oss_path": "symbols"}
        sync_client.bucket_name = "test-bucket"
        sync_client.client = Mock()
        remote_object = Mock(key="symbols/file.bin")
        paginator = sync_client.client.list_objects_v2_paginator.return_value
        paginator.iter_page.return_value = [
            Mock(contents=[remote_object]),
            Mock(contents=None),
        ]

        self.assertEqual([remote_object], list(sync_client._iter_oss_objects()))

        sync_client.client.list_objects_v2_paginator.assert_called_once_with(limit=100)
        request = paginator.iter_page.call_args.args[0]
        self.assertIsInstance(request, oss_sync_module.oss.ListObjectsV2Request)
        self.assertEqual("test-bucket", request.bucket)
        self.assertEqual("symbols/", request.prefix)

    def test_uses_v2_requests_and_normalizes_object_keys(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            local_path = Path(temp_dir)
            local_file = local_path / "nested" / "file.bin"
            local_file.parent.mkdir()
            local_file.write_bytes(b"content")

            sync_client = oss_sync_module.OSSSync.__new__(oss_sync_module.OSSSync)
            sync_client.config = {
                "local_path": local_path,
                "oss_path": "",
            }
            sync_client.bucket_name = "test-bucket"
            sync_client.client = Mock()
            relative_path = Path("nested") / "file.bin"

            sync_client._upload_file(relative_path)
            upload_request, upload_path = (
                sync_client.client.put_object_from_file.call_args.args
            )
            self.assertIsInstance(upload_request, oss_sync_module.oss.PutObjectRequest)
            self.assertEqual("test-bucket", upload_request.bucket)
            self.assertEqual("nested/file.bin", upload_request.key)
            self.assertEqual("application/octet-stream", upload_request.content_type)
            self.assertEqual(str(local_file), upload_path)

            sync_client._download_file(relative_path)
            download_request, download_path = (
                sync_client.client.get_object_to_file.call_args.args
            )
            self.assertIsInstance(download_request, oss_sync_module.oss.GetObjectRequest)
            self.assertEqual("test-bucket", download_request.bucket)
            self.assertEqual("nested/file.bin", download_request.key)
            self.assertEqual(str(local_file), download_path)

            sync_client._delete_file(relative_path)
            delete_request = sync_client.client.delete_object.call_args.args[0]
            self.assertIsInstance(delete_request, oss_sync_module.oss.DeleteObjectRequest)
            self.assertEqual("test-bucket", delete_request.bucket)
            self.assertEqual("nested/file.bin", delete_request.key)

            destination_path = Path("renamed") / "file.bin"
            sync_client._move_file(relative_path, destination_path)
            copy_request = sync_client.client.copy_object.call_args.args[0]
            self.assertIsInstance(copy_request, oss_sync_module.oss.CopyObjectRequest)
            self.assertEqual("test-bucket", copy_request.bucket)
            self.assertEqual("renamed/file.bin", copy_request.key)
            self.assertEqual("test-bucket", copy_request.source_bucket)
            self.assertEqual("nested/file.bin", copy_request.source_key)

            moved_delete_request = sync_client.client.delete_object.call_args.args[0]
            self.assertEqual("nested/file.bin", moved_delete_request.key)


if __name__ == "__main__":
    unittest.main()
