import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from oss_sync import oss_sync as oss_sync_module


class TestInitialSyncProgress(unittest.TestCase):
    def test_logs_local_scan_progress_and_summary(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            local_path = Path(temp_dir)
            (local_path / "first.bin").write_bytes(b"first")
            (local_path / "second.bin").write_bytes(b"second")

            sync_client = oss_sync_module.OSSSync.__new__(oss_sync_module.OSSSync)
            sync_client.config = {
                "local_path": local_path,
                "oss_path": "symbols",
                "exclude": set(),
                "exclude_extension": set(),
                "sync_direction": "local2oss",
            }
            sync_client.bucket = Mock()
            sync_client.os_adapt_sep = "\\"
            sync_client._upload_file = Mock()

            with (
                patch.object(
                    oss_sync_module.time,
                    "monotonic",
                    side_effect=[100.0, 111.0, 112.0, 113.0],
                ),
                patch.object(oss_sync_module.oss2, "ObjectIterator", return_value=[]),
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

            sync_client = oss_sync_module.OSSSync.__new__(oss_sync_module.OSSSync)
            sync_client.config = {
                "local_path": local_path,
                "oss_path": "symbols",
                "exclude": set(),
                "exclude_extension": set(),
                "sync_direction": "local2oss",
            }
            sync_client.bucket = Mock()
            sync_client.os_adapt_sep = "\\"
            sync_client._calculate_file_hash = Mock()
            sync_client._upload_file = Mock()

            with patch.object(oss_sync_module.oss2, "ObjectIterator", return_value=[]):
                sync_client.initial_sync()

        sync_client._calculate_file_hash.assert_not_called()
        sync_client._upload_file.assert_called_once_with("new.bin")

    def test_hashes_common_key_when_metadata_cannot_determine_change(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            local_path = Path(temp_dir)
            local_file = local_path / "existing.bin"
            local_file.write_bytes(b"local content")
            local_stat = local_file.stat()

            sync_client = oss_sync_module.OSSSync.__new__(oss_sync_module.OSSSync)
            sync_client.config = {
                "local_path": local_path,
                "oss_path": "symbols",
                "exclude": set(),
                "exclude_extension": set(),
                "sync_direction": "local2oss",
            }
            sync_client.bucket = Mock()
            sync_client.os_adapt_sep = "\\"
            sync_client._calculate_file_hash = Mock(return_value="local-hash")
            sync_client._upload_file = Mock()
            remote_object = Mock(
                key="symbols/existing.bin",
                last_modified=local_stat.st_mtime + 1,
                size=local_stat.st_size,
                etag='"remote-hash"',
            )

            with patch.object(
                oss_sync_module.oss2,
                "ObjectIterator",
                return_value=[remote_object],
            ):
                sync_client.initial_sync()

        sync_client._calculate_file_hash.assert_called_once_with(local_file)
        sync_client._upload_file.assert_called_once_with("existing.bin")

    def test_skips_hash_when_common_key_size_differs(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            local_path = Path(temp_dir)
            local_file = local_path / "changed.bin"
            local_file.write_bytes(b"local content")
            local_stat = local_file.stat()

            sync_client = oss_sync_module.OSSSync.__new__(oss_sync_module.OSSSync)
            sync_client.config = {
                "local_path": local_path,
                "oss_path": "symbols",
                "exclude": set(),
                "exclude_extension": set(),
                "sync_direction": "local2oss",
            }
            sync_client.bucket = Mock()
            sync_client.os_adapt_sep = "\\"
            sync_client._calculate_file_hash = Mock()
            sync_client._upload_file = Mock()
            remote_object = Mock(
                key="symbols/changed.bin",
                last_modified=local_stat.st_mtime + 1,
                size=local_stat.st_size + 1,
                etag='"remote-hash"',
            )

            with patch.object(
                oss_sync_module.oss2,
                "ObjectIterator",
                return_value=[remote_object],
            ):
                sync_client.initial_sync()

        sync_client._calculate_file_hash.assert_not_called()
        sync_client._upload_file.assert_called_once_with("changed.bin")


if __name__ == "__main__":
    unittest.main()
