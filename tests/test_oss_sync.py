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
        self.assertIn("Local scan progress: 1 files hashed", log_output)
        self.assertIn("Local files scanned: 2 files", log_output)


if __name__ == "__main__":
    unittest.main()
