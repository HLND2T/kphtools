import hashlib
import os
import tempfile
import unittest
from io import BytesIO, StringIO
from types import SimpleNamespace
from unittest.mock import Mock, patch

import alibabacloud_oss_v2 as real_oss
import upload_server


class FakeServiceError(Exception):
    def __init__(self, status_code, code, request_id="request-id"):
        super().__init__(code)
        self.status_code = status_code
        self.code = code
        self.request_id = request_id


class FakeRequest:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


class FakeCredentialsProvider:
    pass


class FakeConfig:
    def __init__(self):
        self.credentials_provider = None
        self.region = None
        self.endpoint = None


class FakeClient:
    def __init__(self, config):
        self.config = config


class FakeOssModule:
    HeadObjectRequest = FakeRequest
    PutObjectRequest = FakeRequest
    Client = FakeClient
    exceptions = SimpleNamespace(ServiceError=FakeServiceError)
    credentials = SimpleNamespace(
        EnvironmentVariableCredentialsProvider=FakeCredentialsProvider
    )
    config = SimpleNamespace(load_default=FakeConfig)


class RecordingStorage:
    def __init__(self, exists=False, file_size=None):
        self.exists = exists
        self.file_size = file_size
        self.saved = []

    def stat_file(self, relative_path):
        self.stat_path = relative_path
        return self.exists, self.file_size

    def save_file(self, relative_path, file_data, file_hash):
        self.saved.append((relative_path, file_data, file_hash))
        return True, "File uploaded successfully", 200


class TestStorageConfiguration(unittest.TestCase):
    def test_storage_mode_defaults_to_disk_and_is_case_insensitive(self):
        self.assertEqual("disk", upload_server.get_storage_mode({}))
        self.assertEqual(
            "oss",
            upload_server.get_storage_mode({"KPHTOOLS_SERVER_STORAGE": " OSS "}),
        )

    def test_storage_mode_rejects_unknown_value(self):
        with self.assertRaisesRegex(ValueError, "KPHTOOLS_SERVER_STORAGE"):
            upload_server.get_storage_mode({"KPHTOOLS_SERVER_STORAGE": "mirror"})

    def test_disk_storage_requires_symbol_directory(self):
        with self.assertRaisesRegex(ValueError, "symboldir"):
            upload_server.create_storage_backend("disk", symboldir=None)

    def test_oss_storage_requires_all_configuration(self):
        with self.assertRaisesRegex(ValueError, "KPHTOOLS_SERVER_OSS_REGION"):
            upload_server.create_storage_backend(
                "oss",
                environ={},
                oss_module=FakeOssModule,
            )

    def test_oss_storage_requires_standard_sdk_credentials(self):
        environ = {
            "KPHTOOLS_SERVER_OSS_REGION": "cn-hangzhou",
            "KPHTOOLS_SERVER_OSS_BUCKET": "kernel-symbols",
        }

        with self.assertRaisesRegex(ValueError, "OSS_ACCESS_KEY_ID"):
            upload_server.create_storage_backend(
                "oss",
                environ=environ,
                oss_module=FakeOssModule,
            )

    def test_oss_storage_uses_environment_configuration(self):
        environ = {
            "KPHTOOLS_SERVER_OSS_REGION": "cn-hangzhou",
            "KPHTOOLS_SERVER_OSS_BUCKET": "kernel-symbols",
            "KPHTOOLS_SERVER_OSS_ENDPOINT": "oss-cn-hangzhou-internal.aliyuncs.com",
            "KPHTOOLS_SERVER_OSS_PREFIX": "/symbols/uploads/",
            "OSS_ACCESS_KEY_ID": "access-key-id",
            "OSS_ACCESS_KEY_SECRET": "access-key-secret",
        }

        storage = upload_server.create_storage_backend(
            "oss",
            environ=environ,
            oss_module=FakeOssModule,
        )

        self.assertIsInstance(storage, upload_server.OssStorage)
        self.assertEqual("kernel-symbols", storage.bucket)
        self.assertEqual("symbols/uploads", storage.prefix)
        self.assertEqual("cn-hangzhou", storage.client.config.region)
        self.assertEqual(
            "oss-cn-hangzhou-internal.aliyuncs.com",
            storage.client.config.endpoint,
        )
        self.assertIsInstance(
            storage.client.config.credentials_provider,
            FakeCredentialsProvider,
        )

    def test_oss_storage_does_not_create_local_symbol_directory(self):
        environ = {
            "KPHTOOLS_SERVER_OSS_REGION": "cn-hangzhou",
            "KPHTOOLS_SERVER_OSS_BUCKET": "kernel-symbols",
            "OSS_ACCESS_KEY_ID": "access-key-id",
            "OSS_ACCESS_KEY_SECRET": "access-key-secret",
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            symbol_dir = os.path.join(temp_dir, "symbols")
            upload_server.create_storage_backend(
                "oss",
                symboldir=symbol_dir,
                environ=environ,
                oss_module=FakeOssModule,
            )

            self.assertFalse(os.path.exists(symbol_dir))

    def test_real_oss_sdk_can_initialize_without_network_access(self):
        environ = {
            "KPHTOOLS_SERVER_OSS_REGION": "cn-hangzhou",
            "KPHTOOLS_SERVER_OSS_BUCKET": "kernel-symbols",
            "OSS_ACCESS_KEY_ID": "access-key-id",
            "OSS_ACCESS_KEY_SECRET": "access-key-secret",
        }

        with patch.dict(os.environ, environ, clear=True):
            storage = upload_server.create_storage_backend("oss")

        self.assertIsInstance(storage, upload_server.OssStorage)
        self.assertEqual("kernel-symbols", storage.bucket)


class TestDiskStorage(unittest.TestCase):
    def test_build_symbol_path_uses_forward_slashes(self):
        path = upload_server.build_symbol_path(
            "amd64",
            "ntoskrnl.exe",
            "10.0.26100.1",
            "a" * 64,
        )

        self.assertEqual(
            f"amd64/ntoskrnl.exe.10.0.26100.1/{'a' * 64}/ntoskrnl.exe",
            path,
        )

    def test_save_stat_and_duplicate_behavior(self):
        file_data = b"kernel-data"
        file_hash = hashlib.sha256(file_data).hexdigest()
        relative_path = upload_server.build_symbol_path(
            "amd64",
            "ntoskrnl.exe",
            "10.0.26100.1",
            file_hash,
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            storage = upload_server.DiskStorage(temp_dir)

            result = storage.save_file(relative_path, file_data, file_hash)
            exists, file_size = storage.stat_file(relative_path)
            duplicate = storage.save_file(relative_path, file_data, file_hash)
            conflict = storage.save_file(
                relative_path,
                b"different-data",
                hashlib.sha256(b"different-data").hexdigest(),
            )

        self.assertEqual((True, "File uploaded successfully", 200), result)
        self.assertTrue(exists)
        self.assertEqual(len(file_data), file_size)
        self.assertEqual(
            (True, "File already exists and is identical", 200),
            duplicate,
        )
        self.assertEqual(
            (False, "File already exists with different content", 409),
            conflict,
        )


class TestOssStorage(unittest.TestCase):
    def setUp(self):
        self.client = Mock()
        self.storage = upload_server.OssStorage(
            self.client,
            FakeOssModule,
            "kernel-symbols",
            "/symbols/",
        )
        self.relative_path = (
            f"amd64/ntoskrnl.exe.10.0.26100.1/{'a' * 64}/ntoskrnl.exe"
        )

    def test_stat_returns_content_length(self):
        self.client.head_object.return_value = SimpleNamespace(content_length=1234)

        result = self.storage.stat_file(self.relative_path)

        self.assertEqual((True, 1234), result)
        request = self.client.head_object.call_args.args[0]
        self.assertEqual("kernel-symbols", request.bucket)
        self.assertEqual(f"symbols/{self.relative_path}", request.key)

    def test_stat_treats_only_no_such_key_as_missing(self):
        self.client.head_object.side_effect = real_oss.exceptions.OperationError(
            name="head_object",
            error=FakeServiceError(404, "NoSuchKey")
        )

        self.assertEqual((False, None), self.storage.stat_file(self.relative_path))

    def test_stat_maps_other_errors_to_storage_error(self):
        self.client.head_object.side_effect = FakeServiceError(404, "NoSuchBucket")

        with patch("sys.stderr", new_callable=StringIO):
            with self.assertRaisesRegex(
                upload_server.StorageError,
                "OSS storage operation failed",
            ):
                self.storage.stat_file(self.relative_path)

    def test_stat_maps_network_errors_to_storage_error(self):
        self.client.head_object.side_effect = TimeoutError("network timeout")

        with patch("sys.stderr", new_callable=StringIO):
            with self.assertRaisesRegex(
                upload_server.StorageError,
                "OSS storage operation failed",
            ):
                self.storage.stat_file(self.relative_path)

    def test_uploads_bytes_without_overwriting(self):
        file_data = b"kernel-data"
        file_hash = hashlib.sha256(file_data).hexdigest()
        self.client.head_object.side_effect = FakeServiceError(404, "NoSuchKey")

        result = self.storage.save_file(self.relative_path, file_data, file_hash)

        self.assertEqual((True, "File uploaded successfully", 200), result)
        request = self.client.put_object.call_args.args[0]
        self.assertEqual("kernel-symbols", request.bucket)
        self.assertEqual(f"symbols/{self.relative_path}", request.key)
        self.assertEqual(file_data, request.body.read())
        self.assertEqual("application/octet-stream", request.content_type)
        self.assertTrue(request.forbid_overwrite)

    def test_existing_object_is_idempotent_success(self):
        self.client.head_object.return_value = SimpleNamespace(
            content_length=len(b"kernel-data")
        )

        result = self.storage.save_file(
            self.relative_path,
            b"kernel-data",
            "a" * 64,
        )

        self.assertEqual(
            (True, "File already exists and is identical", 200),
            result,
        )
        self.client.put_object.assert_not_called()

    def test_concurrent_conflict_is_idempotent_success(self):
        self.client.head_object.side_effect = real_oss.exceptions.OperationError(
            name="head_object",
            error=FakeServiceError(404, "NoSuchKey")
        )
        self.client.put_object.side_effect = real_oss.exceptions.OperationError(
            name="put_object",
            error=FakeServiceError(409, "FileAlreadyExists")
        )

        result = self.storage.save_file(
            self.relative_path,
            b"kernel-data",
            "a" * 64,
        )

        self.assertEqual(
            (True, "File already exists and is identical", 200),
            result,
        )

    def test_upload_maps_non_conflict_errors_to_storage_error(self):
        self.client.head_object.side_effect = FakeServiceError(404, "NoSuchKey")
        self.client.put_object.side_effect = FakeServiceError(403, "AccessDenied")

        with patch("sys.stderr", new_callable=StringIO):
            with self.assertRaisesRegex(
                upload_server.StorageError,
                "OSS storage operation failed",
            ):
                self.storage.save_file(
                    self.relative_path,
                    b"kernel-data",
                    "a" * 64,
                )


class TestUploadHandlerStorageIntegration(unittest.TestCase):
    def test_exists_uses_injected_storage_and_preserves_response_path(self):
        storage = RecordingStorage(exists=True, file_size=1234)
        handler = object.__new__(upload_server.UploadHandler)
        handler.storage = storage
        handler.path = (
            "/exists?filename=ntoskrnl.exe&arch=amd64&fileversion=10.0.26100.1"
            f"&sha256={'a' * 64}"
        )
        handler.send_json_response = Mock()

        handler.do_GET()

        expected_path = (
            f"amd64/ntoskrnl.exe.10.0.26100.1/{'a' * 64}/ntoskrnl.exe"
        )
        self.assertEqual(expected_path, storage.stat_path)
        handler.send_json_response.assert_called_once_with(
            200,
            "File existence checked",
            {
                "filename": "ntoskrnl.exe",
                "arch": "amd64",
                "fileversion": "10.0.26100.1",
                "sha256": "a" * 64,
                "exists": True,
                "path": expected_path,
                "file_size": 1234,
            },
        )

    def test_exists_maps_storage_error_to_bad_gateway(self):
        storage = Mock()
        storage.stat_file.side_effect = upload_server.StorageError(
            "OSS storage operation failed"
        )
        handler = object.__new__(upload_server.UploadHandler)
        handler.storage = storage
        handler.path = (
            "/exists?filename=ntoskrnl.exe&arch=amd64&fileversion=10.0.26100.1"
            f"&sha256={'a' * 64}"
        )
        handler.send_json_response = Mock()

        handler.do_GET()

        handler.send_json_response.assert_called_once_with(
            502,
            "OSS storage operation failed",
        )

    def test_upload_uses_injected_storage(self):
        file_data = b"kernel-data"
        file_hash = hashlib.sha256(file_data).hexdigest()
        storage = RecordingStorage()
        handler = object.__new__(upload_server.UploadHandler)
        handler.storage = storage
        handler.path = "/upload"
        handler.headers = {
            "Content-Length": str(len(file_data)),
            "Content-Type": "application/octet-stream",
        }
        handler.rfile = BytesIO(file_data)
        handler.send_json_response = Mock()

        with patch(
            "upload_server.verify_pe_file",
            return_value={
                "file_name": "ntoskrnl.exe",
                "file_version": "10.0.26100.1",
                "arch": "amd64",
            },
        ), patch("upload_server.verify_signature", return_value=True):
            handler.do_POST()

        self.assertEqual(1, len(storage.saved))
        relative_path, saved_data, saved_hash = storage.saved[0]
        self.assertEqual(file_data, saved_data)
        self.assertEqual(file_hash, saved_hash)
        self.assertEqual(
            f"amd64/ntoskrnl.exe.10.0.26100.1/{file_hash}/ntoskrnl.exe",
            relative_path,
        )
        handler.send_json_response.assert_called_once_with(
            200,
            "File uploaded successfully",
            {
                "file_name": "ntoskrnl.exe",
                "file_version": "10.0.26100.1",
                "arch": "amd64",
                "sha256": file_hash,
            },
        )


if __name__ == "__main__":
    unittest.main()
