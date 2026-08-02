import argparse
import logging
import mimetypes
import os
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

import alibabacloud_oss_v2 as oss
from dotenv import load_dotenv
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

logger = logging.getLogger("aliyun_oss_sync")
DEFAULT_SYMBOL_DIR = 'symbols'
LOCAL_SCAN_PROGRESS_INTERVAL_SECONDS = 10
LOCAL_EVENT_DEBOUNCE_SECONDS = 1.0
DOWNLOAD_EVENT_SUPPRESSION_SECONDS = 2.0
BYTES_PER_MIB = 1024 * 1024
BYTES_PER_GIB = 1024 * BYTES_PER_MIB


def _get_required_env(name):
    """读取必需的环境变量。"""
    value = os.getenv(name)
    if value is None or not value.strip():
        raise ValueError(f"Missing required environment variable: {name}")
    return value.strip()


def _get_env_list(name, default=''):
    """读取英文逗号分隔的环境变量列表。"""
    return [item.strip() for item in os.getenv(name, default).split(',') if item.strip()]


def load_config_from_environment(direction):
    """从环境变量构造单个同步配置。"""
    check_interval_value = os.getenv('KPHTOOLS_OSS_SYNC_CHECK_INTERVAL', '60')
    try:
        check_interval = int(check_interval_value)
    except ValueError as exc:
        raise ValueError("KPHTOOLS_OSS_SYNC_CHECK_INTERVAL must be an integer") from exc
    if check_interval <= 0:
        raise ValueError("KPHTOOLS_OSS_SYNC_CHECK_INTERVAL must be greater than 0")

    local_path = os.getenv('KPHTOOLS_SYMBOLDIR', DEFAULT_SYMBOL_DIR).strip()
    if not local_path:
        raise ValueError("KPHTOOLS_SYMBOLDIR cannot be empty")

    return {
        'access_key_id': _get_required_env('OSS_ACCESS_KEY_ID'),
        'access_key_secret': _get_required_env('OSS_ACCESS_KEY_SECRET'),
        'security_token': os.getenv('OSS_SESSION_TOKEN', '').strip() or None,
        'region': _get_required_env('KPHTOOLS_SERVER_OSS_REGION'),
        'endpoint': _get_required_env('KPHTOOLS_SERVER_OSS_ENDPOINT'),
        'bucket_name': _get_required_env('KPHTOOLS_SERVER_OSS_BUCKET'),
        'local_path': local_path,
        'oss_path': os.getenv('KPHTOOLS_SERVER_OSS_PREFIX', ''),
        'direction': direction,
        'check_interval': check_interval,
        'exclude': _get_env_list('KPHTOOLS_OSS_SYNC_EXCLUDE', '.git,.stfolder'),
        'exclude_extension': _get_env_list(
            'KPHTOOLS_OSS_SYNC_EXCLUDE_EXTENSION',
            '.txt,.yaml,.pdb,.id0,.id1,.id2,.nam,.til,.i64,.log,.stignore'
        )
    }


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description='OSS Sync Tool')
    parser.add_argument(
        '--direction',
        choices=['local2oss', 'oss2local', 'both'],
        default='local2oss',
        help='Sync direction (default: local2oss)'
    )
    parser.add_argument(
        '--once',
        action='store_true',
        help='Synchronize once, verify local and OSS files match, then exit'
    )
    return parser.parse_args(argv)


def setup_logging():
    """将日志输出到标准输出和标准错误。"""
    logger.setLevel(logging.INFO)

    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.setLevel(logging.INFO)
    stdout_handler.addFilter(lambda record: record.levelno < logging.WARNING)
    stdout_handler.setFormatter(formatter)

    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setLevel(logging.WARNING)
    stderr_handler.setFormatter(formatter)

    logger.addHandler(stdout_handler)
    logger.addHandler(stderr_handler)
    return logger


class OSSSync:
    def __init__(self, config):
        # 处理路径中的日期替换
        current_date = datetime.now().strftime('%Y-%m-%d')
        local_path = config['local_path'].format(current_date=current_date)
        oss_path = config['oss_path'].format(current_date=current_date)
        
        # 初始化配置
        self.config = {
            'local_path': Path(local_path).resolve(),
            'oss_path': oss_path.strip('/'),
            'exclude': set(config.get('exclude', [])),
            'exclude_extension': set(config.get('exclude_extension', [])),
            'sync_direction': config.get('direction', 'local2oss'),
            'check_interval': config.get('check_interval', 60)  # 默认60秒检查一次
        }

        # 确保本地目录存在
        try:
            self.config['local_path'].mkdir(parents=True, exist_ok=True)
            logger.info(f"Created local directory: {self.config['local_path']}")
        except Exception as e:
            logger.error(f"Failed to create local directory: {str(e)}")
            raise

        # OSS 客户端初始化
        credentials_provider = oss.credentials.StaticCredentialsProvider(
            config['access_key_id'],
            config['access_key_secret'],
            config.get('security_token'),
        )
        sdk_config = oss.config.load_default()
        sdk_config.credentials_provider = credentials_provider
        sdk_config.region = config['region']
        sdk_config.endpoint = config['endpoint']
        self.client = oss.Client(sdk_config)
        self.bucket_name = config['bucket_name']
        
        # 用于存储上次检查时的OSS文件状态
        self.last_oss_files = {}
        self.running = True
        self.check_thread = None
        self._download_tracking_lock = threading.Lock()
        self._download_suppression_until = {}

    def _convert_path(self, path):
        """统一路径格式为OSS风格"""
        return str(path).replace('\\', '/')

    def _object_key(self, relative_path):
        """构造规范化的 OSS object key。"""
        relative_path = self._convert_path(relative_path).lstrip('/')
        if self.config['oss_path']:
            return f"{self.config['oss_path']}/{relative_path}"
        return relative_path

    def _object_prefix(self):
        """返回用于列举对象的目录前缀。"""
        if self.config['oss_path']:
            return f"{self.config['oss_path']}/"
        return None

    def _relative_object_path(self, object_key):
        """从 OSS object key 提取同步目录内的相对路径。"""
        object_key = self._convert_path(object_key).lstrip('/')
        prefix = self._object_prefix()
        if prefix:
            if not object_key.startswith(prefix):
                return None
            return object_key[len(prefix):]
        return object_key

    def _iter_oss_objects(self):
        """分页遍历同步前缀下的 OSS 对象。"""
        paginator = self.client.list_objects_v2_paginator(limit=100)
        request = oss.ListObjectsV2Request(
            bucket=self.bucket_name,
            prefix=self._object_prefix(),
        )
        for page in paginator.iter_page(request):
            yield from page.contents or []

    def _get_relative_path(self, full_path):
        """获取相对于本地根目录的相对路径"""
        try:
            return Path(full_path).relative_to(self.config['local_path'])
        except ValueError:
            return None

    def _should_ignore(self, path):
        """检查是否在排除列表中"""
        path_str = self._convert_path(path)
        # 检查路径是否在排除列表中
        if any(path_str.startswith(p) for p in self.config['exclude']):
            return True
        # 检查文件扩展名是否在排除列表中
        if self.config['exclude_extension']:
            file_path = Path(path_str)
            file_ext = file_path.suffix.lower()
            file_name = file_path.name.lower()
            if (
                file_ext in self.config['exclude_extension']
                or file_name in self.config['exclude_extension']
            ):
                return True
        return False

    def _calculate_file_crc64(self, file_path):
        """计算与 OSS x-oss-hash-crc64ecma 兼容的 CRC64。"""
        crc64 = oss.crc.Crc64(0)
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(BYTES_PER_MIB), b''):
                crc64.update(chunk)
        return str(crc64.sum64())

    def _get_oss_file_info(self, rel_path):
        """读取 OSS 对象大小和 CRC64；无法获取时返回 None。"""
        try:
            result = self.client.get_object_meta(
                oss.GetObjectMetaRequest(
                    bucket=self.bucket_name,
                    key=self._object_key(rel_path),
                )
            )
        except Exception as e:
            logger.warning(f"Failed to get OSS metadata: {rel_path} - {str(e)}")
            return None

        crc64 = getattr(result, 'hash_crc64', None)
        if crc64 is None or not str(crc64).strip():
            logger.warning(f"OSS CRC64 is unavailable: {rel_path}")
            crc64 = None
        else:
            crc64 = str(crc64).strip()
        return {
            'size': getattr(result, 'content_length', None),
            'crc64': crc64,
        }

    def _local_file_matches_oss(self, rel_path, oss_size=None, local_crc64=None):
        """按文件大小和 CRC64 判断本地文件是否与 OSS 对象一致。"""
        local_file = self.config['local_path'] / rel_path
        if not local_file.is_file():
            return False

        try:
            local_size = local_file.stat().st_size
            if oss_size is not None and local_size != oss_size:
                return False

            oss_file = self._get_oss_file_info(rel_path)
            if oss_file is None or oss_file['crc64'] is None:
                return False
            if oss_file['size'] is not None and local_size != oss_file['size']:
                return False
            if oss_size is None and oss_file['size'] is None:
                return False

            if local_crc64 is None:
                local_crc64 = self._calculate_file_crc64(local_file)
            return local_crc64 == oss_file['crc64']
        except OSError as e:
            logger.warning(f"Failed to verify local file: {rel_path} - {str(e)}")
            return False

    def _upload_file_if_changed(self, rel_path):
        """仅在本地文件与 OSS 对象不一致时上传。"""
        local_file = self.config['local_path'] / rel_path
        if not local_file.is_file():
            return False
        if self._local_file_matches_oss(rel_path):
            logger.info(
                f"Skipping upload of {rel_path} - remote file CRC64 matches"
            )
            return True
        return self._upload_file(rel_path)

    def _set_download_in_progress(self, rel_path):
        path_key = self._convert_path(rel_path)
        with self._download_tracking_lock:
            self._download_suppression_until[path_key] = None

    def _finish_download(self, rel_path, succeeded):
        path_key = self._convert_path(rel_path)
        with self._download_tracking_lock:
            if succeeded:
                self._download_suppression_until[path_key] = (
                    time.monotonic() + DOWNLOAD_EVENT_SUPPRESSION_SECONDS
                )
            else:
                self._download_suppression_until.pop(path_key, None)

    def is_download_event_suppressed(self, rel_path):
        """判断本地事件是否由正在进行或刚完成的 OSS 下载产生。"""
        path_key = self._convert_path(rel_path)
        current_time = time.monotonic()
        with self._download_tracking_lock:
            suppression_until = self._download_suppression_until.get(path_key)
            if suppression_until is None:
                return path_key in self._download_suppression_until
            if current_time <= suppression_until:
                return True
            self._download_suppression_until.pop(path_key, None)
            return False

    def initial_sync(self):
        """初始同步：对比并同步差异"""
        logger.info("Starting initial synchronization...")
        
        # 扫描本地文件
        local_files = {}
        local_scan_started_at = time.monotonic()
        last_progress_logged_at = local_scan_started_at
        scanned_file_count = 0
        scanned_bytes = 0
        for root, _, files in os.walk(self.config['local_path']):
            for file in files:
                full_path = Path(root) / file

                rel_path = self._get_relative_path(full_path)
                if not rel_path or self._should_ignore(rel_path):
                    continue

                file_stat = full_path.stat()
                local_files[self._convert_path(rel_path)] = {
                    'size': file_stat.st_size,
                }

                scanned_file_count += 1
                scanned_bytes += file_stat.st_size
                current_time = time.monotonic()
                if (
                    current_time - last_progress_logged_at
                    >= LOCAL_SCAN_PROGRESS_INTERVAL_SECONDS
                ):
                    elapsed_seconds = current_time - local_scan_started_at
                    logger.info(
                        "Local scan progress: %d files scanned, %.2f GiB discovered "
                        "in %.1f seconds (%.1f files/s)",
                        scanned_file_count,
                        scanned_bytes / BYTES_PER_GIB,
                        elapsed_seconds,
                        scanned_file_count / elapsed_seconds,
                    )
                    last_progress_logged_at = current_time

        local_scan_elapsed_seconds = time.monotonic() - local_scan_started_at
        logger.info(
            "Local files scanned: %d files, %.2f GiB discovered in %.1f seconds",
            scanned_file_count,
            scanned_bytes / BYTES_PER_GIB,
            local_scan_elapsed_seconds,
        )

        # 扫描OSS文件
        oss_files = {}
        for obj in self._iter_oss_objects():
            logger.info(f"OSS object key: {obj.key}")
            logger.info(f"OSS path: {self.config['oss_path']}")
            rel_path = self._relative_object_path(obj.key)
            logger.info(f"Calculated relative path: {rel_path}")
            if not rel_path or self._should_ignore(rel_path):
                continue
            
            oss_files[rel_path] = {
                'size': obj.size,
            }

        logger.info("OSS files scanned...")

        last_hash_progress_logged_at = None
        hashed_file_count = 0
        hashed_bytes = 0
        hashing_elapsed_seconds = 0.0

        def get_local_crc64(rel_path):
            """按需计算并缓存本地文件 CRC64。"""
            nonlocal last_hash_progress_logged_at
            nonlocal hashed_file_count
            nonlocal hashed_bytes
            nonlocal hashing_elapsed_seconds

            local_file = local_files[rel_path]
            if 'crc64' in local_file:
                return local_file['crc64']

            hash_started_at = time.monotonic()
            if last_hash_progress_logged_at is None:
                last_hash_progress_logged_at = hash_started_at
            local_file['crc64'] = self._calculate_file_crc64(
                self.config['local_path'] / rel_path
            )
            hash_completed_at = time.monotonic()
            hashed_file_count += 1
            hashed_bytes += local_file['size']
            hashing_elapsed_seconds += hash_completed_at - hash_started_at

            if (
                hash_completed_at - last_hash_progress_logged_at
                >= LOCAL_SCAN_PROGRESS_INTERVAL_SECONDS
            ):
                hashing_seconds_for_rate = max(
                    hashing_elapsed_seconds,
                    sys.float_info.epsilon,
                )
                logger.info(
                    "Local checksum progress: %d files hashed, %.2f GiB processed "
                    "in %.1f hashing seconds (%.2f MiB/s)",
                    hashed_file_count,
                    hashed_bytes / BYTES_PER_GIB,
                    hashing_elapsed_seconds,
                    hashed_bytes / BYTES_PER_MIB / hashing_seconds_for_rate,
                )
                last_hash_progress_logged_at = hash_completed_at

            return local_file['crc64']

        local_paths = set(local_files)
        oss_paths = set(oss_files)
        common_paths = local_paths & oss_paths
        match_cache = {}

        def local_matches_oss(rel_path):
            if rel_path not in match_cache:
                local_file = local_files[rel_path]
                oss_file = oss_files[rel_path]
                if local_file['size'] != oss_file['size']:
                    match_cache[rel_path] = False
                else:
                    match_cache[rel_path] = self._local_file_matches_oss(
                        rel_path,
                        oss_file['size'],
                        get_local_crc64(rel_path),
                    )
            return match_cache[rel_path]

        # 同步策略
        if self.config['sync_direction'] in ['local2oss', 'both']:
            # 上传本地新增/修改文件
            for rel_path in local_paths - oss_paths:
                self._upload_file(rel_path)
            
            # 对比相同文件
            for rel_path in common_paths:
                if local_matches_oss(rel_path):
                    logger.info(
                        f"Skipping upload of {rel_path} - remote file CRC64 matches"
                    )
                    continue
                if self._upload_file(rel_path):
                    match_cache[rel_path] = True

        if self.config['sync_direction'] in ['oss2local', 'both']:
            # 下载OSS新增/修改文件
            for rel_path in oss_paths - local_paths:
                self._download_file(rel_path)
            
            # 对比相同文件
            for rel_path in common_paths:
                if not local_matches_oss(rel_path):
                    self._download_file(rel_path)
                else:
                    logger.info(
                        f"Skipping download of {rel_path} - local file CRC64 matches"
                    )

        if hashed_file_count:
            logger.info(
                "Local checksum completed: %d files, %.2f GiB processed in %.1f seconds",
                hashed_file_count,
                hashed_bytes / BYTES_PER_GIB,
                hashing_elapsed_seconds,
            )

        logger.info("Initial synchronization completed")

    def is_synchronized(self):
        """检查未排除的本地文件和 OSS 对象是否完全一致。"""
        local_files = {}
        for root, _, files in os.walk(self.config['local_path']):
            for file in files:
                full_path = Path(root) / file
                rel_path = self._get_relative_path(full_path)
                if not rel_path or self._should_ignore(rel_path):
                    continue
                local_files[self._convert_path(rel_path)] = full_path

        oss_files = {}
        for obj in self._iter_oss_objects():
            rel_path = self._relative_object_path(obj.key)
            if not rel_path or self._should_ignore(rel_path):
                continue
            oss_files[rel_path] = {
                'size': obj.size,
            }

        local_paths = set(local_files)
        oss_paths = set(oss_files)
        missing_on_oss = local_paths - oss_paths
        missing_locally = oss_paths - local_paths
        if missing_on_oss or missing_locally:
            logger.error(
                "Synchronization verification failed: %d local-only and %d OSS-only files",
                len(missing_on_oss),
                len(missing_locally),
            )
            return False

        for rel_path in local_paths:
            local_file = local_files[rel_path]
            oss_file = oss_files[rel_path]
            if local_file.stat().st_size != oss_file['size']:
                logger.error(
                    "Synchronization verification failed: size differs for %s",
                    rel_path,
                )
                return False
            if not self._local_file_matches_oss(rel_path, oss_file['size']):
                logger.error(
                    "Synchronization verification failed: content differs for %s",
                    rel_path,
                )
                return False

        logger.info("Synchronization verification completed: local and OSS files match")
        return True

    def _upload_file(self, rel_path):
        """上传文件到OSS"""
        local_full = self.config['local_path'] / rel_path
        oss_key = self._object_key(rel_path)
        content_type = mimetypes.guess_type(str(local_full))[0]
        
        try:
            self.client.put_object_from_file(
                oss.PutObjectRequest(
                    bucket=self.bucket_name,
                    key=oss_key,
                    content_type=content_type,
                ),
                str(local_full),
            )
            logger.info(f"Uploaded: {rel_path}")
            return True
        except Exception as e:
            logger.error(f"Upload failed: {rel_path} - {str(e)}")
            return False

    def _download_file(self, rel_path):
        """从OSS下载文件"""
        oss_key = self._object_key(rel_path)
        local_full = self.config['local_path'] / rel_path
        succeeded = False
        self._set_download_in_progress(rel_path)

        try:
            local_full.parent.mkdir(parents=True, exist_ok=True)
            self.client.get_object_to_file(
                oss.GetObjectRequest(
                    bucket=self.bucket_name,
                    key=oss_key,
                ),
                str(local_full),
            )
            logger.info(f"Downloaded: {rel_path}")
            succeeded = True
            return True
        except Exception as e:
            logger.error(f"Download failed: {rel_path} - {str(e)}")
            return False
        finally:
            self._finish_download(rel_path, succeeded)

    def _delete_file(self, rel_path):
        """删除 OSS 上的文件。"""
        try:
            self.client.delete_object(
                oss.DeleteObjectRequest(
                    bucket=self.bucket_name,
                    key=self._object_key(rel_path),
                )
            )
            logger.info(f"Deleted on OSS: {rel_path}")
        except Exception as e:
            logger.error(f"Delete failed: {rel_path} - {str(e)}")

    def _move_file(self, src_rel_path, dst_rel_path):
        """通过复制并删除源对象在 OSS 上移动文件。"""
        src_oss_key = self._object_key(src_rel_path)
        dst_oss_key = self._object_key(dst_rel_path)
        try:
            self.client.copy_object(
                oss.CopyObjectRequest(
                    bucket=self.bucket_name,
                    key=dst_oss_key,
                    source_bucket=self.bucket_name,
                    source_key=src_oss_key,
                )
            )
            self.client.delete_object(
                oss.DeleteObjectRequest(
                    bucket=self.bucket_name,
                    key=src_oss_key,
                )
            )
            logger.info(f"Moved on OSS: {src_rel_path} -> {dst_rel_path}")
        except Exception as e:
            logger.error(f"Move failed: {src_rel_path} -> {dst_rel_path} - {str(e)}")

    def start_continuous_sync(self):
        """启动持续同步线程"""
        if self.config['sync_direction'] in ['oss2local', 'both']:
            self.check_thread = threading.Thread(target=self._continuous_sync_loop)
            self.check_thread.daemon = True
            self.check_thread.start()
            logger.info("Started continuous sync thread")

    def stop_continuous_sync(self):
        """停止持续同步"""
        self.running = False
        if self.check_thread:
            self.check_thread.join()
            logger.info("Stopped continuous sync thread")

    def _continuous_sync_loop(self):
        """持续同步循环"""
        while self.running:
            try:
                self._check_oss_changes()
            except Exception as e:
                logger.error(f"Error in continuous sync loop: {str(e)}")
            time.sleep(self.config['check_interval'])

    def _check_oss_changes(self):
        """检查OSS文件变化"""
        current_oss_files = {}
        
        for obj in self._iter_oss_objects():
            rel_path = self._relative_object_path(obj.key)
            
            if not rel_path or self._should_ignore(rel_path):
                continue
            
            current_oss_files[rel_path] = {
                'mtime': obj.last_modified.timestamp(),
                'size': obj.size,
                'etag': obj.etag.strip('"'),
            }

        # 检查新增或修改的文件
        for rel_path in set(current_oss_files) - set(self.last_oss_files):
            if self._local_file_matches_oss(
                rel_path,
                current_oss_files[rel_path]['size'],
            ):
                logger.info(
                    f"Skipping download of {rel_path} - local file CRC64 matches"
                )
                continue
            self._download_file(rel_path)
        
        # 检查修改的文件
        for rel_path in set(current_oss_files) & set(self.last_oss_files):
            remote_changed = (
                current_oss_files[rel_path]['etag']
                != self.last_oss_files[rel_path]['etag']
                or current_oss_files[rel_path]['mtime']
                > self.last_oss_files[rel_path]['mtime']
            )
            if remote_changed:
                if self._local_file_matches_oss(
                    rel_path,
                    current_oss_files[rel_path]['size'],
                ):
                    logger.info(
                        f"Skipping download of {rel_path} - local file CRC64 matches"
                    )
                    continue
                self._download_file(rel_path)

        self.last_oss_files = current_oss_files

class SyncEventHandler(FileSystemEventHandler):
    """文件系统事件处理器"""
    def __init__(self, sync_client):
        self.sync_client = sync_client
        self._pending_uploads = {}
        self._pending_upload_lock = threading.Lock()
        self._upload_execution_lock = threading.Lock()
        self._next_upload_generation = 0
        self._closed = False

    def _cancel_pending_upload(self, rel_path):
        path_key = self.sync_client._convert_path(rel_path)
        with self._pending_upload_lock:
            pending_upload = self._pending_uploads.pop(path_key, None)
        if pending_upload:
            pending_upload[1].cancel()

    def _schedule_upload(self, rel_path):
        """按相对路径合并事件，并在文件稳定后校验上传。"""
        path_key = self.sync_client._convert_path(rel_path)
        with self._pending_upload_lock:
            if self._closed:
                return
            previous_upload = self._pending_uploads.get(path_key)
            if previous_upload:
                previous_upload[1].cancel()

            self._next_upload_generation += 1
            generation = self._next_upload_generation
            timer = threading.Timer(
                LOCAL_EVENT_DEBOUNCE_SECONDS,
                self._process_pending_upload,
                args=(path_key, generation),
            )
            timer.daemon = True
            self._pending_uploads[path_key] = (generation, timer)
        timer.start()

    def _process_pending_upload(self, path_key, generation):
        with self._pending_upload_lock:
            pending_upload = self._pending_uploads.get(path_key)
            if (
                self._closed
                or pending_upload is None
                or pending_upload[0] != generation
            ):
                return
            self._pending_uploads.pop(path_key, None)
        with self._upload_execution_lock:
            with self._pending_upload_lock:
                newer_upload = self._pending_uploads.get(path_key)
                if (
                    self._closed
                    or (
                        newer_upload is not None
                        and newer_upload[0] > generation
                    )
                ):
                    return
            self.sync_client._upload_file_if_changed(path_key)

    def close(self):
        """取消尚未触发的上传任务。"""
        with self._pending_upload_lock:
            self._closed = True
            timers = [item[1] for item in self._pending_uploads.values()]
            self._pending_uploads.clear()
        for timer in timers:
            timer.cancel()
        # 等待已经开始的上传校验结束后再完成关闭。
        with self._upload_execution_lock:
            pass

    def _process_event(self, event):
        """处理文件系统事件。"""
        with self._pending_upload_lock:
            if self._closed:
                return
        if event.is_directory:
            return
            
        src_path = Path(event.src_path)
        rel_path = self.sync_client._get_relative_path(src_path)
        
        if not rel_path or self.sync_client._should_ignore(rel_path):
            return
        
        # 处理不同事件类型
        if event.event_type in ['created', 'modified']:
            if self.sync_client.config['sync_direction'] in ['local2oss', 'both']:
                if self.sync_client.is_download_event_suppressed(rel_path):
                    logger.info(
                        f"Ignoring local event from OSS download: {rel_path}"
                    )
                    return
                self._schedule_upload(rel_path)
        
        elif event.event_type == 'deleted':
            self._cancel_pending_upload(rel_path)
            if self.sync_client.config['sync_direction'] in ['local2oss', 'both']:
                self.sync_client._delete_file(rel_path)
        
        elif event.event_type == 'moved':
            self._cancel_pending_upload(rel_path)
            dst_path = Path(event.dest_path)
            dst_rel_path = self.sync_client._get_relative_path(dst_path)
            if not dst_rel_path or self.sync_client._should_ignore(dst_rel_path):
                return
            if self.sync_client.config['sync_direction'] in ['local2oss', 'both']:
                self.sync_client._move_file(rel_path, dst_rel_path)
        else:
            logger.info(f"Unknown event type: {event.event_type}")

    def on_any_event(self, event):
        self._process_event(event)


def main():
    load_dotenv(dotenv_path=Path(__file__).resolve().with_name('.env'), override=False)
    setup_logging()
    args = parse_args()
    observer_list = []
    event_handler_list = []
    sync_clients = []

    try:
        config = load_config_from_environment(args.direction)
        sync_client = OSSSync(config)
        sync_clients.append(sync_client)

        # 执行初始同步
        sync_client.initial_sync()

        if args.once:
            if sync_client.is_synchronized():
                return 0
            logger.error("One-shot synchronization did not converge")
            return 1

        # 启动文件监控
        event_handler = SyncEventHandler(sync_client)
        event_handler_list.append(event_handler)
        observer = Observer()
        observer.schedule(
            event_handler,
            path=str(sync_client.config['local_path']),
            recursive=True
        )
        observer.start()
        observer_list.append(observer)

        # 启动持续同步
        sync_client.start_continuous_sync()

        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    except Exception:
        logger.exception("Error:")
        return 1
    finally:
        for event_handler in event_handler_list:
            event_handler.close()
        for observer in observer_list:
            observer.stop()
        for sync_client in sync_clients:
            sync_client.stop_continuous_sync()
        for observer in observer_list:
            observer.join()

    return 0


if __name__ == '__main__':
    sys.exit(main())
