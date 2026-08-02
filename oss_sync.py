import argparse
import hashlib
import logging
import mimetypes
import os
import sys
import threading
import time
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path

import alibabacloud_oss_v2 as oss
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

logger = logging.getLogger("aliyun_oss_sync")
DEFAULT_SYMBOL_DIR = 'symbols'
LOCAL_SCAN_PROGRESS_INTERVAL_SECONDS = 10
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
        'exclude': _get_env_list('KPHTOOLS_OSS_SYNC_EXCLUDE', '.git/,.stfolder'),
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
    # 设置日志文件名
    log_file = "aliyun_oss_sync.log"
    
    # 创建一个logger
    logger.setLevel(logging.INFO)  # 设置日志级别

    # 创建一个RotatingFileHandler
    # maxBytes=10*1024*1024 表示每个日志文件的最大大小为10MB
    # backupCount=5 表示保留5个备份文件
    handler = RotatingFileHandler(log_file, maxBytes=10*1024*1024, backupCount=5)
    
    # 设置日志格式
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    
    # 将handler添加到logger中
    logger.addHandler(handler)
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
            file_ext = Path(path_str).suffix.lower()
            if file_ext in self.config['exclude_extension']:
                return True
        return False

    def _calculate_file_hash(self, file_path):
        """计算文件哈希值(MD5)"""
        md5 = hashlib.md5()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                md5.update(chunk)
        return md5.hexdigest()

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
                    'mtime': file_stat.st_mtime,
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
                'mtime': obj.last_modified.timestamp(),
                'size': obj.size,
                'hash': obj.etag.strip('"'),
            }

        logger.info("OSS files scanned...")

        last_hash_progress_logged_at = None
        hashed_file_count = 0
        hashed_bytes = 0
        hashing_elapsed_seconds = 0.0

        def get_local_hash(rel_path):
            """按需计算并缓存本地文件哈希。"""
            nonlocal last_hash_progress_logged_at
            nonlocal hashed_file_count
            nonlocal hashed_bytes
            nonlocal hashing_elapsed_seconds

            local_file = local_files[rel_path]
            if 'hash' in local_file:
                return local_file['hash']

            hash_started_at = time.monotonic()
            if last_hash_progress_logged_at is None:
                last_hash_progress_logged_at = hash_started_at
            local_file['hash'] = self._calculate_file_hash(
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
                    "Local hash progress: %d files hashed, %.2f GiB processed "
                    "in %.1f hashing seconds (%.2f MiB/s)",
                    hashed_file_count,
                    hashed_bytes / BYTES_PER_GIB,
                    hashing_elapsed_seconds,
                    hashed_bytes / BYTES_PER_MIB / hashing_seconds_for_rate,
                )
                last_hash_progress_logged_at = hash_completed_at

            return local_file['hash']

        local_paths = set(local_files)
        oss_paths = set(oss_files)
        common_paths = local_paths & oss_paths

        # 同步策略
        if self.config['sync_direction'] in ['local2oss', 'both']:
            # 上传本地新增/修改文件
            for rel_path in local_paths - oss_paths:
                self._upload_file(rel_path)
            
            # 对比相同文件
            for rel_path in common_paths:
                local_file = local_files[rel_path]
                oss_file = oss_files[rel_path]
                if (
                    local_file['size'] != oss_file['size']
                    or local_file['mtime'] > oss_file['mtime']
                    or get_local_hash(rel_path).lower() != oss_file['hash'].lower()
                ):
                    self._upload_file(rel_path)

        if self.config['sync_direction'] in ['oss2local', 'both']:
            # 下载OSS新增/修改文件
            for rel_path in oss_paths - local_paths:
                self._download_file(rel_path)
            
            # 对比相同文件
            for rel_path in common_paths:
                local_file = local_files[rel_path]
                oss_file = oss_files[rel_path]
                if (
                    local_file['size'] != oss_file['size']
                    or local_file['mtime'] < oss_file['mtime']
                    or get_local_hash(rel_path) != oss_file['hash']
                ):
                    self._download_file(rel_path)

        if hashed_file_count:
            logger.info(
                "Local hashing completed: %d files, %.2f GiB hashed in %.1f seconds",
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
                'hash': obj.etag.strip('"'),
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
            if self._calculate_file_hash(local_file).lower() != oss_file['hash'].lower():
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
        except Exception as e:
            logger.error(f"Upload failed: {rel_path} - {str(e)}")

    def _download_file(self, rel_path):
        """从OSS下载文件"""
        oss_key = self._object_key(rel_path)
        local_full = self.config['local_path'] / rel_path
        
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
        except Exception as e:
            logger.error(f"Download failed: {rel_path} - {str(e)}")

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
                'hash': obj.etag.strip('"')
            }

        # 检查新增或修改的文件
        for rel_path in set(current_oss_files) - set(self.last_oss_files):
            local_file = self.config['local_path'] / rel_path
            # 如果本地文件存在，检查哈希值
            if local_file.exists():
                local_hash = self._calculate_file_hash(local_file)
                if local_hash.lower() == current_oss_files[rel_path]['hash'].lower():
                    logger.info(f"Skipping download of {rel_path} - local file hash matches")
                    continue
            self._download_file(rel_path)
        
        # 检查修改的文件
        for rel_path in set(current_oss_files) & set(self.last_oss_files):
            if (current_oss_files[rel_path]['hash'] != self.last_oss_files[rel_path]['hash'] or
                current_oss_files[rel_path]['mtime'] > self.last_oss_files[rel_path]['mtime']):
                local_file = self.config['local_path'] / rel_path
                # 如果本地文件存在，检查哈希值
                if local_file.exists():
                    local_hash = self._calculate_file_hash(local_file)
                    if local_hash.lower() == current_oss_files[rel_path]['hash'].lower():
                        logger.info(f"Skipping download of {rel_path} - local file hash matches")
                        continue
                self._download_file(rel_path)

        self.last_oss_files = current_oss_files

class SyncEventHandler(FileSystemEventHandler):
    """文件系统事件处理器"""
    def __init__(self, sync_client):
        self.sync_client = sync_client
        self.last_trigger = 0
        
    def _process_event(self, event):
        """处理事件（不加防抖处理）"""
        # if time.time() - self.last_trigger < 1:  # 1秒防抖
        #     return
        
        if event.is_directory:
            return
            
        src_path = Path(event.src_path)
        rel_path = self.sync_client._get_relative_path(src_path)
        
        if not rel_path or self.sync_client._should_ignore(rel_path):
            return
        
        # 处理不同事件类型
        if event.event_type in ['created', 'modified']:
            if self.sync_client.config['sync_direction'] in ['local2oss', 'both']:
                self.sync_client._upload_file(rel_path)
        
        elif event.event_type == 'deleted':
            if self.sync_client.config['sync_direction'] in ['local2oss', 'both']:
                self.sync_client._delete_file(rel_path)
        
        elif event.event_type == 'moved':
            dst_path = Path(event.dest_path)
            dst_rel_path = self.sync_client._get_relative_path(dst_path)
            if not dst_rel_path or self.sync_client._should_ignore(dst_rel_path):
                return
            if self.sync_client.config['sync_direction'] in ['local2oss', 'both']:
                self.sync_client._move_file(rel_path, dst_rel_path)
        else:
            logger.info(f"Unknown event type: {event.event_type}")

        self.last_trigger = time.time()

    def on_any_event(self, event):
        self._process_event(event)


def main():
    setup_logging()
    args = parse_args()
    observer_list = []
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
        for observer in observer_list:
            observer.stop()
        for sync_client in sync_clients:
            sync_client.stop_continuous_sync()
        for observer in observer_list:
            observer.join()

    return 0


if __name__ == '__main__':
    sys.exit(main())
