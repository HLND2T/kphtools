# OSS Sync

## 两种上传模式
- trigger 一次性同步 （未实现）
- continue 持续同步，类似于服务
## 参数说明
- start 持续同步服务启动
- stop 持续同步服务关闭
- restart 持续同步服务重启/重新加载配置
- status 持续同步服务状态查询
- trigger 一次性同步（未实现）

## 安装依赖

依赖由仓库根目录的 `pyproject.toml` 和 `uv.lock` 统一管理：

```powershell
uv sync
```

## 后台同步配置

OSS 连接配置与 `upload_server.py` 使用相同的环境变量：

- `KPHTOOLS_SYMBOLDIR`：本地符号目录，可选，默认为 `symbols`（与 `upload_server.py` 一致）
- `OSS_ACCESS_KEY_ID`：阿里云 AccessKey ID，必填
- `OSS_ACCESS_KEY_SECRET`：阿里云 AccessKey Secret，必填
- `KPHTOOLS_SERVER_OSS_ENDPOINT`：OSS endpoint，必填
- `KPHTOOLS_SERVER_OSS_BUCKET`：OSS bucket 名称，必填
- `KPHTOOLS_SERVER_OSS_PREFIX`：OSS 路径前缀，可选，默认为空
- `KPHTOOLS_OSS_SYNC_CHECK_INTERVAL`：OSS 检查间隔（秒），可选，默认为 `60`
- `KPHTOOLS_OSS_SYNC_EXCLUDE`：排除路径，使用英文逗号分隔，可选，默认为 `.git/,.DS_Store`
- `KPHTOOLS_OSS_SYNC_EXCLUDE_EXTENSION`：排除扩展名，使用英文逗号分隔，可选，默认为 `.mdmp,.dmp`

同步方向通过命令行参数设置：

```bash
uv run --env-file .env "oss_sync/oss_sync.py" --direction local2oss
uv run --env-file .env "oss_sync/oss_sync.py" --direction oss2local
uv run --env-file .env "oss_sync/oss_sync.py" --direction both
```