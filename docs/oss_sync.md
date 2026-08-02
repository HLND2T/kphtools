# OSS Sync

## 同步模式

- 默认持续同步：完成初始同步后，持续监控本地文件变更；`oss2local` 和 `both` 还会按配置的间隔轮询 OSS。
- `--once` 一次性同步：完成初始同步后，重新比对本地与 OSS 中未排除文件的路径、大小和内容哈希；验证完成后立即退出，不会启动文件监控或持续轮询。

`--once` 的退出码：

- `0`：本地与 OSS 中所有未排除文件完全一致。
- `1`：仍存在内容、大小或文件集合差异，或同步过程中发生未处理错误。

一次性模式不会删除本地或 OSS 中的多余文件。因此一端存在另一端没有的文件时，校验会以 `1` 退出；如需镜像删除，须使用其他明确的清理流程。

## 安装依赖

依赖由仓库根目录的 `pyproject.toml` 和 `uv.lock` 统一管理：

```powershell
uv sync
```

## 后台同步配置

OSS 同步使用 `alibabacloud-oss-v2`，连接配置与 `upload_server.py` 使用相同的环境变量：

- `KPHTOOLS_SYMBOLDIR`：本地符号目录，可选，默认为 `symbols`（与 `upload_server.py` 一致）
- `OSS_ACCESS_KEY_ID`：阿里云 AccessKey ID，必填
- `OSS_ACCESS_KEY_SECRET`：阿里云 AccessKey Secret，必填
- `OSS_SESSION_TOKEN`：STS 临时凭据的 session token，可选
- `KPHTOOLS_SERVER_OSS_REGION`：OSS region，必填，例如 `cn-hangzhou`
- `KPHTOOLS_SERVER_OSS_ENDPOINT`：OSS endpoint，必填
- `KPHTOOLS_SERVER_OSS_BUCKET`：OSS bucket 名称，必填
- `KPHTOOLS_SERVER_OSS_PREFIX`：OSS 路径前缀，可选，默认为空
- `KPHTOOLS_OSS_SYNC_CHECK_INTERVAL`：OSS 检查间隔（秒），可选，默认为 `60`
- `KPHTOOLS_OSS_SYNC_EXCLUDE`：排除路径，使用英文逗号分隔，可选，默认为 `.git/,.DS_Store`
- `KPHTOOLS_OSS_SYNC_EXCLUDE_EXTENSION`：排除扩展名，使用英文逗号分隔，可选，默认为 `.mdmp,.dmp`

同步方向通过命令行参数设置：

```bash
uv run --env-file .env oss_sync.py --direction local2oss
uv run --env-file .env oss_sync.py --direction oss2local
uv run --env-file .env oss_sync.py --direction both
```

在 CI 或批处理任务中使用 `--once`，以同步结果决定进程退出码：

```bash
uv run --env-file .env oss_sync.py --direction local2oss --once
```
