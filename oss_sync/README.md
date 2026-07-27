# OSS Sync Oss同步


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

也可以运行 `install_deps.bat` 或 `install_deps.sh`，脚本内部同样调用 `uv sync`。

## 后台同步配置

同步配置通过 `KPHTOOL_*` / `KPHTOOLS_*` 环境变量提供：

- `KPHTOOL_ACCESS_KEY_ID`：阿里云 AccessKey ID，必填
- `KPHTOOL_ACCESS_KEY_SECRET`：阿里云 AccessKey Secret，必填
- `KPHTOOL_ENDPOINT`：OSS endpoint，必填
- `KPHTOOL_BUCKET_NAME`：OSS bucket 名称，必填
- `KPHTOOLS_SYMBOLDIR`：本地符号目录，可选，默认为 `symbols`（与 `upload_server.py` 一致）
- `KPHTOOL_OSS_PATH`：OSS 路径前缀，可选，默认为空
- `KPHTOOL_OSS_SYNC_CHECK_INTERVAL`：OSS 检查间隔（秒），可选，默认为 `60`
- `KPHTOOL_OSS_SYNC_EXCLUDE`：排除路径，使用英文逗号分隔，可选，默认为 `.git/,.DS_Store`
- `KPHTOOL_OSS_SYNC_EXCLUDE_EXTENSION`：排除扩展名，使用英文逗号分隔，可选，默认为 `.mdmp,.dmp`

同步方向通过命令行参数设置：

```bash
uv run oss_sync/oss_sync.py --direction local2oss
uv run oss_sync/oss_sync.py --direction oss2local
uv run oss_sync/oss_sync.py --direction both
```

## 一次性同步命令 TODO
```
```

## 同步服务启动命令

```bash
uv run oss_sync/oss_sync_service.py start
```
