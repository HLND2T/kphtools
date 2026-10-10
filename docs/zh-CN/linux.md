# Linux、WSL2 与跨平台 runner

[返回 README](../../README.zh-CN.md) · [依赖和支持边界](requirements.md)

## 本地验证

可以使用 Linux checkout，也可以通过 `/mnt/d/kphtools` 访问 Windows checkout。
共用 checkout 时，将 Linux 虚拟环境放在 Windows `.venv` 之外；在 Linux 安装
锁定版本的依赖，不复用 Windows 可执行文件。

```bash
cd /mnt/d/kphtools
export UV_PROJECT_ENVIRONMENT="$HOME/.cache/kphtools-linux-venv"
uv sync --group ci --frozen
uv run --group ci --frozen python -m unittest discover -s tests -v
uv run --group ci --frozen python -c 'from llvm_tools import resolve_llvm_tool; print(resolve_llvm_tool("llvm-pdbutil")); print(resolve_llvm_tool("llvm-readobj"))'
```

POSIX 进程测试创建自己的 Python supervisor 和监听端口的 worker，不依赖 IDA，
覆盖正常停止、忽略 SIGTERM、supervisor 提前退出。这些测试不能证明某个实际
idalib-mcp 安装可用。kphtools 只记录自己启动的进程组，先发 SIGTERM，必要时升级
为 SIGKILL；worker 必须留在该组内，主动脱离并创建新 session 的进程不属于此回收契约。

## 分析流水线

分析前配置 Linux IDA/Hex-Rays 授权、idalib、`idalib-mcp`，以及所选符号所需的
Agent/LLM 配置。确认 `command -v idalib-mcp` 在 runner 环境中解析为 Linux
可执行文件。项目的 `uv sync` 不会安装 IDA 或配置授权。

在仓库根目录使用隔离数据目录运行：

```bash
export KPHTOOLS_SYMBOLDIR="$HOME/kphtools-linux-data/symbols"
mkdir -p "$HOME/kphtools-linux-data"
curl --fail --location --output "$HOME/kphtools-linux-data/kphdyn.xml" \
  https://raw.githubusercontent.com/winsiderss/systeminformer/refs/heads/master/kphlib/kphdyn.xml
uv run --frozen python download_symbols.py "-xml=$HOME/kphtools-linux-data/kphdyn.xml" -arch=amd64
uv run --frozen python dump_symbols.py -arch=amd64 -debug
uv run --frozen python update_symbols.py "-xml=$HOME/kphtools-linux-data/kphdyn.xml"
```

版本过滤和输出说明见各脚本指南。真实 Linux IDA 验证还需确认生成新 YAML、
导出有效 XML，并在成功、启动失败和恢复路径后检查 MCP 端口已释放。

## 自托管 runner 配置

两个工作流均使用 `runs-on: [self-hosted, cross-platform]`。只给准备就绪的
Windows/Linux runner 添加 `cross-platform` 标签。每次 job 选择一台符合标签的
runner，不是双平台测试矩阵。Windows 步骤使用 `pwsh`，Linux 使用 Bash，
Linux 无需安装 PowerShell。

runner 需提供 Git、uv、LLVM、curl（Linux）和对应平台的 IDA/Agent 工具。
继续使用已有的 `win64` GitHub environment：名称是历史命名，两个系统共用其
secrets 和策略。符号缓存仍按 `RUNNER_OS` 隔离，Linux 不会自动复用 Windows
catalog。Linux 缓存预热沿用 `ci_symbol_cache.py seed` 流程，使用
`--platform Linux` 和权威输入目录。请保留固定 PR 内核输入，Microsoft 可能已
不再提供该版本。在完成真实 IDA 分析和必要缓存输入检查前，不要将 Linux runner
接入生产调度。

PR 保留输入隔离、新 YAML 要求、诊断上传和普通失败后的清理；发布 job 保留
tag/nightly 行为。本地测试不能验证远端 S3/OSS 凭证或发布权限，实际 workflow
调度、发布和 runner 标签修改属于后续运维步骤。
