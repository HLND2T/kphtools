# 依赖要求

[返回 README](../../README.zh-CN.md)

## 必需工具

1. [uv](https://docs.astral.sh/uv/getting-started/installation/)
2. Claude、Codex 或 OpenCode
3. IDA Pro 9.0+
4. [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp)
5. [idalib](https://docs.hex-rays.com/user-guide/idalib)，`ida_analyze_bin.py` 必需
6. Clang/LLVM：`clang`、`llvm-pdbutil`（PDB 类型和 public symbols）、`llvm-readobj`（PE exports）

LLVM 工具查找顺序为：resolver 显式参数 → `KPHTOOLS_LLVM_PDBUTIL` 或
`KPHTOOLS_LLVM_READOBJ` → `PATH` 中的裸名 → `PATH` 中数字版本后缀最高的
可执行文件（例如 `llvm-pdbutil-18`）。覆盖值只能是可执行文件名或路径，不能包含
shell 参数。覆盖无效或工具缺失时，即使未开启 `-debug` 也会报错并停止分析，
不会进入 Agent fallback；真正的符号缺失保留原有 fallback 行为。

Ubuntu 24.04 安装示例：

```bash
sudo apt-get install clang-18 llvm-18
# 可选：固定使用某个 LLVM 安装。
export KPHTOOLS_LLVM_PDBUTIL=/usr/bin/llvm-pdbutil-18
export KPHTOOLS_LLVM_READOBJ=/usr/bin/llvm-readobj-18
```

直接调用 `clang` 的流程仍需确保裸名位于 `PATH`；自动版本后缀查找只适用于上面两个 resolver。

## Linux 支持边界

Linux 当前为**部分支持**。已在 WSL2 Ubuntu 24.04 验证 unittest、真实 POSIX
worker 回收及 LLVM 18 的 PE/PDB 解析。工作流可调度 Windows 或 Linux 自托管
runner，但完整 Linux IDA/Hex-Rays/idalib 分析和实际 Linux CI 发布尚未验证。
Linux 分析需要有授权的 Linux IDA/Hex-Rays 安装，以及 `PATH` 中可运行的 Linux
`idalib-mcp`；Windows 安装不能替代。添加共享 runner 标签前请阅读
[Linux/WSL 与 runner 指南](linux.md)。

使用以下命令安装 Python 依赖：

```bash
uv sync
```
