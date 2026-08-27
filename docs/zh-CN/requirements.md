# 依赖要求

[返回 README](../../README.zh-CN.md)

## 必需工具

1. [uv](https://docs.astral.sh/uv/getting-started/installation/)
2. Claude、Codex 或 OpenCode
3. IDA Pro 9.0+
4. [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp)
5. [idalib](https://docs.hex-rays.com/user-guide/idalib)，`ida_analyze_bin.py` 必需
6. Clang/LLVM，并确保 `clang` 位于 `PATH` 中

使用以下命令安装 Python 依赖：

```bash
uv sync
```
