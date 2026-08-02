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

## 获取 `kphdyn.xml`

使用 `wget`：

```bash
wget https://raw.githubusercontent.com/winsiderss/systeminformer/refs/heads/master/kphlib/kphdyn.xml
```

使用 `curl`：

```bash
curl -O https://raw.githubusercontent.com/winsiderss/systeminformer/refs/heads/master/kphlib/kphdyn.xml
```

使用 PowerShell：

```powershell
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/winsiderss/systeminformer/refs/heads/master/kphlib/kphdyn.xml" -OutFile "kphdyn.xml"
```

## Linux 依赖

上传服务器使用已发布的 LIEF 和 cryptography wheel，不需要 OpenSSL 开发头文件或 `oscrypto` 源码兼容方案。在 Ubuntu 24.04 或其他受支持平台上执行 `uv sync` 即可安装声明的 Python 依赖。

