# Requirements

[Back to README](../README.md)

## Required tools

1. [uv](https://docs.astral.sh/uv/getting-started/installation/)
2. Claude, Codex, or OpenCode
3. IDA Pro 9.0+
4. [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp)
5. [idalib](https://docs.hex-rays.com/user-guide/idalib), mandatory for `ida_analyze_bin.py`
6. Clang/LLVM, with `clang` available in `PATH`

Install the Python dependencies with:

```bash
uv sync
```

## Get `kphdyn.xml`

Using `wget`:

```bash
wget https://raw.githubusercontent.com/winsiderss/systeminformer/refs/heads/master/kphlib/kphdyn.xml
```

Using `curl`:

```bash
curl -O https://raw.githubusercontent.com/winsiderss/systeminformer/refs/heads/master/kphlib/kphdyn.xml
```

Using PowerShell:

```powershell
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/winsiderss/systeminformer/refs/heads/master/kphlib/kphdyn.xml" -OutFile "kphdyn.xml"
```

## Linux dependencies

The upload server uses the published LIEF and cryptography wheels and does not require OpenSSL development headers or an `oscrypto` source workaround. Install the declared Python dependencies with `uv sync` on Ubuntu 24.04 or other supported platforms.
