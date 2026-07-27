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

## Extra Linux dependencies

Ubuntu or Debian:

```bash
sudo apt-get update
sudo apt-get install -y libssl-dev
```

CentOS, RHEL, or Fedora:

```bash
sudo yum install -y openssl-devel
```

On newer distributions, use `sudo dnf install -y openssl-devel` instead.

If oscrypto reports `Error detecting the version of libcrypto`, install its current Git version:

```bash
pip install -I "git+https://github.com/wbond/oscrypto.git" --break-system-packages
```
