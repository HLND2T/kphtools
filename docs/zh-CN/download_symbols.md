# 下载 PE 与 PDB 符号

[返回 README](../../README.zh-CN.md)

`download_symbols.py` 根据 `kphdyn.xml` 中的条目，从 Microsoft Symbol Server 下载 PE 文件及其对应的 PDB 符号文件。

## 用法

方括号中的参数为可选参数：

```bash
uv run download_symbols.py [-xml="path/to/kphdyn.xml"] [-symboldir="path/to/symbols"] [-arch=amd64] [-version=10.0.10240.16393] [-symbol_server="https://msdl.microsoft.com/download/symbols"] [-fast]
```

## 环境变量

Linux 或 macOS：

```bash
export KPHTOOLS_XML="path/to/kphdyn.xml"
export KPHTOOLS_SYMBOLDIR="path/to/symbols"
```

Windows 命令提示符：

```bat
set KPHTOOLS_XML=path/to/kphdyn.xml
set KPHTOOLS_SYMBOLDIR=path/to/symbols
```

## 示例

```bash
uv run download_symbols.py -fast -symboldir="C:\\Symbols"
```

下载的文件会使用以下目录布局：

```text
C:\Symbols\amd64\ntoskrnl.exe.10.0.10240.16393\{sha256}\ntoskrnl.exe
C:\Symbols\amd64\ntoskrnl.exe.10.0.10240.16393\{sha256}\ntkrnlmp.pdb
...others
```

`{sha256}` 是 PE 文件的小写 SHA256 哈希值，例如 `68d5867b5e66fce486c863c11cf69020658cadbbacbbda1e167766f236fefe78`。

下载所需的 PE 和 PDB 文件后，继续阅读 [`dump_symbols.py` 指南](dump_symbols.md)。

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
