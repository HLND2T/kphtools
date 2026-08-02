# Windows 上的 Jenkins 工作流

[返回 README](../../README.zh-CN.md)

此参考工作流的每一步都通过 Windows 命令提示符执行。

- 首次运行下载 PE 和 PDB 文件，可能需要数小时。
- 后续典型运行大约需要 20 分钟。
- 输出文件为 `kphdyn.xml`。

## 下载最新上游 XML

```bat
@echo Download latest kphdyn.xml from upstream

powershell -Command "Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/winsiderss/systeminformer/refs/heads/master/kphlib/kphdyn.xml' -OutFile kphdyn.official.xml"

copy kphdyn.official.xml kphdyn.xml /y
```

## 同步未管理的二进制文件

```bat
@echo Sync unmanaged ntoskrnl to kphdyn.xml

uv run update_symbols.py -xml="%WORKSPACE%\kphdyn.xml" -symboldir="%WORKSPACE%\symbols" -syncfile
```

## 下载 PE 和 PDB 文件

```bat
@echo Download ntoskrnl exe and pdb, this may take hours for the first run

uv sync

uv run download_symbols.py -xml="%WORKSPACE%\kphdyn.xml" -symboldir="%WORKSPACE%\symbols" -fast
```

下载选项和符号目录布局见 [`download_symbols.py` 指南](download_symbols.md)。

## 分析符号

```bat
@echo Analyze symbols and dump YAML artifacts

uv run dump_symbols.py -symboldir="%WORKSPACE%\symbols" -configyaml="%WORKSPACE%\config.yaml"
```

分析和 Agent 选项见 [`dump_symbols.py` 指南](dump_symbols.md)。

## 导出 `kphdyn.xml`

```bat
@echo Update kphdyn.xml with offsets from YAML artifacts

uv run update_symbols.py -xml="%WORKSPACE%\kphdyn.xml" -symboldir="%WORKSPACE%\symbols" -configyaml="%WORKSPACE%\config.yaml"
```

导出器行为见 [`update_symbols.py` 指南](update_symbols.md)。

