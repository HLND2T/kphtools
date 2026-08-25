# KPH Dynamic Data 工具集

[English README](README.md)

本项目包含多个脚本，用于为 [SystemInformer](https://github.com/winsiderss/systeminformer) 的 [`kphdyn.xml`](https://github.com/winsiderss/systeminformer/blob/master/kphlib/kphdyn.xml) 生成 offset，并添加自定义的 `struct_offset` 或 `func_offset` 条目。符号清单和分析流程可以通过 `config.yaml` 定制。

## 快速开始

先安装[依赖](docs/zh-CN/requirements.md)，然后运行完整流水线：

```bash
curl -O https://raw.githubusercontent.com/winsiderss/systeminformer/refs/heads/master/kphlib/kphdyn.xml
uv run download_symbols.py -fast
uv run dump_symbols.py
uv run update_symbols.py
```

首次下载可能需要数小时。后续运行可以复用 `symbols/` 下已保存的 PE、PDB 和 YAML 工件。

## 工作流

1. [`download_symbols.py`](docs/zh-CN/download_symbols.md) 从 Microsoft Symbol Server 下载 PE 文件及匹配的 PDB 符号。
2. [`dump_symbols.py`](docs/zh-CN/dump_symbols.md) 分析每个二进制文件，并在其旁边写入单符号 YAML 工件及聚合的 `artifacts.yaml`。
3. [`update_symbols.py`](docs/zh-CN/update_symbols.md) 将这些 YAML 工件导出回 `kphdyn.xml`。

默认符号目录布局为：

```text
symbols/<arch>/<file>.<version>/<sha256>/
```

四个主流程脚本默认使用当前工作目录下的 `symbols`。设置 `KPHTOOLS_SYMBOLDIR` 可以覆盖该目录；该环境变量优先于 `-symboldir`。

## 文档

- [依赖与环境配置](docs/zh-CN/requirements.md)
- [下载 PE 与 PDB 符号](docs/zh-CN/download_symbols.md)
- [导出 YAML 工件](docs/zh-CN/dump_symbols.md)
- [`LLM_DECOMPILE` Reference YAML](docs/zh-CN/reference_yaml.md)
- [将 YAML 工件导出到 `kphdyn.xml`](docs/zh-CN/update_symbols.md)
- [OSS 同步](docs/zh-CN/oss_sync.md)
- [上传服务器](docs/zh-CN/upload_server.md)
- [Windows Jenkins 工作流](docs/zh-CN/jenkins_windows.md)

