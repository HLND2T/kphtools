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

## Nightly 发布

构建工作流每天在**新加坡时间 03:17（UTC 19:17）**从默认分支 `main` 运行。也可以通过 **Build On Self Runner → Run workflow** 手动触发；手动 nightly 发布仅允许默认分支。

从固定的 [`nightly` 预发布](https://github.com/HLND2T/kphtools/releases/tag/nightly)下载 [`kphdyn.xml`](https://github.com/HLND2T/kphtools/releases/download/nightly/kphdyn.xml)。首次运行创建预发布，后续运行将生成的 XML 与该预发布的附件比较，只有 XML 数据变化才更新 Release、附件和 tag。更新后的 tag 指向本次构建使用的源码 commit。

比较忽略缩进、换行、注释及属性顺序，保留节点顺序、字段编号、文本和所有属性值。比较或下载失败时停止发布；XML 数据相同时跳过发布，符号同步仍继续执行。正式 tag 发布保持现有行为，nightly 预发布不会替换最新正式版本。

## 文档

- [依赖与环境配置](docs/zh-CN/requirements.md)
- [下载 PE 与 PDB 符号](docs/zh-CN/download_symbols.md)
- [导出 YAML 工件](docs/zh-CN/dump_symbols.md)
- [`LLM_DECOMPILE` Reference YAML](docs/zh-CN/reference_yaml.md)
- [将 YAML 工件导出到 `kphdyn.xml`](docs/zh-CN/update_symbols.md)
- [OSS 同步](docs/zh-CN/oss_sync.md)
- [上传服务器](docs/zh-CN/upload_server.md)
- [Windows Jenkins 工作流](docs/zh-CN/jenkins_windows.md)

