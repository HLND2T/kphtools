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

## CI 共享缓存

Windows / Linux 自托管构建与 PR job 使用 S3-compatible bucket `actions-cache-kphtools` 保存符号分片和 uv 依赖缓存。在 `win64` environment 配置 `S3_ENDPOINT_URL`（仅 HTTP(S) origin）、`S3_ACCESS_KEY_ID` 和 `S3_SECRET_ACCESS_KEY`。需要预先创建 bucket，并授予这些凭证列举、读取和写入权限；客户端不会创建 bucket。所有 runner 都需要能够访问 endpoint，服务端须支持带 `IfMatch` 和 `IfNoneMatch` 条件的 `PutObject`。CI 不再使用 `PERSISTED_WORKSPACE`。

符号按 `arch/binary.version/sha256` 分片，每片分为 `inputs`（PE/PDB/IDA 等分析输入）和 `results`（YAML）两个归档，采用 zstd level 1 压缩。构建先恢复 catalog 和 YAML，真正需要分析时才下载对应输入；发布仅上传有变化的部分。不可变归档的 key 按仓库和 runner OS 隔离，小型 `catalog.json` 使用条件写入，避免并发生产者覆盖新 catalog。恢复时校验大小、SHA-256、内容身份和安全路径。OSS 同步保留原有排除规则，仅下载未缓存文件。

不要按对象年龄统一过期所有分片：未变化的输入可能长期被 catalog 引用。后续垃圾回收必须保留仍被引用的对象。迁移不会删除旧 S3 快照。

PR 验证仅下载 `amd64/ntoskrnl.exe.10.0.22621.3668` 的输入分片，再复制到隔离目录，并排除 YAML，确保重新执行分析。缺失的 PE/PDB 根据上游 XML 的精确选择下载；上游已移除此版本时使用 [`.github/pr-kernel.xml`](.github/pr-kernel.xml) 保留的下载元数据。与原 workflow 一致，必须有非空 PE，独立 PDB 可选，分析流程可使用已有 IDA 数据库。验证必须生成新 YAML，实际分析报错时仍失败。PR 结果不更新共享 catalog。两个 job 的 uv 缓存均使用固定 SHA 的 `hzqst/setup-uv` S3 backend。

生成数据位于标准 checkout 下的 `.ci-symbol-cache/` 和 `.ci-pr-analysis/`。PR 的 XML、YAML 和日志在清理前上传为诊断 artifact。每个 job 都在自己的 runner 上清理生成目录，包括正常报错的情况；checkout 和依赖文件保留到 uv 的 post-job 缓存保存结束。不再需要 PR 关闭时的清理 job 或按 PR 编号保留的工作区。runner 关机或被强制终止时仍需 runner 生命周期清理。迁移不会删除历史 `kphtools-pr-*` 目录。

首次运行迁移后的 CI 前，请按 [issue #42](https://github.com/HLND2T/kphtools/issues/42)，在包含迁移代码的 checkout 中运行 `uv run --group ci --frozen python ci_symbol_cache.py seed --symbols <实际-symbols-目录> --repository HLND2T/kphtools --platform Windows`。命令保留源数据，每次仅生成一个组件归档，重试复用已上传对象，全部分片成功后才发布 catalog。已有非空 catalog 时需要 `--merge`，仅在源数据具有权威性时使用。固定 PR 内核版本的 PE/PDB 在 2026-10-09 检查时从 Microsoft Symbol Server 返回 404，请保留现有 PE 和 IDA 数据库，有 PDB 时一并预热。uv 由 CI 中的 `setup-uv` 单独预热。

## 文档

- [依赖与环境配置](docs/zh-CN/requirements.md)
- [Linux/WSL 验证与跨平台 runner](docs/zh-CN/linux.md)
- [下载 PE 与 PDB 符号](docs/zh-CN/download_symbols.md)
- [导出 YAML 工件](docs/zh-CN/dump_symbols.md)
- [`LLM_DECOMPILE` Reference YAML](docs/zh-CN/reference_yaml.md)
- [将 YAML 工件导出到 `kphdyn.xml`](docs/zh-CN/update_symbols.md)
- [OSS 同步](docs/zh-CN/oss_sync.md)
- [上传服务器](docs/zh-CN/upload_server.md)
- [Windows Jenkins 工作流](docs/zh-CN/jenkins_windows.md)

