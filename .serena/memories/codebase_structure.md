# 代码结构

最后核对日期：2026-05-04。

## 顶层入口脚本

- `download_symbols.py`：解析 `kphdyn.xml`，按 arch/version/file 过滤条目，从 Microsoft Symbol Server 下载 PE 和 PDB；输出到 `symbols/<arch>/<file>.<version>/<sha256>/`。支持 `KPHTOOLS_XML`、`KPHTOOLS_SYMBOLDIR`、`KPHTOOLS_SYMBOL_SERVER` 覆盖。
- `dump_symbols.py`：当前主要分析入口。读取 `config.yaml`，默认扫描 `symbols` 下 `amd64,arm64`，按 skill 依赖排序处理每个 binary dir。解析链路包括 PDB resolver、IDA MCP preprocessor、可选 LLM_DECOMPILE、以及 agent fallback；结果写成相邻 `{symbol}.yaml` artifact。
- `update_symbols.py`：当前 YAML-to-XML exporter。加载 `config.yaml` 与 symbol artifacts，同步 `<data>` 文件条目，维护 `<fields>` id，并导出 `kphdyn.xml`。`-syncfile` 会根据 `symboldir` 同步 unmanaged PE 条目；缺失值按 `uint16`/`uint32` 导出 `0xffff`/`0xffffffff`。
- `generate_reference_yaml.py`：为 `LLM_DECOMPILE` 生成 reference YAML。可连接现有 IDA MCP session，也可用 `-auto_start_mcp -binary=...` 自动启动 `idalib-mcp`。
- `upload_server.py`：HTTP 上传服务，提供 `/upload`、`/exists`、`/health`。它校验 PE、FileDescription、Authenticode signer/issuer、arch、version 和 sha256 后保存到符号目录结构。

## 核心库模块

- `symbol_config.py`：`config.yaml` schema/dataclass、skill/symbol 校验、artifact 文件名到 symbol name 的映射。
- `symbol_artifacts.py`：构造 artifact 路径，读写 `struct_offset`、`gv`、`func` YAML payload。
- `pdb_resolver.py`：封装 `llvm-pdbutil` 调用，解析 struct member offset、public symbol RVA、section VA 等。
- `ida_skill_preprocessor.py`：按 skill 名加载 `ida_preprocessor_scripts/find-*.py` 的 `preprocess` 入口并缓存。
- `ida_preprocessor_common.py`：通用 preprocessor 调度和 payload 过滤，支持 `struct_offset`、`gv`、`func`、`func_xrefs`、LLM_DECOMPILE 等路径。
- `ida_mcp_resolver.py`：IDA MCP 查询、LLM_DECOMPILE 请求构造/响应解析、从返回指令地址解析函数/全局变量/结构偏移。
- `ida_llm_utils.py`：OpenAI-compatible client/SSE transport helper。
- `ida_reference_export.py` 与 `ida_reference_export_template.py`：通过 IDA 导出 reference YAML 所需的反汇编、伪代码和元数据。

## 配置、脚本和文档目录

- `config.yaml`：当前主配置，包含 `ntoskrnl` module、PE path、preprocessor skills、expected input/output、symbol category 与 data type。
- `ida_preprocessor_scripts/`：self-describing IDA-backed finder 脚本；包含大量 `find-*.py`、`generic_gv.py`、`generic_func.py`、`generic_struct_offset.py`、`_extract_ntapi.py`、`prompt/call_llm_decompile.md`、`references/ntoskrnl/*.yaml`。
- `tests/`：`unittest` 测试，覆盖 download/dump/update、symbol config/artifacts、PDB resolver、IDA MCP resolver、reference export、preprocessor common 和具体 extractor。
- `docs/`：专题说明与 Superpowers specs/plans，包含 `docs/find-AlpcpDeletePort.md` 和多份历史实现计划。
- `.claude/`、`.codex/`、`.serena/`：本地 agent/skill/memory 配置。

## 本地/生成内容

- `symbols/`：PE/PDB 和 per-symbol YAML artifacts 的主数据目录，可能很大。
- `output/`、`uploads/`：脚本输出和 upload server 临时/保存目录。
- `.venv/`、`__pycache__/`、`.env`、`kphdyn.xml`、`kphdyn.official.xml`：本地环境、缓存或忽略文件。处理任务时应定向读取，避免无目标全量扫描。