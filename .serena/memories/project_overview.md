# 项目概览

最后核对日期：2026-05-04。

## 项目目的

kphtools 是面向 SystemInformer `kphdyn.xml` 的 KPH Dynamic Data 工具集。它围绕 Windows 内核 PE/PDB 输入，生成或补全 `struct_offset`、`func_offset`/函数 RVA、全局变量 RVA 等动态数据；当前主线是先下载 PE/PDB，再分析生成每个符号的 YAML artifact，最后把 artifact 导出回 `kphdyn.xml`。

当前主要流水线：

1. 获取或刷新 `kphdyn.xml`/`kphdyn.official.xml`。
2. 使用 `uv sync` 安装依赖。
3. `download_symbols.py` 根据 `kphdyn.xml` 从 Microsoft Symbol Server 下载 PE 与 PDB 到 `symbols/<arch>/<file>.<version>/<sha256>/`。
4. `dump_symbols.py` 读取 `config.yaml`，扫描 `symbols`，通过 PDB、IDA MCP preprocessor、可选 LLM_DECOMPILE 和 agent fallback 生成 `{symbol}.yaml`。
5. `update_symbols.py` 从 YAML artifacts 导出并同步 `kphdyn.xml` 中 `<data>/<fields>` 映射；缺失或未解析的值按类型导出为 fallback 值。
6. 可选：`upload_server.py` 用于收集并校验上传的 `ntoskrnl.exe`；`generate_reference_yaml.py` 用于生成 LLM_DECOMPILE reference YAML。

## 技术栈

- Python `>=3.10`。
- `uv` 管理依赖，`pyproject.toml` 中 `package = false`，不是可安装 package 项目。
- 声明依赖：`anthropic`、`httpx`、`mcp`、`openai`、`pefile`、`pyyaml`、`requests`、`signify`。
- 测试使用标准库 `unittest`、`unittest.mock`、`IsolatedAsyncioTestCase`，测试文件位于 `tests/`。
- 配置和数据：`config.yaml` 是模块、skill、symbol inventory；`kphdyn.xml` 和 `kphdyn.official.xml` 是本地/忽略的 XML 输入输出文件。

## 外部依赖与运行环境

- Microsoft Symbol Server：下载 PE/PDB。
- `llvm-pdbutil`：PDB type/public symbol 解析。
- `idalib-mcp`、IDA/Hex-Rays：IDA MCP fallback、reference YAML 生成、反汇编/伪代码导出。
- OpenAI-compatible API：`LLM_DECOMPILE` fallback，可通过 `KPHTOOLS_LLM_*` 环境变量或 CLI 参数配置。
- Linux 运行 `signify` 相关 upload server 时需要 OpenSSL development libraries；README 中列出 Debian/Ubuntu 和 RHEL/Fedora 安装方式。

## 注意事项

- `symbols/`、`output/`、`uploads/`、`.venv/`、`__pycache__/`、`.env`、`kphdyn.xml`、`kphdyn.official.xml` 都属于本地/忽略或生成内容，避免无目标地全量扫描或提交敏感信息。
- 涉及 IDA、`llvm-pdbutil`、symbol server、LLM API 时，先确认工具是否可用、路径/端口/API 配置是否存在，再执行长耗时流程。