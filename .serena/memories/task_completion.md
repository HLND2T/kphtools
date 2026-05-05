# 任务完成检查

最后核对日期：2026-05-04。

## 默认原则

- 当前仓库没有统一的 lint/format/build 配置；完成任务时按改动范围做定向验证。
- 按本工作区 AGENTS 规则，除非用户明确要求，不要自行运行 test 或 build 命令。若未运行验证，最终回复必须明确说明未运行以及原因。
- 不要声称测试通过、构建通过或可合并，除非确实运行过对应命令并看到成功结果。

## 常用准备命令

- 安装依赖：`uv sync`。
- Linux 上运行 `upload_server.py`/`signify` 相关逻辑前，按 README 安装 OpenSSL development libraries。
- 涉及 PDB 解析前确认 `llvm-pdbutil` 可执行。
- 涉及 IDA MCP/reference/LLM_DECOMPILE 前确认 `idalib-mcp`、IDA/Hex-Rays、端口和 `KPHTOOLS_LLM_*` 或 CLI LLM 参数。

## 定向验证命令

在用户允许运行测试时，优先选择最小相关集合：

- 单个测试文件：`uv run python -m unittest tests.test_symbol_config -v`。
- 多个相关测试文件：`uv run python -m unittest tests.test_dump_symbols tests.test_update_symbols -v`。
- 单个测试类或方法：`uv run python -m unittest tests.test_update_symbols.TestUpdateSymbols.test_name -v`。
- 全量测试：`uv run python -m unittest discover -s tests -v`。
- 只检查脚本语法时可用：`uv run python -m py_compile <changed_files>`。

## 按改动类型选择验证

- `symbol_config.py` 或 `config.yaml` schema/contract：运行 `tests.test_symbol_config`，必要时补 `tests.test_dump_symbols`、`tests.test_update_symbols`。
- `symbol_artifacts.py` 或 YAML artifact contract：运行 `tests.test_symbol_artifacts`，以及消费方相关测试。
- `pdb_resolver.py`：运行 `tests.test_pdb_resolver`；不要依赖真实 `llvm-pdbutil`，测试中应 mock subprocess。
- `dump_symbols.py`：运行 `tests.test_dump_symbols`；涉及 preprocessor contract 时补 `tests.test_ida_skill_preprocessor`、`tests.test_ida_preprocessor_common`。
- `update_symbols.py`：运行 `tests.test_update_symbols`；涉及 XML 导出时确认 fallback、fields id、sha256/hash 逻辑。
- IDA MCP/LLM resolver：运行 `tests.test_ida_mcp_resolver`、`tests.test_ida_reference_export`、`tests.test_generate_reference_yaml`；测试应 mock MCP/LLM。
- `ida_preprocessor_scripts/` 下 finder 或 generic 脚本：运行对应 generic/extractor 测试、`tests.test_ida_skill_preprocessor` 和 `tests.test_ida_preprocessor_common`。
- `download_symbols.py`：运行 `tests.test_download_symbols`；真实下载需要网络和 symbol server，不应作为默认验证。
- `upload_server.py`：如有专门测试则运行相关测试；手动 smoke 需要真实 PE/signature 或 `/health`，不要默认启动长期 server。

## 工作流级 smoke 建议

仅在用户明确要求、环境已确认且接受耗时时执行：

- 下载：`uv run python download_symbols.py -xml="kphdyn.xml" -symboldir="symbols" -fast`。
- 分析：`uv run python dump_symbols.py -symboldir="symbols" -configyaml="config.yaml" -arch=amd64`。
- 导出：`uv run python update_symbols.py -xml="kphdyn.xml" -symboldir="symbols" -configyaml="config.yaml" -syncfile`。
- Reference YAML：`uv run python generate_reference_yaml.py -func_name="ExReferenceCallBackBlock"`，需要现有 MCP session；或加 `-auto_start_mcp -binary=...`。

## 收尾报告

最终回复应包括：

- 修改了哪些文件或 memory。
- 是否运行验证；如果没有运行，说明是因为任务只更新 memory、用户未要求测试/构建，或外部工具/长耗时条件未满足。
- 若涉及本地生成目录、外部工具、网络或 API key，说明未触碰或已按边界处理。