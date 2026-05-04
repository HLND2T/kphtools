# 常用命令

最后核对日期：2026-05-04。

## 安装依赖

- `uv sync`

Linux 上运行 `upload_server.py`/`signify` 相关功能前，按 README 安装 OpenSSL development libraries：

- Debian/Ubuntu：`sudo apt-get update && sudo apt-get install -y libssl-dev`
- RHEL/CentOS/Fedora：`sudo yum install -y openssl-devel` 或 `sudo dnf install -y openssl-devel`

如遇 `oscrypto` 的 `Error detecting the version of libcrypto`，README 建议：

- `uv pip install -I "git+https://github.com/wbond/oscrypto.git"`

## 获取 kphdyn.xml

- `wget https://raw.githubusercontent.com/winsiderss/systeminformer/refs/heads/master/kphlib/kphdyn.xml`
- `curl -O https://raw.githubusercontent.com/winsiderss/systeminformer/refs/heads/master/kphlib/kphdyn.xml`
- `powershell -Command "Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/winsiderss/systeminformer/refs/heads/master/kphlib/kphdyn.xml' -OutFile kphdyn.xml"`

## 下载 PE 与 PDB

- `uv run python download_symbols.py -xml="path/to/kphdyn.xml" -symboldir="C:/Symbols" [-arch=amd64] [-version=10.0.10240.16393] [-symbol_server="https://msdl.microsoft.com/download/symbols"]`
- Jenkins/批处理常用：`uv run python download_symbols.py -xml="%WORKSPACE%\kphdyn.xml" -symboldir="%WORKSPACE%\symbols" -fast`

相关环境变量：

- Unix：`export KPHTOOLS_XML="path/to/kphdyn.xml"`
- Unix：`export KPHTOOLS_SYMBOLDIR="C:/Symbols"`
- Windows CMD：`set KPHTOOLS_XML=path\to\kphdyn.xml`
- Windows CMD：`set KPHTOOLS_SYMBOLDIR=C:\Symbols`
- 可选：`KPHTOOLS_SYMBOL_SERVER=https://msdl.microsoft.com/download/symbols`

## 分析并生成 YAML artifacts

`dump_symbols.py` 是当前主要分析入口，默认使用 `./symbols`、`config.yaml`，并扫描 `amd64,arm64`。

- `uv run python dump_symbols.py`
- `uv run python dump_symbols.py -symboldir="symbols" -configyaml="config.yaml" -arch=amd64`
- `uv run python dump_symbols.py -symboldir="symbols" -configyaml="config.yaml" -arch=amd64,arm64 -force`
- 调试：`uv run python dump_symbols.py -debug`

LLM_DECOMPILE 相关参数：

- `uv run python dump_symbols.py -llm_model=gpt-5.4 -llm_apikey=your-key -llm_baseurl=https://api.example.com/v1 -llm_temperature=0.2 -llm_effort=medium -llm_fake_as=codex`

也可用环境变量：

- `KPHTOOLS_LLM_MODEL=gpt-5.4`
- `KPHTOOLS_LLM_APIKEY=your-key`
- `KPHTOOLS_LLM_BASEURL=https://api.example.com/v1`
- `KPHTOOLS_LLM_TEMPERATURE=0.2`
- `KPHTOOLS_LLM_EFFORT=high`
- `KPHTOOLS_LLM_FAKE_AS=codex`

## 导出或同步 kphdyn.xml

`update_symbols.py` 当前是 YAML-to-XML exporter。

- `uv run python update_symbols.py -xml="kphdyn.xml" -symboldir="C:/Symbols" -configyaml="config.yaml" -syncfile`
- 使用默认路径同步本地文件条目：`uv run python update_symbols.py -syncfile`
- 输出到其他文件：`uv run python update_symbols.py -xml="kphdyn.xml" -symboldir="symbols" -configyaml="config.yaml" -outxml="output.xml"`

相关环境变量：

- `KPHTOOLS_XML=path/to/kphdyn.xml`
- `KPHTOOLS_SYMBOLDIR=C:/Symbols`

## 生成 LLM_DECOMPILE reference YAML

连接现有 IDA MCP session：

- `uv run python generate_reference_yaml.py -func_name="ExReferenceCallBackBlock"`

自动启动 `idalib-mcp`：

- `uv run python generate_reference_yaml.py -func_name="ExReferenceCallBackBlock" -auto_start_mcp -binary="symbols/amd64/ntoskrnl.exe.10.0.26100.1/{sha256}/ntoskrnl.exe"`

可选参数：

- `-module=<module>`
- `-arch=amd64|arm64`
- `-mcp_host=127.0.0.1`
- `-mcp_port=13337`
- `-debug`

## 启动上传服务

- `uv run python upload_server.py -symboldir="C:/Symbols" [-port=8000]`

相关环境变量：

- Unix：`export KPHTOOLS_SYMBOLDIR="C:/Symbols"`
- Unix：`export KPHTOOLS_SERVER_PORT=8000`
- Windows CMD：`set KPHTOOLS_SYMBOLDIR=C:\Symbols`
- Windows CMD：`set KPHTOOLS_SERVER_PORT=8000`

常用 API：

- 健康检查：`curl "http://localhost:8000/health"`
- 上传 ntoskrnl：`curl -X POST -H "Content-Type: application/octet-stream" --data-binary "@C:/Windows/System32/ntoskrnl.exe" http://localhost:8000/upload`
- 存在性检查：`curl "http://localhost:8000/exists?filename=ntoskrnl.exe&arch=amd64&fileversion=10.0.26100.7462&sha256=<sha256>"`

## 测试与语法检查

按本工作区规则，未被用户明确要求时不要自行运行 test/build；需要验证时优先运行最小相关集合。

- 单个测试文件：`uv run python -m unittest tests.test_symbol_config -v`
- 多个测试文件：`uv run python -m unittest tests.test_dump_symbols tests.test_update_symbols -v`
- 单个测试类/方法：`uv run python -m unittest tests.test_update_symbols.TestUpdateSymbols.test_name -v`
- 全量测试：`uv run python -m unittest discover -s tests -v`
- 语法检查：`uv run python -m py_compile <changed_files>`

## Jenkins 主工作流参考

- `powershell -Command "Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/winsiderss/systeminformer/refs/heads/master/kphlib/kphdyn.xml' -OutFile kphdyn.official.xml"`
- `copy kphdyn.official.xml kphdyn.xml /y`
- `uv run python update_symbols.py -xml="%WORKSPACE%\kphdyn.xml" -symboldir="%WORKSPACE%\symbols" -syncfile`
- `uv sync`
- `uv run python download_symbols.py -xml="%WORKSPACE%\kphdyn.xml" -symboldir="%WORKSPACE%\symbols" -fast`
- `uv run python dump_symbols.py -symboldir="%WORKSPACE%\symbols" -configyaml="%WORKSPACE%\config.yaml"`
- `uv run python update_symbols.py -xml="%WORKSPACE%\kphdyn.xml" -symboldir="%WORKSPACE%\symbols" -configyaml="%WORKSPACE%\config.yaml" -syncfile`