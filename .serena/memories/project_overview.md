# 项目概览

- **目的**：为 SystemInformer 的 `kphdyn.xml` 生成/更新内核符号与结构偏移（struct_offset/func_offset）等动态数据；支持下载符号、解析 PDB、补全/修复偏移，以及基于 IDA + LLM 逆向缺失 PDB 的符号映射。
- **技术栈**：Python 脚本（CLI），配置文件为 XML/YAML；依赖 `pefile`, `requests`, `signify`, `openai`, `anthropic`, `PyYAML`。
- **外部工具**：
  - `llvm-pdbutil`（更新符号偏移/解析 PDB）
  - IDA Pro（`ida64.exe`，用于逆向）
  - 需要访问 Microsoft Symbol Server 下载符号
- **关键配置/数据文件**：`config.yaml`, `kphdyn.xml`
- **主要脚本**：`download_symbols.py`, `dump_symbols.py`, `update_symbols.py`, `upload_server.py`
