# MCP / py_eval 返回格式经验

最后核对日期：2026-05-04。

## 标题

MCP tool JSON 解析必须兼容多种返回形态。

## 触发信号

- 预处理日志出现 `preprocess status ... failed`，但真实 MCP tool 已经返回有效命中。
- `find_bytes`、`py_eval` 或其他 MCP tool 的返回值被解析成 `None`，后续逻辑误判为无结果。
- 代码中出现直接 `json.loads(payload["result"])` 或只支持 `{"result": "..."}` 包装格式的解析逻辑。

## 根因 / 约束

- 当前 MCP tool 返回格式不完全统一。
- 已观察到 `find_bytes` 可直接返回顶层 JSON list，例如 `[{"pattern": "...", "matches": [...] }]`。
- 已观察到 `py_eval` 当前仍返回包装对象，例如 `{"result": "{...}", "stdout": "", "stderr": ""}`。
- 因此解析 helper 不能只假定 `payload["result"]` 存在，也不能只假定 `result` 一定是字符串。

## 正确做法

解析 MCP tool 结果时采用兼容模式：

1. 读取 `tool_result.content[0].text`。
2. `json.loads(text)` 得到 `payload`。
3. 如果 `payload` 不是 dict，或 dict 中没有 `result`，直接返回 `payload`。
4. 如果存在 `result` 且其值是字符串，对该字符串再执行 `json.loads(...)`。
5. 如果存在 `result` 且其值已经是对象，直接返回该对象。
6. 解析失败时返回 `None` 或抛出调用方既有约定中的错误，不吞掉非预期业务异常。

推荐实现形态参考：`ida_preprocessor_scripts/generic_func.py::_parse_tool_json_result`、`ida_preprocessor_scripts/find-PgInitContext.py::_parse_tool_json_result`、`ida_preprocessor_scripts/_extract_ntapi.py::_parse_tool_json_result`。

## 验证方式

- 为解析 helper 添加两类单测：
  - 旧格式：`{"result": "{...}"}` 或 `{"result": "[...]"}`。
  - 新格式：直接顶层 JSON dict/list。
- 对真实 MCP 行为可用 `LazyIdalibSession` 临时调用：
  - `find_bytes` 验证是否直接返回 JSON list。
  - `py_eval` 验证是否仍返回 `result/stdout/stderr` 包装对象。
- 修复具体预处理失败时，重跑对应 `dump_symbols.py -skill ... -debug`，确认日志从 `failed` 变为 `success` 并写出目标 YAML。

## 适用范围

- `ida_preprocessor_scripts/` 中所有 MCP tool 解析逻辑。
- `ida_mcp_resolver.py`、`dump_symbols.py`、`generate_reference_yaml.py`、`ida_reference_export.py` 中所有 `py_eval`/MCP 返回解析逻辑。
- 新增 MCP tool 调用时优先复用或抽取兼容解析 helper，避免复制只支持旧格式的 `json.loads(payload["result"])`。