# kphtools NtSecureConnectPort NtAPI 提取设计

## 背景

`kphtools` 的函数类 IDA preprocessor 当前主要通过 PDB public symbol、
`FUNC_XREFS` 和 LLM decompile fallback 定位函数。`NtSecureConnectPort` 在目标
`ntoskrnl` 中可以通过一个稳定表项模式定位：

- 搜索特征码 `5D 53 26 88 09 00 00 00`
- 特征码后 8 字节是一个 64 位 VA
- 如果该 VA 位于 `PAGE` 或 `.text` 段，则该 VA 对应 `NtSecureConnectPort`

这类规则不是 xref 交集定位，也不适合放进 `FUNC_XREFS`。本次新增一个专门的
NtAPI 表项提取 helper，让未来新增类似 NtAPI 时只需要编写薄脚本声明目标名和特征码。

## 目标

1. 新增 `ida_preprocessor_scripts/find-NtSecureConnectPort.py`。
2. 新增公共 helper `ida_preprocessor_scripts/_extract_ntapi.py`。
3. 每个 NtAPI 脚本独立声明特征码，公共 helper 只负责共享搜索和判定逻辑。
4. 解析顺序为 PDB public symbol 优先；PDB 缺失或解析失败后，再使用特征码 fallback。
5. 输出 YAML 保持函数类契约：`func_name` 与 `func_rva`，并由 artifact writer 添加 `category: func`。
6. 更新 `config.yaml` 的 `skills`，让默认 ntoskrnl workflow 能生成 `NtSecureConnectPort.yaml`。
7. 不在 `config.yaml` 的 `symbols` 中新增 `NtSecureConnectPort`，避免 XML 同步追加该符号。
8. 放宽配置测试，不再要求每个配置 skill 都有 `.claude/skills/<skill>/SKILL.md`。

## 非目标

1. 不把 NtAPI 表项提取规则接入 `ida_preprocessor_common.py`。
2. 不扩展 `FUNC_XREFS` 语义。
3. 不新增 `.claude/skills/find-NtSecureConnectPort/SKILL.md`。
4. 不改变现有 struct/gv/func PDB、xref、LLM decompile 路径。
5. 不引入新的 YAML 字段或依赖。
6. 不把 `NtSecureConnectPort` 加入 XML 导出符号清单。

## 架构

### 薄脚本

`ida_preprocessor_scripts/find-NtSecureConnectPort.py` 只负责声明和转发：

```python
TARGET_FUNCTION_NAMES = ["NtSecureConnectPort"]

NTAPI_SIGNATURES = {
    "NtSecureConnectPort": ["5D 53 26 88 09 00 00 00"],
}

GENERATE_YAML_DESIRED_FIELDS = {
    "NtSecureConnectPort": ["func_name", "func_rva"],
}
```

`preprocess_skill(...)` 直接调用：

```python
_extract_ntapi.preprocess_ntapi_symbols(
    session=session,
    symbol=symbol,
    binary_dir=binary_dir,
    pdb_path=pdb_path,
    debug=debug,
    target_function_names=TARGET_FUNCTION_NAMES,
    ntapi_signatures=NTAPI_SIGNATURES,
    generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
)
```

`llm_config` 保留在签名中以匹配 preprocessor dispatcher，但 helper 不使用它。

### 公共 helper

`ida_preprocessor_scripts/_extract_ntapi.py` 导出：

```python
async def preprocess_ntapi_symbols(...):
    ...
```

职责：

1. 校验当前 `symbol.name` 属于 `target_function_names`。
2. 校验目标有对应 `ntapi_signatures` 和 desired fields。
3. 先尝试 `resolve_public_symbol(pdb_path, symbol.name)`。
4. PDB 成功时直接写出 `func_rva`。
5. PDB 缺失或 public symbol 解析失败时，执行特征码 fallback。
6. fallback 成功后写出 `func_name` 与 `func_rva`。

helper 不负责：

- 调度 skill
- 解析 `config.yaml`
- 处理 LLM fallback
- 管理其他函数定位体系

## 定位流程

特征码 fallback 的流程固定为：

1. 调用 MCP `find_bytes` 搜索 `ntapi_signatures[symbol.name]` 中的每个特征码。
2. 收集所有匹配地址。
3. 通过 `py_eval` 在 IDA 内对每个匹配地址执行：
   - 读取 `match_ea + 8` 处的 qword，得到候选 VA。
   - 查询候选 VA 所在 segment。
   - 只接受 segment 名称为 `PAGE` 或 `.text` 的候选。
   - 使用 IDA image base 计算 `func_rva = candidate_va - image_base`。
4. 所有特征码得到的有效候选去重后必须唯一。
5. 候选唯一则成功；无候选或多候选均失败，不猜测。

节名匹配使用精确匹配，默认允许集合为：

```python
{"PAGE", ".text"}
```

## 错误处理

- 目标名不在脚本声明中，返回 failed。
- desired fields 非法或缺少 `func_name`/`func_rva`，返回 failed。
- `find_bytes` 调用异常、结果 JSON 解析失败，返回 failed。
- `py_eval` 调用异常、结果 JSON 解析失败，返回 failed。
- PDB 解析失败不直接失败，而是进入特征码 fallback。
- 特征码 fallback 无候选或多候选，返回 failed。
- debug 模式输出 PDB miss、候选数量和候选地址概览，不输出大段反汇编。

## 配置变更

`config.yaml` 的 `ntoskrnl` 模块新增 skill：

```yaml
- name: find-NtSecureConnectPort
  expected_output:
  - NtSecureConnectPort.yaml
```

`symbols` 不新增 `NtSecureConnectPort`。

这需要把配置语义拆清楚：

- `module.symbols` 是 XML/export inventory，只列出需要进入 `kphdyn.xml` 的符号。
- `skill.expected_output` 是 preprocessor artifact inventory，可以包含不进入 XML 的中间产物或辅助产物。
- `NtSecureConnectPort.yaml` 属于 preprocessor-only artifact，不参与 `update_symbols.py` 的 XML 字段收集。

新增 skill 不依赖 `AlpcpInitSystem` 或 `AlpcpDeletePort` 的输出。

## 配置加载与 dump 行为

当前 `symbol_config.load_config()` 会要求所有 `skill.expected_output` 都能在
`module.symbols` 中找到同名 `SymbolSpec`。这个约束需要放宽：

1. `load_config()` 不再因为 `expected_output` 缺少同名 `SymbolSpec` 而失败。
2. `dump_symbols.py` 处理缺少 `SymbolSpec` 的输出时，按 artifact 文件名构造轻量 symbol 对象，至少包含 `name`。
3. `find-NtSecureConnectPort.py` 和 `_extract_ntapi.py` 只依赖 `symbol.name`，不依赖 `symbol.category` 或 `symbol.data_type`。
4. 现有依赖 `symbol.category` 的通用 preprocessor 不受影响；它们的输出仍应保留在 `module.symbols` 中。
5. `update_symbols.py` 继续只遍历 `module.symbols`，因此不会读取或导出 `NtSecureConnectPort.yaml`。

## 测试设计

新增或调整以下测试：

1. `_extract_ntapi` PDB 成功时直接写出 `func_rva`，不调用 `find_bytes`。
2. PDB miss 后进入特征码 fallback。
3. fallback 会读取 `match_ea + 8` 的 qword。
4. 候选 VA 在 `PAGE` 或 `.text` 段时接受。
5. 候选 VA 在其他段时拒绝。
6. 有效候选非唯一时失败。
7. `find-NtSecureConnectPort.py` 能把 `NTAPI_SIGNATURES` 和 desired fields 传给 helper。
8. `symbol_config.load_config()` 允许 `skill.expected_output` 中存在不属于 `module.symbols` 的 artifact。
9. `dump_symbols.py` 能对缺少 `SymbolSpec` 的 preprocessor-only artifact 调用对应脚本。
10. `update_symbols.py` 不会把不在 `module.symbols` 中的 `NtSecureConnectPort.yaml` 导出到 XML。
11. `tests/test_ida_skill_preprocessor.py` 的仓库配置检查只要求脚本存在，不再要求 `.claude/skills/<skill>/SKILL.md` 存在。

按仓库规则，代码完成后不主动运行完整 test/build。建议实现完成后按需执行定向测试：

```bash
python -m unittest tests.test_ida_skill_preprocessor tests.test_extract_ntapi
```

## 验收标准

1. `find-NtSecureConnectPort.py` 存在并可由 `ida_skill_preprocessor` 加载。
2. `config.yaml` 中包含 `find-NtSecureConnectPort` skill。
3. `config.yaml` 的 `symbols` 中不包含 `NtSecureConnectPort`。
4. 有 PDB public symbol 时优先使用 PDB 结果。
5. PDB 缺失或解析失败时，使用特征码 `5D 53 26 88 09 00 00 00` 的后 8 字节 VA。
6. 只有 VA 位于 `PAGE` 或 `.text` 段时才接受候选。
7. `NtSecureConnectPort.yaml` 输出 `category: func`、`func_name` 和 `func_rva`。
8. `update_symbols.py` 不会把 `NtSecureConnectPort` 追加到 XML。
9. 不新增 `.claude/skills/find-NtSecureConnectPort/SKILL.md`。
