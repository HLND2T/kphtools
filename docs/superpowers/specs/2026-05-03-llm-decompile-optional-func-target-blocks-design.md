# LLM_DECOMPILE optional funcs target blocks 设计

日期：2026-05-03

## 1. 摘要

本设计扩展 `kphtools` 的 `LLM_DECOMPILE` 公共流程，使 reference YAML 中的 `optional_funcs` 可以参与目标函数导出。

当前 `ida_preprocessor_scripts/find-ObAttributesShift-AND-ObDecodeShift.py` 依赖：

`ida_preprocessor_scripts/references/ntoskrnl/ObpEnumFindHandleProcedure.{arch}.yaml`

在部分 Windows 版本中，`ObpEnumFindHandleProcedure` 会调用 `ExGetHandlePointer`；在另一些版本中，`ExGetHandlePointer` 会被编译器内联成几条位运算指令。为了让 LLM 能同时识别“函数调用形态”和“内联指令形态”，当 reference YAML 中声明的 `optional_funcs` 在当前 IDB 中存在时，需要把这些函数也导出并加入 prompt 的 `{target_blocks}`。

同时，多个 target function 同时出现在 prompt 中时，每个函数的反汇编块必须在头部显式标注函数名，避免 LLM 混淆某段反汇编属于哪个函数。

## 2. 目标

1. 支持 reference YAML 顶层 `optional_funcs` 字段。
2. 当 `optional_funcs` 中的函数在当前 IDB 存在时，把它们加入 `LLM_DECOMPILE` 的 target function 列表。
3. 当 `optional_funcs` 中的函数不存在时，静默跳过，不导致本次 `LLM_DECOMPILE` 失败。
4. 保持主 reference 函数仍然是必需目标；主目标不存在时继续按现有逻辑失败。
5. 在 `{target_blocks}` 中为每个函数的反汇编内容显式标注函数名。
6. 让能力位于公共 `LLM_DECOMPILE` 流程，避免只为单个 finder 写特判。

## 3. 非目标

1. 本次不改变 `LLM_DECOMPILE` tuple 的四字段结构。
2. 本次不修改 `find-ObAttributesShift-AND-ObDecodeShift.py` 的 `LLM_DECOMPILE` 声明。
3. 本次不要求 `optional_funcs` 中的函数一定出现在当前 IDB。
4. 本次不把 optional function 当作新的 reference function。
5. 本次不重新设计 prompt 模板。
6. 本次不执行真实 LLM 调用作为验收条件。

## 4. 方案比较与结论

### 4.1 方案 1：公共请求准备层扩展 target function 列表

在 `ida_mcp_resolver.py` 的 `LLM_DECOMPILE` 请求准备阶段读取 `optional_funcs`，把主函数和当前 reference 声明的 optional functions 合并为 target function name 列表。

优点：

- 所有 `LLM_DECOMPILE` finder 都能复用该能力。
- 不需要修改每个 finder 的 `LLM_DECOMPILE` tuple。
- 复用现有 `_load_llm_decompile_target_details_via_mcp(...)` 的查找和导出逻辑。
- optional function 不存在时，现有导出路径已经可以 debug log 后继续。

缺点：

- 需要让 reference YAML 校验逻辑保留一个新的可选字段。

### 4.2 方案 2：只在 `find-ObAttributesShift-AND-ObDecodeShift.py` 特判

在该 finder 中额外声明 `ExGetHandlePointer`，并让公共流程只服务当前需求。

优点：

- 单点影响面最小。

缺点：

- reference YAML 中 `optional_funcs` 的语义无法公共复用。
- 后续其他 reference 也遇到内联 helper 时需要重复实现。
- finder 会承担 prompt 目标扩展职责，边界不清晰。

### 4.3 方案 3：在 prompt 渲染层临时拼接 optional blocks

在 `_render_llm_decompile_blocks(...)` 附近根据 optional function 追加文本块。

优点：

- 靠近 `{target_blocks}` 输出点。

缺点：

- 渲染层会被迫知道 YAML schema、函数查找和导出细节。
- 容易把数据准备和文本格式化职责混在一起。

### 4.4 选定方案

采用方案 1：在公共请求准备层扩展 target function 列表。

## 5. Reference YAML schema

reference YAML 当前核心字段保持不变：

```yaml
func_name: ObpEnumFindHandleProcedure
func_va: "0x1406c6cd0"
disasm_code: |
  ...
procedure: |
  ...
```

新增可选字段：

```yaml
optional_funcs:
  - ExGetHandlePointer
```

约束：

1. `optional_funcs` 可以不存在。
2. `optional_funcs` 存在时必须是字符串列表。
3. 空字符串、非字符串元素或非列表值视为 invalid reference YAML。
4. `optional_funcs` 只表示“如果当前 IDB 中存在，就作为额外 target function 导出”。
5. `optional_funcs` 不改变 reference function 的身份，也不参与 `reference_blocks`。

## 6. 数据流设计

### 6.1 请求准备

`_prepare_llm_decompile_request(...)` 继续按 `LLM_DECOMPILE` spec 找到 reference YAML。

加载每个 reference YAML 后：

1. 读取主 `func_name`。
2. 读取可选 `optional_funcs`。
3. 把主 `func_name` 加入 `target_func_names`。
4. 再按 YAML 顺序追加 `optional_funcs`。
5. 对合并后的目标函数名去重，保持首次出现顺序。

示例：

```yaml
func_name: ObpEnumFindHandleProcedure
optional_funcs:
  - ExGetHandlePointer
```

生成：

```python
target_func_names = [
    "ObpEnumFindHandleProcedure",
    "ExGetHandlePointer",
]
```

### 6.2 目标函数导出

`resolve_symbol_via_llm_decompile(...)` 继续调用 `_load_llm_decompile_target_details_via_mcp(...)`。

该函数按 `target_func_names` 遍历：

1. 优先从当前 binary_dir 中的 `{func_name}.yaml` 读取 `func_va` 或 `func_rva`。
2. 没有可用 artifact 时，到当前 IDB 中按函数名查找。
3. 找到后导出反汇编和伪代码。
4. 找不到时记录 debug log 并继续。

本设计要求：

- 主 reference function 仍然必须导出成功；如果主函数不存在，本次 `LLM_DECOMPILE` 不能继续。
- optional function 导出失败或不存在时只跳过，不影响主函数 prompt。

### 6.3 Prompt 渲染

`_render_llm_decompile_blocks(...)` 继续生成 `reference_blocks` 和 `target_blocks`。

每个 target block 内部必须明确写出函数名，推荐格式：

````markdown
### Target Function: ExGetHandlePointer

**Disassembly for ExGetHandlePointer**

```c
; Function: ExGetHandlePointer
...
```

**Procedure for ExGetHandlePointer**

```c
...
```
````

关键要求：

1. Markdown 小标题继续保留函数名。
2. 反汇编代码块头部也要有函数名标记。
3. reference block 可以采用同样格式，保持对称性。
4. 该标记只影响 prompt 文本，不改变导出的 YAML 工件。

## 7. 错误处理

1. `optional_funcs` 缺失：等价于空列表。
2. `optional_funcs` 为合法空列表：等价于空列表。
3. `optional_funcs` schema 非法：reference YAML invalid，本次 `LLM_DECOMPILE` 跳过并返回失败。
4. optional function 在当前 IDB 不存在：debug log 后跳过。
5. optional function 导出失败：debug log 后跳过。
6. 主 reference function 在当前 IDB 不存在或导出失败：本次 `LLM_DECOMPILE` 失败。

## 8. 测试设计

新增或调整单元测试覆盖以下行为：

1. `validate_reference_yaml_payload(...)` 保留合法 `optional_funcs`。
2. `validate_reference_yaml_payload(...)` 拒绝非法 `optional_funcs`。
3. `_prepare_llm_decompile_request(...)` 会把主函数和 `optional_funcs` 合并到 `target_func_names`。
4. 多个 reference YAML 或重复 optional function 时，`target_func_names` 去重并保持顺序。
5. optional function 查找失败时，`LLM_DECOMPILE` 仍然使用主函数继续调用。
6. 主 reference function 查找失败时，本次请求失败。
7. `call_llm_decompile(...)` 生成的 prompt 中，每个 target block 的反汇编区域包含对应函数名。

验收不需要真实调用 LLM；通过 mock `call_llm_text`、MCP session 和目标函数导出结果即可验证 prompt 和控制流。

## 9. 影响范围

预计修改文件：

- `ida_reference_export.py`
- `ida_mcp_resolver.py`
- `tests/test_ida_reference_export.py`
- `tests/test_ida_mcp_resolver.py`

预计不修改：

- `ida_preprocessor_scripts/find-ObAttributesShift-AND-ObDecodeShift.py`
- `ida_preprocessor_scripts/references/ntoskrnl/ObpEnumFindHandleProcedure.amd64.yaml`
- `ida_preprocessor_scripts/prompt/call_llm_decompile.md`

## 10. 验收标准

1. `ObpEnumFindHandleProcedure.amd64.yaml` 中现有 `optional_funcs: [ExGetHandlePointer]` 被公共流程读取。
2. 当前 IDB 中存在 `ExGetHandlePointer` 时，`ExGetHandlePointer` 出现在 `{target_blocks}`。
3. 当前 IDB 中不存在 `ExGetHandlePointer` 时，主 `ObpEnumFindHandleProcedure` 仍然可以进入 `{target_blocks}`。
4. `{target_blocks}` 中每个函数的反汇编块头部都明确包含该函数名。
5. 单元测试覆盖 schema、请求准备、缺失跳过、主函数失败和 prompt 渲染。
