# kphtools FUNC_XREFS 与 AlpcpInitSystem 定位设计

## 背景

kphtools 当前的函数类 preprocessor 脚本通过 `FUNC_METADATA` 调用 PDB public symbol 解析，失败后进入 LLM decompile fallback。该路径适合已有 public symbol 或可通过参考反编译推断的目标，但缺少 CS2_VibeSignatures 中基于 xref 约束定位函数的通用能力。

参考项目 `CS2_VibeSignatures` 的 `FUNC_XREFS` 设计是：每个目标函数声明一组正向 xref 来源，分别收集候选函数集合并取交集；再通过排除项扣减候选；最终必须唯一命中一个函数。CS2 现有字段覆盖普通字符串、global variable、字节签名、函数引用和排除项，但没有 `xref_unicode_strings` 字段。本次 kphtools 需要在移植时补充 UTF-16 字符串匹配能力。

## 目标

- 为 kphtools 的 preprocessor 框架新增通用 `FUNC_XREFS` 函数定位能力。
- 保持 kphtools 当前函数 YAML 契约，输出 `func_name` 与 `func_rva`，不引入 CS2 的完整 `func_sig` 体系。
- 支持普通字符串、UTF-16 字符串、字节签名、gv xref、func xref 作为正向来源。
- 支持对应 exclude 字段用于消歧。
- 新增 `ida_preprocessor_scripts/find-AlpcpInitSystem.py`，用给定 `FUNC_XREFS` 定位 `AlpcpInitSystem`。
- 修改 `config.yaml`，让 `dump_symbols.py` 默认可以执行该脚本并导出 `AlpcpInitSystem.yaml`。

## 非目标

- 不移植 CS2 的 `func_sig` 生成、`func_size` 输出、vtable 关系、float xref 过滤或跨版本签名复用体系。
- 不改变现有 struct/gv preprocessor 行为。
- 不改变 `update_symbols.py` 对函数类 YAML 的读取契约。
- 不删除或重排已有 skill，除非新增项需要插入到 ntoskrnl 模块内。

## 接口设计

`ida_preprocessor_common.preprocess_common_skill` 增加可选参数：

```python
func_xrefs: list[dict[str, Any]] | None = None
```

每个 dict 支持以下字段：

```python
{
    "func_name": "AlpcpInitSystem",
    "xref_strings": [],
    "xref_unicode_strings": ["FULLMATCH:ALPC Port"],
    "xref_gvs": [],
    "xref_signatures": ["41 B8 41 6C 49 6E", "41 6C 4D 73"],
    "xref_funcs": [],
    "exclude_funcs": [],
    "exclude_strings": [],
    "exclude_unicode_strings": [],
    "exclude_gvs": [],
    "exclude_signatures": [],
}
```

校验规则：

- `func_xrefs` 为空时保持现有行为。
- 每项必须是 dict，`func_name` 必须是非空字符串。
- 除 `func_name` 外，每个字段必须是 list 或 tuple，并被规范化为 list。
- 不允许未知字段。
- 至少一个正向字段非空：`xref_strings`、`xref_unicode_strings`、`xref_gvs`、`xref_signatures`、`xref_funcs`。
- 重复 `func_name` 视为配置错误并返回失败。

## 定位流程

函数目标处理顺序保持保守：

1. 如果有 PDB，先使用现有 `FUNC_METADATA` alias 路径解析 public symbol。
2. 如果 PDB 路径失败，且目标函数存在 `FUNC_XREFS` spec，则执行 xref fallback。
3. 如果 xref fallback 失败，再进入现有 LLM decompile fallback。

xref fallback 的候选计算：

1. 对每个正向来源收集候选函数起点集合。
2. 对所有正向集合取交集。
3. 收集 exclude 字段命中的函数集合并从交集中扣除。
4. 若最终候选数量不是 1，则返回 `None`，让上层继续 fallback 或整体失败。
5. 唯一命中后返回：

```python
{"func_name": target_name, "func_va": target_va, "func_rva": target_va - image_base}
```

最终写 YAML 前仍由现有 `_filter_payload` 裁剪到脚本声明字段；`find-AlpcpInitSystem.py` 声明 `["func_name", "func_rva"]`。

## xref 字段语义

- `xref_strings`：枚举 IDA string list，默认子串匹配；`FULLMATCH:` 前缀启用完整字符串匹配。
- `xref_unicode_strings`：枚举 IDA string list 中 UTF-16/Unicode 字符串，匹配规则同 `xref_strings`。`FULLMATCH:ALPC Port` 表示完整匹配 UTF-16 字符串 `L"ALPC Port"`。
- `xref_signatures`：通过 MCP `find_bytes` 搜索字节模式，支持现有 MCP 模式语义；每个匹配地址归一化到所在函数起点。
- `xref_gvs`：支持显式 `0x...` 地址，或从当前 binary dir 的 YAML 中读取 `gv_va` / `gv_rva` 后收集引用该地址的函数。
- `xref_funcs`：支持显式 `0x...` 地址，或从当前 binary dir 的 YAML 中读取 `func_va` / `func_rva` 后收集引用该函数地址的函数。
- `exclude_*`：收集方式与对应正向字段一致，但只用于从交集结果中扣除。缺少命中不是失败；解析依赖 YAML 失败才是失败。

## AlpcpInitSystem 脚本

新增文件 `ida_preprocessor_scripts/find-AlpcpInitSystem.py`：

- `TARGET_FUNCTION_NAMES = ["AlpcpInitSystem"]`
- `FUNC_XREFS` 使用用户提供的配置。
- `GENERATE_YAML_DESIRED_FIELDS = {"AlpcpInitSystem": ["func_name", "func_rva"]}`
- `preprocess_skill(...)` 调用 `preprocessor_common.preprocess_common_skill(..., func_names=TARGET_FUNCTION_NAMES, func_xrefs=FUNC_XREFS, generate_yaml_desired_fields=...)`

同时更新 `config.yaml` 的 ntoskrnl 模块：

- skills 增加 `find-AlpcpInitSystem`，输出 `AlpcpInitSystem.yaml`。
- symbols 增加 `AlpcpInitSystem`，`category: func`，`data_type: uint32`。

## 错误处理

- 配置非法时返回 `PREPROCESS_STATUS_FAILED`，保持现有 preprocessor 风格。
- IDA MCP 工具异常、无法解析 JSON、无法归一化函数起点时，xref fallback 返回 `None`。
- 正向字段任一来源没有候选时，xref fallback 返回 `None`。
- 最终候选非唯一时返回 `None`，不猜测目标。
- debug 模式输出候选数量、失败字段和最终候选概览，避免泄漏大量反汇编内容。

## 测试设计

新增或扩展现有 unittest：

- `ida_preprocessor_common` 校验 `func_xrefs` 支持字段、拒绝未知字段、拒绝空正向来源、拒绝重复目标。
- PDB 解析失败后会调用 xref fallback，xref 成功后写出 `func_rva`。
- `find-AlpcpInitSystem.py` 能将 `FUNC_XREFS` 和 desired fields 正确传给 common preprocessor。
- UTF-16 `FULLMATCH:` 查询生成的 IDA Python 代码包含 exact match 与 Unicode 字符串类型过滤。
- 签名匹配结果会归一化为函数起点；非唯一候选时返回失败。

按用户的仓库规则，代码完成后不主动运行完整 test/build。若需要验证，建议执行定向测试：

```bash
uv run python -m unittest tests.test_ida_preprocessor_common tests.test_ida_skill_preprocessor
```

## 验收标准

- `find-AlpcpInitSystem.py` 存在并可由 `ida_skill_preprocessor` 加载。
- `config.yaml` 中包含 `AlpcpInitSystem` skill 与 func symbol。
- 给定 `FUNC_XREFS` 能表达 `FULLMATCH:ALPC Port` 的 UTF-16 完整匹配和两个字节签名交集。
- PDB public symbol 路径不受影响。
- 没有引入 CS2 `func_sig` 输出契约变更。
