# kphtools LLM_DECOMPILE CS2 能力对齐实施计划

日期：2026-07-21

## 1. 目标

把 `D:\CS2_VibeSignatures` 当前 `LLM_DECOMPILE` 的以下能力完整迁移到
`kphtools`：

1. LLM 幻觉校验。
2. 自动纠错对话和验证重试。
3. LLM transport 的暂时性错误识别与指数退避重试。
4. OpenAI Chat Completions API（替换 legacy Completions API）。
5. 完整的 Codex `/responses` SSE 模拟 transport。
6. 目标代码清理和更完整的模板上下文。
7. 把全部 `LLM_DECOMPILE` 声明从 kphtools 四元组迁移为与 CS2 相同的 strict dict
   schema。

本计划中的“1:1”指上述能力的可观察行为、请求/响应约束、错误分类、重试语义和
测试场景与 CS2 对齐；不是把同步实现逐行复制到 kphtools。kphtools 继续保持现有
async 调用链，并保留 Windows 内核特有的 reference、optional function、code-region
target 和缓存能力。

## 2. 源版本基线

移植必须以以下固定版本为基线，避免实现期间继续追随 CS2 工作区的浮动内容：

- 源仓库：`D:\CS2_VibeSignatures`
- 源提交：`3ad7a23f37c2009269765133d719b5efbcebadb6`
- 目标仓库基线：`142f5bc05fdd5cbfa2280d373b29eef836971c4e`
- `ida_llm_utils.py` SHA-256：
  `668CEE02A0A5EAC8B2735249B04FAD263D9487F2A80F44007C8E5BF8386603BF`
- `ida_llm_decompile.py` SHA-256：
  `D1461B971F6DD48CEAD6C0EEB6C4C19BBD31F936396B028027066B74A06C6956`
- `codex_faker.json` SHA-256：
  `D5A9A5BBB0AF41C97785C8F9B18E0A0CDE70ABE9D928F48E32CDFECE4D49B40E`
- `ida_preprocessor_scripts/prompt/call_llm_decompile.md` SHA-256：
  `9AFAFAC46A0ECE8C7C74AF9D41079CE4CD2097D07C7570C0000F15D23BB2CD47`

实现 PR 必须在说明中列出相对该源提交的有意差异。除第 3 节列出的适配外，不得
省略源实现中的校验、错误分支或测试场景。

## 3. 范围与硬性决策

### 3.1 支持的结果类型

kphtools 仅支持以下四类结果：

- `found_call`：直接调用或直接 tail jump。
- `found_funcptr`：对非虚普通函数地址的直接引用。
- `found_gv`：全局变量引用。
- `found_struct_offset`：结构体成员访问。

`found_vcall` 暂不支持，原因是 kphtools 面向 Windows 内核，当前 finder 没有稳定的
虚调用需求。这个限制必须同时写入：

- `ida_llm_decompile.py` 的公共结果契约。
- `ida_preprocessor_scripts/prompt/call_llm_decompile.md`。
- `README.md` 的 LLM_DECOMPILE 文档。
- parser/schema/correction tests。

模型返回 `found_vcall` 时不得静默忽略；它应当被分类为 schema mismatch，并在仍有
重试预算时收到“暂不支持，请改用四类受支持结果或返回空结果”的纠错消息。重试耗尽
后 fail closed，返回四个空列表。

规范空结果固定为：

```yaml
found_call: []
found_funcptr: []
found_gv: []
found_struct_offset: []
```

### 3.2 允许的有意差异

相对 CS2 源实现只允许以下差异：

1. 删除所有 `found_vcall` schema、offset 校验、prompt 示例和下游分支。
2. 使用 `AsyncOpenAI` 和 `httpx.AsyncClient` 实现等价的异步 transport；不得在 event
   loop 内执行同步网络 I/O。
3. `codex_faker.json` 中的 workspace/environment 文本改为 kphtools，不得残留
   `CS2_VibeSignatures`。
4. `{platform}` 在 kphtools 中继续表示 `amd64`/`arm64`，并新增 `{module_name}`；保留
   现有 `{arch}` 兼容替换。
5. dict 的 `symbol_name` 表示 kphtools artifact 名；结构体成员的 LLM 语义查询名从
   `STRUCT_METADATA.symbol_expr` 或 `struct_name/member_name` 派生，不向 CS2 schema
   增加 `llm_query_name` 扩展字段。
6. 保留 kphtools 的 glued YAML header repair 兼容逻辑，但它只能作为候选修复；修复后
   仍必须通过完整 schema 和语义校验。

### 3.3 非目标

- 不新增 vtable/vfunc artifact 或虚函数 slot 解析。
- 不删除 `optional_funcs`、code-region target 或现有 result cache。
- 不把真实外部 LLM 调用作为默认单元测试条件。
- 不改变 PDB、普通 IDA MCP fast path 或 agent fallback 的成功优先级。
- 不保留 legacy tuple compatibility；全部 finder 迁移完成后，tuple 输入必须 fail closed。

### 3.4 LLM_DECOMPILE dict schema

每个 entry 必须与 CS2 使用完全相同的五个字段，不允许缺失字段或未知字段：

```python
{
    "symbol_name": "EpCookie",
    "prompt_path": "prompt/call_llm_decompile.md",
    "reference_yaml_paths": [
        "references/ntoskrnl/PspAllocateProcess.{arch}.yaml",
    ],
    "expected_result_sections": ["found_struct_offset"],
    "dependency_policy": {
        "PspAllocateProcess.yaml": "required",
    },
}
```

字段语义：

- `symbol_name`：唯一的 kphtools artifact 名，也是 specs map 的 key。
- `prompt_path`：相对 `ida_preprocessor_scripts` 的 prompt 路径。
- `reference_yaml_paths`：非空字符串列表；一个 symbol 的多份 reference 合并在同一个
  entry 中，不再通过重复 tuple 表达。
- `expected_result_sections`：非空、去重后的受支持 section 列表，必须显式声明，不能再
  从 category 静默推导。
- `dependency_policy`：非空 dict；key 是 reference YAML 的 `func_name` 在当前 binary dir
  对应的 target artifact basename，不含目录；value 只能是 `required` 或 `optional`。

校验器必须加载每个 `reference_yaml_paths`，读取其 `func_name` 并按 kphtools artifact
命名规则推导 `<func_name>.yaml`；该集合必须与 `dependency_policy` key 一一对应。不能
机械使用 reference 文件 basename，因为 reference 是架构化静态样本（例如
`PspAllocateProcess.amd64.yaml`），当前 binary dir 输入则是 `PspAllocateProcess.yaml`。
`required` 依赖必须来自当前 skill 的 `expected_input`（含 arch-specific inputs）；
`optional` 依赖必须来自新增的 `optional_input`（含 arch-specific inputs）。同一 target
artifact basename 不得同时出现在 required/optional input 中。

删除旧 tuple 第二项 `llm_query_name` 后，prompt/response 的语义名按以下规则派生：

- `struct_offset`：优先使用 `STRUCT_METADATA[symbol_name]["symbol_expr"]`；否则由
  `struct_name` 与 `member_name` 构造 `Struct->Member`。
- `func`、`gv`：默认使用 `symbol_name`。

派生结果只存在于运行时 request context，不进入 spec dict。迁移测试必须逐项证明新
dict 生成的语义查询名与旧四元组第二项相同，避免 KPH 缩写 artifact（例如
`EpCookie`）丢失 `_EPROCESS->Cookie` 语义。

## 4. 目标架构

将 CS2 的单文件实现按 kphtools 的单文件上限拆为四个内部模块，并把 MCP target
导出从 `ida_mcp_resolver.py` 拆出。模块边界如下：

```text
dump_symbols.py
  -> 构造每个 skill 的 effective llm_config
ida_preprocessor_common.py
  -> 校验 spec/category 兼容性并构造 artifact -> semantic query name 映射
ida_mcp_resolver.py
  -> 准备请求、调用 LLM facade、把已验证结果转换为 artifact payload
ida_llm_targets.py
  -> 当前 IDB 的 function/code-region detail 导出和 direct ref target 解析
ida_llm_decompile.py
  -> 公共 facade、构造对话、统一 retry budget、调用 transport
ida_llm_prompt.py
  -> 目标代码清理、block 渲染、模板上下文和 prompt/correction 文本
ida_llm_response.py
  -> YAML candidate 提取、四类 schema 校验、canonical/wrapped response 规范化
ida_llm_validation.py
  -> instruction index、请求 symbol/section 语义校验和 structured issues
ida_llm_specs.py
  -> strict dict 规范化、dependency policy、category compatibility 和 query-name context
ida_llm_utils.py
  -> OpenAI Chat Completions 或 Codex Responses SSE transport
```

职责约束：

- `ida_llm_utils.py` 不理解反汇编或 YAML schema。
- `ida_llm_decompile.py`、`ida_llm_prompt.py`、`ida_llm_response.py` 和
  `ida_llm_validation.py` 不调用 MCP、不读当前 IDB、不写 artifact。
- `ida_llm_targets.py` 是唯一可调用 MCP/IDA detail export 的新模块。
- `ida_llm_specs.py` 是 dict schema 与 dependency policy 的唯一校验入口。
- `ida_mcp_resolver.py` 不再保留第二套 LLM parser/retry 实现。
- `ida_preprocessor_common.py` 只提供 category/metadata context，不复制 spec 规范化逻辑。

## 5. 文件变更范围

新增：

- `ida_llm_decompile.py`
- `ida_llm_prompt.py`
- `ida_llm_response.py`
- `ida_llm_validation.py`
- `ida_llm_targets.py`
- `ida_llm_specs.py`
- `codex_faker.json`
- `tests/test_ida_llm_utils.py`
- `tests/test_ida_llm_decompile.py`
- `tests/test_ida_llm_response.py`
- `tests/test_ida_llm_validation.py`
- `tests/test_ida_llm_targets.py`
- `tests/test_ida_llm_specs.py`
- `tests/test_llm_decompile_preprocessor_integration.py`
- `tests/test_llm_decompile_dump_integration.py`

修改：

- `ida_llm_utils.py`
- `ida_mcp_resolver.py`
- `ida_preprocessor_common.py`
- `ida_skill_preprocessor.py`
- `dump_symbols.py`
- `symbol_config.py`
- `config.yaml`（仅在 audit 发现 optional dependency 时）
- `ida_preprocessor_scripts/prompt/call_llm_decompile.md`
- 使用 `LLM_DECOMPILE` 的全部 `ida_preprocessor_scripts/find-*.py`
- `tests/test_ida_mcp_resolver.py`
- `tests/test_symbol_config.py`
- `tests/test_ida_skill_preprocessor.py`
- `README.md`

原则上不修改：

- `pyproject.toml` 和 `uv.lock`，因为 `openai`、`httpx`、`PyYAML` 已存在。
- reference YAML schema 和生成流程。

## 6. Task 1：把全部 LLM_DECOMPILE 声明迁移为 CS2 dict

**Files:**

- Create: `ida_llm_specs.py`
- Modify: all `ida_preprocessor_scripts/find-*.py` containing `LLM_DECOMPILE`
- Modify: `ida_preprocessor_common.py`
- Modify: `ida_skill_preprocessor.py`
- Modify: `symbol_config.py`
- Modify: `config.yaml` when optional inputs are required
- Test: `tests/test_ida_llm_specs.py`
- Test: `tests/test_symbol_config.py`
- Test: `tests/test_ida_skill_preprocessor.py`

- [ ] 移植 CS2 `_LLM_DECOMPILE_REQUIRED_SPEC_KEYS`、strict unknown-key rejection、
  `_normalize_string_list(...)`、`_normalize_llm_decompile_spec(...)` 和 duplicate symbol
  rejection。
- [ ] `expected_result_sections` 的 valid values 只允许四类 kphtools contract；
  `found_vcall` 在 spec normalization 阶段即失败。
- [ ] `dependency_policy` 只接受 basename template 和 `required|optional`，拒绝 path
  separator、空 policy、重复解析 basename 和未知 policy。
- [ ] 加载每个 reference YAML 的 `func_name`，按 `<func_name>.yaml` 推导 target artifact；
  校验推导集合与 policy key 一一对应，禁止以 reference 文件 basename 代替 target
  artifact basename。
- [ ] 在 `SkillSpec`/config parser 增加 `optional_input`、`optional_input_amd64`、
  `optional_input_arm64`，语义与现有 expected inputs 对称。
- [ ] 把当前 skill/arch 的 expected/optional inputs 注入 LLM spec validation context，检测
  basename 歧义、required/optional overlap 和 policy/config mismatch。
- [ ] 显式校验 `expected_result_sections` 与 artifact category 兼容：
  - `func` -> `found_call` 或 `found_funcptr`
  - `gv` -> `found_gv`
  - `struct_offset` -> `found_struct_offset`
- [ ] 从 metadata 构造 `artifact_symbol_name -> semantic_query_name`；结构体必须保留旧
  tuple 中的 `Struct->Member` 语义。
- [ ] 将重复 symbol 的多条旧 tuple 合并为一个 dict 和多个 `reference_yaml_paths`；policy
  必须覆盖每个 reference basename。
- [ ] 批量迁移所有 finder；迁移完成后删除 tuple normalize path，不提供双 schema。

必须先写的失败测试：

- 完整五字段 dict 被无损规范化。
- legacy tuple、缺字段、未知字段、duplicate symbol 被拒绝。
- 空/非法 reference list、unknown section、`found_vcall` 被拒绝。
- dependency policy 缺失、额外、目录 key、unknown policy 和 input overlap 被拒绝。
- reference `PspAllocateProcess.amd64.yaml` 能正确映射到 target artifact
  `PspAllocateProcess.yaml`，不会要求 config 声明静态 reference 文件。
- expected section/category 不兼容被拒绝。
- 结构体 artifact 缩写能派生与旧 tuple 相同的 semantic query name。
- 一个 symbol 的多个 references 保序、去重并保留各自 policy。
- AST inventory 测试扫描所有 finder，确认所有 `LLM_DECOMPILE` entry 都是 strict dict，
  不再存在 tuple。

验证：

```powershell
uv run python -m unittest tests.test_ida_llm_specs tests.test_symbol_config tests.test_ida_skill_preprocessor -v
```

## 7. Task 2：冻结四类输出契约并建立 response 模块

**Files:**

- Create: `ida_llm_response.py`
- Test: `tests/test_ida_llm_response.py`

- [ ] 从源 `ida_llm_decompile.py` 移植通用常量、YAML candidate 提取、schema issue
  数据结构和四类 empty result。
- [ ] 定义 `LLM_DECOMPILE_RESULT_SECTIONS`，内容严格为四类支持结果。
- [ ] 移植 canonical mapping 和 symbol-wrapped compatibility mapping 的解析、扁平化与
  issue reporting。
- [ ] 移植 required-field 校验：
  - `found_call`：`insn_va`、`insn_disasm`、`func_name`
  - `found_funcptr`：`insn_va`、`insn_disasm`、`funcptr_name`
  - `found_gv`：`insn_va`、`insn_disasm`、`gv_name`
  - `found_struct_offset`：`insn_va`、`insn_disasm`、`offset`、`size`、
    `struct_name`、`member_name`；`bit_offset` 可选
- [ ] 保留 `yaml.BaseLoader` 语义，避免地址、offset 和名称被隐式转换。
- [ ] 把 kphtools 的 glued-header repair 接入 candidate load 后、schema validation 前。
- [ ] 明确拒绝 unknown/mixed top-level keys，尤其是 `found_vcall`。

必须先写的失败测试：

- canonical 四类完整结果可解析。
- 完整四类空结果合法；空文档、`null`、`{}` 和缺 section 的空结果非法。
- fenced YAML、prose 中 YAML 和 symbol-wrapped 兼容结果行为与 CS2 一致。
- section 不是 list、entry 不是 mapping、required field 缺失时产生精确 issue。
- wrapper symbol 与 entry symbol 不一致时失败。
- `found_vcall` 是明确的 unsupported schema issue，不被丢弃。
- glued header 可修复，但修复后的错误内容仍被拒绝。

验证：

```powershell
uv run python -m unittest tests.test_ida_llm_response -v
```

## 8. Task 3：迁移 OpenAI Chat Completions transport

**Files:**

- Modify: `ida_llm_utils.py`
- Test: `tests/test_ida_llm_utils.py`

- [ ] 移植 `require_nonempty_text`、`normalize_optional_temperature`、
  `normalize_optional_effort` 和允许的 effort 集合。
- [ ] 保持 `create_openai_client(...)` 返回 `AsyncOpenAI`，但对 api key/base URL 执行与
  CS2 等价的非空校验。
- [ ] 把 `call_llm_text(...)` 输入从单一 `prompt` 升级为 `messages`，支持 system、user、
  assistant 多轮消息。
- [ ] 普通 provider 改用 `client.chat.completions.create(...)`，传递 `model`、`messages`、
  `reasoning_effort` 和可选 `temperature`。
- [ ] 发送给 Chat Completions 前移除内部 message `id`。
- [ ] 移植字符串、mapping/list content 和带 `.text` 对象的首条 message 文本提取。
- [ ] 空 choices 或非法响应必须抛出明确异常，不返回模糊空字符串。
- [ ] 删除 legacy `client.completions.create(prompt=...)` 路径。

必须先写的失败测试：

- Chat Completions 收到完整对话但不含内部 message IDs。
- effort 缺省为 `medium`，显式值原样转发，非法值在请求前失败。
- temperature 缺省时不发送，数字字符串规范化为 float。
- multipart message content 能稳定拼接。
- 空 choices 失败。

验证：

```powershell
uv run python -m unittest tests.test_ida_llm_utils.TestCallLlmText -v
```

## 9. Task 4：完整迁移 Codex 模拟 transport

**Files:**

- Create: `codex_faker.json`
- Modify: `ida_llm_utils.py`
- Test: `tests/test_ida_llm_utils.py`

- [ ] 以源 `codex_faker.json` 为模板迁移完整 request body、developer/tool 上下文和三个
  placeholder。
- [ ] 只替换 workspace/environment 中的 CS2 路径为 kphtools；不得改动协议字段和
  tool schema。
- [ ] 增加模板加载和递归 placeholder 替换：model、user prompt、prompt cache key。
- [ ] 为 user/assistant message 生成或复用稳定 ID；retry 时 ID 不变化。
- [ ] 迁移 Codex headers，包括 request/session/window IDs、Originator、User-Agent、
  Responses Lite 和 beta feature headers。
- [ ] 使用 `httpx.AsyncClient.stream(...)` 实现 `/responses` SSE，保持源实现的 connect/read
  timeout 和 `trust_env=False`。
- [ ] 校验 `text/event-stream` content type。
- [ ] 处理 delta、completed fallback、`[DONE]`、error、response.error、response.failed、
  response.incomplete。
- [ ] delta 已出现时忽略 completed 中的完整文本，禁止重复拼接。
- [ ] 从 failure payload 提取具体 message；最终空文本必须报错。
- [ ] `prompt_cache_key` 在同一次 LLM_DECOMPILE 的所有 transport/validation retry 中稳定。

必须先写的失败测试直接对齐 CS2 `tests/test_ida_llm_utils.py`：

- 请求 body、headers 和模板 placeholder。
- retry 保留 message IDs/cache key。
- 非 SSE content type 失败。
- delta + completed 不重复。
- 只有 completed 时作为 fallback。
- delta 之后出现 failed/incomplete 仍失败并带服务端错误消息。
- 空 response text 失败。
- 模板缺失、JSON 非法、placeholder 缺失失败。
- `codex_faker.json` 不包含 `CS2_VibeSignatures`，三个 placeholder 各存在一次。

验证：

```powershell
uv run python -m unittest tests.test_ida_llm_utils.TestCallLlmTextCodexHttp -v
```

## 10. Task 5：迁移目标代码清理和模板上下文

**Files:**

- Modify: `ida_llm_decompile.py`
- Create: `ida_llm_prompt.py`
- Modify: `ida_preprocessor_scripts/prompt/call_llm_decompile.md`
- Test: `tests/test_ida_llm_decompile.py`

- [ ] 迁移 quote-aware 的 `;` 反汇编注释清理，保留字符串中的分号。
- [ ] 迁移 C/C++ line/block comment 清理，正确处理引号和 escape。
- [ ] 移除空行和独立 IDA segment/address label；不得删除实际 instruction address。
- [ ] 只清理 target blocks，reference blocks 保持原始证据。
- [ ] 模板支持：`symbol_name_list`、`reference_blocks`、`target_blocks`、`arch`、
  `platform`、`module_name`，并兼容旧 scalar placeholders。
- [ ] `module_name` 从 binary path 中稳定推导；Windows 内核默认可得到 `ntoskrnl`，不得
  把 architecture 误作 module。
- [ ] system message 固定为 Windows-kernel reverse-engineering expert；user message 使用
  格式化后的模板。
- [ ] prompt 改为四类 canonical contract，增加 direct tail jump、jump thunk、普通函数
  指针与结构体函数字段的分类说明。
- [ ] prompt 明文声明 `found_vcall` 暂不支持且不得输出。
- [ ] 无结果时必须返回完整四 section 空 mapping。

必须先写的失败测试：

- target comments/labels 被清理，reference comments 保留。
- quoted semicolon、quoted `//`、escaped quote 不被误删。
- multi-target block 每段函数名仍明确。
- `{arch}`、`{platform}`、`{module_name}` 均正确替换。
- prompt 只声明四类顶层 key，并明确 unsupported `found_vcall`。

## 11. Task 6：迁移幻觉校验

**Files:**

- Modify: `ida_llm_decompile.py`
- Create: `ida_llm_validation.py`
- Test: `tests/test_ida_llm_validation.py`

- [ ] 从所有 target disassembly 构造双向 index：`VA -> normalized instructions` 和
  `instruction -> candidate VAs`。
- [ ] 对四类每个非空结果验证 `insn_va` 和 `insn_disasm` 是目标代码中的真实配对；只
  允许 whitespace 差异。
- [ ] 非空结果在没有可用 target address index 时必须失败。
- [ ] 校验结果 symbol 属于本次 requested symbol set。
- [ ] 规范化结构体结果名为 `struct_name->member_name` 后再匹配 requested symbol。
- [ ] 校验 symbol 所在 section 符合 expected result sections。
- [ ] expected section 映射规则固定为：
  - `func` -> `found_call` 或 `found_funcptr`
  - `gv` -> `found_gv`
  - `struct_offset` -> `found_struct_offset`
- [ ] 返回全部 issue，不在第一个错误处停止，以便一次纠错覆盖整批结果。
- [ ] debug 输出 schema kind、root keys、compatibility flatten 标记和结构化 issue list。

必须先写的失败测试直接覆盖：

- 虚构 VA。
- 正确 instruction 配错误 VA。
- 正确 VA 配错误 instruction。
- instruction 存在于另一个 target block。
- 未请求 symbol。
- function 被错误放入 `found_gv`。
- struct member 被错误放入 `found_funcptr`。
- mixed func + struct batch 各自在正确 section 时通过。
- 四类完整空结果无需 disassembly index 也通过。

## 12. Task 7：迁移自动纠错和统一重试预算

**Files:**

- Modify: `ida_llm_decompile.py`
- Test: `tests/test_ida_llm_decompile.py`

- [ ] 移植 retry 参数规范化，语义与 CS2 一致：`max_retries` 表示总 attempts，最小为 1，
  默认 3。
- [ ] 默认 delay/backoff/max delay 分别为 `1.0`、`2.0`、`8.0` 秒。
- [ ] 识别 HTTP 429、5xx、timeout、rate limit、temporarily unavailable 等暂时性错误。
- [ ] 非暂时性认证、配置、schema 外 transport 错误不重试。
- [ ] transport 失败与 validation 失败共享同一 attempt budget。
- [ ] validation 失败时追加原回答的 assistant message 和精确 user correction message。
- [ ] correction prompt 列出全部 issue、四类 canonical schema、expected section 和真实
  instruction 候选；不得包含 vcall 修复逻辑。
- [ ] retry 使用同一个 prompt cache key 和既有 message IDs。
- [ ] 成功立即返回；预算耗尽 fail closed，返回四类空结果。
- [ ] sleep 必须可 patch，单元测试不得真实等待。

必须先写的失败测试：

- invalid YAML 后第二次修正成功。
- symbol-wrapped/schema mismatch 后 canonical 修正成功。
- hallucinated instruction pair 后修正成功。
- expected section 错误后修正成功。
- 重复 validation 失败后返回空结果。
- transient transport 第 N 次成功。
- non-transient transport 只调用一次。
- transport 与 validation 混合失败共享预算。
- `max_retries=1` 禁止所有 retry。

## 13. Task 8：接入 kphtools resolver 和混合批次

**Files:**

- Modify: `ida_preprocessor_common.py`
- Modify: `ida_mcp_resolver.py`
- Create: `ida_llm_targets.py`
- Test: `tests/test_ida_mcp_resolver.py`
- Test: `tests/test_ida_llm_targets.py`
- Test: `tests/test_llm_decompile_preprocessor_integration.py`

- [ ] 在 `ida_preprocessor_common.py` 调用 `ida_llm_specs`，用当前 skill 的输入、target
  category 和 metadata 验证 strict dict；不得重新推导或覆盖 spec 的
  `expected_result_sections`。
- [ ] resolver 以 dict 的 `symbol_name` 查找 spec，并从由 metadata 派生的
  `semantic_query_name` 构造 prompt、requested symbol set 和完整 batch 的
  `expected_result_sections`。
- [ ] 对同一个派生 query name 出现冲突 artifact/category 时拒绝请求，不猜测分类。
- [ ] 特别覆盖现有混合 finder
  `find-EpCookie-AND-EpSectionObject-AND-MmCreateProcessAddressSpace.py`：两个 struct 和一个
  func 必须在同一请求中得到不同 expected sections。
- [ ] `call_llm_decompile(...)` 接收全部 target disassembly，而不是只拿第一段做校验。
- [ ] 把 `_load_llm_decompile_target_details_via_mcp(...)`、function/code-region detail
  export 和 direct ref target resolvers 移入 `ida_llm_targets.py`；保持原函数行为的 thin
  re-export 仅在迁移期存在。
- [ ] 继续支持多 reference、optional target、code-region target 和 required target 检查。
- [ ] 继续使用现有强 cache key，并加入 normalized expected sections/四类 contract version，
  semantic query names 和 resolved dependency policy，防止不同校验契约复用旧结果。
- [ ] 只缓存通过校验的结果；transport/schema/validation 失败的空结果不缓存，允许稍后
  重试恢复。
- [ ] 从 `ida_mcp_resolver.py` 删除已迁移 parser、renderer 和 retry 重复实现；如测试或
  外部 import 需要，最多保留薄 re-export，不保留双实现。
- [ ] 将现有 `tests/test_ida_mcp_resolver.py` 中的 LLM-specific cases 迁移到新的小型
  module/integration test files，使该既有大文件不再增长，并在可行时缩小到 500 行以内。
- [ ] 下游解析维持现有四类行为：直接 call、funcptr、GV 继续用 IDA refs 解析真实 target，
  struct offset 继续使用 metadata 和 bit offset 约束。

回归测试必须证明：

- 四类现有 resolver happy paths 全部不变。
- dict `symbol_name` 与派生 semantic query name 不同时，prompt、validation 和 artifact
  写入仍分别使用正确名称。
- batched result 只调用一次 LLM，并能被多个 artifact 消费。
- optional target 缺失仍继续，required target 缺失仍失败。
- code-region target 仍可参与 prompt 和 validation index。
- 错误 section、错误 instruction 和 unknown symbol 不会进入 IDA ref resolver。
- validated empty result 不生成 artifact，随后按现有逻辑进入 agent fallback。

## 14. Task 9：接入 per-skill retry 与 dependency context

**Files:**

- Modify: `dump_symbols.py`
- Test: `tests/test_llm_decompile_dump_integration.py`

- [ ] 像 CS2 一样，把当前 skill 的 `max_retries` 写入该次 preprocessor 使用的
  `effective_llm_config["max_retries"]`。
- [ ] 同一个隔离的 `effective_llm_config` 必须包含当前 architecture 的
  `_expected_inputs` 与 `_optional_inputs`，只供 `ida_llm_specs` 验证
  `dependency_policy`，不传给 LLM provider。
- [ ] 不原地修改共享 `llm_config`，避免一个 skill 污染下一个 skill。
- [ ] 保留 `retry_initial_delay`、`retry_backoff_factor`、`retry_max_delay` 内部配置入口；
  首次迁移使用 CS2 默认值，不新增额外 CLI 参数。
- [ ] `skill.max_retries` 仍同时服务现有 agent fallback，含义在文档中区分：LLM 侧为总
  attempts，agent runner 维持现有行为。
- [ ] fake-as Codex 缺少 base URL 时在进入网络层前给出明确错误。

测试：

- skill 显式 `max_retries=4` 时 LLM config 收到 4。
- 未配置时收到默认 3。
- expected/optional input context 在当前 arch 下正确合并并与原始 config 隔离。
- 两个连续 skill 的 config 相互隔离。
- 原始 config object 未被修改。

## 15. Task 10：文档、测试移植审计与最终验证

**Files:**

- Modify: `README.md`
- Modify/Test: all files above

- [ ] README 把 legacy Completions 改为 Chat Completions，并说明 Codex 使用 Responses SSE。
- [ ] README 列出四类 contract、canonical empty response 和 `found_vcall` 暂不支持。
- [ ] README 说明 `effort` 默认 `medium`、Codex 对 base URL 的要求和 skill retry 语义。
- [ ] README 记录 strict dict schema、`dependency_policy` 与 legacy tuple 不再受支持；
  以一个 Windows-kernel struct member 和一个 direct function 的示例说明写法。
- [ ] 建立 CS2 test-to-kphtools parity checklist；源测试若因 vcall 不适用，必须标为
  `excluded: found_vcall`，不得无说明删除。
- [ ] 对 `ida_llm_utils.py`、`ida_llm_decompile.py` 做函数级清单，确认源函数已移植、明确
  排除或由 kphtools 等价函数替代。
- [ ] 检查新增模块函数不超过 100 行；按 facade/prompt/response/validation/target
  export 职责拆分。
- [ ] 每个新增源码和测试文件不超过 500 行；迁移必须减少 `ida_mcp_resolver.py` 的 LLM
  相关体积，不能把 CS2 的 1,592 行实现重新塞回单个文件；现有大测试文件不得因为本次
  工作继续增大。

定向验证：

```powershell
uv run python -m unittest tests.test_ida_llm_utils -v
uv run python -m unittest tests.test_ida_llm_specs -v
uv run python -m unittest tests.test_ida_llm_decompile -v
uv run python -m unittest tests.test_ida_llm_response -v
uv run python -m unittest tests.test_ida_llm_validation -v
uv run python -m unittest tests.test_ida_llm_targets -v
uv run python -m unittest tests.test_ida_mcp_resolver -v
uv run python -m unittest tests.test_llm_decompile_preprocessor_integration -v
uv run python -m unittest tests.test_llm_decompile_dump_integration -v
uv run python -m unittest tests.test_symbol_config tests.test_ida_skill_preprocessor -v
```

全量验证：

```powershell
uv run python -m unittest discover -s tests -v
```

静态/契约检查：

```powershell
uv run python -m compileall ida_llm_utils.py ida_llm_decompile.py ida_llm_prompt.py ida_llm_response.py ida_llm_validation.py ida_llm_targets.py ida_llm_specs.py ida_mcp_resolver.py ida_preprocessor_common.py ida_skill_preprocessor.py dump_symbols.py symbol_config.py
rg -n "client\.completions|CS2_VibeSignatures" ida_llm_utils.py ida_llm_decompile.py ida_llm_prompt.py ida_llm_response.py ida_llm_validation.py ida_llm_targets.py ida_llm_specs.py ida_mcp_resolver.py ida_preprocessor_scripts\prompt\call_llm_decompile.md codex_faker.json README.md
```

预期：

- `client.completions` 无匹配。
- `CS2_VibeSignatures` 无匹配。
- `found_vcall` 只出现在“暂不支持”、拒绝逻辑和对应测试中。
- 所有 finder 的 `LLM_DECOMPILE` 均为 strict dict，legacy tuple 无匹配。
- 全量测试退出码为 0。

可选 smoke test（需要用户提供有效 endpoint/credential，不作为默认 CI 门禁）：

1. 对一个普通 OpenAI-compatible Chat Completions endpoint 执行单个 finder。
2. 对一个 Codex-compatible `/responses` endpoint 执行同一 finder。
3. 人工注入一次 429 或 invalid YAML，确认退避/纠错日志与预算符合预期。
4. 确认 debug log 不输出 API key、Authorization header 或完整 credential。

## 16. 验收标准

以下条件全部满足才可声明迁移完成：

1. 普通 provider 不再调用 legacy Completions API。
2. Codex transport 的 request template、headers、SSE/error/empty/duplicate handling 与源
   CS2 行为一致。
3. 四类非空结果必须通过 YAML schema、requested symbol、expected section 和真实
   instruction pair 校验后才能进入下游 resolver。
4. schema/validation 错误会携带完整上下文自动纠正；暂时性 transport 错误会指数退避；
   两者共享预算。
5. `found_vcall` 在 prompt/README 明确标记为暂不支持，运行时不会被静默接受或丢弃。
6. mixed func/struct batch、multi-reference、optional target、code-region target 和缓存均有
   回归测试。
7. 全部 finder 都使用 CS2 对齐的 strict dict schema；dependency policy 与当前 skill 输入、
   artifact category、派生 semantic query name 均通过验证。
8. CS2 源测试能力清单完成审计，所有非 vcall 场景均有 kphtools 对应测试。
9. 定向测试、全量测试和 compileall 全部通过；无法执行的外部 smoke test必须在交付中
   明确说明。

## 17. 建议提交顺序

1. `refactor(llm): migrate decompile specs to dict`
2. `refactor(llm): extract decompile response contract`
3. `feat(llm): migrate chat completions transport`
4. `feat(llm): migrate codex responses transport`
5. `feat(llm): validate decompile results`
6. `feat(llm): retry invalid and transient responses`
7. `refactor(llm): integrate validated resolver batches`
8. `docs(llm): document supported decompile contract`

每个提交都必须附带对应定向测试，提交信息结尾追加：

```text
Co-Authored-By: Codex (GPT-5.x)
```
