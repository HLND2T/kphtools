# kphtools Claude/Codex 非交互 Agent Infrastructure 1:1 移植计划

日期：2026-07-26

## 1. 目标

将 `D:\CS2_VibeSignatures` 当前 Agent Skill runner 的 Claude、Codex 和
OpenCode 非交互调用能力完整迁移到 `kphtools`，使 `dump_symbols.py` 的 Agent
fallback 在命令构造、MCP preflight、进程执行、输出校验、会话恢复、重试和
模型选择方面与 CS2 保持相同的可观察行为。

本计划中的“1:1”指公开 `run_skill(...)` 合约和实际 CLI 行为对齐，不要求逐行
复制实现。允许保留 kphtools 的 Windows 内核项目提示词、`symbols` 目录权限
和现有 `dump_symbols.py` 调度流程。

## 2. 源版本基线

实现阶段必须以固定版本为基线；如果源仓库继续变化，应先更新本节，不得在实现
过程中隐式追随浮动工作区。

- 源仓库：`D:\CS2_VibeSignatures`
- 源提交：`f8ae1ae3481b10fc951e47ac7a27d8d8c4c4d529`
- 源 `agent_runner.py` SHA-256：
  `68B2B5D73C0DC0D53F24454E3612A39AC4F03E7B8E3E13AFF4B7CC1C8AC29520`
- 目标仓库基线：`5227bd6ac165019558255c2178a4f978fcfb5668`
- 目标 `agent_runner.py` 当前 SHA-256：
  `CFFF253CA3A7B615F9DA6DD9F182DE02C1D3FD2E923218D0BC036262BB2361EA`
- 目标 `dump_symbols.py` 当前 SHA-256：
  `0488DF4BCCD5F0ED4ED342144F8EFDF24FB2F5FF188366BC27B9AC8384CF8862`

CS2 工作树可能包含与 Agent runner 无关的未提交文件；实现只以本节列出的源文件
和配置为依据，不覆盖其他用户改动。

## 3. 当前差距与硬性决策

### 3.1 当前实现差距

- `kphtools/agent_runner.py` 的公开 `run_skill()` 只接受 OpenCode；Claude/Codex
  被拒绝或绕过该模块。
- `dump_symbols.py` 维护了另一套 fallback：非 OpenCode agent 使用 Codex 风格
  `exec -`，通过一次 `subprocess.run()` 执行，`max_retries` 实际被忽略。
- 该 fallback 没有 Claude 专用 `-p`、settings、system prompt、session/resume，
  也没有 Codex `--profile skill_runner`、`--approval-mode full-auto` 和
  `exec resume --last`。
- 非 OpenCode fallback 不执行 MCP preflight，不捕获 stdout/stderr，不设置
  skill timeout，也不识别 `<skill_error>` 或 cybersecurity block。
- `.claude/skill_runner.settings.json`、`.codex/skill_runner.config.toml` 已经
  存在，但 Claude/Codex 执行路径没有真正使用它们。

### 3.2 硬性决策

1. `agent_runner.py` 是唯一 Agent CLI 执行层；禁止在 `dump_symbols.py` 保留
   第二套 Claude/Codex/OpenCode 命令实现。
2. `dump_symbols.py` 继续暴露模块级 `run_skill` 名称，以保持现有调用和测试
   patch seam；该名称直接导入 `agent_runner.run_skill`。
3. 公开 runner 合约与 CS2 保持一致：

   ```python
   def run_skill(
       skill_name,
       agent="claude",
       debug=False,
       expected_yaml_paths=None,
       max_retries=3,
       agent_model="",
       progress_callback=None,
   ) -> bool:
   ```

4. `max_retries` 表示总 attempts，最小有效值为 1；Claude 使用固定 UUID 会话，
   Codex 使用最新会话恢复，OpenCode 优先使用输出中的 `sessionID`。
5. 保留 CS2 当前 MCP preflight 的进程级缓存语义和“按名称匹配 server”的行为，
   不在本次移植中扩大为按 Agent/Server 分键或改变失败连接的判定规则。
6. kphtools 的 Claude settings 权限继续使用 `Read(symbols)`、
   `mcp__ida-pro-mcp__*` 等本项目范围；不得直接复制 CS2 的 `Read(hl2sdk)` 或
   `Read(bin)`。
7. 不新增第三方依赖，不改变 PDB/MCP/LLM preprocessor 的优先级，不改变
   `dump_symbols.py` 的 skill 拓扑排序和失败统计。

## 4. 目标架构与文件范围

### 4.1 文件变更

- Modify: `agent_runner.py`
  - 补齐 CS2 的统一 runner 常量、Claude/Codex prompt 加载、三类命令构造、
    进程捕获、结果校验、重试和 progress callback。
- Modify: `dump_symbols.py`
  - 删除 `_detect_agent_kind`、`_strip_frontmatter` 和本地重复的 `run_skill`。
  - 直接导入 `DEFAULT_AGENT_MODEL`、`run_skill`，保留现有调用参数和模块级 patch
    seam。
- Modify: `tests/test_agent_runner.py`
  - 从当前 OpenCode-only 测试扩展为 CS2 runner 测试矩阵，并适配 kphtools 的
    项目权限和 agent prompt。
- Modify: `tests/test_dump_symbols.py`
  - 删除“一次调用即结束”的旧 Codex 断言，改为验证 `dump_symbols.run_skill`
    委托统一 runner，并保留主流程的 fallback 调用断言。
- Modify: `.opencode/agents/sig-finder.md`
  - 补齐 runner 负责输出校验、Agent 不得自行检查 output YAML 的约束。
- Modify: `README.md`
  - 明确 Claude/Codex/OpenCode 的真实支持范围、非交互调用、模型参数和重试语义。

### 4.2 不变文件

- `.claude/skill_runner.settings.json`
- `.claude/SKILL_RUNNER.md`
- `.codex/skill_runner.config.toml`
- `.opencode/skill_runner.config.json`

上述文件先按当前内容复用；如果实现发现配置与 CS2 行为不一致，只允许做针对
runner 的最小修正，并在最终 diff 中说明原因。

## 5. 实施任务

### Task 1：建立 runner 行为基线和测试夹具

**Files:**

- Modify: `tests/test_agent_runner.py`

- [x] 增加 fake pipe、fake stdin、fake Popen，以及可控 stdout/stderr、returncode、
      timeout 和 kill 状态的夹具。
- [x] 每个测试类的 `setUp()` 重置 `_MCP_PREFLIGHT_DONE` 和
      `_MCP_PREFLIGHT_FAILED`。
- [x] 从 CS2 测试清单迁入并适配以下场景：命令构造、模型参数、MCP preflight、
      输出错误、Codex stdin、超时、debug 双流、重试和 callback。
- [x] 将项目权限断言改为 kphtools 的 `Read(symbols)` 和现有 MCP allow/deny
      列表。
- [x] 迁入的 Claude/Codex 行为用例在旧实现基线下预期失败；统一实现完成后
      已转为通过。

### Task 2：迁移公共进程与结果处理层

**Files:**

- Modify: `agent_runner.py`
- Test: `tests/test_agent_runner.py`

- [x] 保留 `SKILL_TIMEOUT = 1200`、`MCP_LIST_TIMEOUT = 30` 和现有
      `AgentCommand` 数据结构。
- [x] 迁移 `_run_process_with_stream_capture()`：stdin 写入后关闭、stdout/stderr
      独立 drain、`debug=True` 实时转发、超时 kill 并重新抛出
      `subprocess.TimeoutExpired`。
- [x] 统一 `_result_failure_reason()` 的检查顺序：非零返回码、cybersecurity
      block、`<skill_error>`、缺失 expected YAML。
- [x] 保持 developer instructions 脱敏显示，不把完整 `.claude/agents/sig-finder.md`
      内容打印到日志。
- [x] 保持 OpenCode 已有 JSON session ID 提取、`--session` 精确恢复和无 ID 时
      `--continue` 回退行为。

### Task 3：实现 Claude 专用命令和会话

**Files:**

- Modify: `agent_runner.py`
- Test: `tests/test_agent_runner.py`

- [x] 增加常量：
      `CLAUDE_SKILL_RUNNER_SETTINGS = ".claude/skill_runner.settings.json"`、
      `SKILL_RUNNER_SYSTEM_PROMPT = ".claude/SKILL_RUNNER.md"`。
- [x] 实现 Claude 首次命令：

  ```text
  claude -p /<skill> --agent sig-finder
      [--model <model>]
      --settings .claude/skill_runner.settings.json
      --append-system-prompt-file .claude/SKILL_RUNNER.md
      --permission-mode auto
      --session-id <uuid>
  ```

- [x] 重试命令只将 `--session-id <uuid>` 替换为 `--resume <uuid>`，不能创建新会话。
- [x] Claude model 使用 `--model`；provider/model 格式限制只适用于 OpenCode。
- [x] 覆盖 `.cmd`、绝对路径 executable、缺失 CLI 和 session 参数断言。

### Task 4：实现 Codex 专用命令、配置和会话恢复

**Files:**

- Modify: `agent_runner.py`
- Verify: `.codex/skill_runner.config.toml`
- Test: `tests/test_agent_runner.py`

- [x] 实现 Codex developer instructions 加载：读取
      `.claude/agents/sig-finder.md`，剥离 YAML frontmatter，序列化为
      `developer_instructions=<JSON>`。
- [x] 实现首次命令：

  ```text
  codex --profile skill_runner
      -c developer_instructions=<JSON>
      [-m <model>]
      --approval-mode full-auto
      exec -
  ```

- [x] prompt 必须通过 stdin 传入：
      `Run SKILL: .claude/skills/<skill_name>/SKILL.md`。
- [x] 重试使用 `codex --profile skill_runner ... exec resume --last -`，并继续通过
      stdin 发送相同 prompt。
- [x] 验证 `skill_runner.config.toml` 的 `project_doc_fallback_filenames`、
      reasoning、verbosity、approval 和 sandbox 设置确实由 profile 生效；不得
      只把其中一部分通过命令行硬编码。
- [x] 覆盖缺失/空 system prompt、model 参数、stdin 内容、首次/重试命令和
      developer instruction 日志脱敏。

### Task 5：统一公开 API 和 `dump_symbols.py` 接入

**Files:**

- Modify: `agent_runner.py`
- Modify: `dump_symbols.py`
- Test: `tests/test_dump_symbols.py`

- [x] `agent_runner.run_skill()` 按 agent 名称识别 `claude`、`codex`、`opencode`；
      未知 agent 直接返回 `False`，不得以 Codex 参数尝试执行任意 executable。
- [x] 统一执行顺序：校验 skill 文件 -> MCP preflight -> 加载 Codex prompt/
      创建 Claude session -> attempts 循环 -> 输出校验。
- [x] `dump_symbols.py` 直接导入 `run_skill`，删除本地 Codex fallback，确保只剩
      一个实际执行层。
- [x] 保持 `_run_fallback_skill_and_log_outputs()` 的参数、成功统计、产物日志和
      主流程调用行为不变。
- [x] `expected_yaml_paths=None`、空列表、缺失文件和 `max_retries=1` 均按 CS2
      语义处理。
- [x] 保留 `dump_symbols.run_skill` 作为可 patch 的模块级名称；主流程测试不应
      需要改成 patch `agent_runner` 才能验证 fallback。

### Task 6：迁移 OpenCode 配置约束并修正文档

**Files:**

- Modify: `.opencode/agents/sig-finder.md`
- Modify: `README.md`
- Test: `tests/test_agent_runner.py`

- [x] 在 OpenCode agent prompt 中加入：输出 YAML 由 runner 程序校验，Agent 不得
      自行确认或检查 output YAML 是否存在。
- [x] README 命令示例同时列出 `claude`、`codex`、`opencode` 及 Windows `.cmd`
      变体。
- [x] README 说明三类 agent 的非交互协议、`-agent_model`、OpenCode 的
      `provider/model` 限制和 `max_retries` 总 attempts 语义。
- [x] README 不得宣称 Claude/Codex 已支持，除非 Task 3/4 的命令和回归测试全部
      完成。

### Task 7：回归、静态检查和外部 smoke test

**Files:**

- Verify: `agent_runner.py`
- Verify: `dump_symbols.py`
- Verify: `tests/test_agent_runner.py`
- Verify: `tests/test_dump_symbols.py`

- [x] 运行 runner 定向测试：

  ```powershell
  uv run python -m unittest tests.test_agent_runner -v
  ```

- [x] 运行 dump_symbols fallback 测试：

  ```powershell
  uv run python -m unittest tests.test_dump_symbols -v
  ```

- [x] 运行全量单元测试：

  ```powershell
  uv run python -m unittest discover -s tests
  ```

- [x] 执行格式、静态和语法检查：

  ```powershell
  uv run ruff format --check agent_runner.py dump_symbols.py tests/test_agent_runner.py tests/test_dump_symbols.py
  uv run ruff check agent_runner.py dump_symbols.py tests/test_agent_runner.py tests/test_dump_symbols.py
  uv run python -m compileall -q agent_runner.py dump_symbols.py tests
  ```

- [x] 检查不存在第二套 agent 执行路径：

  ```powershell
  rg -n "subprocess\.(run|Popen)|def run_skill|developer_instructions|--profile|--permission-mode" agent_runner.py dump_symbols.py
  ```

  预期 Agent CLI 的 `subprocess` 调用只出现在 `agent_runner.py`；
  `dump_symbols.py` 只保留导入的 `run_skill` 和业务调度。
- [ ] 可选外部 smoke test（需要本机安装 CLI、可用 IDA/MCP 和 credentials，不作为
      默认 CI 门禁）：每类 agent 各运行一个最小 skill，确认首次调用、产物校验和
      一次失败后的会话恢复；日志不得泄露 API key 或完整 developer prompt。

## 6. 允许的有意差异

相对 `CS2_VibeSignatures` 只允许以下差异：

1. Claude agent prompt 继续描述 Windows kernel binary，OpenCode agent prompt
   继续使用 kphtools 的 reverse-engineering 约束。
2. Claude settings 的允许读取目录使用 `symbols`，不引入 CS2 的 `hl2sdk` 或 `bin`。
3. `dump_symbols.py` 保留 kphtools 的 async MCP session、PDB-first preprocessor、
   skill 拓扑排序和现有 YAML 输出路径。
4. kphtools 没有 CS2 Redis reporter 时，`progress_callback` 可以没有生产消费者，
   但 runner API、事件名称和异常隔离行为必须保留。

除此之外，不得省略源 runner 的命令参数、重试分支、输出错误处理、超时处理或测试
场景；若确有差异，必须在实现 PR 中单独列出理由和对应测试。

## 7. 验收标准

以下条件全部满足后，才能声明 Claude/Codex agent infrastructure 已与 CS2 1:1：

1. `dump_symbols.py` 的 Claude、Codex、OpenCode 都经过同一个
   `agent_runner.run_skill()`。
2. Claude 首次/恢复命令、settings、system prompt、session UUID 和 model 参数
   与 CS2 一致。
3. Codex profile、developer instructions、full-auto、stdin prompt、model 参数
   和 `resume --last` 与 CS2 一致。
4. 三类 agent 都执行同样的 MCP preflight、1200 秒 timeout、双流捕获、产物校验、
   错误分类和 retry budget。
5. OpenCode 的现有 session/continue 行为保持不回归，且 agent prompt 测试通过。
6. `max_retries=1` 不会产生 retry；`max_retries=N` 最多执行 N 次；Claude/Codex/
   OpenCode 各自使用正确的恢复语义。
7. `tests.test_agent_runner`、`tests.test_dump_symbols`、全量 unittest、Ruff 和
   compileall 全部通过；无法执行的外部 smoke test 在交付说明中明确标注。
8. `rg` 检查确认没有遗留的 `dump_symbols.py` Codex-only fallback 或第二套
   Agent CLI subprocess 调用。

## 8. 建议提交顺序

1. `test(agent): add Claude and Codex runner behavior matrix`
2. `refactor(agent): unify non-interactive agent runner`
3. `refactor(agent): route dump symbols through shared runner`
4. `test(agent): cover retry timeout and output failure semantics`
5. `fix(agent): align OpenCode prompt constraints`
6. `docs(agent): document Claude Codex and OpenCode non-interactive usage`

每个提交都应包含对应定向测试；提交信息结尾追加：

```text
Co-Authored-By: Codex (GPT-5.x)
```
