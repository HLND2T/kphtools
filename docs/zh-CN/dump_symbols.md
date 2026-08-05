# 导出 YAML 工件

[返回 README](../../README.zh-CN.md)

`dump_symbols.py` 是主要的分析入口。

## 用法

```bash
uv run dump_symbols.py [-symboldir="path/to/symbols"] [-configyaml="config.yaml"] [-version=10.0.26100.8246] [-arch=amd64] [-agent=claude/codex/opencode/"claude.cmd"/"codex.cmd"/"opencode.cmd"] [-agent_model=model] [-debug]
```

脚本扫描 `<symboldir>/<arch>/<file>.<version>/<sha256>/`，将符号解析为 `{symbol}.yaml`，并把文件写在对应的 PE 与 PDB 文件旁边。

每个二进制文件的处理流程和 MCP cleanup 成功后，脚本还会写入 `artifacts.yaml`。该 manifest 使用顶层映射，将模块配置中的每个 symbol 名称映射到对应 artifact payload；缺失的单符号 artifact 记为 `null`。现有单符号 YAML 会继续保留以兼容当前流程。成功的 `-skill` 局部运行会根据当前全部单符号文件重建 manifest；内容未变化时只刷新 manifest 时间戳。

省略 `-symboldir` 时，脚本默认使用当前工作目录下的 `symbols`。`KPHTOOLS_SYMBOLDIR`（包括从 `.env` 加载的值）优先于命令行选项。

## Agent runner

Claude、Codex 和 OpenCode 使用相同的非交互式 runner。启动 skill 前，runner 会检查是否列出了 `ida-pro-mcp`，然后为每个 CLI 统一执行超时、输出校验和重试预算。

- Claude 使用项目设置和固定 UUID session 运行。
- Codex 使用 `skill_runner` profile，并通过 stdin 接收 skill prompt。
- OpenCode 使用 JSON 模式和项目的 `sig-finder` agent 运行。

重试时，Claude 恢复固定 UUID，Codex 使用 `exec resume --last` 恢复最新 session，OpenCode 恢复准确的 `sessionID`，或回退到 `--continue`。`max_retries` 表示总尝试次数（包括第一次），小于 1 的值仍会执行一次尝试。

`-agent_model` 会通过各 CLI 的模型选项传递。Claude 和 Codex 接受各自的原生模型名；OpenCode 的模型名必须使用 `provider/model` 格式。Agent 可执行文件和可选模型也可以通过 `.env` 或环境变量提供。

Linux 或 macOS：

```bash
KPHTOOLS_AGENT=opencode
KPHTOOLS_AGENT_MODEL=openai/gpt-5.4
```

Windows 命令提示符：

```bat
set KPHTOOLS_AGENT=opencode.cmd
set KPHTOOLS_AGENT_MODEL=openai/gpt-5.4
```

等价的 Agent 值包括 `claude`、`codex`、`opencode` 及其 Windows `*.cmd` 变体。

当自动启动的 supervisor 报告匹配的 IDB 处于非活动或不可达状态时，`dump_symbols.py` 会检查自己拥有的 worker，并可能针对该二进制重启一次。重启会等待之前的 supervisor 端口释放；第二次 worker 不可用时会中止该二进制，而不是无限重试。

## LLM 回退

LLM 回退选项由声明 `LLM_DECOMPILE` 的 preprocessor script 共享：

```bash
uv run dump_symbols.py \
  -llm_model=gpt-5.4 \
  -llm_apikey=sk-xxxxxxxxxxxxxxxx \
  -llm_baseurl=https://api.example.com/v1 \
  -llm_temperature=0.2 \
  -llm_effort=medium \
  -llm_fake_as=codex
```

相同的值也可以通过 `.env` 或环境变量提供：

```bash
KPHTOOLS_LLM_MODEL=gpt-5.4
KPHTOOLS_LLM_APIKEY=sk-xxxxxxxxxxxxxxxx
KPHTOOLS_LLM_BASEURL=https://api.example.com/v1
KPHTOOLS_LLM_TEMPERATURE=0.2
KPHTOOLS_LLM_EFFORT=high
KPHTOOLS_LLM_FAKE_AS=codex
KPHTOOLS_AGENT=claude.cmd
KPHTOOLS_AGENT_MODEL=sonnet
```

普通 provider 使用 OpenAI 兼容的 Chat Completions API。`-llm_effort` 默认是 `medium`；未设置时不会传递 `-llm_temperature`。

设置 `-llm_fake_as=codex` 后，helper 会直接使用 `/responses` SSE transport。必须提供非空的 `-llm_baseurl`，并将其指向 provider 的 `/v1` 基础 URL。Codex transport 会在校验和 transport 重试之间保留 conversation message ID 以及一个 prompt cache key。

每个 skill 的 `max_retries` 表示总尝试次数（包括第一次请求）。对于 LLM 回退，schema/校验修正与临时 transport 失败共享该预算；Agent 回退也使用相同的总尝试次数定义。

参考生成器、声明 schema 和已校验响应契约见 [`LLM_DECOMPILE` reference YAML](reference_yaml.md)。

生成工件后，使用 [`update_symbols.py`](update_symbols.md) 将其导出到 `kphdyn.xml`。

