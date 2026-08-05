# Dump YAML Artifacts

[Back to README](../../README.md)

`dump_symbols.py` is the primary analysis entry point.

## Usage

```bash
uv run dump_symbols.py [-symboldir="path/to/symbols"] [-configyaml="config.yaml"] [-version=10.0.26100.8246] [-arch=amd64] [-agent=claude/codex/opencode/"claude.cmd"/"codex.cmd"/"opencode.cmd"] [-agent_model=model] [-debug]
```

The script scans `<symboldir>/<arch>/<file>.<version>/<sha256>/`, resolves symbols into `{symbol}.yaml`, and writes them next to the corresponding PE and PDB files.

After a per-binary pipeline and MCP cleanup succeed, the script also writes `artifacts.yaml`. This manifest is a top-level mapping from every configured module symbol name to its artifact payload; a missing individual artifact is represented as `null`. Existing per-symbol YAML files remain unchanged for compatibility. Successful `-skill` partial runs rebuild the manifest from all current per-symbol files, and unchanged content only refreshes the manifest timestamp.

When `-symboldir` is omitted, the script uses `symbols` under the current working directory. `KPHTOOLS_SYMBOLDIR`, including values loaded from `.env`, takes precedence over the command-line option.

## Agent runner

Claude, Codex, and OpenCode use the same non-interactive runner. Before starting a skill, the runner checks that `ida-pro-mcp` is listed, then enforces the same timeout, output validation, and retry budget for every CLI.

- Claude runs with project settings and a fixed UUID session.
- Codex uses the `skill_runner` profile and receives the skill prompt through stdin.
- OpenCode runs in JSON mode with the project `sig-finder` agent.

On retries, Claude resumes its fixed UUID, Codex resumes the latest session with `exec resume --last`, and OpenCode resumes the exact reported `sessionID` or falls back to `--continue`. `max_retries` is the total number of attempts, including the first, and values below one still produce one attempt.

`-agent_model` is passed through using each CLI's model option. Claude and Codex accept their native model names; OpenCode model names must use `provider/model` format. The agent executable and optional model can also be provided by `.env` or environment variables.

On Linux or macOS:

```bash
KPHTOOLS_AGENT=opencode
KPHTOOLS_AGENT_MODEL=openai/gpt-5.4
```

On Windows Command Prompt:

```bat
set KPHTOOLS_AGENT=opencode.cmd
set KPHTOOLS_AGENT_MODEL=openai/gpt-5.4
```

Equivalent agent values include `claude`, `codex`, `opencode`, and their Windows `*.cmd` variants.

When an auto-started supervisor reports the matching IDB as inactive or unreachable, `dump_symbols.py` checks the owned worker and may restart it once for that binary. The restart waits for the previous supervisor port to be released; a second unavailable-worker failure aborts that binary instead of retrying indefinitely.

## LLM fallback

LLM fallback options are shared by preprocessor scripts that declare `LLM_DECOMPILE`:

```bash
uv run dump_symbols.py \
  -llm_model=gpt-5.4 \
  -llm_apikey=sk-xxxxxxxxxxxxxxxx \
  -llm_baseurl=https://api.example.com/v1 \
  -llm_temperature=0.2 \
  -llm_effort=medium \
  -llm_fake_as=codex
```

The same values can be provided by `.env` or environment variables:

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

Normal providers use the OpenAI-compatible Chat Completions API. `-llm_effort` defaults to `medium`; `-llm_temperature` is omitted when unset.

When `-llm_fake_as=codex` is set, the helper uses a direct `/responses` SSE transport. A non-empty `-llm_baseurl` is required and should point at the provider's `/v1` base URL. The Codex transport preserves conversation message IDs and one prompt cache key across validation and transport retries.

Each skill's `max_retries` is the total number of attempts, including the first request. Schema or validation correction and transient transport failures share that budget for LLM fallback; agent fallback uses the same total-attempt interpretation.

See [Reference YAML for `LLM_DECOMPILE`](reference_yaml.md) for the reference generator, declaration schema, and validated response contract.

After artifacts have been generated, use [`update_symbols.py`](update_symbols.md) to export them to `kphdyn.xml`.
