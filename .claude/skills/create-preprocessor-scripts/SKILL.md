---
name: create-preprocessor-scripts
description: Use when adding or updating kphtools IDA preprocessor finder scripts, config.yaml symbol entries, LLM_DECOMPILE reference YAMLs, generated reference annotations, or merged finder coverage for ntoskrnl symbols.
disable-model-invocation: true
---

# Create Preprocessor Scripts

Create or update kphtools preprocessor finders under `ida_preprocessor_scripts/`, with matching `config.yaml` entries and annotated LLM reference YAML when needed.

## When to Use

- Adding or changing an `ida_preprocessor_scripts/find-XXX.py` finder.
- Adding or changing `config.yaml` `modules[].skills` or `modules[].symbols` entries.
- Generating `ida_preprocessor_scripts/references/<module>/<FuncName>.<arch>.yaml`.
- Adding annotations to generated reference YAML for LLM_DECOMPILE.
- Merging related symbols into one `find-A-AND-B.py` finder.

## Required Inputs

Collect only what the task needs:

- Symbol names and output YAML names.
- Category: `struct_offset`, `gv`, or `func`.
- `data_type`, module name, architecture, aliases, and dependencies if present.
- Discovery source: direct PDB/name metadata or an LLM_DECOMPILE reference function.
- Target struct/member pairs, global variable names, or function names.
- Desired YAML fields for each output artifact.

## Workflow

### 1. Determine Targets and Grouping

- Prefer existing kphtools patterns over inventing a new finder shape.
- Merge symbols when they share the same reference function and can be located from the same evidence.
- Split symbols when they use different reference functions, form dependency chains, or need different discovery logic.
- Merged finder names use `find-A-AND-B-AND-C.py`; the `config.yaml` skill name must match the filename without `.py`.
- When a merge replaces old finders and the current task authorizes cleanup, delete stale `ida_preprocessor_scripts/find-Old.py` files and stale `.claude/skills/find-Old/` directories. Also remove old `config.yaml` skill entries.

### 2. Write the Finder Script

Place scripts at:

```text
ida_preprocessor_scripts/find-<SkillName>.py
```

Use `ida_preprocessor_common.preprocess_common_skill` and keep the current kphtools function signature:

```python
async def preprocess_skill(session, skill, symbol, binary_dir, pdb_path, debug, llm_config):
    return await preprocess_common_skill(
        session=session,
        skill=skill,
        symbol=symbol,
        binary_dir=binary_dir,
        pdb_path=pdb_path,
        debug=debug,
        llm_config=llm_config,
        ...
    )
```

Common module-level variables:

- Struct offsets: `TARGET_STRUCT_MEMBER_NAMES`, `STRUCT_METADATA`, `GENERATE_YAML_DESIRED_FIELDS`.
- Global variables: `TARGET_GLOBALVAR_NAMES`, `GV_METADATA`, `GENERATE_YAML_DESIRED_FIELDS`.
- Functions: `TARGET_FUNCTION_NAMES`, `FUNC_METADATA`, `GENERATE_YAML_DESIRED_FIELDS`.
- LLM_DECOMPILE: `LLM_DECOMPILE`, passed as `llm_decompile_specs=LLM_DECOMPILE`.

Use nearby examples:

- Direct struct offset: `ida_preprocessor_scripts/find-EpObjectTable.py`.
- Global variable: `ida_preprocessor_scripts/find-PspCreateProcessNotifyRoutine.py`.
- Function: `ida_preprocessor_scripts/find-ExReferenceCallBackBlock.py`.
- Single-symbol LLM_DECOMPILE struct offset: `ida_preprocessor_scripts/find-AlpcHandleTableLock.py` (ref: `AlpcAddHandleTableEntry`).
- Merged LLM_DECOMPILE struct offsets (two targets, same ref): `ida_preprocessor_scripts/find-AlpcHandleTable-AND-AlpcPortContext.py` (ref: `AlpcpCreateClientPort`).
- Merged LLM struct offsets: `ida_preprocessor_scripts/find-AlpcAttributes-AND-AlpcAttributesFlags-AND-AlpcCommunicationInfo-AND-AlpcOwnerProcess-AND-AlpcConnectionPort-AND-AlpcServerCommunicationPort-AND-AlpcClientCommunicationPort.py`.

### 3. Update config.yaml

**Check first**: search `config.yaml` for the skill name before editing — the entry may already exist and only need verification, not addition.

For the target module:

- Add one `skills` entry whose `name` exactly matches the script basename.
- Add every produced YAML under `expected_output`.
- Add or update every symbol under `symbols` with correct `name`, `category`, and `data_type`.
- Avoid duplicate symbol entries.
- If the finder depends on prior outputs, add `expected_input` so dependency artifacts are produced first.
- When renaming or merging a finder, remove stale skill entries for old scripts.

### 4. Generate and Annotate Reference YAML

**Check first**: run `Glob ida_preprocessor_scripts/references/<module>/<FuncName>*.yaml` before generating — the file may already exist.

Generate reference YAML with `generate_reference_yaml.py`:

```bash
uv run python generate_reference_yaml.py -func_name=ExReferenceCallBackBlock
```

Omitting `-auto_start_mcp` and `-binary` uses the already-running IDA MCP session, which is the normal case. `-auto_start_mcp` requires `-binary` and is only needed when no IDA instance is running.

Useful flags: `-func_name`, `-module`, `-arch`, `-auto_start_mcp`, `-binary`, `-debug`.

Output path:

```text
ida_preprocessor_scripts/references/<module>/<FuncName>.<arch>.yaml
```

Rules:

- Generate reference YAML sequentially. Do not parallelize IDA/MCP reference generation.
- For LLM_DECOMPILE, annotation is mandatory. Add comments in `procedure` and/or `disasm_code` that make the target unambiguous.
- **Check existing annotations before adding**: the `procedure` section may already contain the needed comments (e.g., from a previous task on the same file). Only add what is missing.
- Annotate **all** visible struct member accesses in the function (not just the primary target). Surrounding context — e.g., `Handles` at `0x0` and `TotalHandles` at `0x10` alongside the target `Lock` at `0x8` — helps the LLM correctly identify and bound the target offset.
- Annotation format in `disasm_code`: append `; 0xXX = YY = Struct->Member` to the relevant instruction line.
- Annotation format in `procedure`: append `// 0xXX = YY = Struct->Member` inline at the end of the relevant statement.
- Decimal value should omit `LL` suffix when the offset is small and unambiguous (e.g., `0x8 = 8 = ...` not `0x8 = 8LL = ...`).
- Preserve generated structure; only add human/LLM guidance comments needed for reliable extraction.

### 5. Validate

Run `dump_symbols.py` to verify the finder is loaded and recognized:

```bash
uv run dump_symbols.py -debug > /tmp/dump_symbols_out.txt 2>&1
```

Then check the output for the skill name:

```bash
grep "find-<SkillName>" /tmp/dump_symbols_out.txt | head -5
```

Expected results (either is a pass):

- `[debug] preprocess status for find-<SkillName>: success` — skill ran and produced output.
- `[debug] skipping find-<SkillName>; expected outputs already exist` — skill is recognized; outputs were cached from a prior run.

Any other status (e.g., `failed`, skill name absent from output) indicates a misconfiguration.

Also run:

- YAML parse check for `config.yaml` and changed reference YAML files.
- `git diff --check`.

### 6. Commit Changes

Check the current branch:

```bash
git branch --show-current
```

- If on `main`: commit to a dev branch (e.g., `dev-idalib` or a new `dev-<feature>` branch).
- If on any other branch: commit directly to the current branch.

Stage only relevant files (finder scripts, reference YAMLs, `config.yaml`). Do not stage `.claude/` tooling directories.

## Common Mistakes

- Script filename and `config.yaml` skill name do not match.
- `expected_output` omits one artifact from a merged finder.
- Symbol exists in script output but not in `config.yaml` `symbols`.
- Old finder scripts or old skill entries remain after an authorized merge.
- `LLM_DECOMPILE` exists but is not passed as `llm_decompile_specs`.
- Reference YAML lacks annotations, so the LLM returns wrong or incomplete offsets.
- Raw LLM output contains non-strict YAML such as repeated top-level keys or a truncated member name; fix the parser/prompt or reference annotation rather than accepting an empty parsed result.
- Reference generation is run in parallel and IDA/MCP sessions interfere with each other.

## Completion Checklist

- Finder script exists and follows local patterns.
- `config.yaml` skill entry, expected outputs, symbols, and dependencies are consistent.
- Reference YAML exists for LLM_DECOMPILE and includes target annotations.
- Stale merged-away scripts/skill entries are removed when cleanup was authorized.
- `dump_symbols.py -debug` shows `preprocess status for find-<SkillName>: success` or `skipping find-<SkillName>; expected outputs already exist` for the new skill.
- Changes committed to the current branch (or a dev branch if on `main`).
