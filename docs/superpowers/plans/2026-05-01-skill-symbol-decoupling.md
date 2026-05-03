# Skill Symbol Decoupling Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove the hard 1:1 `skill.symbol` coupling and derive target symbols from `expected_output` artifact names.

**Architecture:** Keep `symbols[]` as the authoritative source for symbol metadata. Treat `skills[].expected_output` as the only required declaration of produced symbol artifacts, derive symbol names from `<symbol>.yaml`, and make `update_symbols.py` consume only `symbols[]` plus YAML payload contents.

**Tech Stack:** Python, YAML config loading, unittest

---

### Task 1: Update config model and validation

**Files:**
- Modify: `symbol_config.py`
- Test: `tests/test_symbol_config.py`

- [ ] **Step 1: Remove `skill.symbol` from `SkillSpec`**

```python
@dataclass(frozen=True)
class SkillSpec:
    name: str
    expected_output: list[str]
    expected_input: list[str]
    max_retries: int | None = None
```

- [ ] **Step 2: Derive symbol names from `expected_output` artifact names**

```python
def _symbol_name_from_output_name(name: str) -> str:
    if not name.endswith(".yaml"):
        raise ValueError(f"expected_output must end with .yaml: {name}")
    return Path(name).stem
```

```python
produced_symbols = [_symbol_name_from_output_name(item) for item in expected_output]
```

- [ ] **Step 3: Validate every derived symbol exists in module `symbols[]`**

```python
for skill in skills:
    for symbol_name in skill.produced_symbols:
        if symbol_name not in symbol_names:
            raise ValueError(
                f"skill expected_output references unknown symbol: {symbol_name}"
            )
```

- [ ] **Step 4: Update tests for legacy and multi-output configs**

```python
modules:
  - name: ntoskrnl
    path: [ntoskrnl.exe]
    skills:
      - name: find-Callbacks
        expected_output:
          - ExReferenceCallBackBlock.yaml
          - ExDereferenceCallBackBlock.yaml
    symbols:
      - name: ExReferenceCallBackBlock
        category: func
        data_type: uint32
      - name: ExDereferenceCallBackBlock
        category: func
        data_type: uint32
```

### Task 2: Replace single-symbol preprocessing with artifact-derived dispatch

**Files:**
- Modify: `dump_symbols.py`
- Modify: `ida_preprocessor_common.py`
- Test: `tests/test_dump_symbols.py`
- Test: `tests/test_ida_preprocessor_common.py`

- [ ] **Step 1: Iterate derived symbols in `process_binary_dir()`**

```python
for symbol_name in skill.produced_symbols:
    status = await preprocess_single_skill_via_mcp(
        session=session,
        skill=skill,
        symbol=symbol_map[symbol_name],
        binary_dir=Path(binary_dir),
        pdb_path=Path(pdb_path),
        debug=debug,
        llm_config=llm_config,
    )
```

- [ ] **Step 2: Let shared preprocessor resolve by `symbol.name` instead of `skill.symbol`**

```python
target_symbol_name = symbol.name
desired_fields = desired_fields_by_symbol.get(target_symbol_name)
```

```python
writer(artifact_path(binary_dir, target_symbol_name), filtered_payload)
```

- [ ] **Step 3: Keep script metadata lookup keyed by symbol names**

```python
if struct_member_names is not None and target_symbol_name not in struct_member_names:
    return PREPROCESS_STATUS_FAILED
metadata = (struct_metadata or {}).get(target_symbol_name)
```

- [ ] **Step 4: Add regression tests for one skill producing multiple YAML artifacts**

```python
skill = SimpleNamespace(
    name="find-Callbacks",
    expected_output=[
        "ExReferenceCallBackBlock.yaml",
        "ExDereferenceCallBackBlock.yaml",
    ],
    produced_symbols=[
        "ExReferenceCallBackBlock",
        "ExDereferenceCallBackBlock",
    ],
)
```

### Task 3: Remove `update_symbols` dependency on `skill.symbol`

**Files:**
- Modify: `update_symbols.py`
- Test: `tests/test_update_symbols.py`

- [ ] **Step 1: Remove skill-metadata backtracking from `update_symbols.py`**

```python
if "bit_offset" in payload:
    values[spec["name"]] = int(payload["offset"]) * 8 + int(payload["bit_offset"])
else:
    values[spec["name"]] = int(payload["offset"])
```

- [ ] **Step 2: Keep export strictly symbol-driven**

```python
symbol_specs = [vars(symbol) for symbol in module.symbols]
```

- [ ] **Step 3: Add a regression test covering bitfield payload handling without skills**

```python
payloads = {"ObDecodeShift": {"offset": 0x8, "bit_offset": 20}}
```

### Task 4: Final consistency pass

**Files:**
- Review: `symbol_config.py`
- Review: `dump_symbols.py`
- Review: `ida_preprocessor_common.py`
- Review: `update_symbols.py`
- Review: `tests/test_symbol_config.py`
- Review: `tests/test_dump_symbols.py`
- Review: `tests/test_ida_preprocessor_common.py`
- Review: `tests/test_update_symbols.py`

- [ ] **Step 1: Verify no runtime path still requires `skill.symbol`**

Run: `rg -n "skill\\.symbol" symbol_config.py dump_symbols.py ida_preprocessor_common.py update_symbols.py tests`
Expected: only legacy-compat parsing or assertion text remains

- [ ] **Step 2: Document verification limits**

```text
Do not claim tests passed unless they were actually run.
If tests are skipped due to repo instruction, say so explicitly in the handoff.
```
