# Plan: find-AlpcpDeletePort

## Background

`AlpcpDeletePort` is a kernel function registered as a function pointer inside
`AlpcpInitSystem`. The relevant instruction is:

```asm
PAGE:00000001407C5BF8   lea     rax, AlpcpDeletePort
PAGE:00000001407C5C07   mov     [rbp+20h+var_88], rax
```

And in the decompiled procedure:

```c
v5[9] = AlpcpDeletePort;
```

Because the reference is a **`lea` (function-pointer load)** rather than a direct
`call`, the LLM will emit it in `found_funcptr`, not `found_call`.
The current `resolve_symbol_via_llm_decompile` only handles `found_call` for the
`func` category, so support for `found_funcptr` must be added first.

---

## Task List

### 1 — Add `found_funcptr` support to `ida_mcp_resolver.py`

File: `ida_mcp_resolver.py`

**New helper** `_resolve_funcptr_target_via_mcp(session, insn_va)`:
- Mirror of `_resolve_direct_call_target_via_mcp`, but use
  `idautils.DataRefsFrom(insn_ea)` instead of `CodeRefsFrom`.
- For each `target_ea` returned, call `ida_funcs.get_func(target_ea)`.
- Accept only targets where `func.start_ea == target_ea`
  (i.e. the reference points to the very start of a function).
- Return `target_ea` (as `int`) when exactly one valid match is found,
  otherwise `None`.

**In `resolve_symbol_via_llm_decompile`, `func` branch** (around line 884):
After the existing `found_call` loop, add a second loop over
`result.get("found_funcptr", [])`:

```python
for entry in result.get("found_funcptr", []):
    if entry.get("funcptr_name") not in {symbol_name, llm_symbol_name}:
        continue
    func_va = await _resolve_funcptr_target_via_mcp(session, entry.get("insn_va"))
    if func_va is not None:
        return {
            "func_name": symbol_name,
            "func_va": func_va,
            "func_rva": func_va - image_base,
        }
```

Note: the LLM uses the key `funcptr_name` (not `func_name`) for `found_funcptr`
entries (see prompt template).

---

### 2 — Annotate `AlpcpInitSystem.amd64.yaml`

File: `ida_preprocessor_scripts/references/ntoskrnl/AlpcpInitSystem.amd64.yaml`

The reference YAML was generated (func_va `0x1407c5b0c`). Annotations are
needed so the LLM can unambiguously identify `AlpcpDeletePort`.

**In `disasm_code`**, annotate the three relevant lines:

```yaml
  PAGE:00000001407C5BD3                 lea     rax, AlpcpOpenPort   ; function pointer: AlpcpOpenPort (DeleteProcedure sibling)
  PAGE:00000001407C5BE3                 lea     rax, AlpcpClosePort  ; function pointer: AlpcpClosePort (DeleteProcedure sibling)
  PAGE:00000001407C5BF8                 lea     rax, AlpcpDeletePort ; function pointer: AlpcpDeletePort — OB_OBJECT_TYPE DeleteProcedure callback
```

**In `procedure`**, annotate the matching lines:

```c
v5[7] = AlpcpOpenPort;   // function pointer: AlpcpOpenPort  (OpenProcedure)
v5[8] = AlpcpClosePort;  // function pointer: AlpcpClosePort (CloseProcedure)
v5[9] = AlpcpDeletePort; // function pointer: AlpcpDeletePort — OB_OBJECT_TYPE DeleteProcedure callback
```

Surrounding siblings (`AlpcpOpenPort`, `AlpcpClosePort`) give the LLM enough
context to avoid confusing the three adjacent function-pointer stores.

---

### 3 — Create `ida_preprocessor_scripts/find-AlpcpDeletePort.py`

Category: `func`. Uses `LLM_DECOMPILE` with `AlpcpInitSystem` as reference.

```python
from __future__ import annotations

import ida_preprocessor_common as preprocessor_common

TARGET_FUNCTION_NAMES = ["AlpcpDeletePort"]

LLM_DECOMPILE = [
    (
        "AlpcpDeletePort",
        "AlpcpDeletePort",
        "prompt/call_llm_decompile.md",
        "references/ntoskrnl/AlpcpInitSystem.{arch}.yaml",
    ),
]

FUNC_METADATA = {
    "AlpcpDeletePort": {
        "alias": ["AlpcpDeletePort"],
    }
}

GENERATE_YAML_DESIRED_FIELDS = {
    "AlpcpDeletePort": ["func_name", "func_rva"],
}


async def preprocess_skill(session, skill, symbol, binary_dir, pdb_path, debug, llm_config):
    return await preprocessor_common.preprocess_common_skill(
        session=session,
        skill=skill,
        symbol=symbol,
        binary_dir=binary_dir,
        pdb_path=pdb_path,
        debug=debug,
        llm_config=llm_config,
        func_names=TARGET_FUNCTION_NAMES,
        func_metadata=FUNC_METADATA,
        llm_decompile_specs=LLM_DECOMPILE,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
    )
```

---

### 4 — Update `config.yaml`

Under the `ntoskrnl` module:

**Add skill entry** (after `find-AlpcpInitSystem`):

```yaml
  - name: find-AlpcpDeletePort
    expected_input:
    - AlpcpInitSystem.yaml
    expected_output:
    - AlpcpDeletePort.yaml
```

`expected_input` is set because the finder depends on `AlpcpInitSystem.yaml`
being produced first (it is the reference function used in `LLM_DECOMPILE`).

**Add symbol entry** (near other `AlpcpXxx` symbols):

```yaml
  - name: AlpcpDeletePort
    category: func
    data_type: uint32
```

---

### 5 — Validate

```bash
uv run dump_symbols.py -debug > /tmp/dump_symbols_out.txt 2>&1
grep -E "preprocess status for find-AlpcpDeletePort" /tmp/dump_symbols_out.txt
```

Expected: `find-AlpcpDeletePort: success` or `find-AlpcpDeletePort: absent_ok`.

Also run YAML parse checks:

```bash
python -c "import yaml; yaml.safe_load(open('config.yaml'))"
python -c "import yaml; yaml.safe_load(open('ida_preprocessor_scripts/references/ntoskrnl/AlpcpInitSystem.amd64.yaml'))"
```

---

### 6 — Commit

Stage and commit:

```
feat(preprocessor): add find-AlpcpDeletePort via LLM_DECOMPILE AlpcpInitSystem
```

Files to stage:
- `ida_mcp_resolver.py`
- `ida_preprocessor_scripts/find-AlpcpDeletePort.py`
- `ida_preprocessor_scripts/references/ntoskrnl/AlpcpInitSystem.amd64.yaml`
- `config.yaml`
