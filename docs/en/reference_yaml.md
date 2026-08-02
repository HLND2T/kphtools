# Reference YAML for `LLM_DECOMPILE`

[Back to README](../../README.md)

`generate_reference_yaml.py` creates a single reference YAML at:

```text
ida_preprocessor_scripts/references/<module>/<func_name>.<arch>.yaml
```

## Generate a reference

Attach to an existing MCP session:

```bash
uv run generate_reference_yaml.py -func_name="ExReferenceCallBackBlock"
```

The MCP client automatically supports both legacy worker sessions and the newer supervisor protocol. When the supervisor exposes multiple active IDA databases, select one explicitly with its session ID:

```bash
uv run generate_reference_yaml.py \
  -func_name="ExReferenceCallBackBlock" \
  -mcp_database="<session_id>"
```

Auto-start `idalib-mcp` for a specific binary:

```bash
uv run generate_reference_yaml.py \
  -func_name="ExReferenceCallBackBlock" \
  -auto_start_mcp \
  -binary="symbols/amd64/ntoskrnl.exe.10.0.26100.1/{sha256}/ntoskrnl.exe"
```

Reference auto-start mode does not use the analyzer's recovery budget. A matching supervisor IDB that is inactive or unreachable is reported immediately as a reference-generation failure.

## Validate the generated YAML

Check that:

- `func_va` is credible.
- `disasm_code` is non-empty and includes any available comments.
- `disasm_code` includes discontinuous function chunks when IDA associates them with the same function.
- `procedure` is present; it may be an empty string if Hex-Rays is unavailable.

## Declare `LLM_DECOMPILE`

Attach the reference to a preprocessor script with a prompt:

```python
LLM_DECOMPILE = [
    {
        "symbol_name": "AlpcAttributes",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/ntoskrnl/AlpcpDeletePort.{arch}.yaml",
        ],
        "expected_result_sections": ["found_struct_offset"],
        "instruction_rules": [
            {
                "regex": r"(?i)^mov\s+eax,\s*\[[^\]]+\]$",
                "text": "mov eax, [base+offset]",
            },
        ],
        "expected_size": 4,
        "dependency_policy": {"AlpcpDeletePort.yaml": "required"},
    },
    {
        "symbol_name": "MmCreateProcessAddressSpace",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/ntoskrnl/PspAllocateProcess.{arch}.yaml",
        ],
        "expected_result_sections": ["found_call", "found_funcptr"],
        "dependency_policy": {"PspAllocateProcess.yaml": "required"},
    },
]
```

Every entry must contain the five required fields shown above. `instruction_rules` and `expected_size` are optional; `expected_size` is valid only for `found_struct_offset` targets. Each instruction rule contains a full-match `regex` plus human-readable `text` used in correction prompts. Legacy tuples and other unknown fields fail closed.

`prompt_path` and `reference_yaml_paths` support `{arch}`, `{platform}`, and `{module_name}` templates. `dependency_policy` must map every reference YAML `func_name` to its current artifact basename; `required` targets must be declared in the skill's `expected_input`, while `optional` targets must be declared in `optional_input`. Architecture-specific input fields are supported.

`symbol_name` is the kphtools artifact name. Function and global semantic names use that value directly. Struct-member semantic names come from the finder metadata's `symbol_expr`, such as `_ALPC_PORT->PortAttributes`, without adding a non-standard field to the spec.

## Validated response contract

The validated response contract supports only:

- `found_call`: direct calls, direct tail jumps, and jump thunks.
- `found_funcptr`: direct references to regular function addresses.
- `found_gv`: global-variable references.
- `found_struct_offset`: regular struct-member accesses, including function-pointer fields.

`found_vcall` is currently unsupported and is rejected as a schema mismatch. Every non-empty result must match a requested symbol, its declared result section, and a real `(insn_va, insn_disasm)` pair from the target code. When instruction constraints are declared, the instruction must also match one of the configured regexes. Struct results additionally verify `expected_size` when configured and require the reported `offset` to be the memory displacement accessed by that exact instruction. The displacement check supports x86/x64 `+`/`-` forms and ARM64 `#offset` forms; a reported zero offset requires an unindexed base-register operand. Validation failures are returned to the LLM as correction prompts within the shared retry budget. The canonical empty response is:

```yaml
found_call: []
found_funcptr: []
found_gv: []
found_struct_offset: []
```

Pass the list to `preprocess_common_skill(..., llm_decompile_specs=LLM_DECOMPILE)`. Validated direct call, function-pointer, and global-variable results are resolved through IDA references; validated struct results use the finder metadata and bit-offset constraints.

See [`dump_symbols.py`](dump_symbols.md) for LLM provider and retry configuration.
