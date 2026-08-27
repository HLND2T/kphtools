# `LLM_DECOMPILE` 的 Reference YAML

[返回 README](../../README.zh-CN.md)

`generate_reference_yaml.py` 会生成一个 reference YAML，路径为：

```text
ida_preprocessor_scripts/references/<module>/<func_name>.<arch>.yaml
```

## 生成 reference

连接到已有 MCP session：

```bash
uv run generate_reference_yaml.py -func_name="ExReferenceCallBackBlock"
```

MCP client 同时支持旧版 worker session 和新版 supervisor protocol。当 supervisor 暴露多个活动的 IDA database 时，使用 session ID 明确选择一个：

```bash
uv run generate_reference_yaml.py \
  -func_name="ExReferenceCallBackBlock" \
  -mcp_database="<session_id>"
```

针对指定二进制自动启动 `idalib-mcp`：

```bash
uv run generate_reference_yaml.py \
  -func_name="ExReferenceCallBackBlock" \
  -auto_start_mcp \
  -binary="symbols/amd64/ntoskrnl.exe.10.0.26100.1/{sha256}/ntoskrnl.exe"
```

Reference auto-start 模式不使用 analyzer 的恢复预算。匹配的 supervisor IDB 若处于非活动或不可达状态，会立即报告 reference 生成失败。

## 校验生成的 YAML

确认以下内容：

- `func_va` 是可信的。
- `disasm_code` 非空，并包含所有可用注释。
- 当 IDA 将不连续的函数代码块关联到同一个函数时，`disasm_code` 也包含这些代码块。
- 存在 `procedure`；如果 Hex-Rays 不可用，它可以是空字符串。

## 声明 `LLM_DECOMPILE`

使用 prompt 将 reference 关联到 preprocessor script：

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

每个条目必须包含上述五个必需字段。`instruction_rules` 和 `expected_size` 可选；`expected_size` 仅对 `found_struct_offset` 目标有效。每条 instruction rule 包含一个完整匹配的 `regex`，以及用于 correction prompt 的人类可读 `text`。旧版 tuple 和其他未知字段会直接拒绝。

`prompt_path` 与 `reference_yaml_paths` 支持 `{arch}`、`{platform}` 和 `{module_name}` 模板。`dependency_policy` 必须将每个 reference YAML 的 `func_name` 映射到当前工件 basename；`required` 目标必须声明在 skill 的 `expected_input` 中，`optional` 目标必须声明在 `optional_input` 中。支持架构相关的输入字段。

`symbol_name` 是 kphtools 工件名。函数和全局变量的语义名称直接使用该值。结构体成员的语义名称来自 finder metadata 的 `symbol_expr`，例如 `_ALPC_PORT->PortAttributes`，不会向 spec 添加非标准字段。

## 已校验的响应契约

已校验的响应契约仅支持：

- `found_call`：直接调用、直接 tail jump 和 jump thunk。
- `found_funcptr`：对普通函数地址的直接引用。
- `found_gv`：全局变量引用。
- `found_struct_offset`：普通结构体成员访问，包括函数指针字段。

当前不支持 `found_vcall`，遇到它会被作为 schema mismatch 拒绝。每个非空结果必须匹配请求的 symbol、声明的结果 section，以及目标代码中真实的 `(insn_va, insn_disasm)` 对。声明了 instruction constraint 时，指令还必须匹配配置的某个 regex。结构体结果还会在配置时校验 `expected_size`，并要求报告的 `offset` 是该确切指令访问的内存位移。位移校验支持 x86/x64 的 `+`/`-` 形式和 ARM64 的 `#offset` 形式；报告零位移时，必须使用未索引的 base-register operand。校验失败会在共享重试预算内作为 correction prompt 返回给 LLM。标准空响应为：

```yaml
found_call: []
found_funcptr: []
found_gv: []
found_struct_offset: []
```

将列表传递给 `preprocess_common_skill(..., llm_decompile_specs=LLM_DECOMPILE)`。已校验的 direct call、function-pointer 和 global-variable 结果通过 IDA references 解析；已校验的 struct 结果使用 finder metadata 和 bit-offset constraints。

LLM provider 与重试配置见 [`dump_symbols.py`](dump_symbols.md)。
