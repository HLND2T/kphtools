# ida_llm_decompile

## Overview

ida_llm_decompile 是 kphtools 的 LLM 反编译解析基础设施：为 IDA/Hex-Rays 提供的 reference 与 target 代码构造提示词，调用 OpenAI-compatible 或 Codex SSE transport，并把模型输出限制为可验证的四段 YAML 结果。它作为 IDA preprocessor 的 fallback，仅在 PDB/常规 IDA finder 未得到所需 artifact 时介入，随后把已验证结果转换为函数、全局变量或结构成员偏移。

## Responsibilities

- 规范化 LLM_DECOMPILE spec、输入依赖、架构/模块模板和 semantic query name；按符号 category 限制允许的结果 section。
- 从 reference YAML、当前 binary artifact 和 IDA MCP 导出 target disasm_code/procedure，构造批量 LLM 请求。
- 解析 canonical 或 symbol-wrapped YAML，统一为 found_call、found_funcptr、found_gv、found_struct_offset 四段 contract；拒绝 unsupported 的 found_vcall。
- 校验 (insn_va, insn_disasm) 与真实 target 指令、请求符号/section、instruction rules、struct expected_size 和 displacement；失败时生成 correction prompt。
- 在同一 retry budget 内处理 transient transport error 与 validation correction；成功结果按请求上下文缓存，并通过 IDA references 解析为最终 artifact payload。
- 生成并验证供后续 LLM 使用的 reference YAML，支持已有 IDA MCP session 和自动启动 idalib-mcp。

## Involved Files & Symbols

- ida_llm_decompile.py - call_llm_decompile, is_transient_llm_error, _run_llm_attempts
- ida_llm_utils.py - call_llm_text, create_openai_client, _call_llm_text_via_codex_http, _read_codex_sse_response
- ida_llm_prompt.py - render_llm_decompile_blocks, format_prompt_template, build_validation_correction_prompt
- ida_llm_response.py - parse_llm_decompile_response_with_issues, empty_llm_decompile_result
- ida_llm_validation.py - build_target_disasm_index, validate_llm_decompile_result
- ida_llm_specs.py - normalize_llm_decompile_spec, build_llm_decompile_specs_map, validate_llm_decompile_specs, build_semantic_query_names
- ida_llm_targets.py - load_llm_decompile_target_details_via_mcp, resolve_direct_call_target_via_mcp, resolve_funcptr_target_via_mcp, resolve_direct_gv_target_via_mcp
- ida_mcp_resolver.py - _prepare_llm_decompile_request, _load_or_call_llm_result, resolve_symbol_via_llm_decompile
- ida_preprocessor_common.py - _prepare_llm_decompile_context, preprocess_common_skill
- ida_skill_preprocessor.py - _get_preprocess_entry, preprocess_single_skill_via_mcp
- dump_symbols.py - _preprocess_skill_outputs, _build_effective_llm_config_for_skill, _build_llm_config
- generate_reference_yaml.py - run_reference_generation, infer_context_from_binary_path, resolve_reference_target, autostart_mcp_session
- ida_reference_export.py - validate_reference_yaml_payload, export_reference_yaml_via_mcp, export_code_region_yaml_via_mcp
- ida_reference_export_template.py, ida_code_region_export_template.py - IDA-side function/code-region export snippets
- ida_mcp_session.py - open_ida_mcp_session and database/session selection
- symbol_artifacts.py - artifact_path, write_func_yaml, write_gv_yaml, write_struct_yaml
- ida_preprocessor_scripts/find-*-decompiles.py - 12 finder modules declaring LLM_DECOMPILE and delegating to preprocess_common_skill
- ida_preprocessor_scripts/prompt/call_llm_decompile.md, call_llm_decompile_ob_decode_shift.md - prompt templates
- ida_preprocessor_scripts/references/ntoskrnl/*.yaml - reference inputs; generated output path is ida_preprocessor_scripts/references/<module>/<func_name>.<arch>.yaml
- config.yaml - skill ordering and expected_input/optional_input dependency graph
- tests/test_ida_llm_*.py, tests/test_llm_decompile_dump_integration.py, tests/test_llm_decompile_preprocessor_integration.py - unit and integration coverage

## Architecture

主流程由 dump_symbols.py 逐个 skill/symbol 驱动；finder script 只声明目标、metadata、desired fields 和 LLM_DECOMPILE，业务逻辑集中在 ida_preprocessor_common.py。

~~~mermaid
flowchart TD
    A["dump_symbols.py"] --> B["ida_skill_preprocessor.preprocess_single_skill_via_mcp"]
    B --> C["find-*-decompiles.py preprocess_skill"]
    C --> D["ida_preprocessor_common.preprocess_common_skill"]
    D --> E{"PDB/IDA fast path returns payload?"}
    E -->|Yes| F["Filter desired fields and write artifact"]
    E -->|No| G["Validate specs and build semantic query names"]
    G --> H["ida_mcp_resolver.resolve_symbol_via_llm_decompile"]
    H --> I["Load prompt/reference YAML and export target details via IDA MCP"]
    I --> J["ida_llm_decompile.call_llm_decompile"]
    J --> K["ida_llm_utils.call_llm_text"]
    J --> L["Parse YAML response and validate semantics"]
    L --> M{"Valid result?"}
    M -->|No| N["Correction prompt within shared retry budget"]
    N --> J
    M -->|Yes| O["Resolve IDA references or struct offset"]
    O --> F
~~~

call_llm_decompile 的单次请求顺序是：规范化 symbol/section/validation → render_llm_decompile_blocks 清理 target 注释并填充 prompt → 建立 target disassembly index → 发送 system/user messages → 解析 YAML → 做 schema、指令地址/文本、section、instruction rule、size/displacement 校验。校验问题会追加 assistant 原答和 user correction prompt；transport transient error 则按 delay/backoff 重试。所有失败路径返回 canonical empty result，由上层转成 PREPROCESS_STATUS_FAILED。

结果 contract：

- found_call：direct call、tail jump 或 jump thunk；上层通过 IDA CodeRefsFrom 找唯一函数起点。
- found_funcptr：普通函数地址引用；上层通过 IDA DataRefsFrom 找唯一函数起点。
- found_gv：全局变量引用；上层通过 IDA DataRefsFrom 找唯一地址。
- found_struct_offset：结构成员访问；上层按 finder metadata 匹配 struct_name/member_name，解析 offset/可选 bit_offset。

ida_mcp_resolver 会把具有相同 prompt/reference/dependency 签名的 spec 合并成一次 batch 请求；reference target 优先读取当前 binary 目录已有 YAML，缺失时在当前 IDB 按名称查找并通过 ida_llm_targets 导出 detail。只有 required target 全部可用时才调用 LLM；非空结果按包含 binary、model、prompt/reference、目标函数、期望 sections、instruction validations 和 contract version 的 key 做进程内缓存。

reference 生成流程独立但共享 IDA 导出层：

~~~mermaid
flowchart TD
    R["generate_reference_yaml.py"] --> S["Attach to or autostart idalib-mcp"]
    S --> T["Infer module/arch and resolve function or code target"]
    T --> U["ida_reference_export remote py_eval export"]
    U --> V["Atomic YAML write and validate_reference_yaml_payload"]
~~~

## Dependencies

- Internal: dump_symbols.py, ida_mcp_session.py, ida_preprocessor_common.py, ida_skill_preprocessor.py, symbol_artifacts.py, generic IDA finder scripts.
- IDA runtime: IDA/Hex-Rays APIs executed through MCP py_eval; idalib-mcp session management; current IDB and binary/PDB artifacts.
- Python libraries: openai/AsyncOpenAI, httpx, PyYAML, python-dotenv (reference generator).
- Configuration/resources: config.yaml; .env or KPHTOOLS_LLM_MODEL, KPHTOOLS_LLM_APIKEY, KPHTOOLS_LLM_BASEURL, KPHTOOLS_LLM_TEMPERATURE, KPHTOOLS_LLM_EFFORT, KPHTOOLS_LLM_FAKE_AS; prompt templates and ntoskrnl reference YAMLs.

## Notes

- LLM fallback is fail-closed: missing model/API key, invalid spec/reference/prompt, missing required target detail, malformed YAML, unsupported section, or unresolved IDA reference yields empty result / failed preprocess.
- Retry count is total attempts including the first call. Schema correction and transient transport retry share the same budget; default delay/backoff is 1.0s / 2.0x / 8.0s max in ida_llm_decompile, while skill-level max_retries is injected by dump_symbols.py.
- The canonical response must contain all four top-level sections for an explicit empty result. Symbol-wrapped responses are accepted only for requested symbols and flattened; found_vcall is rejected.
- Instruction validation requires exact VA-to-disassembly correspondence after whitespace normalization. Struct offset validation supports x86/x64 signed displacements and ARM64 #offset; zero requires an unindexed base register.
- dependency_policy keys are reference artifact basenames and must agree with reference_yaml_paths; required entries must be in skill expected_input, optional entries in optional_input. Path templates support {arch}, {platform}, {module_name}.
- Struct semantic query names come from finder metadata symbol_expr (for example _ALPC_PORT->PortAttributes), not from an extra spec field.
- Prompt rendering strips comments from target disassembly/C-like procedure before sending to the model, but reference blocks are retained as context.
- Reference export validates remote ack path/format/byte count and then validates YAML payload; remote writes use a temporary file followed by os.replace.
- Result cache is process-local and only stores non-empty results; its key includes _LLM_RESULT_CONTRACT_VERSION, so contract changes invalidate old entries.
- generate_reference_yaml.py rejects unsafe output path components, enforces module/arch consistency with the current binary, and cleans up auto-started IDA MCP plus its port.

## Callers

- dump_symbols._preprocess_skill_outputs -> ida_skill_preprocessor.preprocess_single_skill_via_mcp
- 12 ida_preprocessor_scripts/find-*-decompiles.py finder entrypoints -> ida_preprocessor_common.preprocess_common_skill
- ida_preprocessor_common.preprocess_common_skill -> ida_mcp_resolver.resolve_symbol_via_llm_decompile
- ida_mcp_resolver._load_or_call_llm_result -> ida_llm_decompile.call_llm_decompile
- generate_reference_yaml.py -> ida_reference_export.export_reference_yaml_via_mcp / export_code_region_yaml_via_mcp
- Unit/integration tests under tests/test_ida_llm_*.py and tests/test_llm_decompile_*_integration.py
