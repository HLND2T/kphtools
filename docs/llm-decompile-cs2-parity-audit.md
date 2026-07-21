# LLM_DECOMPILE CS2 Parity Audit

Source baseline: `D:\CS2_VibeSignatures` commit `3ad7a23f37c2009269765133d719b5efbcebadb6`.

## Intentional Differences

- `found_vcall` is excluded and explicitly rejected; kphtools supports only call, funcptr, GV, and struct-offset results.
- Network I/O uses `AsyncOpenAI` and `httpx.AsyncClient` to preserve the existing async pipeline.
- `codex_faker.json` uses the kphtools workspace/environment text.
- `{platform}` remains `amd64`/`arm64`; `{arch}` remains compatible and `{module_name}` is added.
- Struct semantic query names are derived from finder metadata instead of a non-standard spec field.
- Glued YAML headers remain a candidate repair before strict schema validation.

## Source Function Checklist

### `ida_llm_utils.py`

- [x] `require_nonempty_text` -> `ida_llm_utils.require_nonempty_text`.
- [x] `normalize_optional_temperature` -> same name.
- [x] `normalize_optional_effort` -> same name; default remains `medium`.
- [x] `create_openai_client` -> same name, adapted to `AsyncOpenAI`.
- [x] `extract_first_message_text` -> same name.
- [x] `_extract_text_from_message_content` -> same name.
- [x] `_build_responses_input` -> same name, preserving message IDs.
- [x] `_build_chat_completion_messages` -> same name, removing internal IDs.
- [x] `_extract_text_from_response_payload` -> same name.
- [x] `_extract_error_message_from_payload` -> same name.
- [x] `_load_codex_faker_template` -> same name.
- [x] `_fill_codex_template` -> same name.
- [x] `_call_llm_text_via_codex_http` -> same name, adapted to async `httpx` streaming.
- [x] `call_llm_text` -> same name, adapted to async Chat Completions/Responses.

### Source `ida_llm_decompile.py` split

- [x] `_empty_llm_decompile_result` -> `ida_llm_response.empty_llm_decompile_result`.
- [x] `_normalize_llm_retry_attempts`, `_normalize_llm_retry_delay` -> retry normalizers in `ida_llm_decompile.py`.
- [x] `_extract_llm_error_status_code`, `_is_transient_llm_error` -> status/transient helpers in `ida_llm_decompile.py`.
- [x] `_derive_module_name`, `_resolve_llm_decompile_template_value` -> `derive_module_name` and `format_prompt_template` in `ida_llm_prompt.py`.
- [x] `_parse_yaml_mapping`, `_normalize_llm_entries`, `_parse_llm_int_value`, `_normalize_llm_struct_offset_entries` -> strict response normalization in `ida_llm_response.py`.
- [x] `_strip_line_comment_outside_quotes`, `_strip_disasm_comments`, `_strip_c_like_comments` -> comment cleanup in `ida_llm_prompt.py`.
- [x] `_render_llm_decompile_blocks` -> `ida_llm_prompt.render_llm_decompile_blocks`.
- [x] `_new_llm_schema_issue`, `_extract_llm_yaml_candidates`, `_load_llm_yaml_document` -> response issue/candidate loading in `ida_llm_response.py`.
- [x] `_normalize_requested_symbol_names`, `_normalize_llm_decompile_mapping` -> response helpers in `ida_llm_response.py`.
- [x] `_validate_llm_raw_section`, `_classify_canonical_llm_mapping` -> canonical validation in `ida_llm_response.py`.
- [x] `_validate_llm_wrapped_section`, `_flatten_llm_wrapped_mapping`, `_classify_wrapped_llm_mapping` -> compatibility flattening in `ida_llm_response.py`.
- [x] `_parse_llm_decompile_response_with_issues`, `parse_llm_decompile_response` -> response public/parser APIs.
- [x] `_normalize_disasm_whitespace`, `_build_target_disasm_index` -> `ida_llm_validation.py`.
- [x] `_iter_llm_instruction_entries`, `_validate_llm_instruction_pairs` -> `ida_llm_validation.py`.
- [x] `_normalize_expected_result_sections`, `_get_llm_result_symbol_name` -> validation/response helpers using `Struct->Member` names.
- [x] `_validate_llm_result_sections`, `_validate_llm_requested_symbols`, `_validate_llm_decompile_result` -> `validate_llm_decompile_result`.
- [x] `_format_llm_instruction_issue`, `_format_llm_result_section_issue`, `_format_llm_validation_issue` -> correction formatting in `ida_llm_prompt.py`.
- [x] `_build_llm_schema_correction_guidance`, `_build_llm_instruction_correction_prompt` -> `build_validation_correction_prompt` with the four-section schema.
- [x] `_build_llm_result_section_requirements` -> `build_result_section_requirements`.
- [x] `_append_llm_instruction_correction`, `_parse_and_validate_llm_decompile_content` -> conversation update and `_parse_and_validate` in `ida_llm_decompile.py`.
- [x] `_handle_llm_transport_error`, `_call_llm_transport_attempt`, `_call_llm_decompile_with_validation` -> async `_run_llm_attempts`.
- [x] `_prepare_llm_decompile_request`, `_build_llm_decompile_request_cache_key` -> strict request/cache preparation in `ida_mcp_resolver.py` plus `ida_llm_specs.py`.
- [x] `call_llm_decompile` -> validated async facade in `ida_llm_decompile.py`.
- [x] `excluded: found_vcall` — `_extract_memory_displacements`.
- [x] `excluded: found_vcall` — `_instruction_contains_vfunc_offset`.
- [x] `excluded: found_vcall` — `_validate_llm_vcall_offsets`.
- [x] `excluded: found_vcall` — `_format_llm_vcall_offset_issue`.

### Source `ida_analyze_util.py` integration

- [x] `_normalize_string_list`, `_normalize_llm_decompile_spec`, `_build_llm_decompile_specs_map` -> `ida_llm_specs.py`.
- [x] dependency-policy/reference/category validation -> `validate_llm_decompile_specs` with kphtools `<func>.yaml` artifacts.
- [x] semantic query derivation -> `build_semantic_query_names`.
- [x] function/code-region target lookup/export -> `ida_llm_targets.py`.
- [x] direct call/function-pointer/global reference resolution -> `ida_llm_targets.py`.
- [x] request batching, cache, and result consumption -> `ida_mcp_resolver.py`.
- [x] per-skill attempts and dependency context -> `dump_symbols.py`, `ida_skill_preprocessor.py`, and `ida_preprocessor_common.py`.
- [x] `excluded: found_vcall` — vtable generation, slot matching, and vcall artifact consumption.

## Source Test Parity Checklist

### `tests/test_ida_llm_utils.py`

- [x] non-empty text/client creation/effort/temperature cases -> `TestRequireNonemptyText`, `TestCreateOpenAiClient`, `TestNormalizeOptionalValues`.
- [x] string/multipart/empty-choice extraction -> `TestExtractFirstMessageText`.
- [x] Chat Completions conversation, ID removal, request client, effort, and optional temperature -> `TestCallLlmText`.
- [x] Codex request body, headers, template placeholders, IDs, and cache key -> `TestCallLlmTextCodexHttp.test_posts_responses_body_headers_and_template_context` and `.test_preserves_ids_and_cache_key_across_retries`.
- [x] non-SSE rejection -> `.test_rejects_non_sse_content_type`.
- [x] delta/completed de-duplication and completed fallback -> `.test_avoids_completed_text_dup_after_deltas` and `.test_uses_completed_as_fallback_without_deltas`.
- [x] failed/incomplete/error payloads and empty response -> `.test_failure_events_after_delta_include_server_message` and `.test_empty_response_text_fails`.
- [x] missing/invalid template and placeholder counts -> `TestCodexTemplate`.

### `tests/test_ida_analyze_util.py` LLM scenarios

- [x] explicit expected sections and struct canonical names -> `tests/test_ida_llm_validation.py`.
- [x] all four response sections and `found_funcptr` -> `test_parses_all_four_canonical_sections`.
- [x] duplicate struct member keeps smaller offset -> `test_struct_duplicates_keep_the_smallest_numeric_offset`.
- [x] canonical empty classification -> `test_only_complete_explicit_empty_mapping_is_valid`.
- [x] invalid YAML correction -> `test_invalid_yaml_then_correction_succeeds`.
- [x] symbol-wrapped flattening and canonical batched responses -> `test_accepts_fenced_and_symbol_wrapped_yaml` plus decompile retry tests.
- [x] schema/symbol mismatch correction and repeated fail-closed -> `test_wrapped_mismatch_and_hallucinated_pair_are_corrected` and `test_validation_exhaustion_returns_empty`.
- [x] canonical-root prompt requirement -> `test_repository_prompt_declares_four_sections_and_rejects_vcall`.
- [x] hallucinated VA/instruction pairs, all target blocks, and no-address-index rejection -> `tests/test_ida_llm_validation.py`.
- [x] struct member returned in the wrong section -> `test_rejects_struct_member_in_wrong_section` and `test_wrong_section_is_corrected`.
- [x] all result-section mismatches reported -> validation aggregates all issue lists before correction.
- [x] stable correction message IDs/cache key -> `test_retry_preserves_existing_message_ids_and_cache_key`.
- [x] shared transport/validation budget -> `test_transport_and_validation_share_budget`.
- [x] target comment cleanup and reference preservation -> `test_cleans_only_target_blocks` and quote/escape tests.
- [x] temperature, effort, Codex forwarding, transient retry, non-transient stop, exhaustion, and `max_retries=1` -> `tests/test_ida_llm_decompile.py` and `tests/test_ida_llm_utils.py`.
- [x] strict dict normalization, legacy tuple rejection, missing/unknown fields, dependency policy, and category compatibility -> `tests/test_ida_llm_specs.py`.
- [x] multiple references and retry config -> specs tests plus `tests/test_llm_decompile_dump_integration.py`.
- [x] current YAML function VA, name lookup fallback, code-region target, required/optional target checks -> `tests/test_ida_llm_targets.py` and resolver integration tests.
- [x] batch reuse, semantic artifact/query separation, validated-empty no-cache/fallback -> `tests/test_llm_decompile_preprocessor_integration.py`.
- [x] unexpected `found_vcall` schema correction -> `test_unsupported_vcall_is_corrected`.
- [x] `excluded: found_vcall` — `test_call_llm_decompile_retries_vfunc_returned_as_funcptr`.
- [x] adapted from vcall: `test_call_llm_decompile_retries_struct_member_returned_as_vcall` -> unsupported-vcall correction plus struct-section validation.
- [x] `excluded: found_vcall` — `test_call_llm_decompile_retries_vcall_without_offset_instruction`.
- [x] `excluded: found_vcall` — direct vtable/vfunc signature generation and slot-limit tests.
- [x] `excluded: found_vcall` — `test_preprocess_common_skill_uses_llm_decompile_vcall_fallback_for_func_yaml`.

All non-vcall source scenarios above have a kphtools test or an explicitly documented equivalent. Runtime rejection/correction for an unexpected `found_vcall` remains covered even though vcall resolution is excluded.
