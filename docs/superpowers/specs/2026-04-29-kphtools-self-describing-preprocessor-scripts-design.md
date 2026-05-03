# kphtools Self-Describing Preprocessor Scripts Design

Date: 2026-04-29

## 1. Summary

This design refactors the `kphtools` preprocessing layer so that each
`ida_preprocessor_scripts/find-*.py` file becomes the single source of truth
for symbol-locating metadata, following the same calling style used by
`CS2_VibeSignatures`.

The target model is:

- `config.yaml` keeps workflow scheduling data in `skills`
- `config.yaml` keeps symbol inventory data in `symbols`
- symbol-locating details move out of `config.yaml`
- each `find-*.py` script declares its own target metadata and
  `GENERATE_YAML_DESIRED_FIELDS`
- each `find-*.py` script delegates to a unified
  `preprocess_common_skill(...)` entrypoint

This aligns the preprocessing invocation model with:

- `/mnt/d/CS2_VibeSignatures/ida_preprocessor_scripts/find-CGameResourceService_m_pEntitySystem.py`
- `/mnt/d/CS2_VibeSignatures/ida_analyze_util.py::preprocess_common_skill`

while intentionally keeping the smaller `kphtools` YAML schema.

## 2. Goals

1. Make every `find-*.py` preprocessor script self-describing.
2. Remove locating details such as `symbol_expr`, `struct_name`,
   `member_name`, `bits`, and `alias` from `config.yaml`.
3. Keep `config.yaml` as the workflow and symbol inventory file.
4. Introduce a unified `kphtools` preprocessing interface that matches the
   CS2 calling style closely enough for future maintenance.
5. Preserve current YAML output schema for `struct_offset`, `gv`, and `func`.
6. Preserve current `dump_symbols.py -> update_symbols.py` workflow behavior.

## 3. Non-Goals

1. Port the full `CS2_VibeSignatures` preprocessing framework into `kphtools`.
2. Introduce `offset_sig`, `gv_sig`, `func_sig`, `*_va`, `size`, or similar
   extended fields into `kphtools` YAML outputs.
3. Change `update_symbols.py` XML export semantics.
4. Remove the `symbols` section from `config.yaml`.
5. Merge this design with unrelated workflow changes already present in the
   working tree.

## 4. Confirmed Decisions

### 4.1 Configuration Boundary

`config.yaml` remains the only repository-level scheduling config, but its
responsibility is reduced.

`skills[]` keeps only workflow data:

- `name`
- `symbol`
- `expected_input`
- `expected_output`
- `max_retries`

`symbols[]` keeps only symbol directory data:

- `name`
- `category`
- `data_type`

The following fields are no longer allowed in `config.yaml`:

- `skills.agent_skill`
- `symbols.symbol_expr`
- `symbols.struct_name`
- `symbols.member_name`
- `symbols.bits`
- `symbols.alias`

### 4.2 Script Ownership

Each `ida_preprocessor_scripts/find-*.py` file becomes the single source of
truth for:

- target symbol names
- struct-member lookup expressions
- struct/member naming
- bitfield markers
- gv/function alias lookup names
- desired YAML output fields

This means `find-EgeGuid.py` is no longer a thin wrapper around a generic
module. It becomes the true skill definition file for `EgeGuid`.

### 4.3 Output Schema Stays Small

The public YAML contract remains unchanged.

Allowed output fields by category:

- `struct_offset`
  - `struct_name`
  - `member_name`
  - `offset`
  - `bit_offset`
- `gv`
  - `gv_name`
  - `gv_rva`
- `func`
  - `func_name`
  - `func_rva`

`GENERATE_YAML_DESIRED_FIELDS` is used in `kphtools` for explicit script-side
output declaration, not for expanding the artifact schema.

## 5. Target Architecture

### 5.1 Dispatch Layer

`ida_skill_preprocessor.py` keeps its current high-level responsibility:

1. locate `ida_preprocessor_scripts/{skill_name}.py`
2. load exported `preprocess_skill`
3. invoke the script-specific entrypoint

It must not grow category-specific branching again.

### 5.2 New Shared Preprocessor Entry

A new shared module is introduced, recommended path:

- `ida_preprocessor_common.py`

It exports:

- `preprocess_common_skill(...)`

This function is the `kphtools` equivalent of the CS2 shared entrypoint, but
only for the three current categories:

- `struct_offset`
- `gv`
- `func`

### 5.3 Shared Entry Responsibilities

`preprocess_common_skill(...)` performs the following:

1. validate that the active script declaration matches `skill.symbol`
2. read category information from the corresponding `SymbolSpec`
3. route to the correct internal resolution path
4. execute PDB-first resolution
5. fall back to existing MCP/LLM helpers where current behavior already does so
6. assemble the payload using `GENERATE_YAML_DESIRED_FIELDS`
7. write YAML using existing artifact writers

It does not:

- parse workflow config
- discover binaries
- manage skill dependency order
- expand output schema beyond current `kphtools` needs

### 5.4 Internal Helper Strategy

The current modules:

- `ida_preprocessor_scripts/generic_struct_offset.py`
- `ida_preprocessor_scripts/generic_gv.py`
- `ida_preprocessor_scripts/generic_func.py`

stop being used as skill-entry templates.

They should either:

- be turned into pure helper modules used by `ida_preprocessor_common.py`, or
- have their logic moved into `ida_preprocessor_common.py`

The preferred choice is the first one, because it minimizes migration risk and
keeps existing tested resolution logic reusable.

## 6. Script Contract

### 6.1 Common Shape

Every `find-*.py` script uses the same pattern:

1. declare target-name constants
2. declare script-owned metadata tables
3. declare `GENERATE_YAML_DESIRED_FIELDS`
4. implement `preprocess_skill(...)` as a thin call to
   `preprocess_common_skill(...)`

### 6.2 Struct Script Contract

Struct-offset scripts declare:

- `TARGET_STRUCT_MEMBER_NAMES`
- per-symbol metadata containing:
  - `symbol_expr`
  - `struct_name`
  - `member_name`
  - `bits`
- `GENERATE_YAML_DESIRED_FIELDS`

Example use case:

- `find-EgeGuid.py` owns `_ETW_GUID_ENTRY->Guid`
- `find-ObDecodeShift.py` owns `_HANDLE_TABLE_ENTRY->ObjectPointerBits`
  plus `bits=true`

### 6.3 GV Script Contract

GV scripts declare:

- `TARGET_GLOBALVAR_NAMES`
- optional per-symbol `alias`
- `GENERATE_YAML_DESIRED_FIELDS`

Alias selection remains script-owned because it is symbol-location metadata,
not inventory metadata.

### 6.4 Function Script Contract

Function scripts declare:

- `TARGET_FUNCTION_NAMES`
- optional per-symbol `alias`
- `GENERATE_YAML_DESIRED_FIELDS`

This matches the GV model and keeps all name-resolution exceptions inside the
script layer.

## 7. Shared Entry API

### 7.1 Recommended Function Shape

The new shared entry should accept the same runtime context already passed to
current skill scripts:

- `session`
- `skill`
- `symbol`
- `binary_dir`
- `pdb_path`
- `debug`
- `llm_config`

In addition, the script passes declaration data, for example:

- `struct_member_names`
- `gv_names`
- `func_names`
- script-owned metadata maps
- `generate_yaml_desired_fields`

### 7.2 Validation Rules

The shared entry must fail early when:

- `skill.symbol` is not declared by the active script
- the script declaration does not match `symbol.category`
- a requested desired field is not allowed for that category
- required script-owned metadata is missing for the active target

This keeps configuration drift visible and prevents hidden fallback behavior.

## 8. Resolution Behavior

### 8.1 Struct Offset Path

The struct path keeps current `kphtools` behavior:

1. attempt PDB resolution with `resolve_struct_symbol(...)`
2. use script-owned `symbol_expr` and bitfield metadata
3. if PDB lookup fails and LLM is enabled, use existing
   `resolve_struct_offset_via_llm(...)`
4. write only fields explicitly requested by
   `GENERATE_YAML_DESIRED_FIELDS`

### 8.2 GV Path

The GV path keeps current behavior:

1. attempt PDB/public symbol resolution
2. use script-owned alias as lookup name when provided
3. fall back to MCP public-name lookup
4. write only `gv_name` and `gv_rva`

### 8.3 Function Path

The function path mirrors the GV path:

1. attempt PDB/public symbol resolution
2. use script-owned alias when provided
3. fall back to MCP public-name lookup
4. write only `func_name` and `func_rva`

## 9. Migration Plan

### 9.1 Order

Migration should proceed in this order:

1. add `ida_preprocessor_common.py`
2. tighten `symbol_config.py` validation rules
3. migrate one struct sample script:
   - `find-EgeGuid.py`
4. migrate one GV sample script
5. migrate one function sample script
6. migrate the remaining scripts in bulk
7. remove runtime dependence on old symbol-locating config fields

### 9.2 Batch Scope

All current preprocessing skills are migrated to the same model:

- all `struct_offset` skills
- all `gv` skills
- all `func` skills

No mixed old/new script style should remain after the migration lands.

## 10. Verification Strategy

### 10.1 Config Validation Tests

`tests/test_symbol_config.py` must verify:

- repository baseline config still loads
- `symbols` entries containing removed locating fields now fail validation
- `skills.agent_skill` remains rejected

### 10.2 Shared Entry Tests

Add or update tests for the new shared entry to verify:

- struct path uses script-owned `symbol_expr`
- struct bitfield behavior comes from script metadata
- gv alias behavior comes from script metadata
- func alias behavior comes from script metadata
- `GENERATE_YAML_DESIRED_FIELDS` filters payload fields correctly

### 10.3 Script Dispatch Tests

`tests/test_ida_skill_preprocessor.py` must verify that:

- script loading still happens by `skill.name`
- sample scripts now execute through `preprocess_common_skill(...)`
- generic helper modules are no longer treated as skill definitions

### 10.4 Workflow Tests

`tests/test_dump_symbols.py` should continue verifying:

- fallback still uses `.claude/skills/{skill.name}/SKILL.md`
- no `agent_skill` override path exists

### 10.5 Structural Smoke Checks

At minimum, the repository should be able to verify that for every configured
skill:

- `ida_preprocessor_scripts/{skill.name}.py` exists
- `.claude/skills/{skill.name}/SKILL.md` exists

### 10.6 Output Compatibility

`update_symbols.py` and its tests should not require semantic changes, because
the YAML schema remains the same.

## 11. Risks and Mitigations

### 11.1 Risk: Metadata Drift During Bulk Migration

Moving metadata from `config.yaml` into 46 scripts creates copy risk.

Mitigation:

- migrate one sample per category first
- keep structural smoke checks
- keep strict shared-entry validation

### 11.2 Risk: Hidden Dual Sources of Truth

If old fields remain tolerated in config, drift will reappear.

Mitigation:

- reject removed fields explicitly in `symbol_config.py`
- ensure runtime code no longer reads them from config

### 11.3 Risk: Overfitting to CS2 Internals

Directly copying the CS2 shared framework would add unused complexity.

Mitigation:

- align the calling style
- keep the `kphtools` payload model intentionally narrow

## 12. Expected Outcome

After this design is implemented:

- `config.yaml` becomes cleaner and more stable
- each `find-*.py` file fully describes how its symbol is resolved
- preprocessing uses one script-facing API across `struct_offset`, `gv`, and
  `func`
- `kphtools` matches the CS2 preprocessor calling style without inheriting the
  full CS2 artifact model
