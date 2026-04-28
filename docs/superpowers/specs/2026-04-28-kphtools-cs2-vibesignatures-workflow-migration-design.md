# kphtools CS2_VibeSignatures Workflow Migration Design

Date: 2026-04-28

## 1. Summary

This design migrates `kphtools` from the current split workflow:

- `update_symbols.py`: direct PDB parsing plus direct `kphdyn.xml` mutation
- `reverse_symbols.py`: `ida64.exe -A -S` driven reverse workflow plus standalone LLM mapping

to a CS2_VibeSignatures-style workflow:

- `dump_symbols.py`: the single analysis entry point, modeled after `CS2_VibeSignatures/ida_analyze_bin.py`
- `update_symbols.py`: a pure exporter, modeled after `CS2_VibeSignatures/update_gamedata.py`

Under the new model:

- YAML becomes the primary source of truth.
- `kphdyn.xml` becomes an exported artifact.
- `symboldir` remains the only artifact root and serves the same role that `bindir` serves in `CS2_VibeSignatures`.
- IDA interaction moves to `ida-pro-mcp`.
- The old `ida64.exe -A -S` startup flow is removed.
- The old standalone `reverse_symbols.py` workflow is retired.

## 2. Goals

1. Replace the current IDA/LLM workflow in `kphtools` with a CS2_VibeSignatures-style per-skill workflow.
2. Make YAML the primary data layer for resolved symbols and offsets.
3. Keep generated YAML files colocated with the target PE/PDB inside `symboldir`.
4. Align symbol naming and output semantics with `CS2_VibeSignatures`.
5. Reduce `update_symbols.py` to:
   - syncing `<data>` entries from `symboldir`
   - consuming YAML artifacts
   - exporting `kphdyn.xml`

## 3. Non-Goals

1. Preserve the current `reverse_symbols.py` flow.
2. Preserve `update_symbols.py` modes that directly patch XML semantics such as `-fixnull` or `-fixstruct`.
3. Preserve full CLI compatibility with the current `update_symbols.py` and `reverse_symbols.py`.
4. Introduce a second artifact root separate from `symboldir`.
5. Extract a cross-repository shared framework in the first iteration.

## 4. Design Decisions

### 4.1 Workflow Model

The migration follows **Option A** from the design discussion:

- reuse the CS2_VibeSignatures workflow model as directly as possible
- adapt only what is required for `kphtools`
- add a `pdb dump` capability as part of the preprocessor fast path

### 4.2 Source of Truth

YAML is the only authoritative resolved-symbol data source.

`kphdyn.xml` is generated from YAML and must not contain authoritative data that cannot be reproduced from:

- files discovered in `symboldir`
- configuration from the new `config.yaml`
- generated YAML artifacts in `symboldir`

### 4.3 Artifact Location

Generated YAML stays next to the target PE/PDB in `symboldir`.

Example:

```text
symboldir/amd64/ntoskrnl.exe.10.0.22621.5189/<sha256>/
  ntoskrnl.exe
  ntkrnlmp.pdb
  EpObjectTable.amd64.yaml
  PspCreateProcessNotifyRoutine.amd64.yaml
  ExReferenceCallBackBlock.amd64.yaml
```

This is intentional. In `kphtools`, `symboldir` is semantically equivalent to `CS2_VibeSignatures/bin`.

### 4.4 Naming Alignment

New configuration and YAML output names align to `CS2_VibeSignatures`.

New symbol categories:

- `struct_offset`
- `gv`
- `func`

New YAML field names:

- struct member output: `offset`
- global variable output: `gv_rva`
- function output: `func_rva`

In `kphtools`, `{platform}` means architecture, not operating system.

Allowed platform values are:

- `amd64`
- `arm64`

`kphtools` does not use the `CS2_VibeSignatures` meaning of `{platform}` as `windows` or `linux`. The OS dimension is fixed to Windows kernel binaries; the platform dimension distinguishes architecture only.

Legacy `kphtools` names survive only in the XML export mapping layer:

- old `var_offset` maps from new `gv_rva`
- old `fn_offset` maps from new `func_rva`
- old `struct_offset` maps from new `offset`

## 5. Target Architecture

### 5.1 Entry Points

The new workflow has two primary entry points.

#### `dump_symbols.py`

Responsibilities:

1. Parse the new `config.yaml`.
2. Discover target binaries and PDBs inside `symboldir`.
3. Build the per-binary skill execution plan from `expected_input` and `expected_output`.
4. Start and manage `ida-pro-mcp`.
5. Execute each `find-*` skill with CS2-style fallback behavior.
6. Write YAML outputs next to the target PE/PDB.

This script replaces the old split between:

- normal PDB extraction in `update_symbols.py`
- reverse-only logic in `reverse_symbols.py`

#### `update_symbols.py`

Responsibilities:

1. Scan `symboldir`.
2. Sync `<data>` entries into XML for discovered targets.
3. Load colocated YAML artifacts.
4. Convert YAML into `<fields>` values.
5. Reuse or allocate `fields id`.
6. Remove orphan `<fields>`.
7. Save exported `kphdyn.xml`.

This script no longer performs:

- direct PDB parsing
- reverse engineering
- LLM interaction
- XML fallback repair workflows

### 5.2 Configuration Model

The old `kphdyn.yaml` / `kphdyn2.yaml` flat schema is replaced by a `CS2_VibeSignatures/config.yaml`-style schema.

Proposed shape:

```yaml
modules:
  - name: ntoskrnl
    path:
      - ntoskrnl.exe
      - ntkrla57.exe

    skills:
      - name: find-EpObjectTable
        expected_output:
          - EpObjectTable.amd64.yaml

      - name: find-PspCreateProcessNotifyRoutine
        expected_output:
          - PspCreateProcessNotifyRoutine.amd64.yaml

      - name: find-ExReferenceCallBackBlock
        expected_output:
          - ExReferenceCallBackBlock.amd64.yaml

    symbols:
      - name: EpObjectTable
        category: struct_offset
        struct_name: _EPROCESS
        member_name: ObjectTable
        data_type: uint16

      - name: ObDecodeShift
        category: struct_offset
        struct_name: _HANDLE_TABLE_ENTRY
        member_name: ObjectPointerBits
        data_type: uint16
        bits: true

      - name: PspCreateProcessNotifyRoutine
        category: gv
        alias:
          - PspCreateProcessNotifyRoutine
        data_type: uint32

      - name: ExReferenceCallBackBlock
        category: func
        alias:
          - ExReferenceCallBackBlock
        data_type: uint32
```

Notes:

1. `skills` defines workflow execution.
2. `symbols` defines symbol semantics and output interpretation.
3. `expected_input` and `expected_output` keep CS2 semantics.
4. The `{platform}` placeholder means architecture and uses values such as `amd64` and `arm64`.
5. Output suffixes therefore use names such as `.amd64.yaml` and `.arm64.yaml`.
6. `path` is interpreted as candidate file basenames to resolve inside `symboldir`.

### 5.3 Skill Execution Model

`dump_symbols.py` keeps the `CS2_VibeSignatures` per-skill execution semantics:

1. Load all skills for the target module.
2. Build dependency order from `expected_input` and `expected_output`.
3. Skip a skill when all expected outputs already exist, unless forced.
4. For each skill:
   - run preprocessor script first
   - if preprocessor fails, run Agent Skill fallback
   - if both fail, mark the skill failed

The key migration rule is that **PDB extraction becomes part of the preprocessor fast path**, not part of `update_symbols.py`.

## 6. Preprocessor Design

### 6.1 Execution Order Inside a Preprocessor

Each `find-*` preprocessor follows this order:

1. Try `pdb dump`.
2. If `pdb dump` cannot resolve the target, try other deterministic MCP-based methods.
3. If deterministic MCP methods still fail, try LLM-assisted paths such as `LLM_DECOMPILE`, where applicable.
4. If the preprocessor still cannot produce all required outputs, return failure to the workflow engine.
5. The engine then runs the corresponding Agent Skill.

This matches the desired `CS2_VibeSignatures` behavior while adding PDB-first resolution.

### 6.2 Shared PDB Helper Layer

The first implementation should extract and reuse the proven PDB parsing logic already present in the current `update_symbols.py`.

Shared helper responsibilities:

1. `llvm-pdbutil` dump wrappers for:
   - `-types`
   - `-publics`
   - section header extraction
2. structure member lookup
3. nested member lookup
4. multi-candidate member fallback parsing
5. bitfield resolution
6. public symbol RVA calculation

This keeps the mature parsing logic while moving it to the correct layer.

### 6.3 Category-Specific Fast Paths

#### `struct_offset`

Primary path:

- PDB types parsing

Supported semantics:

- direct member lookup
- nested member lookup such as `u1.State`
- multi-candidate syntax inherited from current `kphtools`
- bitfield extraction

Output example:

```yaml
struct_name: _EPROCESS
member_name: ObjectTable
offset: 0x570
size: 0x8
```

Bitfield example:

```yaml
struct_name: _HANDLE_TABLE_ENTRY
member_name: ObjectPointerBits
offset: 0x8
bit_offset: 20
size: 8
```

#### `gv`

Primary path:

- PDB publics plus section parsing

Output example:

```yaml
gv_name: PspCreateProcessNotifyRoutine
gv_va: 0x140456780
gv_rva: 0x456780
```

#### `func`

Primary path:

- PDB publics plus section parsing

Output example:

```yaml
func_name: ExReferenceCallBackBlock
func_va: 0x140123450
func_rva: 0x123450
func_size: 0x40
```

`func_size` may be omitted when no trustworthy source is available. `func_rva` is the required exported value.

## 7. YAML Output Contract

### 7.1 File Naming

Generated YAML file names follow the CS2 convention:

- `<symbol>.<platform>.yaml`

Examples:

- `EpObjectTable.amd64.yaml`
- `PspCreateProcessNotifyRoutine.amd64.yaml`
- `ExReferenceCallBackBlock.amd64.yaml`

### 7.2 File Placement

Outputs are written in the same directory as the matching PE/PDB version instance inside `symboldir`.

### 7.3 Required Fields by Category

#### `struct_offset`

Required:

- `struct_name`
- `member_name`
- `offset`

Optional:

- `size`
- `bit_offset`

#### `gv`

Required:

- `gv_name`
- `gv_rva`

Optional:

- `gv_va`

#### `func`

Required:

- `func_name`
- `func_rva`

Optional:

- `func_va`
- `func_size`

## 8. XML Export Model

### 8.1 `<data>` Sync

`update_symbols.py` still discovers binaries from `symboldir` and syncs `<data>` entries for:

- architecture
- file name
- version
- SHA256
- PE metadata needed by existing XML structure

This is the direct successor to the useful part of the current `-syncfile` mode.

### 8.2 `<fields>` Export

`update_symbols.py` consumes colocated YAML and converts them into field values for the target configuration symbol set.

Mapping rules:

- `struct_offset` symbol -> XML value from YAML `offset`
- `struct_offset` with `bits: true` -> XML value from `offset * 8 + bit_offset`
- `gv` symbol -> XML value from YAML `gv_rva`
- `func` symbol -> XML value from YAML `func_rva`

### 8.3 Fields Reuse

The existing `fields id` reuse model remains valuable and should be retained:

1. collect existing `<fields>`
2. match by exact exported values
3. reuse existing `fields id` when possible
4. allocate new `fields id` when needed
5. remove orphan `<fields>`

### 8.4 Missing YAML Behavior

No XML fallback values are generated in the new design.

If a `<data>` entry does not have the full required YAML set:

- the entry remains `fields="0"`
- the missing outputs are reported
- the operator is expected to rerun `dump_symbols.py`

This removes the old repair loop and keeps XML as a pure export.

## 9. Reverse Workflow Consolidation

The current standalone `reverse_symbols.py` workflow is retired as a primary path.

Its useful purpose is absorbed into `dump_symbols.py`:

- missing or insufficient PDB coverage becomes just another per-skill fallback case
- IDA and LLM are reached through the same workflow engine
- there is only one analysis entry point

This avoids keeping separate "normal update" and "reverse-only" systems alive.

## 10. Error Handling

### 10.1 `dump_symbols.py`

Per-skill success is strict:

1. all `expected_output` files must be created
2. partial output is failure
3. preprocessor success without output is failure
4. Agent success without output is failure

A failed skill does not stop unrelated skills. Final command status should still surface overall failure when required outputs are missing.

### 10.2 `update_symbols.py`

Export behavior is also strict:

1. missing required YAML means no completed fields for that entry
2. the XML exporter never invents fallback values
3. reporting must clearly identify missing symbols or YAML paths

## 11. Cache and Skip Strategy

First iteration caching remains intentionally simple.

### 11.1 `dump_symbols.py`

- if all `expected_output` files exist, skip the skill
- provide a force option for rerunning selected or all skills
- force rerun overwrites only the outputs owned by the selected skill

### 11.2 `update_symbols.py`

- always rescan `symboldir`
- always rebuild XML from the currently visible YAML set
- do not implement incremental XML patching logic

## 12. Migration Plan

1. Introduce a new `config.yaml` in CS2 style and migrate symbol definitions from `kphdyn.yaml` and `kphdyn2.yaml`.
2. Add `dump_symbols.py` using the `ida_analyze_bin.py` orchestration model.
3. Extract shared PDB parsing helpers from the current `update_symbols.py`.
4. Add first-wave `find-*` preprocessors for:
   - `struct_offset`
   - `gv`
   - `func`
5. Rewrite `update_symbols.py` into a pure YAML-to-XML exporter plus `<data>` sync tool.
6. Retire the old standalone `reverse_symbols.py` workflow.
7. Remove obsolete XML repair modes and related arguments.

## 13. Testing Strategy

### 13.1 Configuration Tests

Validate:

1. config parsing
2. skill dependency graph construction
3. category-specific schema rules

### 13.2 PDB Helper Tests

Validate:

1. structure member resolution
2. nested member resolution
3. multi-candidate fallback resolution
4. bitfield resolution
5. `gv_rva` extraction
6. `func_rva` extraction

### 13.3 Workflow Tests

Validate:

1. topological ordering
2. skip behavior when outputs exist
3. fallback from preprocessor to Agent
4. failure when expected outputs are not produced

### 13.4 Exporter Tests

Validate:

1. YAML-to-XML value mapping
2. bitfield export calculation
3. `fields id` reuse
4. orphan field cleanup
5. `fields="0"` behavior for incomplete YAML sets

## 14. Scope Control for the First Implementation

The first implementation explicitly does **not** include:

1. cross-repository framework extraction
2. complex cache invalidation
3. compatibility wrappers for deprecated CLI modes
4. XML repair/fallback workflows
5. a second artifact directory

## 15. Final Outcome

After this migration:

- `dump_symbols.py` becomes the only analysis workflow entry point
- `update_symbols.py` becomes the only XML export entry point
- YAML in `symboldir` becomes the authoritative resolved-symbol data layer
- `ida-pro-mcp` replaces the old `ida64.exe -A -S` execution model
- `kphtools` aligns operationally with `CS2_VibeSignatures` while retaining its own kernel-symbol domain outputs
