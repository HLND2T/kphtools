---
name: find-KpDirectoryTableBase
description: Locate the current binary's _KPROCESS DirectoryTableBase member offset when PDB and LLM_DECOMPILE preprocessing cannot produce KpDirectoryTableBase.yaml.
disable-model-invocation: true
---

# Find KpDirectoryTableBase

Locate the `_KPROCESS->DirectoryTableBase` offset in the current IDA database and
write `KpDirectoryTableBase.yaml` next to the input binary.

This is the final fallback after PDB and `LLM_DECOMPILE`. Derive the offset from
instructions in the current binary. Do not copy an offset or instruction address
from a reference binary.

## Required Output

Use `server_health` to obtain the current IDB's `input_path`. Write exactly one
artifact named `KpDirectoryTableBase.yaml` in the directory containing that
input binary:

```yaml
struct_name: _KPROCESS
member_name: DirectoryTableBase
offset: '0xNN'
category: struct_offset
```

Replace `0xNN` with the verified displacement from the current binary. Keep the
offset as a quoted hexadecimal string. Do not create the file until all
validation steps below succeed.

## Workflow

### 1. Confirm the Current Database

- Call `server_health` and require `auto_analysis_ready` and `hexrays_ready`.
- Analyze only the currently open binary. Never call `open_file` and never
  switch IDBs.
- Use the platform and architecture reported by IDA MCP. Do not infer them from
  local directory names.

### 2. Inspect `MmCreateProcessAddressSpace`

Use `lookup_funcs`, `decompile`, and `disasm` to inspect
`MmCreateProcessAddressSpace`.

Identify the process-object value and the top-level page/directory-table value.
The relevant store normally has all of these properties:

- its base ultimately comes from the process argument;
- its value comes from a newly allocated top-level page, page-frame number, or
  a directory-table-base constructor;
- the value is shifted/aligned to a page boundary and may include PCID-related
  low flag bits;
- the destination is a fixed displacement from the process base.

Do not treat an unrelated process field, list entry, or working-set field as
`DirectoryTableBase` merely because it has a familiar offset.

### 3. Handle the Inlined Case

If `MmCreateProcessAddressSpace` itself contains the qualifying store:

1. Use the decompilation and raw disassembly together.
2. Trace the store's base back to the process object.
3. Trace the stored value back to the top-level page/directory-table
   calculation.
4. Record the store displacement as the `_KPROCESS->DirectoryTableBase`
   offset.

Examples of semantic evidence include a direct assignment to a typed
`Pcb.DirectoryTableBase`, a store of a `KeMakeKernelDirectoryTableBase` result,
or a store of a top-level page value shifted by the architecture's page shift.
These are clues, not mandatory names.

### 4. Handle the Non-Inlined Helper Case

If the caller has no qualifying store, enumerate its direct callees and follow
the top-level page value into the helper that consumes both:

- the process object; and
- the newly allocated top-level page/directory-table value.

Prioritize `MiCreateNewProcessTopLevelMappings` when it exists, but do not depend
on that name. Compilers or newer kernels may rename, merge, or split the helper.
If necessary, identify the helper from the call immediately following the
top-level-page allocation and confirm argument flow with `disasm` or
`trace_data_flow`.

Inside the helper:

1. Trace the first relevant argument back to the caller's process value.
2. Trace the second relevant argument back to the allocated top-level page.
3. Locate the store of the shifted/constructed value through the process base.
4. Record that store's displacement, even though the instruction is outside
   `MmCreateProcessAddressSpace`.

For the known amd64 non-inlined shape, the semantic sequence is equivalent to:

```text
top_level_page = MiAllocateTopLevelPage(process, ...)
helper(process, top_level_page)

helper:
    directory_table_base = top_level_page << page_shift
    directory_table_base |= optional_pcid_flags
    process->DirectoryTableBase = directory_table_base
```

Do not hardcode registers, instruction addresses, the page shift, or the member
offset from this example.

### 5. Exclude the User Directory Table

Some builds also create a user/shadow directory table, often through a function
such as `KeMakeUserDirectoryTableBase`. A store of that value is not the target
unless independent current-binary evidence proves it is the primary
`_KPROCESS->DirectoryTableBase` member.

When both kernel and user/shadow stores exist, select the store used for the
primary process top-level mappings and reject the user/shadow-only field.

### 6. Validate Before Writing

Require all of the following:

- the instruction exists in the current IDB;
- the base register/value is proven to be the process object passed from
  `MmCreateProcessAddressSpace`;
- the stored value is proven to come from the top-level page or equivalent
  kernel directory-table calculation;
- the displacement is taken from the current instruction, not a reference;
- the result fits the `struct_offset` YAML schema above.

Use the MCP `int_convert` tool for number-base conversion. Do not perform manual
hexadecimal/decimal conversion.

If either the process-base provenance or the stored-value provenance remains
ambiguous, do not guess and do not create the YAML. Report:

```text
<skill_error>Unable to verify _KPROCESS->DirectoryTableBase in the current binary.</skill_error>
```

## Completion Checklist

- Current IDB confirmed through IDA MCP.
- `MmCreateProcessAddressSpace` inspected.
- Both inline and helper paths considered.
- Kernel directory table distinguished from the user/shadow directory table.
- Exact current-binary store instruction verified.
- `KpDirectoryTableBase.yaml` written beside the current input binary.
