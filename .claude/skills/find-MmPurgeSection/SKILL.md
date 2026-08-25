---
name: find-MmPurgeSection
description: Locate the current binary's internal MmPurgeSection function when PE export and FUNC_XREFS preprocessing cannot produce MmPurgeSection.yaml.
disable-model-invocation: true
---

# Find MmPurgeSection

Locate `MmPurgeSection` in the current IDA database and write
`MmPurgeSection.yaml` next to the input binary.

This is the final fallback after PE export lookup and all configured
`FUNC_XREFS` strategies fail. Derive the function from control flow and behavior
in the current binary. Do not copy an RVA or instruction address from a
reference binary.

## Required Output

Use `server_health` to obtain the current IDB's `input_path` and `imagebase`.
Write exactly one artifact named `MmPurgeSection.yaml` in the directory
containing that input binary:

```yaml
func_name: MmPurgeSection
func_rva: '0xNNNNNN'
category: func
```

Replace `0xNNNNNN` with the verified current-binary function RVA. Keep the RVA
as a quoted hexadecimal string. Do not create the file until all validation
steps below succeed.

## Workflow

### 1. Confirm the Current Database

- Call `server_health` and require `auto_analysis_ready` and `hexrays_ready`.
- Analyze only the currently open binary. Never call `open_file` and never
  switch IDBs.
- Use the platform, architecture, input path, and image base reported by IDA
  MCP. Do not infer them from local directory names.

### 2. Start from `CcPurgeCacheSection`

Use `lookup_funcs`, `decompile`, `disasm`, and `callees` to inspect
`CcPurgeCacheSection`.

Find the internal callee responsible for purging a section. The relevant call
normally passes values semantically equivalent to:

1. a section-object pointer;
2. an optional file offset or purge starting point;
3. a length or terminal offset;
4. purge flags; and
5. an output byte or boolean result.

The callee may be unnamed, split into hot and cold chunks, or delegate much of
its implementation to an outlined helper. Do not identify it solely from its
argument count.

### 3. Validate the Candidate Semantically

Use decompilation and raw disassembly together. Require multiple independent
properties from the current binary. A valid `MmPurgeSection` candidate normally:

- clears the output byte before doing work;
- accepts or copies an optional purge-offset value;
- calls `MiCanFileBeTruncatedInternal` or a semantic equivalent that returns a
  control-area object and lock/IRQL state;
- handles the no-control-area and cannot-purge cases with boolean returns;
- sets the control-area `0x8000` flag, either with an OR instruction or an
  equivalent bit-set-and-write-back sequence;
- computes a data-flush range and walks subsections or prototype PTE ranges;
- acquires and releases the control-area lock while updating purge state; and
- returns a success/failure byte used by `CcPurgeCacheSection` to decide whether
  to retry or stop.

Names and recovered types are helpful but optional. The control flow, argument
provenance, field accesses, and caller/callee relationships are authoritative.

### 4. Handle Outlined Helpers

Older builds may keep purge validation, PTE walking, and bug-check paths in
`MmPurgeSection` or in non-contiguous function chunks. Newer compilers may move
that work into a separate helper.

If the candidate calls an unnamed helper during the subsection/PTE walk:

1. Follow the call arguments from the candidate into the helper.
2. Confirm the helper consumes the current subsection/range state.
3. Confirm its results flow back into the candidate's success and output-byte
   decisions.
4. Treat a `KeBugCheckEx` call with bug-check code `0xDE` as supporting evidence,
   even when it is inside the helper rather than the candidate.

Do not report the outlined helper itself as `MmPurgeSection`. A helper containing
`mov ecx, 0DEh` may have several callers; the target remains the purge function
called by `CcPurgeCacheSection`.

### 5. Use Signatures Only as Leads

If `CcPurgeCacheSection` is unavailable by name, use `find_bytes`,
`entity_query`, `xref_query`, `callgraph`, and `make_signature_for_function` to
narrow the search. Existing signature families may include:

```text
B9 DE 00 00 00
81 ?? ?? 00 80 00 00
48 89 5C 24 ?? 55 56 57 41 54 41 55 41 56 41 57
48 8D 6C 24 ?? 48 81 EC 90 00 00 00 45 33 ED 33 C0
```

These are search leads, not proof. For every byte-pattern match:

- verify that the match begins at an IDA instruction head;
- disassemble the complete containing instruction;
- normalize the match to its containing function start;
- reject matches beginning inside a displacement or immediate; and
- apply the semantic validation from the previous sections.

In particular, the broad `0x8000` pattern can occur in the middle of an
unrelated `test [global], 8000h` instruction. Never accept such a match merely
because IDA can map its address to a function.

### 6. Validate Before Writing

Require all of the following:

- the candidate start is a defined function in the current IDB;
- a current-binary call edge from `CcPurgeCacheSection` is verified, or equally
  strong caller and argument-flow evidence is available when that name is
  absent;
- the purge-offset, control-area, locking, and success-return behavior is
  verified in the current binary;
- outlined helpers and non-contiguous chunks have been distinguished from the
  top-level target function;
- all supporting signature matches begin at valid instruction boundaries;
- the RVA is calculated from the current function VA and current image base;
  and
- the result fits the `func` YAML schema above.

Use the MCP `int_convert` tool for number-base conversion and RVA arithmetic. Do
not perform manual hexadecimal/decimal conversion.

If the top-level function identity remains ambiguous, do not guess and do not
create the YAML. Report:

```text
<skill_error>Unable to verify MmPurgeSection in the current binary.</skill_error>
```

## Completion Checklist

- Current IDB confirmed through IDA MCP.
- `CcPurgeCacheSection` and its relevant callees inspected.
- Inline, non-contiguous, and outlined-helper layouts considered.
- Control-area flag, flush-range, locking, and return behavior verified.
- Signature matches checked for instruction alignment.
- Exact current-binary function start and RVA verified.
- `MmPurgeSection.yaml` written beside the current input binary.
