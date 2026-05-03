# dump_symbols Lazy IDALIB Startup Design

Date: 2026-04-30

## 1. Summary

This design changes `dump_symbols.py` from eager `idalib-mcp` startup to
binary-scoped lazy startup.

Today, `_process_module_binary()` always starts `idalib-mcp` before any skill
work begins, even when the entire preprocessing path can complete through
`llvm-pdbutil` or direct PDB parsing without any MCP operation. This is
especially expensive for `ntoskrnl.exe`, where opening the IDA-backed session
dominates the runtime of simple preprocess-only paths.

Under the new model:

1. `idalib-mcp` is not started at binary entry time.
2. A binary-scoped lazy session wrapper is created instead.
3. The wrapper starts `idalib-mcp` only when some preprocessor or resolver
   actually performs an MCP operation such as `session.call_tool(...)`.
4. If no MCP operation is needed, no IDA startup occurs for that binary.
5. Once started, the same MCP session is reused for all remaining skills of the
   same binary.
6. Binary cleanup uses graceful IDA shutdown semantics aligned with
   `CS2_VibeSignatures`, instead of raw `process.terminate()`.

## 2. Goals

1. Remove unnecessary `idalib-mcp` startup cost for binaries whose skill
   preprocessing completes through the PDB-only path.
2. Preserve the current binary-level MCP reuse model after the first actual MCP
   access.
3. Keep the change localized to `dump_symbols.py` orchestration, not scattered
   across individual preprocessor scripts.
4. Fix the current cleanup gap where the session is not closed through
   `idc.qexit(0)`-style graceful shutdown.
5. Preserve the current preprocess failure fallback behavior:
   preprocessor failure still falls back to `run_skill(...)`.

## 3. Non-Goals

1. Introduce a new MCP retry or reconnection policy.
2. Redesign skill preprocessing contracts across all `ida_preprocessor_scripts`.
3. Change the existing topological skill ordering logic.
4. Add cross-binary session reuse.
5. Refactor unrelated IDA, PDB, or YAML generation flows.

## 4. Current Problem

The current control flow in `dump_symbols.py` is:

1. `_process_module_binary()` resolves the target PE path.
2. It allocates a local port.
3. It starts `idalib-mcp` immediately.
4. It opens the MCP session immediately.
5. It passes the live session into `process_binary_dir()`.

This has two problems:

1. **Unnecessary startup cost**
   - PDB-first preprocessors such as the generic `func` and `gv` paths often
     succeed without MCP.
   - Even then, `idalib-mcp` has already started and loaded the binary.
2. **Incomplete shutdown semantics**
   - Cleanup currently performs `session.__aexit__()` and then terminates the
     process.
   - This does not match the graceful `qexit`-based shutdown behavior used in
     `CS2_VibeSignatures`.

## 5. Design Decisions

### 5.1 Binary-Scoped Lazy Wrapper

The chosen design is to introduce a binary-scoped lazy session manager in
`dump_symbols.py`.

This wrapper owns:

1. `binary_path`
2. `host`
3. `port`
4. `debug`
5. `process`
6. `streams`
7. `session`
8. startup state such as whether MCP was ever started

The wrapper is created once per binary and reused for all skills of that binary.

### 5.2 Lazy Startup Trigger

The trigger for startup is the first actual MCP operation, not:

1. entering `_process_module_binary()`
2. entering `process_binary_dir()`
3. entering a skill preprocessor
4. predicting that a preprocessor might need MCP

The first call to the wrapper's `call_tool(...)` method performs:

1. local port allocation
2. `start_idalib_mcp(...)`
3. `_open_session(...)`
4. `_session_matches_binary(...)`

Only after those steps succeed does it forward the actual tool call.

### 5.3 Reuse Policy

After the first successful startup, the same MCP session remains alive for the
rest of that binary's processing. This preserves the current reuse behavior and
avoids repeated IDA startups inside one binary.

### 5.4 Graceful Shutdown Policy

Cleanup is part of the wrapper lifecycle.

At binary exit:

1. if the wrapper was never started, `close()` is a no-op
2. if MCP was started, `close()` first attempts `idc.qexit(0)` through MCP
3. it then waits for process exit within a bounded timeout
4. if IDA does not exit in time, it falls back to `kill`

This aligns the shutdown model with `CS2_VibeSignatures`.

## 6. Target Architecture

### 6.1 New Wrapper Responsibility

`dump_symbols.py` gains a wrapper with an interface equivalent to the current
MCP usage surface needed by preprocessors.

Proposed public surface:

```python
class LazyIdalibSession:
    async def call_tool(self, name: str, arguments: dict[str, object]):
        ...

    async def close(self) -> None:
        ...
```

Internal helpers:

```python
class LazyIdalibSession:
    async def ensure_started(self) -> None:
        ...

    async def _graceful_quit(self) -> None:
        ...
```

### 6.2 Orchestration Changes

`_process_module_binary()` changes from eager lifecycle management to wrapper
construction and final cleanup.

Current structure:

1. resolve binary path
2. allocate port
3. start MCP
4. open session
5. validate session target
6. call `process_binary_dir(..., session=session)`
7. tear down session and process

Target structure:

1. resolve binary path
2. create `LazyIdalibSession(binary_path=..., host=..., debug=...)`
3. call `process_binary_dir(..., session=lazy_session)`
4. `finally: await lazy_session.close()`

### 6.3 Call-Site Compatibility

The existing preprocessing stack already depends on only one MCP capability:
`session.call_tool(...)`.

This means the following files can remain interface-compatible:

1. `ida_skill_preprocessor.py`
2. `ida_preprocessor_common.py`
3. `ida_mcp_resolver.py`
4. individual `ida_preprocessor_scripts/*`

They do not need to know whether the provided session object is:

1. a real `ClientSession`, or
2. a lazy wrapper that starts `ClientSession` on first use

## 7. Detailed Flow

### 7.1 PDB-Only Success Path

1. `_process_module_binary()` creates the lazy wrapper.
2. `process_binary_dir()` runs a skill preprocessor.
3. The preprocessor resolves the symbol through `llvm-pdbutil` or direct PDB
   parsing.
4. No MCP call occurs.
5. The wrapper never starts `idalib-mcp`.
6. Binary cleanup calls `close()`, which returns immediately.

Expected outcome:

- preprocessing completes with zero IDA startup cost

### 7.2 PDB Miss Then MCP Fallback Path

1. `_process_module_binary()` creates the lazy wrapper.
2. A preprocessor first attempts the PDB path.
3. The PDB path fails with `KeyError` or equivalent lookup miss.
4. The preprocessor falls back to `session.call_tool(...)`.
5. The wrapper starts `idalib-mcp`, opens the session, validates the binary,
   then forwards the tool call.
6. The resolved value is returned to the preprocessor.
7. Later skills for the same binary reuse the already-started session.

Expected outcome:

- only binaries that truly require MCP pay the IDA startup cost

### 7.3 Startup Failure Path

1. A preprocessor triggers `session.call_tool(...)`.
2. Lazy startup fails during:
   - process spawn
   - port wait
   - session open
   - binary mismatch validation
3. The raised error propagates to the current preprocessing flow.
4. The current skill remains a preprocess failure and falls back to
   `run_skill(...)` under the existing control flow.

Expected outcome:

- no new recovery semantics are introduced
- only startup timing changes

## 8. Error Handling

### 8.1 Startup Errors

The wrapper preserves the existing error boundaries:

1. `start_idalib_mcp(...)` failure remains fatal for that MCP attempt
2. `_open_session(...)` failure remains fatal for that MCP attempt
3. `_session_matches_binary(...) == False` remains a hard mismatch error

No implicit retry loop is added in this design.

### 8.2 Close Errors

Close behavior is best effort:

1. a failed graceful `qexit` attempt does not mask the original skill result
2. if graceful shutdown fails or times out, the wrapper force-kills the process
3. repeated `close()` calls are allowed and become no-ops after cleanup

### 8.3 State Safety

If startup fails partway through, the wrapper must avoid leaving partially
initialized state behind. It should:

1. clear unusable `session` and `streams`
2. kill and reap a started process if startup does not fully complete
3. allow `close()` to run safely afterward

## 9. Testing Strategy

Existing tests in `tests/test_dump_symbols.py` already cover the main
orchestration entry points and should be evolved rather than replaced.

Required coverage additions or updates:

1. **No MCP startup on pure PDB success**
   - `process_binary_dir()` or `_process_module_binary()` path where preprocess
     succeeds without any `call_tool(...)`
   - assert `start_idalib_mcp(...)` is never called
2. **Lazy startup on first MCP access**
   - first `call_tool(...)` triggers port allocation, process spawn, session
     open, and binary validation
   - subsequent `call_tool(...)` calls reuse the same live session
3. **Binary mismatch occurs at lazy start time**
   - mismatch is raised when MCP is first needed, not during binary entry
4. **Graceful close before kill fallback**
   - when the wrapper has started MCP, `close()` first sends `idc.qexit(0)`
   - if the process exits in time, no kill occurs
   - if not, kill is used as fallback

The tests should stay focused on orchestration behavior and mock the actual MCP
transport and process objects.

## 10. File Impact

### 10.1 `dump_symbols.py`

Primary changes:

1. add the lazy session wrapper
2. move port allocation and startup into lazy path
3. replace eager session open in `_process_module_binary()`
4. add graceful close logic aligned with `CS2_VibeSignatures`

### 10.2 `tests/test_dump_symbols.py`

Primary changes:

1. update eager-start assertions that no longer hold
2. add lazy-start behavior tests
3. add graceful-close behavior tests

No functional change is required in:

1. `ida_skill_preprocessor.py`
2. `ida_preprocessor_common.py`
3. `ida_mcp_resolver.py`
4. `ida_preprocessor_scripts/*`

Those files continue to depend only on `session.call_tool(...)`.

## 11. Risks and Trade-Offs

1. **Stateful wrapper complexity**
   - The wrapper adds a small amount of lifecycle state management.
   - This is acceptable because it keeps the rest of the codebase unchanged.
2. **Async cleanup correctness**
   - Cleanup must handle partially started state safely.
   - This is a contained risk and should be covered by targeted tests.
3. **Delayed surfacing of binary mismatch**
   - A target mismatch will now surface only when MCP is first needed.
   - This is acceptable because binaries that never need MCP should not pay any
     validation or startup cost.

## 12. Acceptance Criteria

This design is complete when implementation satisfies all of the following:

1. `dump_symbols.py` does not start `idalib-mcp` unless some preprocessor
   actually performs an MCP operation.
2. A binary that resolves all requested symbols through the PDB path completes
   without starting IDA at all.
3. A binary that needs MCP starts it only once and reuses the same session for
   remaining skills.
4. Session cleanup uses graceful `qexit` semantics before force-kill fallback.
5. The updated orchestration behavior is covered by targeted unit tests in
   `tests/test_dump_symbols.py`.
