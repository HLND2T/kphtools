# dump_symbols Lazy IDALIB Startup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement binary-scoped lazy startup for `idalib-mcp` in `dump_symbols.py` and align teardown with graceful `idc.qexit(0)` shutdown semantics without changing existing preprocessor call sites.

**Architecture:** Add a `LazyIdalibSession` wrapper inside `dump_symbols.py` that defers port allocation, MCP startup, session open, and binary validation until the first `call_tool(...)`. `_process_module_binary()` will pass this wrapper into `process_binary_dir()` and always close it in `finally`, while `tests/test_dump_symbols.py` will lock in no-eager-start, session reuse, startup-failure cleanup, and graceful shutdown behavior.

**Tech Stack:** Python 3, `asyncio`, `subprocess`, MCP `ClientSession`, `unittest`, `unittest.mock`

---

## File Structure

- Modify: `dump_symbols.py`
  - Responsibility: own the binary-scoped `LazyIdalibSession`, lazy startup path, startup-failure cleanup, and graceful shutdown behavior.
- Modify: `tests/test_dump_symbols.py`
  - Responsibility: verify `_process_module_binary()` no longer eagerly starts MCP, the wrapper starts exactly once on first use, startup mismatch cleans up correctly, and `close()` prefers `qexit` before kill fallback.

## Task 1: Lock In Lazy Startup And Session Reuse

**Files:**
- Modify: `tests/test_dump_symbols.py:243-419`
- Modify: `dump_symbols.py:264-399`
- Test: `tests/test_dump_symbols.py`

- [ ] **Step 1: Write the failing tests for no-eager-start and first-call startup**

Add these tests to `tests/test_dump_symbols.py`, replacing the old eager-start orchestration assertion with lazy-start expectations:

```python
    def test_process_module_binary_passes_lazy_session_without_eager_start(self) -> None:
        with TemporaryDirectory() as temp_dir:
            binary_dir = Path(temp_dir)
            binary_path = binary_dir / "ntoskrnl.exe"
            binary_path.write_text("", encoding="utf-8")
            pdb_path = binary_dir / "ntkrnlmp.pdb"
            pdb_path.write_text("", encoding="utf-8")

            module = SimpleNamespace(path=["ntoskrnl.exe"], skills=[], symbols=[])
            args = SimpleNamespace(agent="codex", debug=False, force=False)
            captured_session = None

            async def _fake_process_binary(**kwargs):
                nonlocal captured_session
                captured_session = kwargs["session"]
                return True

            with (
                patch.object(
                    dump_symbols,
                    "process_binary_dir",
                    new=AsyncMock(side_effect=_fake_process_binary),
                ) as mock_process_binary,
                patch.object(dump_symbols, "start_idalib_mcp") as mock_start,
                patch.object(dump_symbols, "_open_session", new=AsyncMock()) as mock_open,
            ):
                ok = asyncio.run(
                    dump_symbols._process_module_binary(module, binary_dir, pdb_path, args)
                )

        self.assertTrue(ok)
        self.assertIsInstance(captured_session, dump_symbols.LazyIdalibSession)
        mock_process_binary.assert_awaited_once()
        mock_start.assert_not_called()
        mock_open.assert_not_awaited()

    def test_lazy_idalib_session_starts_on_first_call_and_reuses_session(self) -> None:
        binary_path = Path("/tmp/ntoskrnl.exe")
        fake_process = MagicMock()
        fake_streams = AsyncMock()
        fake_session = AsyncMock()
        fake_session.call_tool = AsyncMock(
            side_effect=[{"result": "first"}, {"result": "second"}]
        )
        lazy_session = dump_symbols.LazyIdalibSession(
            binary_path=binary_path,
            host="127.0.0.1",
            debug=False,
        )

        with (
            patch.object(
                dump_symbols,
                "_allocate_local_port",
                return_value=24567,
            ) as mock_allocate_port,
            patch.object(
                dump_symbols,
                "start_idalib_mcp",
                return_value=fake_process,
            ) as mock_start,
            patch.object(
                dump_symbols,
                "_open_session",
                new=AsyncMock(return_value=(fake_streams, fake_session)),
            ) as mock_open_session,
            patch.object(
                dump_symbols,
                "_session_matches_binary",
                new=AsyncMock(return_value=True),
            ) as mock_match,
        ):
            first = asyncio.run(lazy_session.call_tool("py_eval", {"code": "1"}))
            second = asyncio.run(lazy_session.call_tool("py_eval", {"code": "2"}))
            asyncio.run(lazy_session.close())

        self.assertEqual({"result": "first"}, first)
        self.assertEqual({"result": "second"}, second)
        mock_allocate_port.assert_called_once_with("127.0.0.1")
        mock_start.assert_called_once_with(
            binary_path,
            host="127.0.0.1",
            port=24567,
            debug=False,
        )
        mock_open_session.assert_awaited_once_with("http://127.0.0.1:24567/mcp")
        mock_match.assert_awaited_once_with(fake_session, binary_path)
        self.assertEqual(2, fake_session.call_tool.await_count)
```

- [ ] **Step 2: Run the targeted tests to verify they fail**

Run:

```bash
uv run python -m unittest \
  tests.test_dump_symbols.TestDumpSymbols.test_process_module_binary_passes_lazy_session_without_eager_start \
  tests.test_dump_symbols.TestDumpSymbols.test_lazy_idalib_session_starts_on_first_call_and_reuses_session \
  -v
```

Expected:

```text
ERROR: test_process_module_binary_passes_lazy_session_without_eager_start
AttributeError: module 'dump_symbols' has no attribute 'LazyIdalibSession'

ERROR: test_lazy_idalib_session_starts_on_first_call_and_reuses_session
AttributeError: module 'dump_symbols' has no attribute 'LazyIdalibSession'
```

- [ ] **Step 3: Implement the minimal lazy session wrapper and rewire `_process_module_binary()`**

Add the wrapper to `dump_symbols.py` near the current MCP helper section and rewire `_process_module_binary()` to pass it downstream:

```python
class LazyIdalibSession:
    def __init__(
        self,
        *,
        binary_path: Path,
        host: str = "127.0.0.1",
        debug: bool = False,
    ) -> None:
        self.binary_path = Path(binary_path)
        self.host = host
        self.debug = debug
        self.port: int | None = None
        self.process = None
        self.streams = None
        self.session = None

    async def ensure_started(self) -> None:
        if self.session is not None:
            return

        if self.port is None:
            self.port = _allocate_local_port(self.host)

        process = start_idalib_mcp(
            self.binary_path,
            host=self.host,
            port=self.port,
            debug=self.debug,
        )
        streams = None
        session = None
        try:
            streams, session = await _open_session(
                f"http://{self.host}:{self.port}/mcp"
            )
            if not await _session_matches_binary(session, self.binary_path):
                raise RuntimeError(
                    f"MCP session target mismatch for {self.binary_path}"
                )
        except Exception:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=1)
            raise

        self.process = process
        self.streams = streams
        self.session = session

    async def call_tool(self, name, arguments):
        await self.ensure_started()
        return await self.session.call_tool(name=name, arguments=arguments)

    async def close(self) -> None:
        if self.session is not None:
            await self.session.__aexit__(None, None, None)
            self.session = None
        if self.streams is not None:
            await self.streams.__aexit__(None, None, None)
            self.streams = None
        if self.process is not None:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=1)
            self.process = None

async def _process_module_binary(module, binary_dir, pdb_path, args):
    binary_path = _resolve_binary_path(module, Path(binary_dir))
    session = LazyIdalibSession(
        binary_path=binary_path,
        host="127.0.0.1",
        debug=args.debug,
    )
    try:
        return await process_binary_dir(
            binary_dir=Path(binary_dir),
            pdb_path=Path(pdb_path),
            skills=module.skills,
            symbols=module.symbols,
            agent=args.agent,
            debug=args.debug,
            force=args.force,
            llm_config=None,
            session=session,
        )
    finally:
        await session.close()
```

- [ ] **Step 4: Run the targeted tests to verify they pass**

Run:

```bash
uv run python -m unittest \
  tests.test_dump_symbols.TestDumpSymbols.test_process_module_binary_passes_lazy_session_without_eager_start \
  tests.test_dump_symbols.TestDumpSymbols.test_lazy_idalib_session_starts_on_first_call_and_reuses_session \
  -v
```

Expected:

```text
test_process_module_binary_passes_lazy_session_without_eager_start
test_lazy_idalib_session_starts_on_first_call_and_reuses_session
OK
```

- [ ] **Step 5: Commit**

```bash
git add dump_symbols.py tests/test_dump_symbols.py
git commit -m "test(dump_symbols): 锁定惰性启动时机"
```

## Task 2: Add Graceful `qexit` Shutdown Semantics

**Files:**
- Modify: `tests/test_dump_symbols.py:243-460`
- Modify: `dump_symbols.py:264-399`
- Test: `tests/test_dump_symbols.py`

- [ ] **Step 1: Write the failing tests for graceful close and kill fallback**

Append these tests to `tests/test_dump_symbols.py`:

```python
    def test_lazy_idalib_session_close_uses_qexit_before_wait(self) -> None:
        lazy_session = dump_symbols.LazyIdalibSession(
            binary_path=Path("/tmp/ntoskrnl.exe"),
            host="127.0.0.1",
            debug=False,
        )
        fake_process = MagicMock()
        fake_process.poll.return_value = None
        fake_session = AsyncMock()
        fake_streams = AsyncMock()

        lazy_session.process = fake_process
        lazy_session.session = fake_session
        lazy_session.streams = fake_streams

        asyncio.run(lazy_session.close())

        fake_session.call_tool.assert_awaited_once_with(
            name="py_eval",
            arguments={"code": "import idc; idc.qexit(0)"},
        )
        fake_process.wait.assert_called_once_with(timeout=10)
        fake_process.kill.assert_not_called()

    def test_lazy_idalib_session_close_kills_after_wait_timeout(self) -> None:
        lazy_session = dump_symbols.LazyIdalibSession(
            binary_path=Path("/tmp/ntoskrnl.exe"),
            host="127.0.0.1",
            debug=False,
        )
        fake_process = MagicMock()
        fake_process.poll.return_value = None
        fake_process.wait.side_effect = [
            subprocess.TimeoutExpired(cmd="idalib-mcp", timeout=10),
            0,
        ]
        fake_session = AsyncMock()
        fake_streams = AsyncMock()

        lazy_session.process = fake_process
        lazy_session.session = fake_session
        lazy_session.streams = fake_streams

        asyncio.run(lazy_session.close())

        fake_session.call_tool.assert_awaited_once_with(
            name="py_eval",
            arguments={"code": "import idc; idc.qexit(0)"},
        )
        fake_process.kill.assert_called_once_with()
        self.assertEqual(2, fake_process.wait.call_count)
```

- [ ] **Step 2: Run the targeted tests to verify they fail**

Run:

```bash
uv run python -m unittest \
  tests.test_dump_symbols.TestDumpSymbols.test_lazy_idalib_session_close_uses_qexit_before_wait \
  tests.test_dump_symbols.TestDumpSymbols.test_lazy_idalib_session_close_kills_after_wait_timeout \
  -v
```

Expected:

```text
FAIL: test_lazy_idalib_session_close_uses_qexit_before_wait
AssertionError: Expected call_tool to have been awaited once

FAIL: test_lazy_idalib_session_close_kills_after_wait_timeout
AssertionError: Expected call_tool to have been awaited once
```

- [ ] **Step 3: Replace terminate-only cleanup with graceful `qexit` cleanup**

Update `LazyIdalibSession.close()` in `dump_symbols.py` so it prefers `qexit` before waiting and killing:

```python
    async def _close_handles(self) -> None:
        if self.session is not None:
            await self.session.__aexit__(None, None, None)
            self.session = None
        if self.streams is not None:
            await self.streams.__aexit__(None, None, None)
            self.streams = None

    async def close(self) -> None:
        process = self.process
        self.process = None
        if process is None:
            await self._close_handles()
            return

        if process.poll() is not None:
            await self._close_handles()
            return

        if self.session is not None:
            try:
                await self.session.call_tool(
                    name="py_eval",
                    arguments={"code": "import idc; idc.qexit(0)"},
                )
            except Exception:
                pass

        await self._close_handles()

        try:
            await asyncio.to_thread(process.wait, timeout=10)
            return
        except subprocess.TimeoutExpired:
            process.kill()
            await asyncio.to_thread(process.wait, timeout=1)
```

- [ ] **Step 4: Run the targeted tests to verify they pass**

Run:

```bash
uv run python -m unittest \
  tests.test_dump_symbols.TestDumpSymbols.test_lazy_idalib_session_close_uses_qexit_before_wait \
  tests.test_dump_symbols.TestDumpSymbols.test_lazy_idalib_session_close_kills_after_wait_timeout \
  -v
```

Expected:

```text
test_lazy_idalib_session_close_uses_qexit_before_wait
test_lazy_idalib_session_close_kills_after_wait_timeout
OK
```

- [ ] **Step 5: Commit**

```bash
git add dump_symbols.py tests/test_dump_symbols.py
git commit -m "fix(dump_symbols): 增加优雅关闭流程"
```

## Task 3: Cover Startup-Failure Cleanup And Run Regression Suite

**Files:**
- Modify: `tests/test_dump_symbols.py:243-520`
- Modify: `dump_symbols.py:264-399`
- Test: `tests/test_dump_symbols.py`

- [ ] **Step 1: Write the failing mismatch-cleanup regression**

Add this test to `tests/test_dump_symbols.py` so startup mismatch is checked at first MCP use and cleanup happens immediately:

```python
    def test_lazy_idalib_session_cleans_up_after_binary_mismatch(self) -> None:
        binary_path = Path("/tmp/ntoskrnl.exe")
        fake_process = MagicMock()
        fake_process.poll.return_value = None
        fake_streams = AsyncMock()
        fake_session = AsyncMock()
        lazy_session = dump_symbols.LazyIdalibSession(
            binary_path=binary_path,
            host="127.0.0.1",
            debug=False,
        )

        with (
            patch.object(
                dump_symbols,
                "_allocate_local_port",
                return_value=24567,
            ),
            patch.object(
                dump_symbols,
                "start_idalib_mcp",
                return_value=fake_process,
            ),
            patch.object(
                dump_symbols,
                "_open_session",
                new=AsyncMock(return_value=(fake_streams, fake_session)),
            ),
            patch.object(
                dump_symbols,
                "_session_matches_binary",
                new=AsyncMock(return_value=False),
            ),
        ):
            with self.assertRaisesRegex(RuntimeError, "MCP session target mismatch"):
                asyncio.run(lazy_session.call_tool("py_eval", {"code": "1"}))

        fake_session.__aexit__.assert_awaited_once()
        fake_streams.__aexit__.assert_awaited_once()
        fake_process.kill.assert_called_once_with()
        fake_process.wait.assert_called_once_with(timeout=1)
        self.assertIsNone(lazy_session.session)
        self.assertIsNone(lazy_session.streams)
        self.assertIsNone(lazy_session.process)
```

- [ ] **Step 2: Run the targeted mismatch test to verify it fails**

Run:

```bash
uv run python -m unittest \
  tests.test_dump_symbols.TestDumpSymbols.test_lazy_idalib_session_cleans_up_after_binary_mismatch \
  -v
```

Expected:

```text
FAIL: test_lazy_idalib_session_cleans_up_after_binary_mismatch
AssertionError: <AsyncMock name='mock.__aexit__' ...> awaited 0 times
```

- [ ] **Step 3: Make startup cleanup idempotent and clear wrapper state on failure**

Tighten `ensure_started()` so failed startup never leaves stale state behind:

```python
    async def ensure_started(self) -> None:
        if self.session is not None:
            return

        if self.port is None:
            self.port = _allocate_local_port(self.host)

        process = start_idalib_mcp(
            self.binary_path,
            host=self.host,
            port=self.port,
            debug=self.debug,
        )
        streams = None
        session = None
        try:
            streams, session = await _open_session(
                f"http://{self.host}:{self.port}/mcp"
            )
            if not await _session_matches_binary(session, self.binary_path):
                raise RuntimeError(
                    f"MCP session target mismatch for {self.binary_path}"
                )
        except Exception:
            if session is not None:
                await session.__aexit__(None, None, None)
            if streams is not None:
                await streams.__aexit__(None, None, None)
            if process.poll() is None:
                process.kill()
                process.wait(timeout=1)
            self.process = None
            self.streams = None
            self.session = None
            raise

        self.process = process
        self.streams = streams
        self.session = session
```

- [ ] **Step 4: Run the full `dump_symbols` regression suite**

Run:

```bash
uv run python -m unittest tests.test_dump_symbols -v
```

Expected:

```text
OK
```

- [ ] **Step 5: Commit**

```bash
git add dump_symbols.py tests/test_dump_symbols.py
git commit -m "test(dump_symbols): 补充启动失败清理回归"
```

## Self-Review

### Spec Coverage

- Lazy startup only on first real MCP access: covered by Task 1.
- Same binary reuses one started session: covered by Task 1.
- No IDA startup on pure PDB-only path: covered by Task 1.
- Graceful `qexit` shutdown before kill fallback: covered by Task 2.
- Partial-startup cleanup on mismatch/failure: covered by Task 3.
- Regression coverage in `tests/test_dump_symbols.py`: covered by Tasks 1-3.

### Placeholder Scan

- No `TODO`, `TBD`, `implement later`, or implicit “write tests” placeholders remain.
- All code-changing steps include concrete code blocks.
- All test steps include exact commands and expected outcomes.

### Type Consistency

- Wrapper name is consistently `LazyIdalibSession`.
- Public methods are consistently `ensure_started()`, `call_tool(...)`, and `close()`.
- The downstream parameter name remains `session`, preserving current call sites in `process_binary_dir()` and `preprocess_single_skill_via_mcp()`.
