# dump_symbols Progress Logging Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add minimal but useful progress output to `dump_symbols.py`, with concise default progress logs and more detailed `-debug` logs.

**Architecture:** Keep the change local to `dump_symbols.py` by adding two tiny stdout helpers, threading a small `did_work` tracker through binary processing, and printing from existing control-flow boundaries rather than introducing a full logging framework. Tests stay in `tests/test_dump_symbols.py` and lock down default progress, skip reporting, and selected debug-path output.

**Tech Stack:** Python 3, `asyncio`, `unittest`, `unittest.mock`

---

## File Structure

- Modify: `dump_symbols.py`
  - Responsibility: own default progress output, `-debug` detail output, binary-level skip/work tracking, and main-loop summary lines.
- Modify: `tests/test_dump_symbols.py`
  - Responsibility: verify empty-scan output, binary processing summary output, skip output, and selected `-debug` log lines.

### Task 1: Add Core Output Helpers And Main-Loop Summary

**Files:**
- Modify: `dump_symbols.py:35-100`
- Modify: `dump_symbols.py:551-558`
- Test: `tests/test_dump_symbols.py`

- [ ] **Step 1: Write the failing tests for empty scan and scan summary**

Add these tests to `tests/test_dump_symbols.py`:

```python
    def test_main_reports_when_no_binary_dirs_match(self) -> None:
        config = SimpleNamespace(modules=[])
        output = io.StringIO()

        with (
            patch.object(dump_symbols, "load_config", return_value=config),
            redirect_stdout(output),
        ):
            exit_code = dump_symbols.main(
                ["-symboldir", "symbols", "-arch", "amd64"]
            )

        self.assertEqual(0, exit_code)
        self.assertIn("Scanning symbols/amd64", output.getvalue())
        self.assertIn("Found 0 candidate binary directories", output.getvalue())
        self.assertIn("No processable binary directories found", output.getvalue())

    def test_main_reports_single_binary_success_summary(self) -> None:
        module = SimpleNamespace(path=["ntoskrnl.exe"], skills=[], symbols=[])
        output = io.StringIO()

        with (
            patch.object(
                dump_symbols,
                "load_config",
                return_value=SimpleNamespace(modules=[module]),
            ),
            patch.object(
                dump_symbols,
                "_iter_binary_dirs",
                return_value=iter(
                    [
                        (
                            module,
                            Path("/tmp/amd64/ntoskrnl.exe.1/sha"),
                            Path("/tmp/amd64/ntoskrnl.exe.1/sha/ntkrnlmp.pdb"),
                        )
                    ]
                ),
            ),
            patch.object(
                dump_symbols,
                "_process_module_binary",
                new=AsyncMock(return_value=(True, True)),
            ),
            redirect_stdout(output),
        ):
            exit_code = dump_symbols.main(
                ["-symboldir", "symbols", "-arch", "amd64"]
            )

        self.assertEqual(0, exit_code)
        text = output.getvalue()
        self.assertIn("Found 1 candidate binary directories", text)
        self.assertIn("Processing /tmp/amd64/ntoskrnl.exe.1/sha", text)
        self.assertIn("Processed /tmp/amd64/ntoskrnl.exe.1/sha successfully", text)
        self.assertIn("Summary: 1 succeeded, 0 failed, 0 skipped", text)
```

- [ ] **Step 2: Run the targeted tests to verify they fail**

Run:

```bash
uv run python -m unittest \
  tests.test_dump_symbols.TestDumpSymbols.test_main_reports_when_no_binary_dirs_match \
  tests.test_dump_symbols.TestDumpSymbols.test_main_reports_single_binary_success_summary \
  -v
```

Expected:

```text
FAIL: test_main_reports_when_no_binary_dirs_match
FAIL: test_main_reports_single_binary_success_summary
```

- [ ] **Step 3: Add lightweight output helpers and main summary printing**

Update `dump_symbols.py` with minimal helpers near the constants and rework `main()` to materialize candidates and print summary lines:

```python
def _progress(message: str) -> None:
    print(message)


def _debug_log(debug: bool, message: str) -> None:
    if debug:
        print(f"[debug] {message}")
```

Then update `main()` to follow this shape:

```python
def main(argv=None):
    args = parse_args(argv)
    config = load_config(args.configyaml)
    arch_dir = Path(args.symboldir) / args.arch
    _progress(f"Scanning {arch_dir}")

    candidates = list(_iter_binary_dirs(Path(args.symboldir), args.arch, config))
    _progress(f"Found {len(candidates)} candidate binary directories")
    if not candidates:
        _progress("No processable binary directories found")
        return 0

    succeeded = 0
    failed = 0
    skipped = 0
    for module, binary_dir, pdb_path in candidates:
        _progress(f"Processing {binary_dir}")
        ok, did_work = asyncio.run(
            _process_module_binary(module, binary_dir, pdb_path, args)
        )
        if not ok:
            failed += 1
            _progress(f"Processing {binary_dir} failed")
            _progress(
                f"Summary: {succeeded} succeeded, {failed} failed, {skipped} skipped"
            )
            return 1
        if did_work:
            succeeded += 1
            _progress(f"Processed {binary_dir} successfully")
        else:
            skipped += 1
            _progress(f"Skipped {binary_dir} (no work required)")

    _progress(f"Summary: {succeeded} succeeded, {failed} failed, {skipped} skipped")
    return 0
```

- [ ] **Step 4: Run the targeted tests to verify they pass**

Run:

```bash
uv run python -m unittest \
  tests.test_dump_symbols.TestDumpSymbols.test_main_reports_when_no_binary_dirs_match \
  tests.test_dump_symbols.TestDumpSymbols.test_main_reports_single_binary_success_summary \
  -v
```

Expected:

```text
OK
```

- [ ] **Step 5: Commit**

```bash
git add dump_symbols.py tests/test_dump_symbols.py
git commit -m "feat(dump_symbols): 增加基础进度输出"
```

### Task 2: Track Binary-Level Work And Report Skip Paths

**Files:**
- Modify: `dump_symbols.py:202-245`
- Modify: `dump_symbols.py:528-548`
- Modify: `tests/test_dump_symbols.py:341-423`
- Test: `tests/test_dump_symbols.py`

- [ ] **Step 1: Write the failing tests for skip tracking and no-eager-start summary**

Add these tests to `tests/test_dump_symbols.py`:

```python
    def test_process_module_binary_returns_did_work_false_for_empty_pipeline(self) -> None:
        with TemporaryDirectory() as temp_dir:
            binary_dir = Path(temp_dir)
            (binary_dir / "ntoskrnl.exe").write_text("", encoding="utf-8")
            pdb_path = binary_dir / "ntkrnlmp.pdb"
            pdb_path.write_text("", encoding="utf-8")

            module = SimpleNamespace(path=["ntoskrnl.exe"], skills=[], symbols=[])
            args = SimpleNamespace(agent="codex", debug=False, force=False)

            ok, did_work = asyncio.run(
                dump_symbols._process_module_binary(module, binary_dir, pdb_path, args)
            )

        self.assertTrue(ok)
        self.assertFalse(did_work)

    def test_main_reports_skip_when_outputs_already_exist(self) -> None:
        with TemporaryDirectory() as temp_dir:
            symboldir = Path(temp_dir) / "symbols"
            binary_dir = symboldir / "amd64" / "ntoskrnl.exe.1" / "sha"
            binary_dir.mkdir(parents=True)
            (binary_dir / "ntoskrnl.exe").write_text("", encoding="utf-8")
            (binary_dir / "ntkrnlmp.pdb").write_text("", encoding="utf-8")
            (binary_dir / "EpObjectTable.yaml").write_text("done", encoding="utf-8")

            module = SimpleNamespace(
                path=["ntoskrnl.exe"],
                skills=[
                    SimpleNamespace(
                        name="find-EpObjectTable",
                        symbol="EpObjectTable",
                        expected_output=["EpObjectTable.yaml"],
                    )
                ],
                symbols=[
                    SimpleNamespace(
                        name="EpObjectTable",
                        category="struct_offset",
                        data_type="uint16",
                    )
                ],
            )
            output = io.StringIO()

            with (
                patch.object(
                    dump_symbols,
                    "load_config",
                    return_value=SimpleNamespace(modules=[module]),
                ),
                patch.object(dump_symbols, "start_idalib_mcp") as mock_start,
                patch.object(dump_symbols, "_open_session", new=AsyncMock()) as mock_open,
                redirect_stdout(output),
            ):
                exit_code = dump_symbols.main(
                    ["-symboldir", str(symboldir), "-arch", "amd64"]
                )

        self.assertEqual(0, exit_code)
        self.assertIn(
            f"Skipped {binary_dir} (no work required)",
            output.getvalue(),
        )
        self.assertIn("Summary: 0 succeeded, 0 failed, 1 skipped", output.getvalue())
        mock_start.assert_not_called()
        mock_open.assert_not_awaited()
```

- [ ] **Step 2: Run the targeted tests to verify they fail**

Run:

```bash
uv run python -m unittest \
  tests.test_dump_symbols.TestDumpSymbols.test_process_module_binary_returns_did_work_false_for_empty_pipeline \
  tests.test_dump_symbols.TestDumpSymbols.test_main_reports_skip_when_outputs_already_exist \
  -v
```

Expected:

```text
FAIL: test_process_module_binary_returns_did_work_false_for_empty_pipeline
FAIL: test_main_reports_skip_when_outputs_already_exist
```

- [ ] **Step 3: Thread a minimal `did_work` tracker through binary processing**

Update `process_binary_dir()` to accept an optional activity tracker and mark actual work only when a skill really needs preprocess or fallback:

```python
async def process_binary_dir(
    binary_dir,
    pdb_path,
    skills,
    symbols,
    agent,
    debug,
    force,
    llm_config,
    session=None,
    activity=None,
):
    if activity is None:
        activity = {"did_work": False}

    skill_map = {_field(skill, "name"): skill for skill in skills}
    symbol_map = {_field(symbol, "name"): symbol for symbol in symbols}

    for skill_name in topological_sort_skills(skills):
        skill = skill_map[skill_name]
        expected_outputs = [
            str(Path(binary_dir) / name) for name in _string_list(skill, "expected_output")
        ]
        if not force and expected_outputs and all(Path(path).exists() for path in expected_outputs):
            continue

        activity["did_work"] = True
        symbol_name = _field(skill, "symbol")
        status = await preprocess_single_skill_via_mcp(
            session=session,
            skill=skill,
            symbol=symbol_map[symbol_name],
            binary_dir=Path(binary_dir),
            pdb_path=Path(pdb_path),
            debug=debug,
            llm_config=llm_config,
        )
        if status == PREPROCESS_STATUS_SUCCESS:
            continue

        skill_max_retries = _field(skill, "max_retries") or 3
        if not run_skill(
            skill_name,
            agent=agent,
            debug=debug,
            expected_yaml_paths=expected_outputs,
            max_retries=skill_max_retries,
        ):
            return False
    return True
```

Then update `_process_module_binary()` to return `(ok, did_work)`:

```python
async def _process_module_binary(module, binary_dir, pdb_path, args):
    binary_path = _resolve_binary_path(module, Path(binary_dir))
    session = LazyIdalibSession(
        binary_path,
        host="127.0.0.1",
        debug=args.debug,
    )
    activity = {"did_work": False}
    try:
        ok = await process_binary_dir(
            binary_dir=Path(binary_dir),
            pdb_path=Path(pdb_path),
            skills=module.skills,
            symbols=module.symbols,
            agent=args.agent,
            debug=args.debug,
            force=args.force,
            llm_config=None,
            session=session,
            activity=activity,
        )
        return ok, activity["did_work"]
    finally:
        await session.close()
```

Update the existing `_process_module_binary` tests to unpack `(ok, did_work)` instead of a bare boolean.

- [ ] **Step 4: Run the targeted tests to verify they pass**

Run:

```bash
uv run python -m unittest \
  tests.test_dump_symbols.TestDumpSymbols.test_process_module_binary_returns_did_work_false_for_empty_pipeline \
  tests.test_dump_symbols.TestDumpSymbols.test_main_reports_skip_when_outputs_already_exist \
  tests.test_dump_symbols.TestDumpSymbols.test_process_module_binary_real_empty_pipeline_does_not_eager_start \
  -v
```

Expected:

```text
OK
```

- [ ] **Step 5: Commit**

```bash
git add dump_symbols.py tests/test_dump_symbols.py
git commit -m "feat(dump_symbols): 补充跳过与汇总输出"
```

### Task 3: Add `-debug` Detail Logs For Skills And Lazy Session

**Files:**
- Modify: `dump_symbols.py:162-245`
- Modify: `dump_symbols.py:295-501`
- Modify: `tests/test_dump_symbols.py`
- Test: `tests/test_dump_symbols.py`

- [ ] **Step 1: Write the failing tests for debug-specific output**

Add these tests to `tests/test_dump_symbols.py`:

```python
    def test_process_binary_dir_debug_logs_preprocess_failure_and_fallback(self) -> None:
        with TemporaryDirectory() as temp_dir:
            binary_dir = Path(temp_dir)
            output = io.StringIO()
            skills = [
                {
                    "name": "find-EpObjectTable",
                    "symbol": "EpObjectTable",
                    "expected_output": ["EpObjectTable.yaml"],
                }
            ]
            symbols = [
                {
                    "name": "EpObjectTable",
                    "category": "struct_offset",
                    "data_type": "uint16",
                }
            ]

            with (
                patch.object(
                    dump_symbols,
                    "preprocess_single_skill_via_mcp",
                    new=AsyncMock(return_value="failed"),
                ),
                patch.object(dump_symbols, "run_skill", return_value=True),
                redirect_stdout(output),
            ):
                ok = asyncio.run(
                    dump_symbols.process_binary_dir(
                        binary_dir=binary_dir,
                        pdb_path=binary_dir / "ntkrnlmp.pdb",
                        skills=skills,
                        symbols=symbols,
                        agent="codex",
                        debug=True,
                        force=False,
                        llm_config=None,
                    )
                )

        self.assertTrue(ok)
        text = output.getvalue()
        self.assertIn("[debug] skill find-EpObjectTable started", text)
        self.assertIn("[debug] preprocess status for find-EpObjectTable: failed", text)
        self.assertIn("[debug] falling back to run_skill for find-EpObjectTable", text)

    def test_lazy_idalib_session_debug_logs_startup(self) -> None:
        binary_path = Path("/tmp/ntoskrnl.exe")
        fake_process = MagicMock()
        fake_process.poll.return_value = None
        fake_streams = AsyncMock()
        fake_session = AsyncMock()
        fake_session.call_tool = AsyncMock(return_value={"result": "ok"})
        output = io.StringIO()

        session = dump_symbols.LazyIdalibSession(binary_path=binary_path, debug=True)

        with (
            patch.object(dump_symbols, "_allocate_local_port", return_value=24567),
            patch.object(dump_symbols, "start_idalib_mcp", return_value=fake_process),
            patch.object(
                dump_symbols,
                "_open_session",
                new=AsyncMock(return_value=(fake_streams, fake_session)),
            ),
            patch.object(
                dump_symbols,
                "_session_matches_binary",
                new=AsyncMock(return_value=True),
            ),
            redirect_stdout(output),
        ):
            async def run_sequence():
                await session.call_tool("py_eval", {"code": "1"})
                await session.close()

            asyncio.run(run_sequence())

        text = output.getvalue()
        self.assertIn("[debug] allocating lazy MCP session for /tmp/ntoskrnl.exe", text)
        self.assertIn("[debug] opening MCP session at http://127.0.0.1:24567/mcp", text)
        self.assertIn("[debug] closing lazy MCP session for /tmp/ntoskrnl.exe", text)
```

- [ ] **Step 2: Run the targeted tests to verify they fail**

Run:

```bash
uv run python -m unittest \
  tests.test_dump_symbols.TestDumpSymbols.test_process_binary_dir_debug_logs_preprocess_failure_and_fallback \
  tests.test_dump_symbols.TestDumpSymbols.test_lazy_idalib_session_debug_logs_startup \
  -v
```

Expected:

```text
FAIL: test_process_binary_dir_debug_logs_preprocess_failure_and_fallback
FAIL: test_lazy_idalib_session_debug_logs_startup
```

- [ ] **Step 3: Add debug logs at existing control-flow boundaries**

Update `dump_symbols.py` with small `_debug_log()` calls rather than new abstractions. Use these patterns:

```python
def run_skill(...):
    _debug_log(debug, f"running fallback skill {skill_name}")
    completed = subprocess.run(cmd, input=prompt, text=True, check=False)
    if completed.returncode != 0:
        _debug_log(debug, f"skill failed: {skill_name}")
        return False
    return all(Path(path).exists() for path in expected_yaml_paths)
```

```python
async def process_binary_dir(...):
    ...
    for skill_name in topological_sort_skills(skills):
        skill = skill_map[skill_name]
        _debug_log(debug, f"skill {skill_name} started")
        expected_outputs = [...]
        if not force and expected_outputs and all(Path(path).exists() for path in expected_outputs):
            _debug_log(debug, f"skipping {skill_name}; expected outputs already exist")
            continue
        ...
        status = await preprocess_single_skill_via_mcp(...)
        _debug_log(debug, f"preprocess status for {skill_name}: {status}")
        if status == PREPROCESS_STATUS_SUCCESS:
            continue
        _debug_log(debug, f"falling back to run_skill for {skill_name}")
```

```python
async def _open_session(base_url: str):
    _debug_log(True, f"opening MCP session at {base_url}")  # replace with explicit debug parameter
```

Implement `_open_session(base_url: str, debug: bool = False)` and thread `debug=self.debug` from `LazyIdalibSession.ensure_started()`:

```python
async def _open_session(base_url: str, debug: bool = False):
    _debug_log(debug, f"opening MCP session at {base_url}")
    ...
```

```python
async def ensure_started(self):
    if self.session is not None:
        return self.session

    if self.port is None:
        _debug_log(self.debug, f"allocating lazy MCP session for {self.binary_path}")
        self.port = _allocate_local_port(self.host)
    ...
    if self.streams is None or self.session is None:
        self.streams, self.session = await _open_session(
            f"http://{self.host}:{self.port}/mcp",
            debug=self.debug,
        )
```

Add close-path detail:

```python
async def close(self) -> None:
    _debug_log(self.debug, f"closing lazy MCP session for {self.binary_path}")
    ...
```

Also add `_debug_log()` calls for binary mismatch, startup cleanup, and `close()` cancel fallback, but keep the messages short and stable enough for tests.

- [ ] **Step 4: Run the targeted tests and the full regression suite**

Run:

```bash
uv run python -m unittest \
  tests.test_dump_symbols.TestDumpSymbols.test_process_binary_dir_debug_logs_preprocess_failure_and_fallback \
  tests.test_dump_symbols.TestDumpSymbols.test_lazy_idalib_session_debug_logs_startup \
  -v
```

Expected:

```text
OK
```

Then run:

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
git commit -m "feat(dump_symbols): 增加调试细节日志"
```

## Self-Review

### Spec Coverage

- 默认输出关键进度：Task 1、Task 2 覆盖。
- `0` 候选目录时明确输出：Task 1 覆盖。
- 每个 binary 的开始/成功/失败/跳过：Task 1、Task 2 覆盖。
- `-debug` 时输出 skill 与 lazy session 细节：Task 3 覆盖。
- 保持轻量、仅修改 `dump_symbols.py` 和测试：所有任务保持一致。

### Placeholder Scan

- 无占位符、延期实现标记或空泛步骤描述。
- 每个测试步骤都给了具体测试代码与命令。
- 每个代码步骤都给了明确的函数签名或更新片段。

### Type Consistency

- `_progress(message: str)` 与 `_debug_log(debug: bool, message: str)` 在全部任务中命名一致。
- `_process_module_binary()` 的返回值统一为 `(ok, did_work)`。
- `process_binary_dir(..., activity=None)` 的 `activity["did_work"]` 在 Task 2 与 Task 3 中语义一致。
