# NtSecureConnectPort NtAPI Extraction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a PDB-first, signature-fallback IDA preprocessor for extracting `NtSecureConnectPort` RVA without adding it to XML export symbols.

**Architecture:** `find-NtSecureConnectPort.py` is a thin declaration script that calls `ida_preprocessor_scripts/_extract_ntapi.py`. The helper resolves PDB public symbols first, then falls back to searching script-provided signatures, reading the qword at `match_ea + 8`, and accepting the VA only when it points into `PAGE` or `.text`. `config.yaml` records the new skill output as a preprocessor-only artifact, while `module.symbols` remains the XML/export inventory.

**Tech Stack:** Python 3, unittest, AsyncMock, IDA MCP `find_bytes` and `py_eval`, existing `symbol_artifacts` YAML writer, existing `pdb_resolver.resolve_public_symbol`.

---

## File Structure

- Create `ida_preprocessor_scripts/_extract_ntapi.py`
  - Owns reusable NtAPI table-entry extraction logic.
  - Depends only on `pdb_resolver`, `symbol_artifacts`, MCP `find_bytes`, and MCP `py_eval`.
  - Supports dict-like and object-like `symbol` values by reading only `name`.

- Create `ida_preprocessor_scripts/find-NtSecureConnectPort.py`
  - Declares `TARGET_FUNCTION_NAMES`, `NTAPI_SIGNATURES`, and `GENERATE_YAML_DESIRED_FIELDS`.
  - Calls `_extract_ntapi.preprocess_ntapi_symbols(...)` directly.

- Modify `symbol_config.py`
  - Stop rejecting `skill.expected_output` entries missing from `module.symbols`.
  - Preserve `SkillSpec.produced_symbols` and all artifact-name validation.

- Modify `dump_symbols.py`
  - Add a helper that returns an existing `SymbolSpec` when present, otherwise returns `{"name": symbol_name}`.
  - This lets preprocessor-only artifacts run without entering XML export inventory.

- Modify `config.yaml`
  - Add `find-NtSecureConnectPort` under the `ntoskrnl` module `skills`.
  - Do not add `NtSecureConnectPort` under `symbols`.

- Modify `tests/test_symbol_config.py`
  - Replace the unknown-output rejection test with acceptance of preprocessor-only artifacts.
  - Update the repository baseline assertion so not every produced artifact must be in `module.symbols`.

- Modify `tests/test_dump_symbols.py`
  - Add coverage for dispatching a required output that has no `SymbolSpec`.

- Modify `tests/test_update_symbols.py`
  - Add coverage that YAML files not represented in `module.symbols` are ignored during XML export.

- Modify `tests/test_ida_skill_preprocessor.py`
  - Remove the repository-wide `.claude/skills/<skill>/SKILL.md` requirement.
  - Add dispatch coverage for `find-NtSecureConnectPort.py`.

- Create `tests/test_extract_ntapi.py`
  - Covers PDB-first behavior, signature fallback, segment filtering, non-unique candidates, and artifact writing.

## Task 1: Allow Preprocessor-Only Artifacts In Config And Dump

**Files:**
- Modify: `symbol_config.py`
- Modify: `dump_symbols.py`
- Modify: `tests/test_symbol_config.py`
- Modify: `tests/test_dump_symbols.py`

- [ ] **Step 1: Replace the symbol-config rejection test with an acceptance test**

In `tests/test_symbol_config.py`, replace `test_load_config_rejects_unknown_skill_output_symbol` with:

```python
    def test_load_config_accepts_preprocessor_only_skill_output(self) -> None:
        with TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "config.yaml"
            config_path.write_text(
                textwrap.dedent(
                    """
                    modules:
                      - name: ntoskrnl
                        path: [ntoskrnl.exe]
                        skills:
                          - name: find-NtSecureConnectPort
                            expected_output: [NtSecureConnectPort.yaml]
                        symbols:
                          - name: EpObjectTable
                            category: struct_offset
                            data_type: uint16
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )

            config = symbol_config.load_config(config_path)

        self.assertEqual(
            ["NtSecureConnectPort"],
            config.modules[0].skills[0].produced_symbols,
        )
        self.assertEqual(
            {"EpObjectTable"},
            {symbol.name for symbol in config.modules[0].symbols},
        )
```

- [ ] **Step 2: Update repository baseline config expectations**

In `tests/test_symbol_config.py`, replace the body of `test_load_config_reads_repository_baseline` with:

```python
    def test_load_config_reads_repository_baseline(self) -> None:
        config = symbol_config.load_config(Path("config.yaml"))

        self.assertEqual(1, len(config.modules))
        self.assertEqual("ntoskrnl", config.modules[0].name)
        self.assertGreater(len(config.modules[0].symbols), 0)
        symbol_names = {symbol.name for symbol in config.modules[0].symbols}
        self.assertNotIn("NtSecureConnectPort", symbol_names)
        for skill in config.modules[0].skills:
            self.assertTrue(skill.produced_symbols)
```

- [ ] **Step 3: Run the focused symbol-config test to verify it fails before implementation**

Run:

```bash
python -m unittest tests.test_symbol_config.TestSymbolConfig.test_load_config_accepts_preprocessor_only_skill_output
```

Expected: FAIL with `ValueError: skill output references unknown symbol: NtSecureConnectPort`.

- [ ] **Step 4: Remove the strict expected-output-to-symbols validation**

In `symbol_config.py`, remove this block from `load_config()`:

```python
        symbol_names = {symbol.name for symbol in symbols}
        skills = [_load_skill(_require_mapping(item, "skill")) for item in skill_items]
        for skill in skills:
            for symbol_name in skill.produced_symbols:
                if symbol_name not in symbol_names:
                    raise ValueError(
                        f"skill output references unknown symbol: {symbol_name}"
                    )
```

Replace it with:

```python
        skills = [_load_skill(_require_mapping(item, "skill")) for item in skill_items]
```

- [ ] **Step 5: Run the symbol-config focused tests**

Run:

```bash
python -m unittest \
  tests.test_symbol_config.TestSymbolConfig.test_load_config_accepts_preprocessor_only_skill_output \
  tests.test_symbol_config.TestSymbolConfig.test_load_config_reads_repository_baseline
```

Expected: PASS.

- [ ] **Step 6: Add a dump-symbols regression test for missing SymbolSpec**

Add this test to `tests/test_dump_symbols.py` near the other `process_binary_dir` tests:

```python
    def test_process_binary_preprocesses_expected_output_without_symbol_spec(self) -> None:
        with TemporaryDirectory() as temp_dir:
            binary_dir = Path(temp_dir)
            config = {
                "skills": [
                    {
                        "name": "find-NtSecureConnectPort",
                        "expected_output": ["NtSecureConnectPort.yaml"],
                    }
                ],
                "symbols": [],
            }
            preprocess_mock = AsyncMock(
                return_value=dump_symbols.PREPROCESS_STATUS_SUCCESS
            )
            with (
                patch.object(
                    dump_symbols,
                    "preprocess_single_skill_via_mcp",
                    new=preprocess_mock,
                ),
                patch.object(dump_symbols, "run_skill", return_value=True) as mock_run_skill,
            ):
                ok = asyncio.run(
                    dump_symbols.process_binary_dir(
                        binary_dir=binary_dir,
                        pdb_path=binary_dir / "ntkrnlmp.pdb",
                        skills=config["skills"],
                        symbols=config["symbols"],
                        agent="codex",
                        debug=False,
                        force=False,
                        llm_config=None,
                    )
                )

        self.assertTrue(ok)
        preprocess_mock.assert_awaited_once()
        self.assertEqual(
            {"name": "NtSecureConnectPort"},
            preprocess_mock.await_args.kwargs["symbol"],
        )
        mock_run_skill.assert_not_called()
```

- [ ] **Step 7: Run the focused dump-symbols test to verify it fails before implementation**

Run:

```bash
python -m unittest tests.test_dump_symbols.TestDumpSymbols.test_process_binary_preprocesses_expected_output_without_symbol_spec
```

Expected: FAIL with `KeyError: 'NtSecureConnectPort'`.

- [ ] **Step 8: Add a helper for missing symbol specs**

In `dump_symbols.py`, add this helper after `_output_symbol_names(...)`:

```python
def _symbol_for_output(symbol_map: dict[str, Any], symbol_name: str) -> Any:
    return symbol_map.get(symbol_name, {"name": symbol_name})
```

- [ ] **Step 9: Use the helper during preprocessor dispatch**

In `dump_symbols.py`, change `_preprocess_skill_outputs(...)` from:

```python
        status = await preprocess_single_skill_via_mcp(
            session=session,
            skill=skill,
            symbol=symbol_map[symbol_name],
            binary_dir=Path(binary_dir),
            pdb_path=pdb_path,
            debug=debug,
            llm_config=llm_config,
        )
```

to:

```python
        status = await preprocess_single_skill_via_mcp(
            session=session,
            skill=skill,
            symbol=_symbol_for_output(symbol_map, symbol_name),
            binary_dir=Path(binary_dir),
            pdb_path=pdb_path,
            debug=debug,
            llm_config=llm_config,
        )
```

- [ ] **Step 10: Run focused config and dump tests**

Run:

```bash
python -m unittest \
  tests.test_symbol_config.TestSymbolConfig.test_load_config_accepts_preprocessor_only_skill_output \
  tests.test_symbol_config.TestSymbolConfig.test_load_config_reads_repository_baseline \
  tests.test_dump_symbols.TestDumpSymbols.test_process_binary_preprocesses_expected_output_without_symbol_spec
```

Expected: PASS.

- [ ] **Step 11: Commit Task 1**

```bash
git add symbol_config.py dump_symbols.py tests/test_symbol_config.py tests/test_dump_symbols.py
git commit -m "refactor: 支持预处理专用产物"
```

## Task 2: Add The NtAPI Extraction Helper

**Files:**
- Create: `ida_preprocessor_scripts/_extract_ntapi.py`
- Create: `tests/test_extract_ntapi.py`

- [ ] **Step 1: Write the NtAPI helper tests**

Create `tests/test_extract_ntapi.py`:

```python
from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

from ida_preprocessor_scripts import _extract_ntapi
from symbol_artifacts import load_artifact


def _tool_result(payload):
    return SimpleNamespace(
        content=[
            SimpleNamespace(
                text=json.dumps({"result": json.dumps(payload)})
            )
        ]
    )


def _base_kwargs(temp_dir, session, pdb_path=None):
    return {
        "session": session,
        "skill": SimpleNamespace(name="find-NtSecureConnectPort"),
        "symbol": {"name": "NtSecureConnectPort"},
        "binary_dir": Path(temp_dir),
        "pdb_path": pdb_path,
        "debug": True,
        "target_function_names": ["NtSecureConnectPort"],
        "ntapi_signatures": {
            "NtSecureConnectPort": ["5D 53 26 88 09 00 00 00"],
        },
        "generate_yaml_desired_fields": {
            "NtSecureConnectPort": ["func_name", "func_rva"],
        },
    }


class TestExtractNtApi(unittest.IsolatedAsyncioTestCase):
    async def test_pdb_success_writes_artifact_without_signature_search(self) -> None:
        session = AsyncMock()
        with TemporaryDirectory() as temp_dir:
            with patch.object(
                _extract_ntapi,
                "resolve_public_symbol",
                return_value={"rva": 0x12340},
            ) as mock_resolve:
                status = await _extract_ntapi.preprocess_ntapi_symbols(
                    **_base_kwargs(
                        temp_dir,
                        session,
                        pdb_path=Path(temp_dir) / "ntkrnlmp.pdb",
                    )
                )

            self.assertEqual(_extract_ntapi.PREPROCESS_STATUS_SUCCESS, status)
            mock_resolve.assert_called_once_with(
                Path(temp_dir) / "ntkrnlmp.pdb",
                "NtSecureConnectPort",
            )
            session.call_tool.assert_not_awaited()
            self.assertEqual(
                {
                    "category": "func",
                    "func_name": "NtSecureConnectPort",
                    "func_rva": 0x12340,
                },
                load_artifact(Path(temp_dir) / "NtSecureConnectPort.yaml"),
            )

    async def test_pdb_miss_uses_signature_fallback(self) -> None:
        session = AsyncMock()
        session.call_tool.side_effect = [
            _tool_result(
                [
                    {
                        "pattern": "5D 53 26 88 09 00 00 00",
                        "matches": ["0x140989840"],
                    }
                ]
            ),
            _tool_result(
                {
                    "candidates": [
                        {
                            "match_ea": "0x140989840",
                            "ptr_ea": "0x140989848",
                            "func_va": "0x1405e8d70",
                            "func_rva": "0x5e8d70",
                            "segment": "PAGE",
                        }
                    ]
                }
            ),
        ]

        with TemporaryDirectory() as temp_dir:
            with patch.object(
                _extract_ntapi,
                "resolve_public_symbol",
                side_effect=KeyError("NtSecureConnectPort"),
            ):
                status = await _extract_ntapi.preprocess_ntapi_symbols(
                    **_base_kwargs(
                        temp_dir,
                        session,
                        pdb_path=Path(temp_dir) / "ntkrnlmp.pdb",
                    )
                )

            self.assertEqual(_extract_ntapi.PREPROCESS_STATUS_SUCCESS, status)
            self.assertEqual(
                "find_bytes",
                session.call_tool.await_args_list[0].kwargs["name"],
            )
            self.assertEqual(
                {"patterns": ["5D 53 26 88 09 00 00 00"]},
                session.call_tool.await_args_list[0].kwargs["arguments"],
            )
            py_eval_code = session.call_tool.await_args_list[1].kwargs["arguments"]["code"]
            self.assertIn("+ 8", py_eval_code)
            self.assertIn("ida_bytes.get_qword", py_eval_code)
            self.assertIn("PAGE", py_eval_code)
            self.assertIn(".text", py_eval_code)
            self.assertEqual(
                {
                    "category": "func",
                    "func_name": "NtSecureConnectPort",
                    "func_rva": 0x5E8D70,
                },
                load_artifact(Path(temp_dir) / "NtSecureConnectPort.yaml"),
            )

    async def test_rejects_candidates_outside_allowed_segments(self) -> None:
        session = AsyncMock()
        session.call_tool.side_effect = [
            _tool_result(
                [
                    {
                        "pattern": "5D 53 26 88 09 00 00 00",
                        "matches": ["0x140989840"],
                    }
                ]
            ),
            _tool_result({"candidates": []}),
        ]

        with TemporaryDirectory() as temp_dir:
            status = await _extract_ntapi.preprocess_ntapi_symbols(
                **_base_kwargs(temp_dir, session, pdb_path=None)
            )

            self.assertEqual(_extract_ntapi.PREPROCESS_STATUS_FAILED, status)
            self.assertFalse((Path(temp_dir) / "NtSecureConnectPort.yaml").exists())

    async def test_rejects_non_unique_candidates(self) -> None:
        session = AsyncMock()
        session.call_tool.side_effect = [
            _tool_result(
                [
                    {
                        "pattern": "5D 53 26 88 09 00 00 00",
                        "matches": ["0x140989840", "0x140999000"],
                    }
                ]
            ),
            _tool_result(
                {
                    "candidates": [
                        {
                            "match_ea": "0x140989840",
                            "ptr_ea": "0x140989848",
                            "func_va": "0x1405e8d70",
                            "func_rva": "0x5e8d70",
                            "segment": "PAGE",
                        },
                        {
                            "match_ea": "0x140999000",
                            "ptr_ea": "0x140999008",
                            "func_va": "0x140600000",
                            "func_rva": "0x600000",
                            "segment": ".text",
                        },
                    ]
                }
            ),
        ]

        with TemporaryDirectory() as temp_dir:
            status = await _extract_ntapi.preprocess_ntapi_symbols(
                **_base_kwargs(temp_dir, session, pdb_path=None)
            )

            self.assertEqual(_extract_ntapi.PREPROCESS_STATUS_FAILED, status)
            self.assertFalse((Path(temp_dir) / "NtSecureConnectPort.yaml").exists())
```

- [ ] **Step 2: Run the helper tests to verify they fail before implementation**

Run:

```bash
python -m unittest tests.test_extract_ntapi
```

Expected: FAIL with `ImportError` because `ida_preprocessor_scripts._extract_ntapi` does not exist.

- [ ] **Step 3: Implement `_extract_ntapi.py`**

Create `ida_preprocessor_scripts/_extract_ntapi.py`:

```python
from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from pdb_resolver import resolve_public_symbol
from symbol_artifacts import artifact_path, write_func_yaml


PREPROCESS_STATUS_SUCCESS = "success"
PREPROCESS_STATUS_FAILED = "failed"

_ALLOWED_SEGMENTS = frozenset({"PAGE", ".text"})
_ALLOWED_FUNC_FIELDS = frozenset({"func_name", "func_rva"})


def _field(value: Any, field_name: str) -> Any:
    if isinstance(value, Mapping):
        return value.get(field_name)
    return getattr(value, field_name, None)


def _parse_tool_json_result(tool_result: Any) -> Any | None:
    try:
        text = tool_result.content[0].text
        payload = json.loads(text)
        return json.loads(payload["result"])
    except Exception:
        return None


def _parse_int_value(value: Any) -> int:
    if isinstance(value, int):
        return value
    text = str(value).strip()
    return int(text, 0 if text.lower().startswith("0x") else 10)


def _normalize_desired_fields(
    generate_yaml_desired_fields: Any,
    symbol_name: str,
) -> list[str] | None:
    if not isinstance(generate_yaml_desired_fields, Mapping):
        return None
    fields = generate_yaml_desired_fields.get(symbol_name)
    if not isinstance(fields, list) or not fields:
        return None
    if any(not isinstance(field, str) for field in fields):
        return None
    if any(field not in _ALLOWED_FUNC_FIELDS for field in fields):
        return None
    if "func_name" not in fields or "func_rva" not in fields:
        return None
    return fields


def _filter_payload(payload: dict[str, Any], fields: list[str]) -> dict[str, Any] | None:
    if any(field not in payload for field in fields):
        return None
    return {field: payload[field] for field in fields}


def _normalize_signatures(
    ntapi_signatures: Any,
    symbol_name: str,
) -> list[str] | None:
    if not isinstance(ntapi_signatures, Mapping):
        return None
    signatures = ntapi_signatures.get(symbol_name)
    if not isinstance(signatures, Iterable) or isinstance(signatures, (str, bytes)):
        return None
    normalized = list(signatures)
    if not normalized or any(not isinstance(item, str) or not item for item in normalized):
        return None
    return normalized


async def _find_signature_matches(
    *,
    session,
    signatures: list[str],
    debug: bool,
) -> set[int] | None:
    try:
        result = await session.call_tool(
            name="find_bytes",
            arguments={"patterns": signatures},
        )
    except Exception as exc:
        if debug:
            print(f"    Preprocess: find_bytes failed for NtAPI signatures: {exc}")
        return None

    payload = _parse_tool_json_result(result)
    if not isinstance(payload, list):
        return None

    matches: set[int] = set()
    for item in payload:
        raw_matches = item.get("matches", []) if isinstance(item, Mapping) else []
        if not isinstance(raw_matches, list):
            return None
        for raw_ea in raw_matches:
            try:
                matches.add(_parse_int_value(raw_ea))
            except (TypeError, ValueError):
                continue
    return matches


async def _extract_candidates_from_matches(
    *,
    session,
    match_eas: set[int],
    debug: bool,
) -> list[dict[str, int | str]] | None:
    if not match_eas:
        return []

    py_lines = [
        "import ida_bytes, ida_nalt, ida_segment, json",
        f"match_eas = {json.dumps([hex(ea) for ea in sorted(match_eas)])}",
        f"allowed_segments = {json.dumps(sorted(_ALLOWED_SEGMENTS))}",
        "image_base = int(ida_nalt.get_imagebase())",
        "candidates = []",
        "for raw_ea in match_eas:",
        "    try:",
        "        ea = int(str(raw_ea), 16)",
        "        ptr_ea = ea + 8",
        "        func_va = int(ida_bytes.get_qword(ptr_ea))",
        "    except Exception:",
        "        continue",
        "    seg = ida_segment.getseg(func_va)",
        "    if seg is None:",
        "        continue",
        "    seg_name = ida_segment.get_segm_name(seg)",
        "    if seg_name not in allowed_segments:",
        "        continue",
        "    candidates.append({",
        "        'match_ea': hex(ea),",
        "        'ptr_ea': hex(ptr_ea),",
        "        'func_va': hex(func_va),",
        "        'func_rva': hex(func_va - image_base),",
        "        'segment': seg_name,",
        "    })",
        "result = json.dumps({'candidates': candidates})",
    ]

    try:
        result = await session.call_tool(
            name="py_eval",
            arguments={"code": "\n".join(py_lines) + "\n"},
        )
    except Exception as exc:
        if debug:
            print(f"    Preprocess: py_eval failed for NtAPI candidates: {exc}")
        return None

    payload = _parse_tool_json_result(result)
    candidates = payload.get("candidates") if isinstance(payload, Mapping) else None
    if not isinstance(candidates, list):
        return None

    parsed: list[dict[str, int | str]] = []
    for item in candidates:
        if not isinstance(item, Mapping):
            continue
        try:
            parsed.append(
                {
                    "func_va": _parse_int_value(item["func_va"]),
                    "func_rva": _parse_int_value(item["func_rva"]),
                    "segment": str(item.get("segment", "")),
                }
            )
        except (KeyError, TypeError, ValueError):
            continue
    return parsed


async def _resolve_by_signature(
    *,
    session,
    symbol_name: str,
    signatures: list[str],
    debug: bool,
) -> dict[str, int | str] | None:
    matches = await _find_signature_matches(
        session=session,
        signatures=signatures,
        debug=debug,
    )
    if matches is None or not matches:
        return None

    candidates = await _extract_candidates_from_matches(
        session=session,
        match_eas=matches,
        debug=debug,
    )
    if candidates is None:
        return None

    by_va: dict[int, dict[str, int | str]] = {
        int(candidate["func_va"]): candidate
        for candidate in candidates
    }
    if debug:
        print(
            "    Preprocess: NtAPI candidates for "
            f"{symbol_name}: {[hex(va) for va in sorted(by_va)]}"
        )
    if len(by_va) != 1:
        return None

    candidate = next(iter(by_va.values()))
    return {
        "func_name": symbol_name,
        "func_rva": int(candidate["func_rva"]),
    }


async def preprocess_ntapi_symbols(
    *,
    session,
    skill,
    symbol,
    binary_dir: str | Path,
    pdb_path: str | Path | None,
    debug: bool,
    target_function_names: list[str],
    ntapi_signatures,
    generate_yaml_desired_fields,
):
    symbol_name = _field(symbol, "name")
    if not isinstance(symbol_name, str) or symbol_name not in target_function_names:
        return PREPROCESS_STATUS_FAILED

    desired_fields = _normalize_desired_fields(
        generate_yaml_desired_fields,
        symbol_name,
    )
    signatures = _normalize_signatures(ntapi_signatures, symbol_name)
    if desired_fields is None or signatures is None:
        return PREPROCESS_STATUS_FAILED

    payload: dict[str, int | str] | None = None
    if pdb_path is not None:
        try:
            resolved = resolve_public_symbol(pdb_path, symbol_name)
            payload = {
                "func_name": symbol_name,
                "func_rva": resolved["rva"],
            }
        except Exception as exc:
            if debug:
                print(f"    Preprocess: PDB miss for {symbol_name}: {exc}")

    if payload is None:
        payload = await _resolve_by_signature(
            session=session,
            symbol_name=symbol_name,
            signatures=signatures,
            debug=debug,
        )
    if payload is None:
        return PREPROCESS_STATUS_FAILED

    filtered_payload = _filter_payload(payload, desired_fields)
    if filtered_payload is None:
        return PREPROCESS_STATUS_FAILED

    write_func_yaml(artifact_path(binary_dir, symbol_name), filtered_payload)
    return PREPROCESS_STATUS_SUCCESS
```

- [ ] **Step 4: Run helper tests**

Run:

```bash
python -m unittest tests.test_extract_ntapi
```

Expected: PASS.

- [ ] **Step 5: Commit Task 2**

```bash
git add ida_preprocessor_scripts/_extract_ntapi.py tests/test_extract_ntapi.py
git commit -m "feat: 增加NtAPI提取公共逻辑"
```

## Task 3: Add NtSecureConnectPort Script And Dispatch Coverage

**Files:**
- Create: `ida_preprocessor_scripts/find-NtSecureConnectPort.py`
- Modify: `tests/test_ida_skill_preprocessor.py`

- [ ] **Step 1: Relax the repository skill-doc test**

In `tests/test_ida_skill_preprocessor.py`, rename `test_repository_config_skills_have_matching_script_and_skill_doc` to `test_repository_config_skills_have_matching_script` and replace the body with:

```python
    def test_repository_config_skills_have_matching_script(self) -> None:
        config = load_config("config.yaml")

        for module in config.modules:
            for skill in module.skills:
                script_path = Path("ida_preprocessor_scripts") / f"{skill.name}.py"
                self.assertTrue(script_path.is_file(), script_path)
```

- [ ] **Step 2: Add dispatch coverage for NtSecureConnectPort**

Add this test near the existing `test_alpcp_init_system_script_dispatches_func_xrefs` test:

```python
    async def test_ntsecureconnectport_script_dispatches_ntapi_signatures(self) -> None:
        with patch(
            "ida_preprocessor_scripts._extract_ntapi.preprocess_ntapi_symbols",
            new=AsyncMock(return_value=ida_skill_preprocessor.PREPROCESS_STATUS_SUCCESS),
        ) as mock_ntapi:
            status = await ida_skill_preprocessor.preprocess_single_skill_via_mcp(
                session=AsyncMock(),
                skill=SkillSpec(
                    name="find-NtSecureConnectPort",
                    expected_output=["NtSecureConnectPort.yaml"],
                    expected_input=[],
                ),
                symbol={"name": "NtSecureConnectPort"},
                binary_dir=Path("/tmp"),
                pdb_path=Path("/tmp/ntkrnlmp.pdb"),
                debug=False,
                llm_config=None,
            )

        self.assertEqual(ida_skill_preprocessor.PREPROCESS_STATUS_SUCCESS, status)
        self.assertEqual(
            ["NtSecureConnectPort"],
            mock_ntapi.await_args.kwargs["target_function_names"],
        )
        self.assertEqual(
            {
                "NtSecureConnectPort": ["5D 53 26 88 09 00 00 00"],
            },
            mock_ntapi.await_args.kwargs["ntapi_signatures"],
        )
        self.assertEqual(
            {"NtSecureConnectPort": ["func_name", "func_rva"]},
            mock_ntapi.await_args.kwargs["generate_yaml_desired_fields"],
        )
        self.assertEqual(
            Path("/tmp/ntkrnlmp.pdb"),
            mock_ntapi.await_args.kwargs["pdb_path"],
        )
```

- [ ] **Step 3: Run the dispatch test to verify it fails before script creation**

Run:

```bash
python -m unittest tests.test_ida_skill_preprocessor.TestIdaSkillPreprocessor.test_ntsecureconnectport_script_dispatches_ntapi_signatures
```

Expected: FAIL with status `failed` because `find-NtSecureConnectPort.py` does not exist.

- [ ] **Step 4: Create `find-NtSecureConnectPort.py`**

Create `ida_preprocessor_scripts/find-NtSecureConnectPort.py`:

```python
from __future__ import annotations

from ida_preprocessor_scripts import _extract_ntapi


TARGET_FUNCTION_NAMES = ["NtSecureConnectPort"]

NTAPI_SIGNATURES = {
    "NtSecureConnectPort": ["5D 53 26 88 09 00 00 00"],
}

GENERATE_YAML_DESIRED_FIELDS = {
    "NtSecureConnectPort": ["func_name", "func_rva"],
}


async def preprocess_skill(session, skill, symbol, binary_dir, pdb_path, debug, llm_config):
    return await _extract_ntapi.preprocess_ntapi_symbols(
        session=session,
        skill=skill,
        symbol=symbol,
        binary_dir=binary_dir,
        pdb_path=pdb_path,
        debug=debug,
        target_function_names=TARGET_FUNCTION_NAMES,
        ntapi_signatures=NTAPI_SIGNATURES,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
    )
```

- [ ] **Step 5: Run dispatch-focused tests**

Run:

```bash
python -m unittest \
  tests.test_ida_skill_preprocessor.TestIdaSkillPreprocessor.test_repository_config_skills_have_matching_script \
  tests.test_ida_skill_preprocessor.TestIdaSkillPreprocessor.test_ntsecureconnectport_script_dispatches_ntapi_signatures
```

Expected: the dispatch test passes. The repository-config script test may still pass before `config.yaml` is changed because the new skill is not listed yet.

- [ ] **Step 6: Commit Task 3**

```bash
git add ida_preprocessor_scripts/find-NtSecureConnectPort.py tests/test_ida_skill_preprocessor.py
git commit -m "feat: 增加NtSecureConnectPort预处理脚本"
```

## Task 4: Add Config Entry Without XML Symbol Entry

**Files:**
- Modify: `config.yaml`
- Modify: `tests/test_update_symbols.py`

- [ ] **Step 1: Add XML-export ignore coverage**

Add this test to `tests/test_update_symbols.py` near the other `export_xml` tests:

```python
    def test_export_xml_ignores_yaml_without_symbol_spec(self) -> None:
        tree = update_symbols.ET.ElementTree(update_symbols.ET.fromstring(XML_TEXT))
        config = self._build_config()

        with TemporaryDirectory() as temp_dir:
            sha_dir = Path(temp_dir) / "amd64" / "ntoskrnl.exe.10.0.1" / "abc"
            sha_dir.mkdir(parents=True, exist_ok=True)
            (sha_dir / "EpObjectTable.yaml").write_text(
                "category: struct_offset\noffset: 0x570\n",
                encoding="utf-8",
            )
            (sha_dir / "NtSecureConnectPort.yaml").write_text(
                "category: func\n"
                "func_name: NtSecureConnectPort\n"
                "func_rva: 0x5e8d70\n",
                encoding="utf-8",
            )
            with patch.object(
                update_symbols,
                "_load_binary_metadata",
                return_value={"timestamp": "0x0", "size": "0x0"},
            ):
                update_symbols.export_xml(tree, config, Path(temp_dir))

        fields_elem = tree.getroot().find("fields")
        self.assertEqual("0x570", fields_elem.get("EpObjectTable"))
        self.assertIsNone(fields_elem.get("NtSecureConnectPort"))
```

- [ ] **Step 2: Run the XML-export ignore test**

Run:

```bash
python -m unittest tests.test_update_symbols.TestUpdateSymbols.test_export_xml_ignores_yaml_without_symbol_spec
```

Expected: PASS without changing `update_symbols.py`, because export already only iterates `module.symbols`.

- [ ] **Step 3: Add the new skill to `config.yaml`**

In `config.yaml`, add this skill under the `ntoskrnl` module `skills` list near the other function preprocessors:

```yaml
  - name: find-NtSecureConnectPort
    expected_output:
    - NtSecureConnectPort.yaml
```

Do not add this block anywhere under `symbols`:

```yaml
  - name: NtSecureConnectPort
    category: func
    data_type: uint32
```

- [ ] **Step 4: Run config and script repository checks**

Run:

```bash
python -m unittest \
  tests.test_symbol_config.TestSymbolConfig.test_load_config_reads_repository_baseline \
  tests.test_ida_skill_preprocessor.TestIdaSkillPreprocessor.test_repository_config_skills_have_matching_script \
  tests.test_ida_skill_preprocessor.TestIdaSkillPreprocessor.test_repository_config_skills_export_loadable_preprocess_entries
```

Expected: PASS.

- [ ] **Step 5: Commit Task 4**

```bash
git add config.yaml tests/test_update_symbols.py
git commit -m "feat: 启用NtSecureConnectPort预处理"
```

## Task 5: Final Focused Verification

**Files:**
- No source edits expected.

- [ ] **Step 1: Run all directly affected tests**

Run:

```bash
python -m unittest \
  tests.test_extract_ntapi \
  tests.test_ida_skill_preprocessor \
  tests.test_symbol_config \
  tests.test_dump_symbols \
  tests.test_update_symbols
```

Expected: PASS.

- [ ] **Step 2: Inspect final diff**

Run:

```bash
git status --short
git diff --stat HEAD~4..HEAD
```

Expected: the changed files are limited to:

```text
config.yaml
dump_symbols.py
symbol_config.py
ida_preprocessor_scripts/_extract_ntapi.py
ida_preprocessor_scripts/find-NtSecureConnectPort.py
tests/test_dump_symbols.py
tests/test_extract_ntapi.py
tests/test_ida_skill_preprocessor.py
tests/test_symbol_config.py
tests/test_update_symbols.py
```

- [ ] **Step 3: Confirm acceptance criteria manually**

Check:

```bash
rg -n "find-NtSecureConnectPort|NtSecureConnectPort" config.yaml ida_preprocessor_scripts tests
```

Expected:

- `config.yaml` contains `find-NtSecureConnectPort` under `skills`.
- `config.yaml` does not contain a `symbols` entry for `NtSecureConnectPort`.
- `find-NtSecureConnectPort.py` contains the signature `5D 53 26 88 09 00 00 00`.
- Tests cover PDB-first behavior and signature fallback.

- [ ] **Step 4: Commit final verification notes if any cleanup edits were needed**

If Task 5 required cleanup edits, commit them:

```bash
git add \
  config.yaml \
  dump_symbols.py \
  symbol_config.py \
  ida_preprocessor_scripts/_extract_ntapi.py \
  ida_preprocessor_scripts/find-NtSecureConnectPort.py \
  tests/test_dump_symbols.py \
  tests/test_extract_ntapi.py \
  tests/test_ida_skill_preprocessor.py \
  tests/test_symbol_config.py \
  tests/test_update_symbols.py
git commit -m "test: 补充NtSecureConnectPort验证"
```

If Task 5 required no cleanup edits, do not create an empty commit.

## Self-Review Notes

- Spec coverage: Tasks 2 and 3 implement PDB-first NtAPI extraction and the thin script. Task 4 adds the skill without adding a symbol entry. Task 1 implements preprocessor-only artifact handling. Task 4 verifies XML export ignores `NtSecureConnectPort.yaml`.
- Placeholder scan: no placeholder markers, deferred error handling, or unspecified test bodies remain in this plan.
- Type consistency: `preprocess_ntapi_symbols(...)` reads `symbol.name` through `_field(...)`, so both `{"name": ...}` and object-style symbols work. `dump_symbols.py` creates `{"name": symbol_name}` only for missing `SymbolSpec` outputs.
