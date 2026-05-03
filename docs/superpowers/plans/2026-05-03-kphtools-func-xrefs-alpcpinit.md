# kphtools FUNC_XREFS AlpcpInitSystem Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add reusable `FUNC_XREFS`-based function discovery to kphtools preprocessor scripts and add `find-AlpcpInitSystem`.

**Architecture:** Keep the existing kphtools YAML contract for function outputs. `ida_preprocessor_common.py` validates and routes `func_xrefs`; `ida_preprocessor_scripts/generic_func.py` owns xref-based function resolution through IDA MCP tools. The new Alpcp script and `config.yaml` use the same preprocessor entry shape as existing finders.

**Tech Stack:** Python 3.10+, unittest, PyYAML, IDA MCP `py_eval` / `find_bytes`, existing kphtools symbol artifact helpers.

---

## File Structure

- Modify `ida_preprocessor_common.py`
  - Add `func_xrefs` validation.
  - Allow function targets that are present only in `func_xrefs`.
  - Pass the per-target xref spec into `preprocess_func_symbol`.
- Modify `ida_preprocessor_scripts/generic_func.py`
  - Preserve PDB public symbol behavior.
  - Add IDA MCP helper functions for string, UTF-16 string, signature, gv, and func xref candidate collection.
  - Add exact-match support through the `FULLMATCH:` prefix.
  - Return `func_name`, `func_va`, and `func_rva` from xref fallback; common field filtering controls final YAML fields.
- Create `ida_preprocessor_scripts/find-AlpcpInitSystem.py`
  - Declare the user-provided `FUNC_XREFS`.
  - Output `AlpcpInitSystem.yaml`.
- Modify `config.yaml`
  - Add the `find-AlpcpInitSystem` skill under `ntoskrnl`.
  - Add the `AlpcpInitSystem` function symbol.
- Create `.claude/skills/find-AlpcpInitSystem/SKILL.md`
  - Keep fallback skill documentation consistent with configured skill inventory.
- Modify `tests/test_ida_preprocessor_common.py`
  - Cover `func_xrefs` validation and common preprocessor routing.
- Create `tests/test_generic_func_xrefs.py`
  - Cover xref helper behavior without requiring IDA.
- Modify `tests/test_ida_skill_preprocessor.py`
  - Cover script dispatch for `find-AlpcpInitSystem`.

---

### Task 1: Add Generic Function Xref Tests

**Files:**
- Create: `tests/test_generic_func_xrefs.py`
- Modify: none
- Test: `tests/test_generic_func_xrefs.py`

- [ ] **Step 1: Create the failing tests**

Create `tests/test_generic_func_xrefs.py` with this content:

```python
from __future__ import annotations

import json
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

from ida_preprocessor_scripts import generic_func


def _tool_result(payload):
    return SimpleNamespace(
        content=[
            SimpleNamespace(
                text=json.dumps({"result": json.dumps(payload)})
            )
        ]
    )


class TestGenericFuncXrefs(unittest.IsolatedAsyncioTestCase):
    async def test_preprocess_func_symbol_uses_xref_after_pdb_miss(self) -> None:
        with (
            patch.object(
                generic_func,
                "resolve_public_symbol",
                side_effect=KeyError("AlpcpInitSystem"),
            ) as mock_resolve_public,
            patch.object(
                generic_func,
                "preprocess_func_xrefs_symbol",
                new=AsyncMock(
                    return_value={
                        "func_name": "AlpcpInitSystem",
                        "func_va": 0x140123000,
                        "func_rva": 0x123000,
                    }
                ),
            ) as mock_xrefs,
        ):
            payload = await generic_func.preprocess_func_symbol(
                session=AsyncMock(),
                symbol_name="AlpcpInitSystem",
                metadata={"alias": ["AlpcpInitSystem"]},
                pdb_path="/tmp/ntkrnlmp.pdb",
                debug=True,
                llm_config=None,
                binary_dir="/tmp/bin",
                image_base=0x140000000,
                func_xref={"xref_unicode_strings": ["FULLMATCH:ALPC Port"]},
            )

        self.assertEqual(
            {
                "func_name": "AlpcpInitSystem",
                "func_va": 0x140123000,
                "func_rva": 0x123000,
            },
            payload,
        )
        mock_resolve_public.assert_called_once_with(
            "/tmp/ntkrnlmp.pdb",
            "AlpcpInitSystem",
        )
        mock_xrefs.assert_awaited_once()
        self.assertEqual(
            {"xref_unicode_strings": ["FULLMATCH:ALPC Port"]},
            mock_xrefs.await_args.kwargs["func_xref"],
        )

    async def test_collect_unicode_string_xrefs_generates_fullmatch_filter(self) -> None:
        session = AsyncMock()
        session.call_tool.return_value = _tool_result(
            {"func_starts": ["0x140010000"]}
        )

        addrs = await generic_func._collect_xref_func_starts_for_string(
            session=session,
            xref_string="FULLMATCH:ALPC Port",
            unicode_only=True,
            debug=True,
        )

        self.assertEqual({0x140010000}, addrs)
        session.call_tool.assert_awaited_once()
        kwargs = session.call_tool.await_args.kwargs
        self.assertEqual("py_eval", kwargs["name"])
        code = kwargs["arguments"]["code"]
        self.assertIn("unicode_only = True", code)
        self.assertIn("current_str == search_str", code)
        self.assertIn("ALPC Port", code)
        self.assertIn("STRTYPE_C_16", code)

    async def test_signature_xrefs_parse_find_bytes_matches(self) -> None:
        session = AsyncMock()
        session.call_tool.side_effect = [
            _tool_result(
                [
                    {
                        "pattern": "41 B8 41 6C 49 6E",
                        "matches": ["0x140020123", "0x140020456"],
                    }
                ]
            ),
            _tool_result({"func_starts": ["0x140020000"]}),
        ]

        addrs = await generic_func._collect_xref_func_starts_for_signature(
            session=session,
            xref_signature="41 B8 41 6C 49 6E",
            debug=True,
        )

        self.assertEqual({0x140020000}, addrs)
        self.assertEqual("find_bytes", session.call_tool.await_args_list[0].kwargs["name"])
        self.assertEqual(
            {"patterns": ["41 B8 41 6C 49 6E"]},
            session.call_tool.await_args_list[0].kwargs["arguments"],
        )

    async def test_func_xrefs_intersects_positive_sources_and_excludes(self) -> None:
        session = AsyncMock()
        with (
            patch.object(
                generic_func,
                "_collect_xref_func_starts_for_string",
                new=AsyncMock(
                    side_effect=[
                        {0x140010000, 0x140020000},
                        {0x140020000},
                        {0x140030000},
                    ]
                ),
            ) as mock_string,
            patch.object(
                generic_func,
                "_collect_xref_func_starts_for_signature",
                new=AsyncMock(return_value={0x140020000, 0x140030000}),
            ) as mock_signature,
        ):
            payload = await generic_func.preprocess_func_xrefs_symbol(
                session=session,
                symbol_name="AlpcpInitSystem",
                func_xref={
                    "xref_strings": ["ALPC"],
                    "xref_unicode_strings": ["FULLMATCH:ALPC Port"],
                    "xref_signatures": ["41 B8 41 6C 49 6E"],
                    "xref_gvs": [],
                    "xref_funcs": [],
                    "exclude_strings": ["not this function"],
                    "exclude_unicode_strings": [],
                    "exclude_gvs": [],
                    "exclude_funcs": [],
                    "exclude_signatures": [],
                },
                binary_dir="/tmp/bin",
                image_base=0x140000000,
                debug=True,
            )

        self.assertEqual(
            {
                "func_name": "AlpcpInitSystem",
                "func_va": 0x140020000,
                "func_rva": 0x20000,
            },
            payload,
        )
        self.assertEqual(3, mock_string.await_count)
        mock_signature.assert_awaited_once()

    async def test_func_xrefs_returns_none_for_non_unique_candidates(self) -> None:
        with patch.object(
            generic_func,
            "_collect_xref_func_starts_for_signature",
            new=AsyncMock(return_value={0x140020000, 0x140030000}),
        ):
            payload = await generic_func.preprocess_func_xrefs_symbol(
                session=AsyncMock(),
                symbol_name="AlpcpInitSystem",
                func_xref={
                    "xref_strings": [],
                    "xref_unicode_strings": [],
                    "xref_signatures": ["41 6C 4D 73"],
                    "xref_gvs": [],
                    "xref_funcs": [],
                    "exclude_strings": [],
                    "exclude_unicode_strings": [],
                    "exclude_gvs": [],
                    "exclude_funcs": [],
                    "exclude_signatures": [],
                },
                binary_dir="/tmp/bin",
                image_base=0x140000000,
                debug=True,
            )

        self.assertIsNone(payload)
```

- [ ] **Step 2: Run the new tests to verify they fail**

Run:

```bash
uv run python -m unittest tests.test_generic_func_xrefs -v
```

Expected: FAIL with errors that `preprocess_func_xrefs_symbol`, `_collect_xref_func_starts_for_string`, or `_collect_xref_func_starts_for_signature` is missing or has the old signature.

---

### Task 2: Implement Generic Function Xref Resolution

**Files:**
- Modify: `ida_preprocessor_scripts/generic_func.py`
- Test: `tests/test_generic_func_xrefs.py`

- [ ] **Step 1: Replace `generic_func.py` with the xref-capable implementation**

Replace `ida_preprocessor_scripts/generic_func.py` with:

```python
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from pdb_resolver import resolve_public_symbol


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


def _is_explicit_address_literal(value: Any) -> bool:
    return isinstance(value, str) and value.strip().lower().startswith("0x")


def _intersect_addr_sets(candidate_sets: list[set[int]]) -> set[int]:
    if not candidate_sets:
        return set()
    common = set(candidate_sets[0])
    for addr_set in candidate_sets[1:]:
        common &= set(addr_set)
    return common


async def _collect_func_starts_for_code_addrs(
    *,
    session,
    code_addrs: set[int],
    debug: bool = False,
) -> set[int] | None:
    if not code_addrs:
        return set()
    py_code = (
        "import ida_funcs, json\n"
        f"code_addrs = {json.dumps([hex(addr) for addr in sorted(code_addrs)])}\n"
        "func_starts = set()\n"
        "for raw_ea in code_addrs:\n"
        "    try:\n"
        "        ea = int(str(raw_ea), 16)\n"
        "    except Exception:\n"
        "        continue\n"
        "    func = ida_funcs.get_func(ea)\n"
        "    if func is not None:\n"
        "        func_starts.add(int(func.start_ea))\n"
        "result = json.dumps({'func_starts': [hex(ea) for ea in sorted(func_starts)]})\n"
    )
    try:
        result = await session.call_tool(
            name="py_eval",
            arguments={"code": py_code},
        )
    except Exception as exc:
        if debug:
            print(f"    Preprocess: py_eval failed while normalizing function starts: {exc}")
        return None
    payload = _parse_tool_json_result(result)
    starts = payload.get("func_starts") if isinstance(payload, dict) else None
    if not isinstance(starts, list):
        return None
    parsed: set[int] = set()
    for item in starts:
        try:
            parsed.add(_parse_int_value(item))
        except (TypeError, ValueError):
            continue
    return parsed


async def _collect_xref_func_starts_for_string(
    *,
    session,
    xref_string: str,
    unicode_only: bool = False,
    debug: bool = False,
) -> set[int] | None:
    if not isinstance(xref_string, str) or not xref_string:
        return set()

    search_str = xref_string
    match_expr = "search_str in current_str"
    if xref_string.startswith("FULLMATCH:"):
        search_str = xref_string[len("FULLMATCH:") :]
        if not search_str:
            return set()
        match_expr = "current_str == search_str"

    py_lines = [
        "import ida_funcs, ida_nalt, idautils, json",
        f"search_str = {json.dumps(search_str)}",
        f"unicode_only = {bool(unicode_only)!r}",
        "unicode_type_names = ('STRTYPE_C_16', 'STRTYPE_C_32', 'STRTYPE_LEN2_16', 'STRTYPE_LEN2_32')",
        "unicode_types = {getattr(ida_nalt, name) for name in unicode_type_names if hasattr(ida_nalt, name)}",
        "strings = idautils.Strings(default_setup=False)",
        "if unicode_only and unicode_types:",
        "    try:",
        "        strings.setup(strtypes=list(unicode_types), minlen=2)",
        "    except Exception:",
        "        pass",
        "func_starts = set()",
        "for s in strings:",
        "    current_str = str(s)",
        "    string_type = getattr(s, 'type', None)",
        "    if unicode_only and unicode_types and string_type not in unicode_types:",
        "        continue",
        f"    if {match_expr}:",
        "        for xref in idautils.XrefsTo(s.ea, 0):",
        "            func = ida_funcs.get_func(xref.frm)",
        "            if func is not None:",
        "                func_starts.add(int(func.start_ea))",
        "result = json.dumps({'func_starts': [hex(ea) for ea in sorted(func_starts)]})",
    ]
    try:
        result = await session.call_tool(
            name="py_eval",
            arguments={"code": "\n".join(py_lines) + "\n"},
        )
    except Exception as exc:
        if debug:
            print(f"    Preprocess: py_eval failed for xref string search: {exc}")
        return None

    payload = _parse_tool_json_result(result)
    starts = payload.get("func_starts") if isinstance(payload, dict) else None
    if not isinstance(starts, list):
        return None
    parsed: set[int] = set()
    for item in starts:
        try:
            parsed.add(_parse_int_value(item))
        except (TypeError, ValueError):
            continue
    return parsed


async def _collect_xref_func_starts_for_signature(
    *,
    session,
    xref_signature: str,
    debug: bool = False,
) -> set[int] | None:
    if not isinstance(xref_signature, str) or not xref_signature:
        return set()
    try:
        result = await session.call_tool(
            name="find_bytes",
            arguments={"patterns": [xref_signature]},
        )
    except Exception as exc:
        if debug:
            print(f"    Preprocess: find_bytes failed for xref signature: {exc}")
        return None
    payload = _parse_tool_json_result(result)
    if not isinstance(payload, list) or not payload:
        return set()

    raw_matches = payload[0].get("matches", [])
    if not isinstance(raw_matches, list):
        return set()
    code_addrs: set[int] = set()
    for item in raw_matches:
        try:
            code_addrs.add(_parse_int_value(item))
        except (TypeError, ValueError):
            continue
    return await _collect_func_starts_for_code_addrs(
        session=session,
        code_addrs=code_addrs,
        debug=debug,
    )


async def _collect_xref_func_starts_for_ea(
    *,
    session,
    target_ea: int,
    debug: bool = False,
) -> set[int] | None:
    py_code = (
        "import ida_funcs, idautils, json\n"
        f"target_ea = {int(target_ea)}\n"
        "func_starts = set()\n"
        "for xref in idautils.XrefsTo(target_ea, 0):\n"
        "    func = ida_funcs.get_func(xref.frm)\n"
        "    if func is not None:\n"
        "        func_starts.add(int(func.start_ea))\n"
        "result = json.dumps({'func_starts': [hex(ea) for ea in sorted(func_starts)]})\n"
    )
    try:
        result = await session.call_tool(
            name="py_eval",
            arguments={"code": py_code},
        )
    except Exception as exc:
        if debug:
            print(f"    Preprocess: py_eval failed for xref ea {hex(target_ea)}: {exc}")
        return None
    payload = _parse_tool_json_result(result)
    starts = payload.get("func_starts") if isinstance(payload, dict) else None
    if not isinstance(starts, list):
        return None
    parsed: set[int] = set()
    for item in starts:
        try:
            parsed.add(_parse_int_value(item))
        except (TypeError, ValueError):
            continue
    return parsed


def _load_yaml_symbol_addr(
    *,
    binary_dir,
    symbol_name: str,
    va_field: str,
    rva_field: str,
    image_base: int,
    debug: bool = False,
) -> int | None:
    path = Path(binary_dir) / f"{symbol_name}.yaml"
    try:
        payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except OSError:
        if debug:
            print(f"    Preprocess: missing xref dependency YAML: {path}")
        return None
    if not isinstance(payload, dict):
        return None
    for field_name in (va_field, rva_field):
        if field_name not in payload:
            continue
        try:
            parsed = _parse_int_value(payload[field_name])
        except (TypeError, ValueError):
            continue
        if field_name == va_field:
            return parsed
        return image_base + parsed
    if debug:
        print(f"    Preprocess: YAML {path} lacks {va_field}/{rva_field}")
    return None


def _load_xref_ea(
    *,
    binary_dir,
    item: str,
    va_field: str,
    rva_field: str,
    image_base: int,
    debug: bool = False,
) -> int | None:
    if _is_explicit_address_literal(item):
        try:
            return _parse_int_value(item)
        except (TypeError, ValueError):
            return None
    return _load_yaml_symbol_addr(
        binary_dir=binary_dir,
        symbol_name=item,
        va_field=va_field,
        rva_field=rva_field,
        image_base=image_base,
        debug=debug,
    )


async def _append_ea_candidate_sets(
    *,
    session,
    candidate_sets: list[set[int]],
    items: list[str],
    binary_dir,
    va_field: str,
    rva_field: str,
    image_base: int,
    debug: bool,
) -> bool:
    for item in items:
        target_ea = _load_xref_ea(
            binary_dir=binary_dir,
            item=item,
            va_field=va_field,
            rva_field=rva_field,
            image_base=image_base,
            debug=debug,
        )
        if target_ea is None:
            return False
        addr_set = await _collect_xref_func_starts_for_ea(
            session=session,
            target_ea=target_ea,
            debug=debug,
        )
        if addr_set is None or not addr_set:
            return False
        candidate_sets.append(addr_set)
    return True


async def _collect_excluded_ea_func_addrs(
    *,
    session,
    items: list[str],
    binary_dir,
    va_field: str,
    rva_field: str,
    image_base: int,
    debug: bool,
) -> set[int] | None:
    excluded: set[int] = set()
    for item in items:
        target_ea = _load_xref_ea(
            binary_dir=binary_dir,
            item=item,
            va_field=va_field,
            rva_field=rva_field,
            image_base=image_base,
            debug=debug,
        )
        if target_ea is None:
            return None
        addr_set = await _collect_xref_func_starts_for_ea(
            session=session,
            target_ea=target_ea,
            debug=debug,
        )
        if addr_set is None:
            return None
        excluded |= addr_set
    return excluded


async def preprocess_func_xrefs_symbol(
    *,
    session,
    symbol_name: str,
    func_xref: dict,
    binary_dir,
    image_base: int = 0x140000000,
    debug: bool = False,
) -> dict[str, int | str] | None:
    candidate_sets: list[set[int]] = []

    for item in func_xref.get("xref_strings", []):
        addr_set = await _collect_xref_func_starts_for_string(
            session=session,
            xref_string=item,
            unicode_only=False,
            debug=debug,
        )
        if addr_set is None or not addr_set:
            return None
        candidate_sets.append(addr_set)

    for item in func_xref.get("xref_unicode_strings", []):
        addr_set = await _collect_xref_func_starts_for_string(
            session=session,
            xref_string=item,
            unicode_only=True,
            debug=debug,
        )
        if addr_set is None or not addr_set:
            return None
        candidate_sets.append(addr_set)

    if not await _append_ea_candidate_sets(
        session=session,
        candidate_sets=candidate_sets,
        items=func_xref.get("xref_gvs", []),
        binary_dir=binary_dir,
        va_field="gv_va",
        rva_field="gv_rva",
        image_base=image_base,
        debug=debug,
    ):
        return None

    for item in func_xref.get("xref_signatures", []):
        addr_set = await _collect_xref_func_starts_for_signature(
            session=session,
            xref_signature=item,
            debug=debug,
        )
        if addr_set is None or not addr_set:
            return None
        candidate_sets.append(addr_set)

    if not await _append_ea_candidate_sets(
        session=session,
        candidate_sets=candidate_sets,
        items=func_xref.get("xref_funcs", []),
        binary_dir=binary_dir,
        va_field="func_va",
        rva_field="func_rva",
        image_base=image_base,
        debug=debug,
    ):
        return None

    common_funcs = _intersect_addr_sets(candidate_sets)
    if not common_funcs:
        return None

    excluded: set[int] = set()
    for item in func_xref.get("exclude_strings", []):
        addr_set = await _collect_xref_func_starts_for_string(
            session=session,
            xref_string=item,
            unicode_only=False,
            debug=debug,
        )
        if addr_set is None:
            return None
        excluded |= addr_set

    for item in func_xref.get("exclude_unicode_strings", []):
        addr_set = await _collect_xref_func_starts_for_string(
            session=session,
            xref_string=item,
            unicode_only=True,
            debug=debug,
        )
        if addr_set is None:
            return None
        excluded |= addr_set

    excluded_gv_addrs = await _collect_excluded_ea_func_addrs(
        session=session,
        items=func_xref.get("exclude_gvs", []),
        binary_dir=binary_dir,
        va_field="gv_va",
        rva_field="gv_rva",
        image_base=image_base,
        debug=debug,
    )
    if excluded_gv_addrs is None:
        return None
    excluded |= excluded_gv_addrs

    excluded_func_addrs = await _collect_excluded_ea_func_addrs(
        session=session,
        items=func_xref.get("exclude_funcs", []),
        binary_dir=binary_dir,
        va_field="func_va",
        rva_field="func_rva",
        image_base=image_base,
        debug=debug,
    )
    if excluded_func_addrs is None:
        return None
    excluded |= excluded_func_addrs

    for item in func_xref.get("exclude_signatures", []):
        addr_set = await _collect_xref_func_starts_for_signature(
            session=session,
            xref_signature=item,
            debug=debug,
        )
        if addr_set is None:
            return None
        excluded |= addr_set

    common_funcs -= excluded
    if debug:
        print(
            "    Preprocess: func_xrefs candidates for "
            f"{symbol_name}: {[hex(addr) for addr in sorted(common_funcs)]}"
        )
    if len(common_funcs) != 1:
        return None

    func_va = next(iter(common_funcs))
    return {
        "func_name": symbol_name,
        "func_va": func_va,
        "func_rva": func_va - image_base,
    }


async def preprocess_func_symbol(
    *,
    session,
    symbol_name: str,
    metadata: dict,
    pdb_path,
    debug: bool,
    llm_config,
    binary_dir=None,
    image_base: int = 0x140000000,
    func_xref: dict | None = None,
):
    aliases = metadata.get("alias") or [symbol_name]
    lookup_name = aliases[0]
    if pdb_path is not None:
        try:
            payload = resolve_public_symbol(pdb_path, lookup_name)
            return {"func_name": symbol_name, "func_rva": payload["rva"]}
        except KeyError:
            pass

    if func_xref is not None:
        return await preprocess_func_xrefs_symbol(
            session=session,
            symbol_name=symbol_name,
            func_xref=func_xref,
            binary_dir=binary_dir,
            image_base=image_base,
            debug=debug,
        )

    return None
```

- [ ] **Step 2: Run the generic function xref tests**

Run:

```bash
uv run python -m unittest tests.test_generic_func_xrefs -v
```

Expected: PASS.

- [ ] **Step 3: Commit Task 2**

Run:

```bash
git add ida_preprocessor_scripts/generic_func.py tests/test_generic_func_xrefs.py
git commit -m "feat(preprocessor): 增加函数xref定位"
```

Expected: commit succeeds. Do not stage unrelated files such as `1.log`.

---

### Task 3: Add Common Preprocessor Validation and Routing

**Files:**
- Modify: `ida_preprocessor_common.py`
- Modify: `tests/test_ida_preprocessor_common.py`
- Test: `tests/test_ida_preprocessor_common.py`

- [ ] **Step 1: Add failing common preprocessor tests**

Append these tests inside `class TestIdaPreprocessorCommon` in `tests/test_ida_preprocessor_common.py`:

```python
    async def test_preprocess_common_skill_rejects_unknown_func_xrefs_key(self) -> None:
        with TemporaryDirectory() as temp_dir:
            status = await ida_preprocessor_common.preprocess_common_skill(
                session=AsyncMock(),
                skill=SimpleNamespace(name="find-AlpcpInitSystem"),
                symbol=SimpleNamespace(
                    name="AlpcpInitSystem",
                    category="func",
                    data_type="uint32",
                ),
                binary_dir=Path(temp_dir),
                pdb_path=None,
                debug=True,
                llm_config=None,
                func_names=["AlpcpInitSystem"],
                func_xrefs=[
                    {
                        "func_name": "AlpcpInitSystem",
                        "xref_unicode_strings": ["FULLMATCH:ALPC Port"],
                        "unknown": [],
                    }
                ],
                generate_yaml_desired_fields={
                    "AlpcpInitSystem": ["func_name", "func_rva"]
                },
            )

        self.assertEqual(ida_preprocessor_common.PREPROCESS_STATUS_FAILED, status)

    async def test_preprocess_common_skill_rejects_empty_func_xrefs_sources(self) -> None:
        with TemporaryDirectory() as temp_dir:
            status = await ida_preprocessor_common.preprocess_common_skill(
                session=AsyncMock(),
                skill=SimpleNamespace(name="find-AlpcpInitSystem"),
                symbol=SimpleNamespace(
                    name="AlpcpInitSystem",
                    category="func",
                    data_type="uint32",
                ),
                binary_dir=Path(temp_dir),
                pdb_path=None,
                debug=True,
                llm_config=None,
                func_names=["AlpcpInitSystem"],
                func_xrefs=[
                    {
                        "func_name": "AlpcpInitSystem",
                        "xref_strings": [],
                        "xref_unicode_strings": [],
                        "xref_gvs": [],
                        "xref_signatures": [],
                        "xref_funcs": [],
                        "exclude_funcs": [],
                        "exclude_strings": [],
                        "exclude_unicode_strings": [],
                        "exclude_gvs": [],
                        "exclude_signatures": [],
                    }
                ],
                generate_yaml_desired_fields={
                    "AlpcpInitSystem": ["func_name", "func_rva"]
                },
            )

        self.assertEqual(ida_preprocessor_common.PREPROCESS_STATUS_FAILED, status)

    async def test_preprocess_common_skill_routes_func_xrefs_without_pdb(self) -> None:
        with TemporaryDirectory() as temp_dir:
            with (
                patch.object(
                    ida_preprocessor_common,
                    "preprocess_func_symbol",
                    new=AsyncMock(
                        return_value={
                            "func_name": "AlpcpInitSystem",
                            "func_va": 0x140123000,
                            "func_rva": 0x123000,
                        }
                    ),
                ) as mock_func,
                patch.object(
                    ida_preprocessor_common,
                    "resolve_symbol_via_llm_decompile",
                    new=AsyncMock(return_value=None),
                ) as mock_llm,
            ):
                status = await ida_preprocessor_common.preprocess_common_skill(
                    session=AsyncMock(),
                    skill=SimpleNamespace(name="find-AlpcpInitSystem"),
                    symbol=SimpleNamespace(
                        name="AlpcpInitSystem",
                        category="func",
                        data_type="uint32",
                    ),
                    binary_dir=Path(temp_dir),
                    pdb_path=None,
                    debug=True,
                    llm_config=None,
                    func_names=["AlpcpInitSystem"],
                    func_xrefs=[
                        {
                            "func_name": "AlpcpInitSystem",
                            "xref_strings": [],
                            "xref_unicode_strings": ["FULLMATCH:ALPC Port"],
                            "xref_gvs": [],
                            "xref_signatures": ["41 B8 41 6C 49 6E"],
                            "xref_funcs": [],
                            "exclude_funcs": [],
                            "exclude_strings": [],
                            "exclude_unicode_strings": [],
                            "exclude_gvs": [],
                            "exclude_signatures": [],
                        }
                    ],
                    generate_yaml_desired_fields={
                        "AlpcpInitSystem": ["func_name", "func_rva"]
                    },
                )

        self.assertEqual(ida_preprocessor_common.PREPROCESS_STATUS_SUCCESS, status)
        mock_func.assert_awaited_once()
        mock_llm.assert_not_awaited()
        self.assertEqual(
            ["FULLMATCH:ALPC Port"],
            mock_func.await_args.kwargs["func_xref"]["xref_unicode_strings"],
        )
        self.assertEqual(Path(temp_dir), mock_func.await_args.kwargs["binary_dir"])
        payload = load_artifact(Path(temp_dir) / "AlpcpInitSystem.yaml")
        self.assertEqual(
            {
                "category": "func",
                "func_name": "AlpcpInitSystem",
                "func_rva": 0x123000,
            },
            payload,
        )

    async def test_preprocess_common_skill_allows_xref_only_function_target(self) -> None:
        with TemporaryDirectory() as temp_dir, patch.object(
            ida_preprocessor_common,
            "preprocess_func_symbol",
            new=AsyncMock(
                return_value={
                    "func_name": "AlpcpInitSystem",
                    "func_rva": 0x123000,
                }
            ),
        ):
            status = await ida_preprocessor_common.preprocess_common_skill(
                session=AsyncMock(),
                skill=SimpleNamespace(name="find-AlpcpInitSystem"),
                symbol=SimpleNamespace(
                    name="AlpcpInitSystem",
                    category="func",
                    data_type="uint32",
                ),
                binary_dir=Path(temp_dir),
                pdb_path=None,
                debug=False,
                llm_config=None,
                func_names=[],
                func_xrefs=[
                    {
                        "func_name": "AlpcpInitSystem",
                        "xref_unicode_strings": ["FULLMATCH:ALPC Port"],
                    }
                ],
                generate_yaml_desired_fields={
                    "AlpcpInitSystem": ["func_name", "func_rva"]
                },
            )

        self.assertEqual(ida_preprocessor_common.PREPROCESS_STATUS_SUCCESS, status)
```

- [ ] **Step 2: Run the targeted common tests to verify they fail**

Run:

```bash
uv run python -m unittest tests.test_ida_preprocessor_common.TestIdaPreprocessorCommon.test_preprocess_common_skill_rejects_unknown_func_xrefs_key tests.test_ida_preprocessor_common.TestIdaPreprocessorCommon.test_preprocess_common_skill_rejects_empty_func_xrefs_sources tests.test_ida_preprocessor_common.TestIdaPreprocessorCommon.test_preprocess_common_skill_routes_func_xrefs_without_pdb tests.test_ida_preprocessor_common.TestIdaPreprocessorCommon.test_preprocess_common_skill_allows_xref_only_function_target -v
```

Expected: FAIL because `preprocess_common_skill` does not accept the `func_xrefs` keyword yet.

- [ ] **Step 3: Add `func_xrefs` normalization helpers**

In `ida_preprocessor_common.py`, add these constants and helper after `_ALLOWED_FIELDS_BY_CATEGORY`:

```python
_FUNC_XREFS_ALLOWED_KEYS = frozenset(
    {
        "func_name",
        "xref_strings",
        "xref_unicode_strings",
        "xref_gvs",
        "xref_signatures",
        "xref_funcs",
        "exclude_funcs",
        "exclude_strings",
        "exclude_unicode_strings",
        "exclude_gvs",
        "exclude_signatures",
    }
)

_FUNC_XREFS_LIST_KEYS = (
    "xref_strings",
    "xref_unicode_strings",
    "xref_gvs",
    "xref_signatures",
    "xref_funcs",
    "exclude_funcs",
    "exclude_strings",
    "exclude_unicode_strings",
    "exclude_gvs",
    "exclude_signatures",
)

_FUNC_XREFS_POSITIVE_KEYS = (
    "xref_strings",
    "xref_unicode_strings",
    "xref_gvs",
    "xref_signatures",
    "xref_funcs",
)


def _normalize_func_xrefs(
    func_xrefs: Any,
    *,
    debug: bool = False,
) -> dict[str, dict[str, list[Any]]] | None:
    if func_xrefs is None:
        return {}
    if not isinstance(func_xrefs, Iterable) or isinstance(func_xrefs, (str, bytes)):
        return None

    normalized: dict[str, dict[str, list[Any]]] = {}
    for spec in func_xrefs:
        if not isinstance(spec, Mapping):
            return None
        unknown_keys = sorted(set(spec) - _FUNC_XREFS_ALLOWED_KEYS)
        if unknown_keys:
            if debug:
                print(
                    "    Preprocess: unknown func_xrefs keys for "
                    f"{spec.get('func_name')}: {unknown_keys}"
                )
            return None
        func_name = spec.get("func_name")
        if not isinstance(func_name, str) or not func_name:
            return None
        if func_name in normalized:
            return None

        normalized_spec: dict[str, list[Any]] = {}
        for field_name in _FUNC_XREFS_LIST_KEYS:
            field_value = spec.get(field_name, [])
            if not isinstance(field_value, (list, tuple)):
                return None
            normalized_spec[field_name] = list(field_value)

        if not any(normalized_spec[field_name] for field_name in _FUNC_XREFS_POSITIVE_KEYS):
            if debug:
                print(f"    Preprocess: empty func_xrefs spec for {func_name}")
            return None

        normalized[func_name] = normalized_spec
    return normalized
```

- [ ] **Step 4: Update `preprocess_common_skill` signature and function routing**

Change the function signature to include `func_xrefs`:

```python
async def preprocess_common_skill(
    *,
    session,
    skill,
    symbol,
    binary_dir: str | Path,
    pdb_path: str | Path | None,
    debug: bool,
    llm_config,
    struct_member_names: list[str] | None = None,
    struct_metadata: dict[str, dict[str, Any]] | None = None,
    gv_names: list[str] | None = None,
    gv_metadata: dict[str, dict[str, Any]] | None = None,
    func_names: list[str] | None = None,
    func_metadata: dict[str, dict[str, Any]] | None = None,
    func_xrefs=None,
    llm_decompile_specs=None,
    generate_yaml_desired_fields=None,
):
```

After desired fields normalization, add:

```python
    func_xrefs_map = _normalize_func_xrefs(func_xrefs, debug=debug)
    if func_xrefs_map is None:
        return PREPROCESS_STATUS_FAILED
```

Replace the `elif symbol.category == "func":` block with:

```python
    elif symbol.category == "func":
        allowed_func_names = set(func_names or []) | set(func_xrefs_map)
        if func_names is not None and target_symbol_name not in allowed_func_names:
            return PREPROCESS_STATUS_FAILED
        metadata = (func_metadata or {}).get(target_symbol_name, {})
        if not isinstance(metadata, dict):
            return PREPROCESS_STATUS_FAILED
        func_xref = func_xrefs_map.get(target_symbol_name)
        if has_pdb or func_xref is not None:
            payload = await preprocess_func_symbol(
                session=session,
                symbol_name=target_symbol_name,
                metadata=metadata,
                pdb_path=pdb_path,
                debug=debug,
                llm_config=llm_config,
                binary_dir=Path(binary_dir),
                image_base=0x140000000,
                func_xref=func_xref,
            )
        writer = write_func_yaml
```

- [ ] **Step 5: Run common tests**

Run:

```bash
uv run python -m unittest tests.test_ida_preprocessor_common -v
```

Expected: PASS.

- [ ] **Step 6: Run generic xref tests**

Run:

```bash
uv run python -m unittest tests.test_generic_func_xrefs -v
```

Expected: PASS.

- [ ] **Step 7: Commit Task 3**

Run:

```bash
git add ida_preprocessor_common.py tests/test_ida_preprocessor_common.py
git commit -m "feat(preprocessor): 接入FUNC_XREFS路由"
```

Expected: commit succeeds.

---

### Task 4: Add AlpcpInitSystem Finder, Config, and Skill Doc

**Files:**
- Create: `ida_preprocessor_scripts/find-AlpcpInitSystem.py`
- Create: `.claude/skills/find-AlpcpInitSystem/SKILL.md`
- Modify: `config.yaml`
- Modify: `tests/test_ida_skill_preprocessor.py`
- Test: `tests/test_ida_skill_preprocessor.py`

- [ ] **Step 1: Add a failing dispatch test**

Append this test inside `class TestIdaSkillPreprocessor` in `tests/test_ida_skill_preprocessor.py`:

```python
    async def test_alpcp_init_system_script_dispatches_func_xrefs(self) -> None:
        with patch(
            "ida_preprocessor_common.preprocess_common_skill",
            new=AsyncMock(return_value=ida_skill_preprocessor.PREPROCESS_STATUS_SUCCESS),
        ) as mock_common:
            status = await ida_skill_preprocessor.preprocess_single_skill_via_mcp(
                session=AsyncMock(),
                skill=SkillSpec(
                    name="find-AlpcpInitSystem",
                    expected_output=["AlpcpInitSystem.yaml"],
                    expected_input=[],
                ),
                symbol=SymbolSpec(
                    name="AlpcpInitSystem",
                    category="func",
                    data_type="uint32",
                ),
                binary_dir=Path("/tmp"),
                pdb_path=None,
                debug=False,
                llm_config=None,
            )

        self.assertEqual(ida_skill_preprocessor.PREPROCESS_STATUS_SUCCESS, status)
        self.assertEqual(
            ["AlpcpInitSystem"],
            mock_common.await_args.kwargs["func_names"],
        )
        self.assertEqual(
            [
                {
                    "func_name": "AlpcpInitSystem",
                    "xref_strings": [],
                    "xref_unicode_strings": ["FULLMATCH:ALPC Port"],
                    "xref_gvs": [],
                    "xref_signatures": ["41 B8 41 6C 49 6E", "41 6C 4D 73"],
                    "xref_funcs": [],
                    "exclude_funcs": [],
                    "exclude_strings": [],
                    "exclude_unicode_strings": [],
                    "exclude_gvs": [],
                    "exclude_signatures": [],
                }
            ],
            mock_common.await_args.kwargs["func_xrefs"],
        )
        self.assertEqual(
            {"AlpcpInitSystem": ["func_name", "func_rva"]},
            mock_common.await_args.kwargs["generate_yaml_desired_fields"],
        )
```

- [ ] **Step 2: Run the dispatch test to verify it fails**

Run:

```bash
uv run python -m unittest tests.test_ida_skill_preprocessor.TestIdaSkillPreprocessor.test_alpcp_init_system_script_dispatches_func_xrefs -v
```

Expected: FAIL because `ida_preprocessor_scripts/find-AlpcpInitSystem.py` does not exist.

- [ ] **Step 3: Create the finder script**

Create `ida_preprocessor_scripts/find-AlpcpInitSystem.py`:

```python
from __future__ import annotations

import ida_preprocessor_common as preprocessor_common

TARGET_FUNCTION_NAMES = ["AlpcpInitSystem"]

FUNC_XREFS = [
    {
        "func_name": "AlpcpInitSystem",
        "xref_strings": [],
        "xref_unicode_strings": ["FULLMATCH:ALPC Port"],
        "xref_gvs": [],
        "xref_signatures": ["41 B8 41 6C 49 6E", "41 6C 4D 73"],
        "xref_funcs": [],
        "exclude_funcs": [],
        "exclude_strings": [],
        "exclude_unicode_strings": [],
        "exclude_gvs": [],
        "exclude_signatures": [],
    },
]

GENERATE_YAML_DESIRED_FIELDS = {
    "AlpcpInitSystem": ["func_name", "func_rva"],
}


async def preprocess_skill(session, skill, symbol, binary_dir, pdb_path, debug, llm_config):
    return await preprocessor_common.preprocess_common_skill(
        session=session,
        skill=skill,
        symbol=symbol,
        binary_dir=binary_dir,
        pdb_path=pdb_path,
        debug=debug,
        llm_config=llm_config,
        func_names=TARGET_FUNCTION_NAMES,
        func_xrefs=FUNC_XREFS,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
    )
```

- [ ] **Step 4: Add the fallback skill doc**

Create `.claude/skills/find-AlpcpInitSystem/SKILL.md`:

```markdown
---
name: find-AlpcpInitSystem
description: Locate ntoskrnl AlpcpInitSystem with FUNC_XREFS using the UTF-16 string L"ALPC Port" and signature byte patterns.
disable-model-invocation: true
---

# find-AlpcpInitSystem

This kphtools fallback skill corresponds to `ida_preprocessor_scripts/find-AlpcpInitSystem.py`.

It produces `AlpcpInitSystem.yaml` for the current ntoskrnl binary with:

- `category: func`
- `func_name: AlpcpInitSystem`
- `func_rva`

The primary automated path is `FUNC_XREFS` in the preprocessor script:

- UTF-16 exact string reference: `FULLMATCH:ALPC Port`
- Signature references: `41 B8 41 6C 49 6E` and `41 6C 4D 73`
```

- [ ] **Step 5: Update `config.yaml`**

Under `modules[0].skills`, add this entry near the existing ALPC skills:

```yaml
  - name: find-AlpcpInitSystem
    expected_output:
    - AlpcpInitSystem.yaml
```

Under `modules[0].symbols`, add this entry near the existing function symbols:

```yaml
  - name: AlpcpInitSystem
    category: func
    data_type: uint32
```

- [ ] **Step 6: Run the dispatch test**

Run:

```bash
uv run python -m unittest tests.test_ida_skill_preprocessor.TestIdaSkillPreprocessor.test_alpcp_init_system_script_dispatches_func_xrefs -v
```

Expected: PASS.

- [ ] **Step 7: Run config load check**

Run:

```bash
uv run python - <<'PY'
from symbol_config import load_config
config = load_config("config.yaml")
skills = [skill.name for module in config.modules for skill in module.skills]
symbols = [symbol.name for module in config.modules for symbol in module.symbols]
assert "find-AlpcpInitSystem" in skills
assert "AlpcpInitSystem" in symbols
print("config ok")
PY
```

Expected: prints `config ok`.

- [ ] **Step 8: Commit Task 4**

Run:

```bash
git add ida_preprocessor_scripts/find-AlpcpInitSystem.py config.yaml tests/test_ida_skill_preprocessor.py
git add -f .claude/skills/find-AlpcpInitSystem/SKILL.md
git commit -m "feat(preprocessor): 增加AlpcpInitSystem定位"
```

Expected: commit succeeds.

---

### Task 5: Final Focused Verification

**Files:**
- No source changes expected.
- Test: `tests/test_generic_func_xrefs.py`
- Test: `tests/test_ida_preprocessor_common.py`
- Test: `tests/test_ida_skill_preprocessor.py`

- [ ] **Step 1: Run focused unit tests**

Run:

```bash
uv run python -m unittest tests.test_generic_func_xrefs tests.test_ida_preprocessor_common tests.test_ida_skill_preprocessor -v
```

Expected: PASS. If existing repository state lacks historical `.claude/skills/find-*/SKILL.md` files for older configured skills, report that as pre-existing inventory debt and still verify the new `find-AlpcpInitSystem` dispatch test directly.

- [ ] **Step 2: Run syntax compile check for changed modules**

Run:

```bash
uv run python -m py_compile ida_preprocessor_common.py ida_preprocessor_scripts/generic_func.py ida_preprocessor_scripts/find-AlpcpInitSystem.py
```

Expected: no output and exit code 0.

- [ ] **Step 3: Run whitespace check**

Run:

```bash
git diff --check
```

Expected: no output and exit code 0.

- [ ] **Step 4: Review final diff**

Run:

```bash
git status --short
git diff --stat HEAD
git diff -- ida_preprocessor_common.py ida_preprocessor_scripts/generic_func.py ida_preprocessor_scripts/find-AlpcpInitSystem.py config.yaml tests/test_generic_func_xrefs.py tests/test_ida_preprocessor_common.py tests/test_ida_skill_preprocessor.py .claude/skills/find-AlpcpInitSystem/SKILL.md
```

Expected:

- Only files in this plan are modified or newly created.
- `1.log` remains unstaged if it is still present.
- `config.yaml` contains exactly one `find-AlpcpInitSystem` skill and one `AlpcpInitSystem` symbol.

- [ ] **Step 5: Final commit if Task 5 changed files**

If Task 5 required any correction, commit those corrections:

```bash
git add ida_preprocessor_common.py ida_preprocessor_scripts/generic_func.py ida_preprocessor_scripts/find-AlpcpInitSystem.py config.yaml tests/test_generic_func_xrefs.py tests/test_ida_preprocessor_common.py tests/test_ida_skill_preprocessor.py
git add -f .claude/skills/find-AlpcpInitSystem/SKILL.md
git commit -m "fix(preprocessor): 完善FUNC_XREFS验证"
```

Expected: commit succeeds only if there were final corrections. If there were no corrections, do not create an empty commit.

---

## Self-Review

- Spec coverage: Tasks 2 and 3 implement common `FUNC_XREFS`; Task 2 covers UTF-16 string, signature, gv, and func xrefs; Task 4 adds `find-AlpcpInitSystem`, `config.yaml`, and skill doc; Task 5 covers focused verification.
- Placeholder scan: The plan contains concrete file paths, function names, code snippets, commands, and expected results.
- Type consistency: `func_xrefs` is normalized in `ida_preprocessor_common.py` to a `dict[str, dict[str, list[Any]]]`; `generic_func.preprocess_func_symbol` receives one normalized per-target dict through `func_xref`; helper payloads use `func_name`, `func_va`, and `func_rva`; final YAML keeps `func_name` and `func_rva`.
