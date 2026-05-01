# kphtools Reference YAML Generator Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 为 `kphtools` 新增一个独立 `generate_reference_yaml.py` CLI，按 `module + arch` 语义生成单函数 reference YAML，并严格对齐 `CS2_VibeSignatures` 当前 `procedure` / `disasm_code` 导出实现。

**Architecture:** 方案拆成两层。`ida_reference_export.py` 负责 CS2 对齐的 IDA `py_eval` 导出器、payload 校验与远端 YAML 落盘；`generate_reference_yaml.py` 负责 CLI 参数、当前 IDA binary 上下文解析、普通工件优先的函数地址解析，以及 MCP 会话编排。测试分成“导出器字符串级验证”和“CLI/编排级单元测试”，避免依赖真实 IDA。

**Tech Stack:** Python 3.10、`unittest`、`unittest.mock`、`asyncio`、`PyYAML`、现有 `dump_symbols.py` MCP helper、现有 `symbol_artifacts.load_artifact`

---

## File Structure

- Create: `ida_reference_export.py`
  - 放置 CS2 对齐的 `build_function_detail_export_py_eval(...)`
  - 放置 `build_remote_text_export_py_eval(...)`、reference payload 校验、remote YAML export ack 校验
- Create: `generate_reference_yaml.py`
  - 放置 CLI 参数解析、输出路径构造、当前 binary 上下文解析、函数地址解析、MCP 会话编排、`main()`
- Create: `tests/test_ida_reference_export.py`
  - 字符串级验证导出器包含 comments / chunk 回退 / code-head 补齐逻辑
  - 验证 remote YAML export ack 与 payload 校验
- Create: `tests/test_generate_reference_yaml.py`
  - 覆盖 CLI 参数、输出路径、上下文推断、函数地址解析、主流程编排
- Modify: `README.md`
  - 新增 reference YAML 用法、生成后检查点、`LLM_DECOMPILE` 接线路径说明

不计划修改：

- `dump_symbols.py`
- `symbol_artifacts.py`
- `pyproject.toml`

这些文件当前已经提供本计划所需的 MCP helper 和 YAML 工件读取能力，首版不做共享层重构。

### Task 1: CS2 对齐导出器

**Files:**
- Create: `ida_reference_export.py`
- Test: `tests/test_ida_reference_export.py`

- [ ] **Step 1: 写导出器失败测试**

在 `tests/test_ida_reference_export.py` 中写入：

```python
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import AsyncMock

import ida_reference_export


class TestIdaReferenceExport(unittest.IsolatedAsyncioTestCase):
    def test_build_function_detail_export_py_eval_contains_chunk_and_comment_logic(self) -> None:
        py_code = ida_reference_export.build_function_detail_export_py_eval(0x140001000)

        self.assertIn("idautils.Chunks(func.start_ea)", py_code)
        self.assertIn("func_tail_iterator_t", py_code)
        self.assertIn("CodeRefsFrom(ea, False)", py_code)
        self.assertIn("get_extra_cmt", py_code)
        self.assertIn("collected_eas.update(fallback_eas)", py_code)
        self.assertIn("cfunc.get_pseudocode()", py_code)

    def test_build_reference_yaml_export_py_eval_writes_yaml_and_overrides_func_name(self) -> None:
        py_code = ida_reference_export.build_reference_yaml_export_py_eval(
            0x140001000,
            output_path=Path("/tmp/ref.yaml"),
            func_name="ExReferenceCallBackBlock",
        )

        self.assertIn("payload['func_name'] = \"ExReferenceCallBackBlock\"", py_code)
        self.assertIn("format_name = 'yaml'", py_code)
        self.assertIn("yaml.dump(", py_code)
        self.assertIn("LiteralDumper", py_code)

    def test_validate_reference_yaml_payload_rejects_missing_disasm(self) -> None:
        with self.assertRaisesRegex(
            ida_reference_export.ReferenceGenerationError,
            "invalid reference YAML payload",
        ):
            ida_reference_export.validate_reference_yaml_payload(
                {
                    "func_name": "ExReferenceCallBackBlock",
                    "func_va": "0x140001000",
                    "disasm_code": "",
                    "procedure": "",
                }
            )

    async def test_export_reference_yaml_via_mcp_validates_ack_and_written_yaml(self) -> None:
        session = AsyncMock()
        with TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "ref.yaml"
            output_path.write_text(
                "\n".join(
                    [
                        "func_name: ExReferenceCallBackBlock",
                        "func_va: '0x140001000'",
                        "disasm_code: |-",
                        "  nt:140001000                 mov eax, eax",
                        "procedure: ''",
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            session.call_tool.return_value.content = [
                type(
                    "Text",
                    (),
                    {
                        "text": (
                            '{"result":"{'
                            '\\"ok\\": true, '
                            f'\\"output_path\\": \\"{output_path}\\", '
                            '\\"bytes_written\\": 120, '
                            '\\"format\\": \\"yaml\\"'
                            '}"}'
                        )
                    },
                )()
            ]

            result = await ida_reference_export.export_reference_yaml_via_mcp(
                session,
                func_name="ExReferenceCallBackBlock",
                func_va="0x140001000",
                output_path=output_path,
            )

        self.assertEqual(output_path, result)
        session.call_tool.assert_awaited_once()
```

- [ ] **Step 2: 运行测试确认当前失败**

Run:

```bash
uv run python -m unittest tests.test_ida_reference_export -v
```

Expected:

```text
ImportError: Failed to import test module: test_ida_reference_export
...
ModuleNotFoundError: No module named 'ida_reference_export'
```

- [ ] **Step 3: 实现 `ida_reference_export.py`**

创建 `ida_reference_export.py`：

```python
from __future__ import annotations

import json
import os
import textwrap
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import yaml


class ReferenceGenerationError(RuntimeError):
    pass


class LiteralDumper(yaml.SafeDumper):
    pass


def _literal_str_representer(dumper: yaml.Dumper, value: str) -> yaml.Node:
    style = "|" if "\n" in value else None
    return dumper.represent_scalar("tag:yaml.org,2002:str", value, style=style)


LiteralDumper.add_representer(str, _literal_str_representer)


def _normalize_non_empty_text(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    return text or None


def _normalize_address_text(value: Any, *, require_string: bool = False) -> str | None:
    if require_string:
        text = _normalize_non_empty_text(value)
        if text is None:
            return None
        try:
            int(text, 0)
        except (TypeError, ValueError):
            return None
        return text

    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            int(text, 0)
        except (TypeError, ValueError):
            return None
        return text

    if isinstance(value, int):
        return hex(value)

    return None


def validate_reference_yaml_payload(payload: Mapping[str, Any]) -> dict[str, str]:
    func_name = _normalize_non_empty_text(payload.get("func_name"))
    func_va = _normalize_address_text(payload.get("func_va"))
    disasm_code = _normalize_non_empty_text(payload.get("disasm_code"))
    procedure_raw = payload.get("procedure", "")

    if func_name is None or func_va is None or disasm_code is None:
        raise ReferenceGenerationError("invalid reference YAML payload")

    if procedure_raw is None:
        procedure = ""
    elif isinstance(procedure_raw, str):
        procedure = procedure_raw
    else:
        raise ReferenceGenerationError("invalid reference YAML payload")

    return {
        "func_name": func_name,
        "func_va": func_va,
        "disasm_code": disasm_code,
        "procedure": procedure,
    }


def build_remote_text_export_py_eval(
    *,
    output_path,
    producer_code,
    content_var="payload_text",
    format_name="text",
):
    output_path_str = os.fspath(output_path)
    if not os.path.isabs(output_path_str):
        raise ValueError(f"output_path must be absolute, got {output_path_str!r}")
    if not str(producer_code).strip():
        raise ValueError("producer_code cannot be empty")
    if not str(content_var).strip():
        raise ValueError("content_var cannot be empty")

    producer_block = textwrap.indent(str(producer_code).rstrip(), "    ")
    return (
        "import json, os, traceback\n"
        f"output_path = {output_path_str!r}\n"
        f"format_name = {str(format_name)!r}\n"
        "tmp_path = output_path + '.tmp'\n"
        "def _truncate_text(value, limit=800):\n"
        "    text = '' if value is None else str(value)\n"
        "    return text if len(text) <= limit else text[:limit] + ' [truncated]'\n"
        "try:\n"
        "    if not os.path.isabs(output_path):\n"
        "        raise ValueError(f'output_path must be absolute: {output_path}')\n"
        f"{producer_block}\n"
        f"    payload_text = str({content_var})\n"
        "    parent_dir = os.path.dirname(output_path)\n"
        "    if parent_dir:\n"
        "        os.makedirs(parent_dir, exist_ok=True)\n"
        "    with open(tmp_path, 'w', encoding='utf-8') as handle:\n"
        "        handle.write(payload_text)\n"
        "    os.replace(tmp_path, output_path)\n"
        "    result = json.dumps({\n"
        "        'ok': True,\n"
        "        'output_path': output_path,\n"
        "        'bytes_written': len(payload_text.encode('utf-8')),\n"
        "        'format': format_name,\n"
        "    })\n"
        "except Exception as exc:\n"
        "    try:\n"
        "        if os.path.exists(tmp_path):\n"
        "            os.unlink(tmp_path)\n"
        "    except Exception:\n"
        "        pass\n"
        "    result = json.dumps({\n"
        "        'ok': False,\n"
        "        'output_path': output_path,\n"
        "        'error': _truncate_text(exc),\n"
        "        'traceback': _truncate_text(traceback.format_exc()),\n"
        "    })\n"
    )


def build_function_detail_export_py_eval(func_va_int: int) -> str:
    return textwrap.dedent(
        fr"""
        import ida_bytes, ida_funcs, ida_lines, ida_segment, idautils, idc, json
        try:
            import ida_hexrays
        except Exception:
            ida_hexrays = None

        func_ea = {func_va_int}

        def _append_chunk_range(chunk_ranges, start_ea, end_ea):
            try:
                start_ea = int(start_ea)
                end_ea = int(end_ea)
            except Exception:
                return
            if start_ea < end_ea:
                chunk_ranges.append((start_ea, end_ea))

        def _collect_chunk_ranges(func):
            chunk_ranges = []
            try:
                initial_chunk_ranges = []
                for start_ea, end_ea in idautils.Chunks(func.start_ea):
                    _append_chunk_range(initial_chunk_ranges, start_ea, end_ea)
                chunk_ranges = initial_chunk_ranges
            except Exception:
                pass
            if not chunk_ranges:
                tail_chunk_ranges = []
                try:
                    try:
                        tail_iterator = ida_funcs.func_tail_iterator_t(func)
                    except Exception:
                        tail_iterator = ida_funcs.func_tail_iterator_t()
                        if not tail_iterator.set_ea(func.start_ea):
                            tail_iterator = None
                    if tail_iterator is not None and tail_iterator.first():
                        while True:
                            chunk = tail_iterator.chunk()
                            _append_chunk_range(
                                tail_chunk_ranges,
                                getattr(chunk, 'start_ea', None),
                                getattr(chunk, 'end_ea', None),
                            )
                            if not tail_iterator.next():
                                break
                except Exception:
                    tail_chunk_ranges = []
                if tail_chunk_ranges:
                    _append_chunk_range(
                        tail_chunk_ranges,
                        func.start_ea,
                        func.end_ea,
                    )
                    chunk_ranges = tail_chunk_ranges
            if not chunk_ranges:
                chunk_ranges = [(int(func.start_ea), int(func.end_ea))]
            return sorted(set(chunk_ranges))

        def _find_chunk_end(ea, chunk_ranges):
            for start_ea, end_ea in chunk_ranges:
                if start_ea <= ea < end_ea:
                    return end_ea
            return None

        def _is_in_chunk_ranges(ea, chunk_ranges):
            return _find_chunk_end(ea, chunk_ranges) is not None

        def _format_address(ea):
            seg = ida_segment.getseg(ea)
            seg_name = ida_segment.get_segm_name(seg) if seg else ''
            return f"{{seg_name}}:{{ea:016X}}" if seg_name else f"{{ea:016X}}"

        def _iter_comment_lines(ea):
            seen = set()
            for repeatable in (0, 1):
                try:
                    comment = idc.get_cmt(ea, repeatable)
                except Exception:
                    comment = None
                if not comment:
                    continue
                text = ida_lines.tag_remove(comment).strip()
                if text and text not in seen:
                    seen.add(text)
                    yield text

            get_extra_cmt = getattr(idc, 'get_extra_cmt', None)
            if get_extra_cmt is None:
                return

            for index in range(-10, 11):
                try:
                    comment = get_extra_cmt(ea, index)
                except Exception:
                    continue
                if not comment:
                    continue
                text = ida_lines.tag_remove(comment).strip()
                if text and text not in seen:
                    seen.add(text)
                    yield text

        def _iter_chunk_code_heads(chunk_ranges):
            for start_ea, end_ea in chunk_ranges:
                ea = int(start_ea)
                while ea != idc.BADADDR and ea < end_ea:
                    try:
                        flags = ida_bytes.get_flags(ea)
                    except Exception:
                        break
                    if ida_bytes.is_code(flags):
                        yield ea
                    try:
                        next_ea = idc.next_head(ea, end_ea)
                    except Exception:
                        break
                    if next_ea == idc.BADADDR or next_ea <= ea:
                        break
                    ea = next_ea

        def _render_disasm_lines(eas):
            lines = []
            for ea in eas:
                ea = int(ea)
                address_text = _format_address(ea)
                for comment in _iter_comment_lines(ea):
                    lines.append(f"{{address_text}}                 ; {{comment}}")
                disasm_line = ida_lines.tag_remove(idc.generate_disasm_line(ea, 0) or '').strip()
                if disasm_line:
                    lines.append(f"{{address_text}}                 {{disasm_line}}")
            return '\n'.join(lines).strip()

        def get_disasm(start_ea):
            func = ida_funcs.get_func(start_ea)
            if func is None:
                return ''

            chunk_ranges = _collect_chunk_ranges(func)
            fallback_eas = sorted(set(int(ea) for ea in _iter_chunk_code_heads(chunk_ranges)))
            if not fallback_eas:
                return ''

            try:
                pending_eas = [int(func.start_ea)]
                visited_eas = set()
                collected_eas = set()
                code_head_count = len(fallback_eas)
                max_steps = code_head_count * 4 + 256
                steps = 0

                while pending_eas and steps < max_steps:
                    ea = int(pending_eas.pop())
                    while True:
                        if not _is_in_chunk_ranges(ea, chunk_ranges):
                            break
                        flags = ida_bytes.get_flags(ea)
                        if not ida_bytes.is_code(flags):
                            break
                        if ea in visited_eas:
                            break

                        visited_eas.add(ea)
                        collected_eas.add(ea)
                        steps += 1

                        mnem = (idc.print_insn_mnem(ea) or '').lower()
                        refs = [
                            int(ref)
                            for ref in idautils.CodeRefsFrom(ea, False)
                            if _is_in_chunk_ranges(int(ref), chunk_ranges)
                        ]
                        chunk_end = _find_chunk_end(ea, chunk_ranges)
                        next_ea = idc.next_head(ea, chunk_end) if chunk_end is not None else idc.BADADDR

                        if mnem in ('ret', 'retn', 'retf', 'iret', 'iretd', 'iretq', 'int3', 'hlt', 'ud2'):
                            break
                        if mnem == 'jmp':
                            for ref in reversed(refs):
                                if ref not in visited_eas:
                                    pending_eas.append(ref)
                            break
                        if mnem.startswith('j'):
                            for ref in reversed(refs):
                                if ref not in visited_eas:
                                    pending_eas.append(ref)
                            if next_ea == idc.BADADDR or next_ea <= ea:
                                break
                            ea = int(next_ea)
                            continue
                        if next_ea == idc.BADADDR or next_ea <= ea:
                            break
                        ea = int(next_ea)

                collected_eas.update(fallback_eas)
                return _render_disasm_lines(sorted(collected_eas))
            except Exception:
                return _render_disasm_lines(fallback_eas)

        def get_pseudocode(start_ea):
            if ida_hexrays is None:
                return ''
            try:
                if not ida_hexrays.init_hexrays_plugin():
                    return ''
                cfunc = ida_hexrays.decompile(start_ea)
            except Exception:
                return ''
            if not cfunc:
                return ''
            return '\n'.join(ida_lines.tag_remove(line.line) for line in cfunc.get_pseudocode())

        globals().update(locals())

        func = ida_funcs.get_func(func_ea)
        if func is None:
            raise ValueError(f"Function not found: {{hex(func_ea)}}")

        func_start = int(func.start_ea)
        result = json.dumps(
            {{
                "func_name": ida_funcs.get_func_name(func_start) or f"sub_{{func_start:X}}",
                "func_va": hex(func_start),
                "disasm_code": get_disasm(func_start),
                "procedure": get_pseudocode(func_start),
            }}
        )
        """
    ).strip() + "\n"


def build_reference_yaml_export_py_eval(
    func_va_int: int,
    *,
    output_path: str | Path,
    func_name: str,
) -> str:
    normalized_func_name = str(func_name).strip()
    producer_code = (
        build_function_detail_export_py_eval(func_va_int).rstrip()
        + "\n"
        + "payload = json.loads(result)\n"
        + f"payload['func_name'] = {json.dumps(normalized_func_name)}\n"
        + "import yaml\n"
        + "class LiteralDumper(yaml.SafeDumper):\n"
        + "    pass\n"
        + "def _literal_str_representer(dumper, value):\n"
        + "    style = '|' if '\\n' in value else None\n"
        + "    return dumper.represent_scalar('tag:yaml.org,2002:str', value, style=style)\n"
        + "LiteralDumper.add_representer(str, _literal_str_representer)\n"
        + "payload_text = yaml.dump(\n"
        + "    payload,\n"
        + "    Dumper=LiteralDumper,\n"
        + "    sort_keys=False,\n"
        + "    allow_unicode=True,\n"
        + ")\n"
    )
    return build_remote_text_export_py_eval(
        output_path=output_path,
        producer_code=producer_code,
        content_var="payload_text",
        format_name="yaml",
    )


def _parse_py_eval_json_result(result: Any) -> dict[str, Any] | None:
    content = getattr(result, "content", None)
    if not content:
        return None
    item = content[0]
    raw = getattr(item, "text", None)
    if not isinstance(raw, str):
        raw = str(item)
    try:
        payload = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(payload, dict):
        return None
    result_text = payload.get("result", "")
    if not isinstance(result_text, str) or not result_text:
        return None
    try:
        parsed = json.loads(result_text)
    except (json.JSONDecodeError, TypeError):
        return None
    return parsed if isinstance(parsed, dict) else None


def _is_valid_remote_export_ack(
    export_ack: Any,
    *,
    output_path: str | Path,
    format_name: str,
) -> bool:
    if not isinstance(export_ack, Mapping):
        return False
    if not bool(export_ack.get("ok")):
        return False
    if str(export_ack.get("output_path", "")).strip() != os.fspath(output_path):
        return False
    if str(export_ack.get("format", "")).strip() != format_name:
        return False
    try:
        bytes_written = int(export_ack.get("bytes_written"))
    except (TypeError, ValueError):
        return False
    return bytes_written >= 0


async def export_reference_yaml_via_mcp(
    session: Any,
    *,
    func_name: str,
    func_va: str,
    output_path: str | Path,
    debug: bool = False,
) -> Path:
    del debug
    normalized_input_func_va = _normalize_address_text(func_va)
    if normalized_input_func_va is None:
        raise ReferenceGenerationError("unable to export reference YAML via IDA")

    resolved_output_path = Path(output_path).resolve()
    func_va_int = int(normalized_input_func_va, 0)

    try:
        py_code = build_reference_yaml_export_py_eval(
            func_va_int,
            output_path=resolved_output_path,
            func_name=func_name,
        )
        eval_result = await session.call_tool(
            name="py_eval",
            arguments={"code": py_code},
        )
        export_ack = _parse_py_eval_json_result(eval_result)
    except Exception as exc:
        raise ReferenceGenerationError("unable to export reference YAML via IDA") from exc

    if not _is_valid_remote_export_ack(
        export_ack,
        output_path=resolved_output_path,
        format_name="yaml",
    ):
        raise ReferenceGenerationError("unable to export reference YAML via IDA")

    try:
        payload = yaml.safe_load(resolved_output_path.read_text(encoding="utf-8")) or {}
        validate_reference_yaml_payload(payload)
    except Exception as exc:
        raise ReferenceGenerationError("unable to export reference YAML via IDA") from exc

    return resolved_output_path
```

- [ ] **Step 4: 运行测试确认通过**

Run:

```bash
uv run python -m unittest tests.test_ida_reference_export -v
```

Expected:

```text
test_build_function_detail_export_py_eval_contains_chunk_and_comment_logic ... ok
test_build_reference_yaml_export_py_eval_writes_yaml_and_overrides_func_name ... ok
test_validate_reference_yaml_payload_rejects_missing_disasm ... ok
test_export_reference_yaml_via_mcp_validates_ack_and_written_yaml ... ok
```

- [ ] **Step 5: 提交**

```bash
git add ida_reference_export.py tests/test_ida_reference_export.py
git commit -m "feat(reference): 添加CS2导出辅助模块"
```

### Task 2: CLI 骨架与输出路径

**Files:**
- Create: `generate_reference_yaml.py`
- Test: `tests/test_generate_reference_yaml.py`

- [ ] **Step 1: 写 CLI 骨架失败测试**

在 `tests/test_generate_reference_yaml.py` 中写入：

```python
from pathlib import Path
import unittest

import generate_reference_yaml


class TestGenerateReferenceYaml(unittest.TestCase):
    def test_parse_args_requires_binary_for_auto_start(self) -> None:
        with self.assertRaises(SystemExit):
            generate_reference_yaml.parse_args(
                ["-func_name", "ExReferenceCallBackBlock", "-auto_start_mcp"]
            )

    def test_parse_args_requires_auto_start_for_binary(self) -> None:
        with self.assertRaises(SystemExit):
            generate_reference_yaml.parse_args(
                [
                    "-func_name",
                    "ExReferenceCallBackBlock",
                    "-binary",
                    "symbols/amd64/ntoskrnl.exe.10.0.1/hash/ntoskrnl.exe",
                ]
            )

    def test_build_reference_output_path_uses_module_and_arch(self) -> None:
        path = generate_reference_yaml.build_reference_output_path(
            Path("/repo"),
            module="ntoskrnl",
            func_name="ExReferenceCallBackBlock",
            arch="amd64",
        )

        self.assertEqual(
            Path("/repo")
            / "ida_preprocessor_scripts"
            / "references"
            / "ntoskrnl"
            / "ExReferenceCallBackBlock.amd64.yaml",
            path,
        )
```

- [ ] **Step 2: 运行测试确认当前失败**

Run:

```bash
uv run python -m unittest tests.test_generate_reference_yaml.TestGenerateReferenceYaml -v
```

Expected:

```text
ImportError: Failed to import test module: test_generate_reference_yaml
...
ModuleNotFoundError: No module named 'generate_reference_yaml'
```

- [ ] **Step 3: 实现 CLI 骨架**

创建 `generate_reference_yaml.py`：

```python
#!/usr/bin/env python3

from __future__ import annotations

import argparse
from collections.abc import Sequence
from pathlib import Path

from ida_reference_export import ReferenceGenerationError


SUPPORTED_ARCHES = ("amd64", "arm64")


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate reference YAML for kphtools LLM_DECOMPILE workflows",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("-func_name", required=True, help="Canonical function name")
    parser.add_argument("-module", default=None, help="Module name override")
    parser.add_argument("-arch", choices=SUPPORTED_ARCHES, default=None, help="Architecture override")
    parser.add_argument("-mcp_host", default="127.0.0.1", help="MCP host")
    parser.add_argument("-mcp_port", type=int, default=13337, help="MCP port")
    parser.add_argument("-debug", action="store_true", help="Enable debug output")
    parser.add_argument("-binary", default=None, help="Binary path for auto-start mode")
    parser.add_argument(
        "-auto_start_mcp",
        action="store_true",
        help="Start idalib-mcp automatically; must be used with -binary",
    )

    args = parser.parse_args(argv)
    if args.auto_start_mcp and not args.binary:
        parser.error("-auto_start_mcp requires -binary")
    if args.binary and not args.auto_start_mcp:
        parser.error("-binary requires -auto_start_mcp")
    return args


def build_reference_output_path(
    repo_root: str | Path,
    *,
    module: str,
    func_name: str,
    arch: str,
) -> Path:
    normalized_module = str(module).strip()
    normalized_func_name = str(func_name).strip()
    normalized_arch = str(arch).strip().lower()
    if not normalized_module or not normalized_func_name or normalized_arch not in SUPPORTED_ARCHES:
        raise ReferenceGenerationError("invalid reference output target")
    return (
        Path(repo_root)
        / "ida_preprocessor_scripts"
        / "references"
        / normalized_module
        / f"{normalized_func_name}.{normalized_arch}.yaml"
    )
```

- [ ] **Step 4: 运行测试确认通过**

Run:

```bash
uv run python -m unittest tests.test_generate_reference_yaml.TestGenerateReferenceYaml -v
```

Expected:

```text
test_parse_args_requires_binary_for_auto_start ... ok
test_parse_args_requires_auto_start_for_binary ... ok
test_build_reference_output_path_uses_module_and_arch ... ok
```

- [ ] **Step 5: 提交**

```bash
git add generate_reference_yaml.py tests/test_generate_reference_yaml.py
git commit -m "feat(reference): 添加reference yaml命令行骨架"
```

### Task 3: 当前 binary 上下文解析

**Files:**
- Modify: `generate_reference_yaml.py`
- Modify: `tests/test_generate_reference_yaml.py`

- [ ] **Step 1: 写上下文解析失败测试**

在 `tests/test_generate_reference_yaml.py` 追加：

```python
from tempfile import TemporaryDirectory
import textwrap


class TestGenerateReferenceYamlContext(unittest.TestCase):
    def test_infer_context_from_binary_path_uses_arch_and_module_from_symbol_dir(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            binary_dir = root / "symbols" / "amd64" / "ntoskrnl.exe.10.0.26100.1" / "deadbeef"
            binary_dir.mkdir(parents=True)
            (binary_dir / "ntoskrnl.exe").write_text("", encoding="utf-8")
            config_path = root / "config.yaml"
            config_path.write_text(
                textwrap.dedent(
                    """
                    modules:
                      - name: ntoskrnl
                        path: [ntoskrnl.exe, ntkrla57.exe]
                        skills:
                          - name: find-ExReferenceCallBackBlock
                            symbol: ExReferenceCallBackBlock
                            expected_output: [ExReferenceCallBackBlock.yaml]
                        symbols:
                          - name: ExReferenceCallBackBlock
                            category: func
                            data_type: uint32
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )

            context = generate_reference_yaml.infer_context_from_binary_path(
                binary_dir / "ntoskrnl.exe.i64",
                config_path=config_path,
            )

        self.assertEqual("amd64", context["arch"])
        self.assertEqual("ntoskrnl", context["module"])
        self.assertEqual(binary_dir, context["binary_dir"])
        self.assertEqual(binary_dir / "ntoskrnl.exe", context["binary_path"])

    def test_infer_context_from_binary_path_rejects_unknown_arch(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            binary_path = root / "symbols" / "x64" / "ntoskrnl.exe.10.0.1" / "deadbeef" / "ntoskrnl.exe.i64"
            binary_path.parent.mkdir(parents=True)

            with self.assertRaisesRegex(
                generate_reference_yaml.ReferenceGenerationError,
                "unable to infer arch",
            ):
                generate_reference_yaml.infer_context_from_binary_path(
                    binary_path,
                    config_path=root / "config.yaml",
                )
```

- [ ] **Step 2: 运行测试确认当前失败**

Run:

```bash
uv run python -m unittest tests.test_generate_reference_yaml.TestGenerateReferenceYamlContext -v
```

Expected:

```text
AttributeError: module 'generate_reference_yaml' has no attribute 'infer_context_from_binary_path'
```

- [ ] **Step 3: 实现上下文解析**

在 `generate_reference_yaml.py` 中追加：

```python
from typing import Any

from dump_symbols import _resolve_binary_path
from symbol_config import load_config


def _find_arch_from_path(binary_path: Path) -> str:
    for part in reversed(binary_path.parts):
        lowered = str(part).lower()
        if lowered in SUPPORTED_ARCHES:
            return lowered
    raise ReferenceGenerationError("unable to infer arch from binary path")


def _match_module_spec(config: Any, binary_dir: Path, version_dir_name: str):
    matches = []
    for module in config.modules:
        if any((binary_dir / candidate).exists() for candidate in module.path):
            matches.append(module)
            continue
        for candidate in module.path:
            if version_dir_name.lower().startswith(f"{candidate.lower()}."):
                matches.append(module)
                break
    if len(matches) != 1:
        raise ReferenceGenerationError("unable to infer module from binary path")
    return matches[0]


def infer_context_from_binary_path(
    binary_hint_path: str | Path,
    *,
    config_path: str | Path = "config.yaml",
    module: str | None = None,
    arch: str | None = None,
) -> dict[str, Any]:
    resolved_hint = Path(binary_hint_path).resolve(strict=False)
    binary_dir = resolved_hint.parent
    version_dir = binary_dir.parent

    resolved_arch = arch.lower() if isinstance(arch, str) and arch.strip() else _find_arch_from_path(resolved_hint)
    if resolved_arch not in SUPPORTED_ARCHES:
        raise ReferenceGenerationError("unable to infer arch from binary path")

    config = load_config(config_path)
    matched_module = _match_module_spec(config, binary_dir, version_dir.name)
    resolved_module_name = module.strip() if isinstance(module, str) and module.strip() else matched_module.name
    if resolved_module_name != matched_module.name:
        raise ReferenceGenerationError("module override does not match current binary directory")

    resolved_binary_path = _resolve_binary_path(matched_module, binary_dir)
    return {
        "arch": resolved_arch,
        "module": resolved_module_name,
        "binary_dir": binary_dir,
        "binary_path": resolved_binary_path,
        "module_spec": matched_module,
    }
```

- [ ] **Step 4: 运行测试确认通过**

Run:

```bash
uv run python -m unittest tests.test_generate_reference_yaml.TestGenerateReferenceYamlContext -v
```

Expected:

```text
test_infer_context_from_binary_path_uses_arch_and_module_from_symbol_dir ... ok
test_infer_context_from_binary_path_rejects_unknown_arch ... ok
```

- [ ] **Step 5: 提交**

```bash
git add generate_reference_yaml.py tests/test_generate_reference_yaml.py
git commit -m "feat(reference): 添加binary上下文解析逻辑"
```

### Task 4: 普通工件优先的函数地址解析

**Files:**
- Modify: `generate_reference_yaml.py`
- Modify: `tests/test_generate_reference_yaml.py`

- [ ] **Step 1: 写函数地址解析失败测试**

在 `tests/test_generate_reference_yaml.py` 追加：

```python
from unittest.mock import AsyncMock


class TestGenerateReferenceYamlResolution(unittest.IsolatedAsyncioTestCase):
    async def test_resolve_func_va_prefers_existing_func_va(self) -> None:
        with TemporaryDirectory() as temp_dir:
            binary_dir = Path(temp_dir)
            (binary_dir / "ExReferenceCallBackBlock.yaml").write_text(
                "category: func\nfunc_name: ExReferenceCallBackBlock\nfunc_va: '0x140001234'\n",
                encoding="utf-8",
            )

            func_va = await generate_reference_yaml.resolve_func_va(
                session=AsyncMock(),
                binary_dir=binary_dir,
                func_name="ExReferenceCallBackBlock",
            )

        self.assertEqual("0x140001234", func_va)

    async def test_resolve_func_va_builds_va_from_func_rva(self) -> None:
        with TemporaryDirectory() as temp_dir:
            binary_dir = Path(temp_dir)
            (binary_dir / "ExReferenceCallBackBlock.yaml").write_text(
                "category: func\nfunc_name: ExReferenceCallBackBlock\nfunc_rva: '0x1234'\n",
                encoding="utf-8",
            )
            session = AsyncMock()
            session.call_tool.return_value.content = [
                type("Text", (), {"text": '{"result":"{\\"image_base\\": \\"0x140000000\\"}"}'})()
            ]

            func_va = await generate_reference_yaml.resolve_func_va(
                session=session,
                binary_dir=binary_dir,
                func_name="ExReferenceCallBackBlock",
            )

        self.assertEqual("0x140001234", func_va)

    async def test_resolve_func_va_falls_back_to_ida_exact_name(self) -> None:
        session = AsyncMock()
        session.call_tool.return_value.content = [
            type(
                "Text",
                (),
                {"text": '{"result":"{\\"matches\\": {\\"0x140004321\\": [\\"ExReferenceCallBackBlock\\"]}}"}'},
            )()
        ]

        func_va = await generate_reference_yaml.resolve_func_va(
            session=session,
            binary_dir=Path("/tmp/missing"),
            func_name="ExReferenceCallBackBlock",
        )

        self.assertEqual("0x140004321", func_va)

    async def test_resolve_func_va_rejects_multiple_unique_matches(self) -> None:
        session = AsyncMock()
        session.call_tool.return_value.content = [
            type(
                "Text",
                (),
                {
                    "text": (
                        '{"result":"{'
                        '\\"matches\\": {'
                        '\\"0x140004321\\": [\\"ExReferenceCallBackBlock\\"], '
                        '\\"0x140004555\\": [\\"ExReferenceCallBackBlock\\"]'
                        '}}"}'
                    )
                },
            )()
        ]

        with self.assertRaisesRegex(
            generate_reference_yaml.ReferenceGenerationError,
            "multiple function addresses",
        ):
            await generate_reference_yaml.resolve_func_va(
                session=session,
                binary_dir=Path("/tmp/missing"),
                func_name="ExReferenceCallBackBlock",
            )
```

- [ ] **Step 2: 运行测试确认当前失败**

Run:

```bash
uv run python -m unittest tests.test_generate_reference_yaml.TestGenerateReferenceYamlResolution -v
```

Expected:

```text
AttributeError: module 'generate_reference_yaml' has no attribute 'resolve_func_va'
```

- [ ] **Step 3: 实现函数地址解析**

在 `generate_reference_yaml.py` 中追加：

```python
import json

from dump_symbols import _parse_py_eval_result_json
from symbol_artifacts import load_artifact


def _load_existing_func_artifact(binary_dir: Path, func_name: str) -> dict[str, Any] | None:
    artifact_path = binary_dir / f"{func_name}.yaml"
    if not artifact_path.exists():
        return None
    payload = load_artifact(artifact_path)
    return payload if isinstance(payload, dict) else None


async def _fetch_image_base(session) -> int:
    result = await session.call_tool(
        name="py_eval",
        arguments={
            "code": (
                "import ida_nalt, json\n"
                "result = json.dumps({'image_base': hex(int(ida_nalt.get_imagebase()))})\n"
            )
        },
    )
    payload = _parse_py_eval_result_json(result)
    if not isinstance(payload, dict):
        raise ReferenceGenerationError("unable to resolve image base")
    image_base = payload.get("image_base")
    if not isinstance(image_base, str):
        raise ReferenceGenerationError("unable to resolve image base")
    return int(image_base, 0)


async def _lookup_function_starts_by_name(session, candidate_names: list[str]) -> list[int]:
    py_code = (
        "import ida_funcs, idc, json\n"
        f"candidate_names = {candidate_names!r}\n"
        "matches = {}\n"
        "for name in candidate_names:\n"
        "    ea = idc.get_name_ea_simple(name)\n"
        "    if ea == idc.BADADDR:\n"
        "        continue\n"
        "    func = ida_funcs.get_func(ea)\n"
        "    if func is None:\n"
        "        continue\n"
        "    matches.setdefault(hex(int(func.start_ea)), []).append(name)\n"
        "result = json.dumps({'matches': matches})\n"
    )
    result = await session.call_tool(name="py_eval", arguments={"code": py_code})
    payload = _parse_py_eval_result_json(result)
    if not isinstance(payload, dict):
        return []
    matches = payload.get("matches", {})
    if not isinstance(matches, dict):
        return []
    return sorted({int(ea_text, 0) for ea_text in matches})


async def resolve_func_va(
    *,
    session,
    binary_dir: Path,
    func_name: str,
) -> str:
    artifact = _load_existing_func_artifact(binary_dir, func_name)
    if artifact is not None:
        existing_func_va = artifact.get("func_va")
        if isinstance(existing_func_va, int):
            return hex(existing_func_va)
        if isinstance(existing_func_va, str) and existing_func_va.strip():
            return existing_func_va.strip()

        existing_func_rva = artifact.get("func_rva")
        if isinstance(existing_func_rva, int):
            image_base = await _fetch_image_base(session)
            return hex(image_base + existing_func_rva)

    matches = await _lookup_function_starts_by_name(session, [func_name])
    if not matches:
        raise ReferenceGenerationError(f"unable to resolve function address for {func_name}")
    if len(matches) != 1:
        raise ReferenceGenerationError(f"multiple function addresses resolved for {func_name}")
    return hex(matches[0])
```

- [ ] **Step 4: 运行测试确认通过**

Run:

```bash
uv run python -m unittest tests.test_generate_reference_yaml.TestGenerateReferenceYamlResolution -v
```

Expected:

```text
test_resolve_func_va_prefers_existing_func_va ... ok
test_resolve_func_va_builds_va_from_func_rva ... ok
test_resolve_func_va_falls_back_to_ida_exact_name ... ok
test_resolve_func_va_rejects_multiple_unique_matches ... ok
```

- [ ] **Step 5: 提交**

```bash
git add generate_reference_yaml.py tests/test_generate_reference_yaml.py
git commit -m "feat(reference): 添加函数地址解析逻辑"
```

### Task 5: MCP 编排、主流程与 README

**Files:**
- Modify: `generate_reference_yaml.py`
- Modify: `tests/test_generate_reference_yaml.py`
- Modify: `README.md`

- [ ] **Step 1: 写主流程失败测试**

在 `tests/test_generate_reference_yaml.py` 追加：

```python
from contextlib import asynccontextmanager
from io import StringIO
from unittest.mock import patch


class TestGenerateReferenceYamlWorkflow(unittest.IsolatedAsyncioTestCase):
    async def test_run_reference_generation_attach_mode_exports_yaml(self) -> None:
        fake_session = AsyncMock()

        @asynccontextmanager
        async def fake_attach_existing_mcp_session(host: str, port: int, debug: bool):
            self.assertEqual("127.0.0.1", host)
            self.assertEqual(13337, port)
            self.assertFalse(debug)
            yield fake_session

        args = generate_reference_yaml.parse_args(["-func_name", "ExReferenceCallBackBlock"])

        with (
            patch.object(
                generate_reference_yaml,
                "attach_existing_mcp_session",
                fake_attach_existing_mcp_session,
            ),
            patch.object(
                generate_reference_yaml,
                "survey_current_binary_path",
                AsyncMock(return_value=Path("/repo/symbols/amd64/ntoskrnl.exe.10.0.1/hash/ntoskrnl.exe.i64")),
            ),
            patch.object(
                generate_reference_yaml,
                "infer_context_from_binary_path",
                return_value={
                    "module": "ntoskrnl",
                    "arch": "amd64",
                    "binary_dir": Path("/repo/symbols/amd64/ntoskrnl.exe.10.0.1/hash"),
                    "binary_path": Path("/repo/symbols/amd64/ntoskrnl.exe.10.0.1/hash/ntoskrnl.exe"),
                    "module_spec": object(),
                },
            ),
            patch.object(
                generate_reference_yaml,
                "resolve_func_va",
                AsyncMock(return_value="0x140001234"),
            ),
            patch(
                "generate_reference_yaml.export_reference_yaml_via_mcp",
                AsyncMock(return_value=Path("/repo/ida_preprocessor_scripts/references/ntoskrnl/ExReferenceCallBackBlock.amd64.yaml")),
            ) as mock_export,
        ):
            output_path = await generate_reference_yaml.run_reference_generation(args)

        self.assertEqual(
            Path("/repo/ida_preprocessor_scripts/references/ntoskrnl/ExReferenceCallBackBlock.amd64.yaml"),
            output_path,
        )
        mock_export.assert_awaited_once()

    def test_main_prints_generated_path(self) -> None:
        stdout = StringIO()
        with (
            patch.object(
                generate_reference_yaml,
                "run_reference_generation",
                AsyncMock(return_value=Path("/repo/out.yaml")),
            ),
            patch("sys.stdout", stdout),
        ):
            exit_code = generate_reference_yaml.main(["-func_name", "ExReferenceCallBackBlock"])

        self.assertEqual(0, exit_code)
        self.assertIn("/repo/out.yaml", stdout.getvalue())
```

- [ ] **Step 2: 运行测试确认当前失败**

Run:

```bash
uv run python -m unittest tests.test_generate_reference_yaml.TestGenerateReferenceYamlWorkflow -v
```

Expected:

```text
AttributeError: module 'generate_reference_yaml' has no attribute 'run_reference_generation'
```

- [ ] **Step 3: 实现 MCP 编排与主流程**

在 `generate_reference_yaml.py` 中追加：

```python
import asyncio
import subprocess
import sys
from contextlib import asynccontextmanager

import dump_symbols
from ida_reference_export import export_reference_yaml_via_mcp


async def survey_current_binary_path(session) -> Path:
    result = await session.call_tool(
        name="py_eval",
        arguments={"code": dump_symbols.SURVEY_CURRENT_IDB_PATH_PY_EVAL},
    )
    payload = dump_symbols._parse_py_eval_result_json(result)
    if not isinstance(payload, dict):
        raise ReferenceGenerationError("failed to survey current IDA binary")
    metadata = payload.get("metadata")
    if not isinstance(metadata, dict):
        raise ReferenceGenerationError("failed to survey current IDA binary")
    raw_path = metadata.get("path")
    if not isinstance(raw_path, str) or not raw_path.strip():
        raise ReferenceGenerationError("failed to survey current IDA binary")
    return Path(raw_path).resolve(strict=False)


@asynccontextmanager
async def attach_existing_mcp_session(host: str, port: int, debug: bool):
    streams, session = await dump_symbols._open_session(f"http://{host}:{port}/mcp", debug=debug)
    try:
        yield session
    finally:
        await session.__aexit__(None, None, None)
        await streams.__aexit__(None, None, None)


@asynccontextmanager
async def autostart_mcp_session(binary_path: Path, host: str, port: int, debug: bool):
    process = dump_symbols.start_idalib_mcp(binary_path, host=host, port=port, debug=debug)
    streams = None
    session = None
    try:
        streams, session = await dump_symbols._open_session(f"http://{host}:{port}/mcp", debug=debug)
        if not await dump_symbols._session_matches_binary(session, binary_path):
            raise ReferenceGenerationError(f"MCP session target mismatch for {binary_path}")
        yield session
    finally:
        if session is not None:
            try:
                await asyncio.wait_for(
                    session.call_tool(
                        name="py_eval",
                        arguments={"code": "import idc; idc.qexit(0)"},
                    ),
                    timeout=dump_symbols.IDALIB_QEXIT_TIMEOUT_SECONDS,
                )
            except Exception:
                pass
            await session.__aexit__(None, None, None)
        if streams is not None:
            await streams.__aexit__(None, None, None)
        if process.poll() is None:
            try:
                await asyncio.to_thread(process.wait, timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                await asyncio.to_thread(process.wait, timeout=1)


async def run_reference_generation(args: argparse.Namespace) -> Path:
    session_cm = (
        autostart_mcp_session(Path(args.binary), args.mcp_host, args.mcp_port, args.debug)
        if args.auto_start_mcp
        else attach_existing_mcp_session(args.mcp_host, args.mcp_port, args.debug)
    )
    async with session_cm as session:
        binary_hint_path = (
            Path(args.binary).resolve(strict=False)
            if args.auto_start_mcp
            else await survey_current_binary_path(session)
        )
        context = infer_context_from_binary_path(
            binary_hint_path,
            config_path="config.yaml",
            module=args.module,
            arch=args.arch,
        )
        func_va = await resolve_func_va(
            session=session,
            binary_dir=context["binary_dir"],
            func_name=args.func_name,
        )
        output_path = build_reference_output_path(
            Path.cwd(),
            module=context["module"],
            func_name=args.func_name,
            arch=context["arch"],
        )
        return await export_reference_yaml_via_mcp(
            session,
            func_name=args.func_name,
            func_va=func_va,
            output_path=output_path,
            debug=args.debug,
        )


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = parse_args(argv)
        output_path = asyncio.run(run_reference_generation(args))
    except ReferenceGenerationError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(f"Generated reference YAML: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

在 `README.md` 的 “Dump YAML artifacts” 段落之后追加：

````md
## Generate reference YAML for LLM_DECOMPILE

`generate_reference_yaml.py` creates a single reference YAML at:

`ida_preprocessor_scripts/references/<module>/<func_name>.<arch>.yaml`

Attach to an existing MCP session:

```bash
uv run python generate_reference_yaml.py -func_name="ExReferenceCallBackBlock"
```

Auto-start `idalib-mcp` for a specific binary:

```bash
uv run python generate_reference_yaml.py \
  -func_name="ExReferenceCallBackBlock" \
  -auto_start_mcp \
  -binary="symbols/amd64/ntoskrnl.exe.10.0.26100.1/deadbeef/ntoskrnl.exe"
```

Check the generated YAML:

- `func_va` is credible
- `disasm_code` is non-empty and includes any available comments
- `disasm_code` includes discontinuous function chunks when IDA associates them with the same function
- `procedure` is present; it may be an empty string if Hex-Rays is unavailable
````

- [ ] **Step 4: 运行定向测试确认通过**

Run:

```bash
uv run python -m unittest tests.test_generate_reference_yaml -v
```

Expected:

```text
test_parse_args_requires_binary_for_auto_start ... ok
test_parse_args_requires_auto_start_for_binary ... ok
test_build_reference_output_path_uses_module_and_arch ... ok
test_infer_context_from_binary_path_uses_arch_and_module_from_symbol_dir ... ok
test_infer_context_from_binary_path_rejects_unknown_arch ... ok
test_resolve_func_va_prefers_existing_func_va ... ok
test_resolve_func_va_builds_va_from_func_rva ... ok
test_resolve_func_va_falls_back_to_ida_exact_name ... ok
test_resolve_func_va_rejects_multiple_unique_matches ... ok
test_run_reference_generation_attach_mode_exports_yaml ... ok
test_main_prints_generated_path ... ok
```

- [ ] **Step 5: 提交**

```bash
git add generate_reference_yaml.py tests/test_generate_reference_yaml.py README.md
git commit -m "feat(reference): 串联reference yaml生成流程"
```
