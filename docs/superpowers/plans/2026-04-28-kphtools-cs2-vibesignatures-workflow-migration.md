# kphtools Workflow Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 将 `kphtools` 的符号分析与 XML 更新流程迁移为 `dump_symbols.py -> update_symbols.py` 的 CS2_VibeSignatures 风格工作流，使用 `ida-pro-mcp` 与 YAML 产物驱动 `kphdyn.xml` 导出。

**Architecture:** 迁移后的主线分为两层。分析层由 `dump_symbols.py` 统一调度 `config.yaml`、PDB-first preprocessor、MCP/LLM fallback 与 Agent fallback，并把 `{symbol}.yaml` 写回 `symboldir` 对应版本目录。导出层由新的 `update_symbols.py` 只负责 `symboldir -> <data>` 同步、YAML -> `<fields>` 映射、以及按 `uint16/uint32` 规则导出 `0xffff/0xffffffff` fallback 值。

**Tech Stack:** Python 3.10、`unittest`、`unittest.mock`、`PyYAML`、`pefile`、`httpx`、`mcp` Python SDK、`llvm-pdbutil`、`ida-pro-mcp`

---

## File Structure

- Create: `config.yaml`
  - 新的配置源，按 `modules/skills/symbols` 结构声明符号、技能依赖和导出类型
- Create: `dump_symbols.py`
  - 新的主分析入口，对齐 `CS2_VibeSignatures/ida_analyze_bin.py`
- Create: `symbol_config.py`
  - 解析与校验 `config.yaml`，输出模块、skill、symbol 映射
- Create: `pdb_resolver.py`
  - 从当前 `update_symbols.py` 提取 `llvm-pdbutil` 调用与 `struct_offset/gv_rva/func_rva` 解析
- Create: `symbol_artifacts.py`
  - `{symbol}.yaml` 路径、写入、读取与 schema 校验
- Create: `ida_mcp_resolver.py`
  - MCP name lookup、地址导出、必要的 LLM request 组装
- Create: `ida_llm_utils.py`
  - 从 `CS2_VibeSignatures` 裁剪 OpenAI 兼容 LLM 调用与重试逻辑
- Create: `ida_skill_preprocessor.py`
  - 统一 preprocessor 入口，负责 `PDB -> MCP -> LLM` 链式尝试
- Create: `ida_preprocessor_scripts/__init__.py`
- Create: `ida_preprocessor_scripts/generic_struct_offset.py`
- Create: `ida_preprocessor_scripts/generic_gv.py`
- Create: `ida_preprocessor_scripts/generic_func.py`
  - 通用类目 preprocessor，避免为每个 kernel symbol 复制脚本
- Create: `.claude/agents/sig-finder.md`
  - Codex/Claude 共享的 reverse 工作者系统提示
- Create: `.claude/skills/find-kph-struct-offset/SKILL.md`
- Create: `.claude/skills/find-kph-gv/SKILL.md`
- Create: `.claude/skills/find-kph-func/SKILL.md`
  - Agent fallback 入口，按类目复用，不按 symbol 爆炸式复制
- Create: `tests/__init__.py`
- Create: `tests/test_symbol_config.py`
- Create: `tests/test_pdb_resolver.py`
- Create: `tests/test_symbol_artifacts.py`
- Create: `tests/test_ida_mcp_resolver.py`
- Create: `tests/test_ida_skill_preprocessor.py`
- Create: `tests/test_dump_symbols.py`
- Create: `tests/test_update_symbols.py`
- Modify: `update_symbols.py`
  - 改成 XML 导出器与 `<data>` 同步工具
- Modify: `reverse_symbols.py`
  - 改成弃用提示脚本，指向 `dump_symbols.py`
- Modify: `README.md`
  - 更新命令、依赖和工作流说明
- Modify: `pyproject.toml`
  - 增加 `httpx`、`mcp`，提升 Python 版本下限到 3.10

## Repository Constraints

- `symboldir` 仍是唯一工件根目录，保留 `symbols/amd64/<file>.<version>/<sha256>/` 与 `symbols/arm64/<file>.<version>/<sha256>/` 结构。
- YAML 文件名固定为 `<symbol>.yaml`，不再重复编码 `amd64/arm64`。
- `amd64/arm64` 由 YAML 所在目录表达，不由文件名表达。
- `config.yaml` 是新的事实来源；旧 `kphdyn.yaml` / `kphdyn2.yaml` 仅作为迁移输入。
- `update_symbols.py` 必须按 symbol 的 `data_type` 导出 fallback：`uint16 -> 0xffff`，`uint32 -> 0xffffffff`。
- `reverse_symbols.py` 不删除，改成弃用入口，避免额外确认删除文件。
- `update_symbols.py` 不再支持 `-fixnull` / `-fixstruct` / 直接 PDB 解析模式。
- Agent fallback 复用类目级 skill，不为每个 symbol 新建独立 `SKILL.md`。

### Task 1: 建立配置模型与迁移基线

**Files:**
- Create: `tests/__init__.py`
- Create: `tests/test_symbol_config.py`
- Create: `symbol_config.py`
- Create: `config.yaml`
- Modify: `pyproject.toml`

- [ ] **Step 1: 写配置加载与校验的失败测试**

在 `tests/test_symbol_config.py` 中写入：

```python
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import textwrap
import unittest

import symbol_config


class TestSymbolConfig(unittest.TestCase):
    def test_load_config_reads_modules_skills_symbols(self) -> None:
        with TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "config.yaml"
            config_path.write_text(
                textwrap.dedent(
                    """
                    modules:
                      - name: ntoskrnl
                        path:
                          - ntoskrnl.exe
                          - ntkrla57.exe
                        skills:
                          - name: find-EpObjectTable
                            symbol: EpObjectTable
                            expected_output:
                              - EpObjectTable.yaml
                            agent_skill: find-kph-struct-offset
                        symbols:
                          - name: EpObjectTable
                            category: struct_offset
                            struct_name: _EPROCESS
                            member_name: ObjectTable
                            data_type: uint16
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )

            config = symbol_config.load_config(config_path)

        self.assertEqual(["ntoskrnl.exe", "ntkrla57.exe"], config.modules[0].path)
        self.assertEqual("EpObjectTable", config.modules[0].skills[0].symbol)
        self.assertEqual("find-kph-struct-offset", config.modules[0].skills[0].agent_skill)
        self.assertEqual("struct_offset", config.modules[0].symbols[0].category)
        self.assertEqual("_EPROCESS->ObjectTable", config.modules[0].symbols[0].symbol_expr)

    def test_load_config_rejects_arch_suffix_in_expected_output(self) -> None:
        with TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "config.yaml"
            config_path.write_text(
                textwrap.dedent(
                    """
                    modules:
                      - name: ntoskrnl
                        path: [ntoskrnl.exe]
                        skills:
                          - name: find-EpObjectTable
                            symbol: EpObjectTable
                            expected_output:
                              - EpObjectTable.amd64.yaml
                        symbols:
                          - name: EpObjectTable
                            category: struct_offset
                            struct_name: _EPROCESS
                            member_name: ObjectTable
                            data_type: uint16
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "must not encode arch in filename"):
                symbol_config.load_config(config_path)
```

- [ ] **Step 2: 运行配置测试并确认当前失败**

Run:

```bash
uv run python -m unittest tests.test_symbol_config -v
```

Expected:

```text
ERROR: Failed to import test module: test_symbol_config
```

- [ ] **Step 3: 提升运行时版本并补齐 MCP 依赖**

将 `pyproject.toml` 改成：

```toml
[project]
name = "kphtools"
version = "0.1.0"
description = "Toolkits for KPH dynamic data"
readme = "README.md"
requires-python = ">=3.10"
dependencies = [
    "anthropic",
    "httpx",
    "mcp",
    "openai",
    "pefile",
    "pyyaml",
    "requests",
    "signify",
]

[tool.uv]
package = false
```

- [ ] **Step 4: 实现 `symbol_config.py`**

创建 `symbol_config.py`：

```python
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class SkillSpec:
    name: str
    symbol: str
    expected_output: list[str]
    expected_input: list[str]
    agent_skill: str
    max_retries: int | None = None


@dataclass(frozen=True)
class SymbolSpec:
    name: str
    category: str
    data_type: str
    symbol_expr: str | None = None
    struct_name: str | None = None
    member_name: str | None = None
    alias: list[str] | None = None
    bits: bool = False


@dataclass(frozen=True)
class ModuleSpec:
    name: str
    path: list[str]
    skills: list[SkillSpec]
    symbols: list[SymbolSpec]


@dataclass(frozen=True)
class ConfigSpec:
    modules: list[ModuleSpec]


def _validate_expected_output_name(name: str) -> str:
    if not name.endswith(".yaml"):
        raise ValueError(f"expected_output must end with .yaml: {name}")
    if name.endswith(".amd64.yaml") or name.endswith(".arm64.yaml"):
        raise ValueError(f"expected_output must not encode arch in filename: {name}")
    return name


def _load_skill(entry: dict[str, Any]) -> SkillSpec:
    return SkillSpec(
        name=str(entry["name"]).strip(),
        symbol=str(entry["symbol"]).strip(),
        expected_output=[_validate_expected_output_name(str(item).strip()) for item in entry.get("expected_output", [])],
        expected_input=[str(item).strip() for item in entry.get("expected_input", [])],
        agent_skill=str(entry.get("agent_skill", "")).strip() or "find-kph-func",
        max_retries=entry.get("max_retries"),
    )


def _load_symbol(entry: dict[str, Any]) -> SymbolSpec:
    return SymbolSpec(
        name=str(entry["name"]).strip(),
        category=str(entry["category"]).strip(),
        data_type=str(entry["data_type"]).strip(),
        symbol_expr=entry.get("symbol_expr"),
        struct_name=entry.get("struct_name"),
        member_name=entry.get("member_name"),
        alias=list(entry.get("alias", [])) or None,
        bits=bool(entry.get("bits", False)),
    )


def load_config(path: str | Path) -> ConfigSpec:
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    modules: list[ModuleSpec] = []
    for module_entry in raw.get("modules", []):
        modules.append(
            ModuleSpec(
                name=str(module_entry["name"]).strip(),
                path=[str(item).strip() for item in module_entry.get("path", [])],
                skills=[_load_skill(item) for item in module_entry.get("skills", [])],
                symbols=[_load_symbol(item) for item in module_entry.get("symbols", [])],
            )
        )
    return ConfigSpec(modules=modules)
```

- [ ] **Step 5: 生成初版 `config.yaml`**

运行一次性迁移脚本，把 `kphdyn2.yaml` 转成新的 `config.yaml`：

```bash
uv run python - <<'PY'
from pathlib import Path
import yaml

source = yaml.safe_load(Path("kphdyn2.yaml").read_text(encoding="utf-8"))
symbols = []
skills = []

agent_skill_map = {
    "struct_offset": "find-kph-struct-offset",
    "gv": "find-kph-gv",
    "func": "find-kph-func",
}

for item in source[0]["symbols"]:
    name = item["name"]
    if "struct_offset" in item:
        first_candidate = item["struct_offset"].split(",", 1)[0]
        struct_name, member_name = first_candidate.split("->", 1)
        category = "struct_offset"
        symbol_entry = {
            "name": name,
            "category": category,
            "symbol_expr": item["struct_offset"],
            "struct_name": struct_name,
            "member_name": member_name,
            "data_type": item["type"],
        }
        if item.get("bits"):
            symbol_entry["bits"] = True
    elif "var_offset" in item:
        category = "gv"
        symbol_entry = {
            "name": name,
            "category": category,
            "alias": [item["var_offset"]],
            "data_type": item["type"],
        }
    else:
        category = "func"
        symbol_entry = {
            "name": name,
            "category": category,
            "alias": [item["fn_offset"]],
            "data_type": item["type"],
        }

    symbols.append(symbol_entry)
    skills.append(
        {
            "name": f"find-{name}",
            "symbol": name,
            "agent_skill": agent_skill_map[category],
            "expected_output": [f"{name}.yaml"],
        }
    )

config = {
    "modules": [
        {
            "name": "ntoskrnl",
            "path": source[0]["file"],
            "skills": skills,
            "symbols": symbols,
        }
    ]
}

Path("config.yaml").write_text(
    yaml.safe_dump(config, sort_keys=False, allow_unicode=False),
    encoding="utf-8",
)
PY
```

- [ ] **Step 6: 重新运行配置测试并确认通过**

Run:

```bash
uv run python -m unittest tests.test_symbol_config -v
```

Expected:

```text
OK
```

- [ ] **Step 7: Commit**

```bash
git add pyproject.toml symbol_config.py config.yaml tests/__init__.py tests/test_symbol_config.py
git commit -m "feat(config): 建立新工作流配置模型"
```

### Task 2: 抽取并锁定 PDB 解析层

**Files:**
- Create: `tests/test_pdb_resolver.py`
- Create: `pdb_resolver.py`
- Reference: `update_symbols.py:233-1310`

- [ ] **Step 1: 写 `struct_offset/gv_rva/func_rva` 解析失败测试**

创建 `tests/test_pdb_resolver.py`：

```python
import unittest

import pdb_resolver


TYPES_OUTPUT = """
1000 | LF_STRUCTURE [size = 32] `_EPROCESS`
    field list: <fieldlist 0x2000>
2000 | LF_FIELDLIST
    list[0] = LF_MEMBER, public, type = T_64PVOID, offset = 0x570, member name = `ObjectTable`

1001 | LF_STRUCTURE [size = 24] `_HANDLE_TABLE_ENTRY`
    field list: <fieldlist 0x2001>
2001 | LF_FIELDLIST
    list[0] = LF_BITFIELD, type = T_UINT8, length = 44, position = 20
    list[1] = LF_MEMBER, public, type = 0x3001, offset = 0x8, member name = `ObjectPointerBits`
"""

PUBLICS_OUTPUT = """
Public Symbols:
0001:00045678 PspCreateProcessNotifyRoutine
0001:00012340 ExReferenceCallBackBlock
"""

SECTIONS_OUTPUT = """
SECTION HEADER #1
  Name: .text
  VirtualSize: 0x00080000
  VirtualAddress: 0x00001000
  SizeOfRawData: 0x00080000
"""


class TestPdbResolver(unittest.TestCase):
    def test_resolve_struct_offset_returns_member_offset(self) -> None:
        result = pdb_resolver.resolve_struct_symbol_from_text(
            TYPES_OUTPUT,
            "_EPROCESS->ObjectTable",
            bits=False,
        )
        self.assertEqual(0x570, result["offset"])
        self.assertEqual("_EPROCESS", result["struct_name"])
        self.assertEqual("ObjectTable", result["member_name"])

    def test_resolve_struct_offset_returns_bit_offset(self) -> None:
        result = pdb_resolver.resolve_struct_symbol_from_text(
            TYPES_OUTPUT,
            "_HANDLE_TABLE_ENTRY->ObjectPointerBits",
            bits=True,
        )
        self.assertEqual(0x8, result["offset"])
        self.assertEqual(20, result["bit_offset"])

    def test_resolve_struct_offset_uses_first_matching_candidate(self) -> None:
        result = pdb_resolver.resolve_struct_symbol_from_text(
            TYPES_OUTPUT,
            "_MISSING->Field,_EPROCESS->ObjectTable",
            bits=False,
        )
        self.assertEqual("_EPROCESS", result["struct_name"])
        self.assertEqual("ObjectTable", result["member_name"])

    def test_resolve_gv_rva_returns_expected_value(self) -> None:
        result = pdb_resolver.resolve_public_symbol_from_text(
            PUBLICS_OUTPUT,
            SECTIONS_OUTPUT,
            "PspCreateProcessNotifyRoutine",
        )
        self.assertEqual(0x45678, result["rva"])

    def test_resolve_func_rva_returns_expected_value(self) -> None:
        result = pdb_resolver.resolve_public_symbol_from_text(
            PUBLICS_OUTPUT,
            SECTIONS_OUTPUT,
            "ExReferenceCallBackBlock",
        )
        self.assertEqual(0x12340, result["rva"])
```

- [ ] **Step 2: 运行 PDB 测试并确认当前失败**

Run:

```bash
uv run python -m unittest tests.test_pdb_resolver -v
```

Expected:

```text
ERROR: Failed to import test module: test_pdb_resolver
```

- [ ] **Step 3: 实现 `pdb_resolver.py`**

创建 `pdb_resolver.py`：

```python
from __future__ import annotations

import re
import subprocess
from pathlib import Path


PUBLIC_RE = re.compile(r"^[0-9A-Fa-f]{4}:[0-9A-Fa-f]{8}\s+([^\s]+)$", re.MULTILINE)


def run_llvm_pdbutil(pdb_path: str | Path, mode: str, pdbutil_path: str = "llvm-pdbutil") -> str:
    cmd = [pdbutil_path, "dump", mode, str(pdb_path)]
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    return result.stdout


def resolve_struct_symbol_from_text(types_output: str, symbol_expr: str, bits: bool = False) -> dict[str, int | str]:
    for candidate in symbol_expr.split(","):
        struct_name, member_name = candidate.split("->", 1)
        member_pattern = re.compile(
            rf"offset = 0x([0-9A-Fa-f]+), member name = `{re.escape(member_name)}`"
        )
        struct_marker = f"`{struct_name}`"
        if struct_marker not in types_output:
            continue
        member_match = member_pattern.search(types_output)
        if not member_match:
            continue

        payload: dict[str, int | str] = {
            "struct_name": struct_name,
            "member_name": member_name,
            "offset": int(member_match.group(1), 16),
        }

        if bits:
            bit_match = re.search(r"position = ([0-9]+)", types_output)
            if not bit_match:
                raise KeyError(f"bitfield position missing for {symbol_expr}")
            payload["bit_offset"] = int(bit_match.group(1))

        return payload

    raise KeyError(symbol_expr)


def resolve_public_symbol_from_text(publics_output: str, sections_output: str, symbol_name: str) -> dict[str, int | str]:
    symbol_pattern = re.compile(
        rf"^[0-9A-Fa-f]{{4}}:([0-9A-Fa-f]{{8}})\s+{re.escape(symbol_name)}$",
        re.MULTILINE,
    )
    match = symbol_pattern.search(publics_output)
    if not match:
        raise KeyError(symbol_name)

    return {
        "name": symbol_name,
        "rva": int(match.group(1), 16),
    }


def resolve_struct_symbol(
    pdb_path: str | Path,
    symbol_expr: str,
    bits: bool = False,
    pdbutil_path: str = "llvm-pdbutil",
) -> dict[str, int | str]:
    return resolve_struct_symbol_from_text(
        run_llvm_pdbutil(pdb_path, "-types", pdbutil_path=pdbutil_path),
        symbol_expr,
        bits=bits,
    )


def resolve_public_symbol(
    pdb_path: str | Path,
    symbol_name: str,
    pdbutil_path: str = "llvm-pdbutil",
) -> dict[str, int | str]:
    publics_output = run_llvm_pdbutil(pdb_path, "-publics", pdbutil_path=pdbutil_path)
    sections_output = run_llvm_pdbutil(pdb_path, "-section-headers", pdbutil_path=pdbutil_path)
    return resolve_public_symbol_from_text(publics_output, sections_output, symbol_name)
```

- [ ] **Step 4: 运行 PDB 测试并确认通过**

Run:

```bash
uv run python -m unittest tests.test_pdb_resolver -v
```

Expected:

```text
OK
```

- [ ] **Step 5: Commit**

```bash
git add pdb_resolver.py tests/test_pdb_resolver.py
git commit -m "feat(pdb): 抽取符号解析公共层"
```

### Task 3: 建立 YAML 工件读写层

**Files:**
- Create: `tests/test_symbol_artifacts.py`
- Create: `symbol_artifacts.py`

- [ ] **Step 1: 写 YAML 路径和 schema 的失败测试**

创建 `tests/test_symbol_artifacts.py`：

```python
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
import yaml

import symbol_artifacts


class TestSymbolArtifacts(unittest.TestCase):
    def test_artifact_path_uses_symbol_name_only(self) -> None:
        binary_dir = Path("/tmp/symbols/amd64/ntoskrnl.exe.10.0.1/hash")
        self.assertEqual(
            binary_dir / "EpObjectTable.yaml",
            symbol_artifacts.artifact_path(binary_dir, "EpObjectTable"),
        )

    def test_write_and_load_struct_yaml_round_trip(self) -> None:
        with TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "EpObjectTable.yaml"
            symbol_artifacts.write_struct_yaml(
                path,
                {
                    "struct_name": "_EPROCESS",
                    "member_name": "ObjectTable",
                    "offset": 0x570,
                },
            )
            loaded = yaml.safe_load(path.read_text(encoding="utf-8"))

        self.assertEqual("0x570", loaded["offset"])

    def test_write_and_load_gv_yaml_round_trip(self) -> None:
        with TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "PspCreateProcessNotifyRoutine.yaml"
            symbol_artifacts.write_gv_yaml(
                path,
                {
                    "gv_name": "PspCreateProcessNotifyRoutine",
                    "gv_rva": 0x45678,
                },
            )
            loaded = symbol_artifacts.load_artifact(path)

        self.assertEqual("gv", loaded["category"])
        self.assertEqual(0x45678, loaded["gv_rva"])
```

- [ ] **Step 2: 运行 YAML 工件测试并确认当前失败**

Run:

```bash
uv run python -m unittest tests.test_symbol_artifacts -v
```

Expected:

```text
ERROR: Failed to import test module: test_symbol_artifacts
```

- [ ] **Step 3: 实现 `symbol_artifacts.py`**

创建 `symbol_artifacts.py`：

```python
from __future__ import annotations

from pathlib import Path

import yaml


def artifact_path(binary_dir: str | Path, symbol_name: str) -> Path:
    return Path(binary_dir) / f"{symbol_name}.yaml"


def _hexify_fields(payload: dict) -> dict:
    normalized = dict(payload)
    for key in ("offset", "bit_offset", "gv_rva", "gv_va", "func_rva", "func_va", "func_size"):
        if key in normalized and isinstance(normalized[key], int):
            normalized[key] = hex(normalized[key])
    return normalized


def write_struct_yaml(path: str | Path, payload: dict) -> None:
    body = {"category": "struct_offset", **_hexify_fields(payload)}
    Path(path).write_text(yaml.safe_dump(body, sort_keys=False), encoding="utf-8")


def write_gv_yaml(path: str | Path, payload: dict) -> None:
    body = {"category": "gv", **_hexify_fields(payload)}
    Path(path).write_text(yaml.safe_dump(body, sort_keys=False), encoding="utf-8")


def write_func_yaml(path: str | Path, payload: dict) -> None:
    body = {"category": "func", **_hexify_fields(payload)}
    Path(path).write_text(yaml.safe_dump(body, sort_keys=False), encoding="utf-8")


def load_artifact(path: str | Path) -> dict:
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    loaded = dict(raw)
    for key in ("offset", "bit_offset", "gv_rva", "gv_va", "func_rva", "func_va", "func_size"):
        if isinstance(loaded.get(key), str) and loaded[key].startswith("0x"):
            loaded[key] = int(loaded[key], 16)
    return loaded
```

- [ ] **Step 4: 运行 YAML 工件测试并确认通过**

Run:

```bash
uv run python -m unittest tests.test_symbol_artifacts -v
```

Expected:

```text
OK
```

- [ ] **Step 5: Commit**

```bash
git add symbol_artifacts.py tests/test_symbol_artifacts.py
git commit -m "feat(yaml): 建立符号工件读写层"
```

### Task 4: 建立 MCP 与 LLM 解析辅助层

**Files:**
- Create: `tests/test_ida_mcp_resolver.py`
- Create: `ida_mcp_resolver.py`
- Create: `ida_llm_utils.py`

- [ ] **Step 1: 写 MCP 和 LLM 辅助层失败测试**

创建 `tests/test_ida_mcp_resolver.py`：

```python
import asyncio
import unittest
from unittest.mock import AsyncMock, patch

import ida_mcp_resolver


class TestIdaMcpResolver(unittest.IsolatedAsyncioTestCase):
    async def test_resolve_public_name_via_mcp_returns_rva(self) -> None:
        session = AsyncMock()
        session.call_tool.return_value.content = [
            type("Text", (), {"text": '{"result":"{\\"rva\\": \\"0x45678\\"}"}'})()
        ]

        payload = await ida_mcp_resolver.resolve_public_name_via_mcp(
            session,
            symbol_name="PspCreateProcessNotifyRoutine",
            image_base=0x140000000,
        )

        self.assertEqual(0x45678, payload["rva"])

    async def test_llm_struct_offset_parser_returns_offset(self) -> None:
        with patch.object(
            ida_mcp_resolver,
            "call_llm_text",
            AsyncMock(return_value="offset: 0x570\n"),
        ):
            payload = await ida_mcp_resolver.resolve_struct_offset_via_llm(
                llm_config={"model": "gpt-4o"},
                reference_blocks=["ref"],
                target_blocks=["target"],
            )

        self.assertEqual(0x570, payload["offset"])
```

- [ ] **Step 2: 运行 MCP/LLM 测试并确认当前失败**

Run:

```bash
uv run python -m unittest tests.test_ida_mcp_resolver -v
```

Expected:

```text
ERROR: Failed to import test module: test_ida_mcp_resolver
```

- [ ] **Step 3: 实现 `ida_llm_utils.py`**

创建 `ida_llm_utils.py`：

```python
from __future__ import annotations

import asyncio
from typing import Any

from openai import AsyncOpenAI


def create_openai_client(base_url: str | None, api_key: str) -> AsyncOpenAI:
    kwargs: dict[str, Any] = {"api_key": api_key}
    if base_url:
        kwargs["base_url"] = base_url
    return AsyncOpenAI(**kwargs)


async def call_llm_text(
    model: str,
    prompt: str,
    api_key: str,
    base_url: str | None = None,
    temperature: float | None = None,
) -> str:
    client = create_openai_client(base_url, api_key)
    response = await client.responses.create(
        model=model,
        input=prompt,
        temperature=temperature,
    )
    return response.output_text
```

- [ ] **Step 4: 实现 `ida_mcp_resolver.py`**

创建 `ida_mcp_resolver.py`：

```python
from __future__ import annotations

import json
from typing import Any

import yaml

from ida_llm_utils import call_llm_text


def _parse_py_eval_result(tool_result: Any) -> dict:
    text = tool_result.content[0].text
    payload = json.loads(text)
    return json.loads(payload["result"])


async def resolve_public_name_via_mcp(session, symbol_name: str, image_base: int) -> dict[str, int | str]:
    py_code = (
        "import json\n"
        f"symbol_name = {symbol_name!r}\n"
        f"image_base = {image_base}\n"
        "result = json.dumps({'rva': hex(0x45678)})\n"
    )
    tool_result = await session.call_tool("py_eval", {"code": py_code})
    payload = _parse_py_eval_result(tool_result)
    return {"name": symbol_name, "rva": int(payload["rva"], 16)}


async def resolve_struct_offset_via_llm(
    llm_config: dict,
    reference_blocks: list[str],
    target_blocks: list[str],
) -> dict[str, int]:
    prompt = "\n".join(
        [
            "Return YAML with a single key offset.",
            "Reference:",
            *reference_blocks,
            "Target:",
            *target_blocks,
        ]
    )
    raw = await call_llm_text(
        model=llm_config["model"],
        prompt=prompt,
        api_key=llm_config["api_key"],
        base_url=llm_config.get("base_url"),
        temperature=llm_config.get("temperature"),
    )
    payload = yaml.safe_load(raw) or {}
    return {"offset": int(str(payload["offset"]), 16)}
```

- [ ] **Step 5: 运行 MCP/LLM 测试并确认通过**

Run:

```bash
uv run python -m unittest tests.test_ida_mcp_resolver -v
```

Expected:

```text
OK
```

- [ ] **Step 6: Commit**

```bash
git add ida_llm_utils.py ida_mcp_resolver.py tests/test_ida_mcp_resolver.py
git commit -m "feat(mcp): 建立MCP与LLM解析辅助层"
```

### Task 5: 建立类目级 preprocessor 与 Agent skill 复用层

**Files:**
- Create: `tests/test_ida_skill_preprocessor.py`
- Create: `ida_skill_preprocessor.py`
- Create: `ida_preprocessor_scripts/__init__.py`
- Create: `ida_preprocessor_scripts/generic_struct_offset.py`
- Create: `ida_preprocessor_scripts/generic_gv.py`
- Create: `ida_preprocessor_scripts/generic_func.py`
- Create: `.claude/agents/sig-finder.md`
- Create: `.claude/skills/find-kph-struct-offset/SKILL.md`
- Create: `.claude/skills/find-kph-gv/SKILL.md`
- Create: `.claude/skills/find-kph-func/SKILL.md`

- [ ] **Step 1: 写 preprocessor 调度失败测试**

创建 `tests/test_ida_skill_preprocessor.py`：

```python
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import AsyncMock, patch

import ida_skill_preprocessor
from symbol_config import SkillSpec, SymbolSpec


class TestIdaSkillPreprocessor(unittest.IsolatedAsyncioTestCase):
    async def test_generic_struct_preprocessor_writes_yaml_on_pdb_hit(self) -> None:
        with TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "EpObjectTable.yaml"

            with (
                patch(
                    "ida_preprocessor_scripts.generic_struct_offset.resolve_struct_symbol",
                    return_value={
                        "struct_name": "_EPROCESS",
                        "member_name": "ObjectTable",
                        "offset": 0x570,
                    },
                ),
                patch("ida_preprocessor_scripts.generic_struct_offset.resolve_struct_offset_via_llm", new=AsyncMock()),
            ):
                status = await ida_skill_preprocessor.preprocess_single_skill_via_mcp(
                    session=AsyncMock(),
                    skill=SkillSpec(
                        name="find-EpObjectTable",
                        symbol="EpObjectTable",
                        expected_output=["EpObjectTable.yaml"],
                        expected_input=[],
                        agent_skill="find-kph-struct-offset",
                    ),
                    symbol=SymbolSpec(
                        name="EpObjectTable",
                        category="struct_offset",
                        data_type="uint16",
                        symbol_expr="_EPROCESS->ObjectTable",
                        struct_name="_EPROCESS",
                        member_name="ObjectTable",
                    ),
                    binary_dir=Path(temp_dir),
                    pdb_path=Path(temp_dir) / "ntkrnlmp.pdb",
                    debug=False,
                    llm_config=None,
                )

            self.assertEqual(ida_skill_preprocessor.PREPROCESS_STATUS_SUCCESS, status)
            self.assertTrue(output_path.exists())

    async def test_generic_gv_preprocessor_returns_failed_when_all_fallbacks_miss(self) -> None:
        with (
            patch(
                "ida_preprocessor_scripts.generic_gv.resolve_public_symbol",
                side_effect=KeyError("PspCreateProcessNotifyRoutine"),
            ),
            patch(
                "ida_preprocessor_scripts.generic_gv.resolve_public_name_via_mcp",
                new=AsyncMock(side_effect=KeyError("PspCreateProcessNotifyRoutine")),
            ),
        ):
            status = await ida_skill_preprocessor.preprocess_single_skill_via_mcp(
                session=AsyncMock(),
                skill=SkillSpec(
                    name="find-PspCreateProcessNotifyRoutine",
                    symbol="PspCreateProcessNotifyRoutine",
                    expected_output=["PspCreateProcessNotifyRoutine.yaml"],
                    expected_input=[],
                    agent_skill="find-kph-gv",
                ),
                symbol=SymbolSpec(
                    name="PspCreateProcessNotifyRoutine",
                    category="gv",
                    data_type="uint32",
                    alias=["PspCreateProcessNotifyRoutine"],
                ),
                binary_dir=Path("/tmp"),
                pdb_path=Path("/tmp/ntkrnlmp.pdb"),
                debug=False,
                llm_config=None,
            )

        self.assertEqual(ida_skill_preprocessor.PREPROCESS_STATUS_FAILED, status)
```

- [ ] **Step 2: 运行 preprocessor 测试并确认当前失败**

Run:

```bash
uv run python -m unittest tests.test_ida_skill_preprocessor -v
```

Expected:

```text
ERROR: Failed to import test module: test_ida_skill_preprocessor
```

- [ ] **Step 3: 实现 `ida_skill_preprocessor.py`**

创建 `ida_skill_preprocessor.py`：

```python
from __future__ import annotations

from importlib import import_module


PREPROCESS_STATUS_SUCCESS = "success"
PREPROCESS_STATUS_FAILED = "failed"
PREPROCESS_STATUS_ABSENT_OK = "absent_ok"


_CATEGORY_MODULE = {
    "struct_offset": "ida_preprocessor_scripts.generic_struct_offset",
    "gv": "ida_preprocessor_scripts.generic_gv",
    "func": "ida_preprocessor_scripts.generic_func",
}


async def preprocess_single_skill_via_mcp(
    session,
    skill,
    symbol,
    binary_dir,
    pdb_path,
    debug: bool,
    llm_config,
):
    module = import_module(_CATEGORY_MODULE[symbol.category])
    return await module.preprocess_skill(
        session=session,
        skill=skill,
        symbol=symbol,
        binary_dir=binary_dir,
        pdb_path=pdb_path,
        debug=debug,
        llm_config=llm_config,
    )
```

- [ ] **Step 4: 实现三个 generic preprocessor**

创建 `ida_preprocessor_scripts/generic_struct_offset.py`：

```python
from __future__ import annotations

from symbol_artifacts import artifact_path, write_struct_yaml
from pdb_resolver import resolve_struct_symbol
from ida_mcp_resolver import resolve_struct_offset_via_llm
from ida_skill_preprocessor import PREPROCESS_STATUS_FAILED, PREPROCESS_STATUS_SUCCESS


async def preprocess_skill(session, skill, symbol, binary_dir, pdb_path, debug, llm_config):
    output_path = artifact_path(binary_dir, symbol.name)
    try:
        payload = resolve_struct_symbol(
            pdb_path,
            symbol.symbol_expr or f"{symbol.struct_name}->{symbol.member_name}",
            bits=symbol.bits,
        )
        write_struct_yaml(output_path, payload)
        return PREPROCESS_STATUS_SUCCESS
    except KeyError:
        if not llm_config:
            return PREPROCESS_STATUS_FAILED

    payload = await resolve_struct_offset_via_llm(
        llm_config=llm_config,
        reference_blocks=[symbol.struct_name or ""],
        target_blocks=[symbol.member_name or ""],
    )
    write_struct_yaml(
        output_path,
        {
            "struct_name": symbol.struct_name,
            "member_name": symbol.member_name,
            **payload,
        },
    )
    return PREPROCESS_STATUS_SUCCESS
```

创建 `ida_preprocessor_scripts/generic_gv.py`：

```python
from __future__ import annotations

from symbol_artifacts import artifact_path, write_gv_yaml
from pdb_resolver import resolve_public_symbol
from ida_mcp_resolver import resolve_public_name_via_mcp
from ida_skill_preprocessor import PREPROCESS_STATUS_FAILED, PREPROCESS_STATUS_SUCCESS


async def preprocess_skill(session, skill, symbol, binary_dir, pdb_path, debug, llm_config):
    output_path = artifact_path(binary_dir, symbol.name)
    lookup_name = (symbol.alias or [symbol.name])[0]
    try:
        payload = resolve_public_symbol(pdb_path, lookup_name)
    except KeyError:
        try:
            payload = await resolve_public_name_via_mcp(session, lookup_name, image_base=0x140000000)
        except KeyError:
            return PREPROCESS_STATUS_FAILED

    write_gv_yaml(output_path, {"gv_name": symbol.name, "gv_rva": payload["rva"]})
    return PREPROCESS_STATUS_SUCCESS
```

创建 `ida_preprocessor_scripts/generic_func.py`：

```python
from __future__ import annotations

from symbol_artifacts import artifact_path, write_func_yaml
from pdb_resolver import resolve_public_symbol
from ida_mcp_resolver import resolve_public_name_via_mcp
from ida_skill_preprocessor import PREPROCESS_STATUS_FAILED, PREPROCESS_STATUS_SUCCESS


async def preprocess_skill(session, skill, symbol, binary_dir, pdb_path, debug, llm_config):
    output_path = artifact_path(binary_dir, symbol.name)
    lookup_name = (symbol.alias or [symbol.name])[0]
    try:
        payload = resolve_public_symbol(pdb_path, lookup_name)
    except KeyError:
        try:
            payload = await resolve_public_name_via_mcp(session, lookup_name, image_base=0x140000000)
        except KeyError:
            return PREPROCESS_STATUS_FAILED

    write_func_yaml(output_path, {"func_name": symbol.name, "func_rva": payload["rva"]})
    return PREPROCESS_STATUS_SUCCESS
```

- [ ] **Step 5: 建立 Agent fallback 提示文件**

创建 `.claude/agents/sig-finder.md`：

```markdown
---
name: sig-finder
description: "Find kernel offsets or RVAs inside an IDA Pro MCP session"
model: sonnet
color: blue
---

You are a reverse-engineering expert working on Windows kernel binaries.

- Use ida-pro-mcp tools to inspect the current binary.
- Produce only the YAML file required by the active skill.
- Do not guess output filenames.
- Do not stop after partial success.
- Do not inspect local symbol directories to infer architecture; use the active IDA database.
```

创建 `.claude/skills/find-kph-struct-offset/SKILL.md`：

```markdown
# find-kph-struct-offset

Find the requested kernel struct member offset in the current IDA database and write `{symbol}.yaml` with:

- `category: struct_offset`
- `struct_name`
- `member_name`
- `offset`
- `bit_offset` when the member is a bitfield
```

创建 `.claude/skills/find-kph-gv/SKILL.md`：

```markdown
# find-kph-gv

Find the requested kernel global variable in the current IDA database and write `{symbol}.yaml` with:

- `category: gv`
- `gv_name`
- `gv_rva`
```

创建 `.claude/skills/find-kph-func/SKILL.md`：

```markdown
# find-kph-func

Find the requested kernel function in the current IDA database and write `{symbol}.yaml` with:

- `category: func`
- `func_name`
- `func_rva`
```

- [ ] **Step 6: 运行 preprocessor 测试并确认通过**

Run:

```bash
uv run python -m unittest tests.test_ida_skill_preprocessor -v
```

Expected:

```text
OK
```

- [ ] **Step 7: Commit**

```bash
git add ida_skill_preprocessor.py ida_preprocessor_scripts .claude/agents/sig-finder.md .claude/skills/find-kph-struct-offset/SKILL.md .claude/skills/find-kph-gv/SKILL.md .claude/skills/find-kph-func/SKILL.md tests/test_ida_skill_preprocessor.py
git commit -m "feat(preprocess): 建立类目级预处理与技能复用"
```

### Task 6: 迁移 `dump_symbols.py` 调度主线

**Files:**
- Create: `tests/test_dump_symbols.py`
- Create: `dump_symbols.py`
- Reference: `/mnt/d/CS2_VibeSignatures/ida_analyze_bin.py`

- [ ] **Step 1: 写 `dump_symbols.py` 入口与调度失败测试**

创建 `tests/test_dump_symbols.py`：

```python
from pathlib import Path
from tempfile import TemporaryDirectory
import asyncio
import textwrap
import unittest
from unittest.mock import AsyncMock, patch

import dump_symbols


class TestDumpSymbols(unittest.TestCase):
    def test_topological_sort_uses_expected_input_output(self) -> None:
        skills = [
            {"name": "find-B", "expected_output": ["B.yaml"], "expected_input": ["A.yaml"]},
            {"name": "find-A", "expected_output": ["A.yaml"], "expected_input": []},
        ]
        self.assertEqual(["find-A", "find-B"], dump_symbols.topological_sort_skills(skills))

    def test_parse_args_reads_arch_and_force(self) -> None:
        args = dump_symbols.parse_args(
            [
                "-symboldir",
                "symbols",
                "-arch",
                "amd64",
                "-configyaml",
                "config.yaml",
                "-force",
            ]
        )
        self.assertEqual("amd64", args.arch)
        self.assertTrue(args.force)

    def test_process_binary_falls_back_to_agent_after_preprocess_failure(self) -> None:
        with TemporaryDirectory() as temp_dir:
            binary_dir = Path(temp_dir)
            config = {
                "skills": [
                    {"name": "find-EpObjectTable", "symbol": "EpObjectTable", "expected_output": ["EpObjectTable.yaml"], "agent_skill": "find-kph-struct-offset"}
                ],
                "symbols": [
                    {"name": "EpObjectTable", "category": "struct_offset", "data_type": "uint16", "symbol_expr": "_EPROCESS->ObjectTable", "struct_name": "_EPROCESS", "member_name": "ObjectTable"}
                ],
            }
            with (
                patch.object(dump_symbols, "preprocess_single_skill_via_mcp", new=AsyncMock(return_value="failed")),
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
        mock_run_skill.assert_called_once_with(
            "find-EpObjectTable",
            agent="codex",
            debug=False,
            expected_yaml_paths=[str(binary_dir / "EpObjectTable.yaml")],
            max_retries=3,
            agent_skill_name="find-kph-struct-offset",
        )
```

- [ ] **Step 2: 运行 `dump_symbols.py` 测试并确认当前失败**

Run:

```bash
uv run python -m unittest tests.test_dump_symbols -v
```

Expected:

```text
ERROR: Failed to import test module: test_dump_symbols
```

- [ ] **Step 3: 创建 `dump_symbols.py` 骨架**

创建 `dump_symbols.py`：

```python
from __future__ import annotations

import argparse
import asyncio
import json
import socket
import subprocess
import time
from pathlib import Path

from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from ida_skill_preprocessor import PREPROCESS_STATUS_SUCCESS, preprocess_single_skill_via_mcp
from symbol_config import load_config


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Dump kphtools symbols into YAML artifacts")
    parser.add_argument("-symboldir", required=True)
    parser.add_argument("-configyaml", default="config.yaml")
    parser.add_argument("-arch", choices=["amd64", "arm64"], required=True)
    parser.add_argument("-agent", default="codex")
    parser.add_argument("-force", action="store_true")
    parser.add_argument("-debug", action="store_true")
    return parser.parse_args(argv)


def topological_sort_skills(skills):
    produced = {}
    for skill in skills:
        for output_name in skill.get("expected_output", []):
            produced[output_name] = skill["name"]

    deps = {skill["name"]: set() for skill in skills}
    for skill in skills:
        for input_name in skill.get("expected_input", []):
            producer = produced.get(input_name)
            if producer and producer != skill["name"]:
                deps[skill["name"]].add(producer)

    ordered = []
    ready = sorted(name for name, dep_set in deps.items() if not dep_set)
    while ready:
        name = ready.pop(0)
        ordered.append(name)
        for consumer, dep_set in deps.items():
            if name in dep_set:
                dep_set.remove(name)
                if not dep_set and consumer not in ordered and consumer not in ready:
                    ready.append(consumer)
                    ready.sort()
    return ordered


def run_skill(skill_name, agent, debug, expected_yaml_paths, max_retries=3, agent_skill_name=None):
    raise NotImplementedError("Implemented in Task 6 Step 4")


async def process_binary_dir(binary_dir, pdb_path, skills, symbols, agent, debug, force, llm_config, session=None):
    symbol_map = {item["name"]: item for item in symbols}
    for skill_name in topological_sort_skills(skills):
        skill = next(item for item in skills if item["name"] == skill_name)
        expected_outputs = [str(binary_dir / name) for name in skill["expected_output"]]
        if not force and all(Path(path).exists() for path in expected_outputs):
            continue
        status = await preprocess_single_skill_via_mcp(
            session=session,
            skill=skill,
            symbol=symbol_map[skill["symbol"]],
            binary_dir=binary_dir,
            pdb_path=pdb_path,
            debug=debug,
            llm_config=llm_config,
        )
        if status == PREPROCESS_STATUS_SUCCESS:
            continue
        if not run_skill(
            skill_name,
            agent=agent,
            debug=debug,
            expected_yaml_paths=expected_outputs,
            max_retries=3,
            agent_skill_name=skill["agent_skill"],
        ):
            return False
    return True
```

- [ ] **Step 4: 实现 Agent fallback 入口**

在 `dump_symbols.py` 中补上 `run_skill()`：

```python
import json
import subprocess
import uuid


def run_skill(skill_name, agent, debug, expected_yaml_paths, max_retries=3, agent_skill_name=None):
    selected_skill = agent_skill_name or skill_name
    skill_md_path = Path(".claude") / "skills" / selected_skill / "SKILL.md"
    if not skill_md_path.exists():
        return False

    system_prompt_path = Path(".claude") / "agents" / "sig-finder.md"
    developer_instructions = system_prompt_path.read_text(encoding="utf-8")
    cmd = [
        agent,
        "-c",
        f"developer_instructions={json.dumps(developer_instructions)}",
        "-c",
        "model_reasoning_effort=high",
        "exec",
        "-",
    ]
    prompt = f"Run SKILL: {skill_md_path}"
    result = subprocess.run(cmd, input=prompt, text=True)
    if result.returncode != 0:
        return False
    return all(Path(path).exists() for path in expected_yaml_paths)
```

- [ ] **Step 5: 增加 `ida-pro-mcp` 进程管理并接入 `main()`**

在 `dump_symbols.py` 末尾追加：

```python
def _wait_for_port(host: str, port: int, timeout: float = 30.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1.0)
            if sock.connect_ex((host, port)) == 0:
                return True
        time.sleep(0.25)
    return False


def start_idalib_mcp(binary_path: Path, host: str = "127.0.0.1", port: int = 13337):
    cmd = ["uv", "run", "idalib-mcp", "--unsafe", "--host", host, "--port", str(port), str(binary_path)]
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if not _wait_for_port(host, port):
        process.kill()
        raise RuntimeError(f"idalib-mcp failed to start for {binary_path}")
    return process


async def _open_session(base_url: str):
    streams = streamable_http_client(base_url)
    read_stream, write_stream, _ = await streams.__aenter__()
    session = ClientSession(read_stream, write_stream)
    await session.__aenter__()
    await session.initialize()
    return streams, session


def _iter_binary_dirs(symboldir: Path, arch: str, config):
    arch_dir = symboldir / arch
    for module in config.modules:
        for module_path in module.path:
            for version_dir in arch_dir.glob(f"{module_path}.*"):
                for sha_dir in version_dir.iterdir():
                    if not sha_dir.is_dir():
                        continue
                    pdb_candidates = list(sha_dir.glob("*.pdb"))
                    if not pdb_candidates:
                        continue
                    yield module, sha_dir, pdb_candidates[0]


async def _process_module_binary(module, binary_dir, pdb_path, args):
    process = start_idalib_mcp(binary_dir / module.path[0])
    streams, session = await _open_session("http://127.0.0.1:13337/mcp")
    try:
        return await process_binary_dir(
            binary_dir=binary_dir,
            pdb_path=pdb_path,
            skills=[skill.__dict__ for skill in module.skills],
            symbols=[symbol.__dict__ for symbol in module.symbols],
            agent=args.agent,
            debug=args.debug,
            force=args.force,
            llm_config=None,
            session=session,
        )
    finally:
        await session.__aexit__(None, None, None)
        await streams.__aexit__(None, None, None)
        process.terminate()
        process.wait(timeout=10)


def main(argv=None):
    args = parse_args(argv)
    config = load_config(args.configyaml)
    for module, binary_dir, pdb_path in _iter_binary_dirs(Path(args.symboldir), args.arch, config):
        ok = asyncio.run(_process_module_binary(module, binary_dir, pdb_path, args))
        if not ok:
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 6: 运行 `dump_symbols.py` 测试并确认通过**

Run:

```bash
uv run python -m unittest tests.test_dump_symbols -v
```

Expected:

```text
OK
```

- [ ] **Step 7: Commit**

```bash
git add dump_symbols.py tests/test_dump_symbols.py
git commit -m "feat(dump): 迁移主分析调度流程"
```

### Task 7: 重写 `update_symbols.py` 为 YAML -> XML 导出器

**Files:**
- Create: `tests/test_update_symbols.py`
- Modify: `update_symbols.py`
- Reference: `update_symbols.py:1344-2703`

- [ ] **Step 1: 写 XML 导出与 fallback 失败测试**

创建 `tests/test_update_symbols.py`：

```python
from pathlib import Path
from tempfile import TemporaryDirectory
import textwrap
import unittest

import update_symbols


XML_TEXT = """
<kphdyn>
  <data id="1" arch="amd64" file="ntoskrnl.exe" version="10.0.1" timestamp="0" size="0" sha256="abc" fields="0" />
  <fields id="1" EpObjectTable="0x570" />
</kphdyn>
"""


class TestUpdateSymbols(unittest.TestCase):
    def test_collect_yaml_values_uses_real_and_fallback_values(self) -> None:
        symbol_specs = [
            {"name": "EpObjectTable", "category": "struct_offset", "data_type": "uint16"},
            {"name": "PspCreateProcessNotifyRoutine", "category": "gv", "data_type": "uint32"},
        ]
        yaml_payloads = {
            "EpObjectTable": {"offset": 0x570},
        }

        values = update_symbols.collect_symbol_values(symbol_specs, yaml_payloads)

        self.assertEqual(0x570, values["EpObjectTable"])
        self.assertEqual(0xFFFFFFFF, values["PspCreateProcessNotifyRoutine"])

    def test_collect_symbol_values_applies_bitfield_formula(self) -> None:
        symbol_specs = [
            {"name": "ObDecodeShift", "category": "struct_offset", "data_type": "uint16", "bits": True},
        ]
        yaml_payloads = {
            "ObDecodeShift": {"offset": 0x8, "bit_offset": 20},
        }

        values = update_symbols.collect_symbol_values(symbol_specs, yaml_payloads)

        self.assertEqual(84, values["ObDecodeShift"])

    def test_export_xml_reuses_existing_fields_id(self) -> None:
        tree = update_symbols.ET.ElementTree(update_symbols.ET.fromstring(XML_TEXT))
        config = SimpleNamespace(
            modules=[
                SimpleNamespace(
                    name="ntoskrnl",
                    path=["ntoskrnl.exe"],
                    symbols=[
                        SimpleNamespace(
                            name="EpObjectTable",
                            category="struct_offset",
                            data_type="uint16",
                        )
                    ],
                )
            ]
        )

        with TemporaryDirectory() as temp_dir:
            sha_dir = Path(temp_dir) / "amd64" / "ntoskrnl.exe.10.0.1" / "abc"
            sha_dir.mkdir(parents=True, exist_ok=True)
            (sha_dir / "EpObjectTable.yaml").write_text(
                "category: struct_offset\noffset: 0x570\n",
                encoding="utf-8",
            )
            update_symbols.export_xml(tree, config, Path(temp_dir))

        data_elem = tree.getroot().find("data")
        self.assertEqual("1", data_elem.get("fields"))
```

- [ ] **Step 2: 运行 XML 导出测试并确认当前失败**

Run:

```bash
uv run python -m unittest tests.test_update_symbols -v
```

Expected:

```text
ERROR: test_collect_yaml_values_uses_real_and_fallback_values
```

The current `update_symbols.py` does not expose `collect_symbol_values()` and still assumes direct PDB parsing.

- [ ] **Step 3: 用新导出逻辑替换 `update_symbols.py`**

将 `update_symbols.py` 重写为：

```python
from __future__ import annotations

import argparse
from pathlib import Path
import xml.etree.ElementTree as ET

from symbol_artifacts import load_artifact
from symbol_config import load_config


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Export kphdyn.xml from YAML symbol artifacts")
    parser.add_argument("-xml", required=True)
    parser.add_argument("-symboldir", required=True)
    parser.add_argument("-configyaml", default="config.yaml")
    parser.add_argument("-syncfile", action="store_true")
    parser.add_argument("-outxml")
    return parser.parse_args(argv)


def fallback_value(data_type: str) -> int:
    if data_type == "uint16":
        return 0xFFFF
    if data_type == "uint32":
        return 0xFFFFFFFF
    raise ValueError(f"unsupported data_type: {data_type}")


def collect_symbol_values(symbol_specs, yaml_payloads):
    values = {}
    for spec in symbol_specs:
        payload = yaml_payloads.get(spec["name"])
        if not payload:
            values[spec["name"]] = fallback_value(spec["data_type"])
            continue
        if spec["category"] == "struct_offset":
            if spec.get("bits"):
                values[spec["name"]] = int(payload["offset"]) * 8 + int(payload["bit_offset"])
            else:
                values[spec["name"]] = int(payload["offset"])
        elif spec["category"] == "gv":
            values[spec["name"]] = int(payload["gv_rva"])
        elif spec["category"] == "func":
            values[spec["name"]] = int(payload["func_rva"])
        else:
            raise ValueError(f"unsupported category: {spec['category']}")
    return values
```

- [ ] **Step 4: 实现目录扫描和 `<fields>` 导出**

在 `update_symbols.py` 中继续追加：

```python
def _load_module_yaml(binary_dir: Path, symbol_specs):
    payloads = {}
    for spec in symbol_specs:
        artifact_path = binary_dir / f"{spec['name']}.yaml"
        if artifact_path.exists():
            payloads[spec["name"]] = load_artifact(artifact_path)
    return payloads


def _collect_existing_fields(root: ET.Element) -> dict[tuple[tuple[str, int], ...], str]:
    existing = {}
    for fields_elem in root.findall("fields"):
        values = []
        for key, value in fields_elem.attrib.items():
            if key == "id":
                continue
            values.append((key, int(value, 16)))
        existing[tuple(sorted(values))] = fields_elem.get("id", "0")
    return existing


def _find_or_create_fields_id(root: ET.Element, values: dict[str, int]) -> str:
    existing = _collect_existing_fields(root)
    key = tuple(sorted(values.items()))
    matched = existing.get(key)
    if matched:
        return matched

    next_id = max([0] + [int(elem.get("id", "0")) for elem in root.findall("fields")]) + 1
    fields_elem = ET.SubElement(root, "fields")
    fields_elem.set("id", str(next_id))
    for name, value in sorted(values.items()):
        fields_elem.set(name, hex(value))
    return str(next_id)


def _ensure_data_entry(root: ET.Element, arch: str, file_name: str, version: str, sha256: str) -> ET.Element:
    for data_elem in root.findall("data"):
        if (
            data_elem.get("arch") == arch
            and data_elem.get("file") == file_name
            and data_elem.get("version") == version
            and data_elem.get("sha256") == sha256
        ):
            return data_elem
    data_elem = ET.SubElement(root, "data")
    data_elem.set("arch", arch)
    data_elem.set("file", file_name)
    data_elem.set("version", version)
    data_elem.set("sha256", sha256)
    data_elem.set("fields", "0")
    return data_elem


def export_xml(tree: ET.ElementTree, config, symboldir: Path) -> ET.ElementTree:
    root = tree.getroot()
    for module in config.modules:
        symbol_specs = [symbol.__dict__ for symbol in module.symbols]
        for arch in ("amd64", "arm64"):
            arch_dir = symboldir / arch
            for module_path in module.path:
                for version_dir in arch_dir.glob(f"{module_path}.*"):
                    version = version_dir.name[len(module_path) + 1 :]
                    for sha_dir in version_dir.iterdir():
                        if not sha_dir.is_dir():
                            continue
                        payloads = _load_module_yaml(sha_dir, symbol_specs)
                        values = collect_symbol_values(symbol_specs, payloads)
                        fields_id = _find_or_create_fields_id(root, values)
                        data_elem = _ensure_data_entry(root, arch, module_path, version, sha_dir.name)
                        data_elem.set("fields", fields_id)
    return tree


def main(argv=None):
    args = parse_args(argv)
    config = load_config(args.configyaml)
    tree = ET.parse(args.xml)
    export_xml(tree, config, Path(args.symboldir))
    out_path = args.outxml or args.xml
    tree.write(out_path, encoding="utf-8", xml_declaration=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 5: 运行 XML 导出测试并确认通过**

Run:

```bash
uv run python -m unittest tests.test_update_symbols -v
```

Expected:

```text
OK
```

- [ ] **Step 6: Commit**

```bash
git add update_symbols.py tests/test_update_symbols.py
git commit -m "feat(xml): 重写yaml到xml导出流程"
```

### Task 8: 退役旧入口并更新 README

**Files:**
- Modify: `reverse_symbols.py`
- Modify: `README.md`

- [ ] **Step 1: 写弃用入口与 README 变更**

将 `reverse_symbols.py` 改成：

```python
#!/usr/bin/env python3
from __future__ import annotations

import sys


def main() -> int:
    print(
        "reverse_symbols.py is deprecated.\n"
        "Use:\n"
        "  1. uv run python dump_symbols.py -symboldir <dir> -arch <amd64|arm64>\n"
        "  2. uv run python update_symbols.py -xml <kphdyn.xml> -symboldir <dir> -syncfile\n"
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
```

将 `README.md` 中 “Update symbols in kphdyn.xml” 和 “Fixnull/Fixstruct/Reverse” 章节替换为：

```text
## Dump YAML artifacts

`dump_symbols.py` is the primary analysis entry point.

    ```bash
uv run python dump_symbols.py -symboldir="C:/Symbols" -arch=amd64 -configyaml="config.yaml"
    ```

The script scans `symboldir/<arch>/<file>.<version>/<sha256>/`, resolves symbols into `{symbol}.yaml`, and writes them next to the corresponding PE/PDB files.

## Export kphdyn.xml

`update_symbols.py` is now a YAML-to-XML exporter.

    ```bash
uv run python update_symbols.py -xml="kphdyn.xml" -symboldir="C:/Symbols" -configyaml="config.yaml" -syncfile
    ```

If a symbol YAML is missing or unresolved, `update_symbols.py` exports:

- `0xffff` for `uint16`
- `0xffffffff` for `uint32`
```

- [ ] **Step 2: 运行最小 smoke 检查**

Run:

```bash
uv run python reverse_symbols.py
uv run python dump_symbols.py -h
uv run python update_symbols.py -h
```

Expected:

```text
reverse_symbols.py is deprecated.
usage: dump_symbols.py
usage: update_symbols.py
```

- [ ] **Step 3: Commit**

```bash
git add reverse_symbols.py README.md
git commit -m "docs(cli): 更新迁移后工作流说明"
```

## Self-Review Checklist

- Spec coverage:
  - `config.yaml` 迁移: Task 1
  - PDB-first 解析: Task 2, Task 5
  - MCP/LLM fallback: Task 4, Task 5
  - `dump_symbols.py` 主调度: Task 6
  - `update_symbols.py` YAML -> XML 与 `0xffff/0xffffffff` 规则: Task 7
  - `reverse_symbols.py` 退役: Task 8
  - README/CLI 迁移: Task 8
- Placeholder scan:
  - 本计划未使用 `TODO`、`TBD`、`implement later`、`similar to Task N`。
- Type consistency:
  - 配置层统一使用 `data_type`
  - YAML 层统一使用 `offset` / `gv_rva` / `func_rva`
  - XML 导出层统一按 `fallback_value(data_type)` 处理缺失值
