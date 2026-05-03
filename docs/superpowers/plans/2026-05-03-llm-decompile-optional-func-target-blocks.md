# LLM_DECOMPILE Optional Func Target Blocks Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 让 reference YAML 的 `optional_funcs` 在当前 IDB 中存在时加入 `LLM_DECOMPILE` 的 `{target_blocks}`，并让每个函数反汇编块显式标注函数名。

**Architecture:** 在 reference YAML 校验层保留 `optional_funcs`，在 `ida_mcp_resolver.py` 请求准备层合并主函数与 optional function。主 reference 函数作为 required target 必须导出成功，optional function 复用现有目标函数导出逻辑，缺失或导出失败时跳过。Prompt 渲染层只负责文本格式，给每个 disassembly/procedure 区块加入函数名。

**Tech Stack:** Python 3.10、`unittest`、`unittest.mock.AsyncMock`、`tempfile.TemporaryDirectory`、`PyYAML`

---

## File Structure

- Modify: `ida_reference_export.py`
  - 扩展 `validate_reference_yaml_payload(...)`，保留合法 `optional_funcs`
  - 新增一个小型校验 helper，避免把 optional schema 写进主函数主体
- Modify: `ida_mcp_resolver.py`
  - `_prepare_llm_decompile_request(...)` 生成 `target_func_names` 和 `required_target_func_names`
  - `resolve_symbol_via_llm_decompile(...)` 检查 required target 是否导出成功
  - `_render_llm_decompile_blocks(...)` 在每个函数的反汇编和伪代码区块标题中标注函数名
- Modify: `tests/test_ida_reference_export.py`
  - 覆盖合法和非法 `optional_funcs`
- Modify: `tests/test_ida_mcp_resolver.py`
  - 覆盖 target name 合并、去重、optional 缺失跳过、主函数缺失失败、prompt 函数名标注

不修改：

- `ida_preprocessor_scripts/find-ObAttributesShift-AND-ObDecodeShift.py`
- `ida_preprocessor_scripts/references/ntoskrnl/ObpEnumFindHandleProcedure.amd64.yaml`
- `ida_preprocessor_scripts/prompt/call_llm_decompile.md`

### Task 1: Reference YAML 保留 optional_funcs

**Files:**
- Modify: `ida_reference_export.py`
- Test: `tests/test_ida_reference_export.py`

- [ ] **Step 1: 写合法 optional_funcs 的失败测试**

在 `tests/test_ida_reference_export.py` 的 `TestIdaReferenceExport` 中，放在 `test_validate_reference_yaml_payload_rejects_missing_disasm` 后面：

```python
    def test_validate_reference_yaml_payload_preserves_optional_funcs(self) -> None:
        payload = ida_reference_export.validate_reference_yaml_payload(
            {
                "func_name": "ObpEnumFindHandleProcedure",
                "func_va": "0x1406c6cd0",
                "disasm_code": "mov rax, rcx",
                "procedure": "",
                "optional_funcs": ["ExGetHandlePointer"],
            }
        )

        self.assertEqual("ObpEnumFindHandleProcedure", payload["func_name"])
        self.assertEqual(["ExGetHandlePointer"], payload["optional_funcs"])
```

- [ ] **Step 2: 写非法 optional_funcs 的失败测试**

继续在 `TestIdaReferenceExport` 中加入：

```python
    def test_validate_reference_yaml_payload_rejects_invalid_optional_funcs(self) -> None:
        invalid_values = [
            "ExGetHandlePointer",
            ["ExGetHandlePointer", ""],
            ["ExGetHandlePointer", 123],
            [""],
        ]

        for optional_funcs in invalid_values:
            with self.subTest(optional_funcs=optional_funcs):
                with self.assertRaisesRegex(
                    ida_reference_export.ReferenceGenerationError,
                    "invalid reference YAML payload",
                ):
                    ida_reference_export.validate_reference_yaml_payload(
                        {
                            "func_name": "ObpEnumFindHandleProcedure",
                            "func_va": "0x1406c6cd0",
                            "disasm_code": "mov rax, rcx",
                            "procedure": "",
                            "optional_funcs": optional_funcs,
                        }
                    )
```

- [ ] **Step 3: 运行测试确认当前失败**

Run:

```bash
uv run python -m unittest tests.test_ida_reference_export.TestIdaReferenceExport.test_validate_reference_yaml_payload_preserves_optional_funcs tests.test_ida_reference_export.TestIdaReferenceExport.test_validate_reference_yaml_payload_rejects_invalid_optional_funcs -v
```

Expected:

```text
FAIL: test_validate_reference_yaml_payload_preserves_optional_funcs
KeyError: 'optional_funcs'
```

The invalid test may also fail because current validation ignores `optional_funcs`.

- [ ] **Step 4: 实现 optional_funcs 校验 helper**

在 `ida_reference_export.py` 中，放在 `_normalize_address_text(...)` 后面：

```python
def _normalize_optional_func_names(value: Any) -> list[str] | None:
    if value is None:
        return []
    if not isinstance(value, list):
        return None

    names: list[str] = []
    for item in value:
        if not isinstance(item, str):
            return None
        name = item.strip()
        if not name:
            return None
        names.append(name)
    return names
```

- [ ] **Step 5: 修改 validate_reference_yaml_payload**

把 `validate_reference_yaml_payload(...)` 的签名和主体调整为：

```python
def validate_reference_yaml_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    func_name = _normalize_non_empty_text(payload.get("func_name"))
    func_va = _normalize_address_text(payload.get("func_va"))
    disasm_code = _normalize_non_empty_text(payload.get("disasm_code"))
    procedure_raw = payload.get("procedure", "")
    optional_funcs = _normalize_optional_func_names(payload.get("optional_funcs"))
    if (
        func_name is None
        or func_va is None
        or disasm_code is None
        or optional_funcs is None
    ):
        raise ReferenceGenerationError("invalid reference YAML payload")
    if procedure_raw is None:
        procedure = ""
    elif isinstance(procedure_raw, str):
        procedure = procedure_raw
    else:
        raise ReferenceGenerationError("invalid reference YAML payload")

    result: dict[str, Any] = {
        "func_name": func_name,
        "func_va": func_va,
        "disasm_code": disasm_code,
        "procedure": procedure,
    }
    if optional_funcs:
        result["optional_funcs"] = optional_funcs
    return result
```

- [ ] **Step 6: 运行 reference export 定向测试**

Run:

```bash
uv run python -m unittest tests.test_ida_reference_export -v
```

Expected:

```text
OK
```

- [ ] **Step 7: 提交 Task 1**

```bash
git add ida_reference_export.py tests/test_ida_reference_export.py
git commit -m "feat: 支持reference可选函数字段"
```

### Task 2: 请求准备阶段合并主函数与 optional function

**Files:**
- Modify: `ida_mcp_resolver.py`
- Test: `tests/test_ida_mcp_resolver.py`

- [ ] **Step 1: 写 target_func_names 合并测试**

在 `tests/test_ida_mcp_resolver.py` 中增加 imports：

```python
from pathlib import Path
from tempfile import TemporaryDirectory
```

在 `TestIdaMcpResolver` 中，放在 `test_llm_decompile_specs_require_four_tuple` 后面：

```python
    def test_prepare_llm_decompile_request_includes_optional_funcs(self) -> None:
        with TemporaryDirectory() as temp_dir:
            scripts_dir = Path(temp_dir)
            (scripts_dir / "prompt").mkdir()
            (scripts_dir / "references" / "ntoskrnl").mkdir(parents=True)
            (scripts_dir / "prompt" / "call_llm_decompile.md").write_text(
                "{reference_blocks}\n{target_blocks}\n{symbol_name_list}",
                encoding="utf-8",
            )
            (scripts_dir / "references" / "ntoskrnl" / "Ref.amd64.yaml").write_text(
                "\n".join(
                    [
                        "func_name: ObpEnumFindHandleProcedure",
                        "func_va: '0x1406c6cd0'",
                        "disasm_code: mov rax, rcx",
                        "procedure: ''",
                        "optional_funcs:",
                        "  - ExGetHandlePointer",
                        "",
                    ]
                ),
                encoding="utf-8",
            )

            with patch.object(
                ida_mcp_resolver,
                "_get_preprocessor_scripts_dir",
                return_value=scripts_dir,
            ):
                request = ida_mcp_resolver._prepare_llm_decompile_request(
                    symbol_name="ObDecodeShift",
                    llm_decompile_specs=[
                        (
                            "ObDecodeShift",
                            "_HANDLE_TABLE_ENTRY->ObjectPointerBits",
                            "prompt/call_llm_decompile.md",
                            "references/ntoskrnl/Ref.{arch}.yaml",
                        )
                    ],
                    llm_config={"model": "test-model", "api_key": "test-key"},
                    binary_dir="/tmp/amd64/ntoskrnl",
                )

        self.assertIsNotNone(request)
        self.assertEqual(
            ["ObpEnumFindHandleProcedure", "ExGetHandlePointer"],
            request["target_func_names"],
        )
        self.assertEqual(
            ["ObpEnumFindHandleProcedure"],
            request["required_target_func_names"],
        )
```

- [ ] **Step 2: 写去重和顺序测试**

继续在 `TestIdaMcpResolver` 中加入：

```python
    def test_prepare_llm_decompile_request_deduplicates_optional_funcs(self) -> None:
        with TemporaryDirectory() as temp_dir:
            scripts_dir = Path(temp_dir)
            (scripts_dir / "prompt").mkdir()
            (scripts_dir / "references" / "ntoskrnl").mkdir(parents=True)
            (scripts_dir / "prompt" / "call_llm_decompile.md").write_text(
                "{reference_blocks}\n{target_blocks}\n{symbol_name_list}",
                encoding="utf-8",
            )
            for ref_name, func_name, optional_func in [
                ("RefA", "PrimaryA", "SharedHelper"),
                ("RefB", "PrimaryB", "SharedHelper"),
            ]:
                (scripts_dir / "references" / "ntoskrnl" / f"{ref_name}.amd64.yaml").write_text(
                    "\n".join(
                        [
                            f"func_name: {func_name}",
                            "func_va: '0x140001000'",
                            "disasm_code: mov rax, rcx",
                            "procedure: ''",
                            "optional_funcs:",
                            f"  - {optional_func}",
                            "  - PrimaryA",
                            "",
                        ]
                    ),
                    encoding="utf-8",
                )

            with patch.object(
                ida_mcp_resolver,
                "_get_preprocessor_scripts_dir",
                return_value=scripts_dir,
            ):
                request = ida_mcp_resolver._prepare_llm_decompile_request(
                    symbol_name="ObDecodeShift",
                    llm_decompile_specs=[
                        (
                            "ObDecodeShift",
                            "_HANDLE_TABLE_ENTRY->ObjectPointerBits",
                            "prompt/call_llm_decompile.md",
                            "references/ntoskrnl/RefA.{arch}.yaml",
                        ),
                        (
                            "ObDecodeShift",
                            "_HANDLE_TABLE_ENTRY->ObjectPointerBits",
                            "prompt/call_llm_decompile.md",
                            "references/ntoskrnl/RefB.{arch}.yaml",
                        ),
                    ],
                    llm_config={"model": "test-model", "api_key": "test-key"},
                    binary_dir="/tmp/amd64/ntoskrnl",
                )

        self.assertIsNotNone(request)
        self.assertEqual(
            ["PrimaryA", "SharedHelper", "PrimaryB"],
            request["target_func_names"],
        )
        self.assertEqual(["PrimaryA", "PrimaryB"], request["required_target_func_names"])
```

- [ ] **Step 3: 运行测试确认当前失败**

Run:

```bash
uv run python -m unittest tests.test_ida_mcp_resolver.TestIdaMcpResolver.test_prepare_llm_decompile_request_includes_optional_funcs tests.test_ida_mcp_resolver.TestIdaMcpResolver.test_prepare_llm_decompile_request_deduplicates_optional_funcs -v
```

Expected:

```text
KeyError: 'required_target_func_names'
```

or an assertion showing `target_func_names` does not contain optional functions.

- [ ] **Step 4: 新增有序去重 helper**

在 `ida_mcp_resolver.py` 中，放在 `_load_reference_item(...)` 前面：

```python
def _append_unique_text(items: list[str], seen: set[str], value: Any) -> None:
    text = str(value or "").strip()
    if not text or text in seen:
        return
    seen.add(text)
    items.append(text)
```

- [ ] **Step 5: 修改 _prepare_llm_decompile_request 的 target name 组装**

在 `_prepare_llm_decompile_request(...)` 中，把当前的：

```python
    target_func_names: list[str] = []
```

替换为：

```python
    target_func_names: list[str] = []
    required_target_func_names: list[str] = []
    seen_target_func_names: set[str] = set()
```

在 `for spec in llm_specs:` 循环中，加载 `reference_item` 后，把当前：

```python
        target_func_names.append(reference_item["func_name"])
```

替换为：

```python
        required_func_name = reference_item["func_name"]
        required_target_func_names.append(required_func_name)
        _append_unique_text(
            target_func_names,
            seen_target_func_names,
            required_func_name,
        )
        for optional_func_name in reference_item.get("optional_funcs", []):
            _append_unique_text(
                target_func_names,
                seen_target_func_names,
                optional_func_name,
            )
```

在 return dict 中加入：

```python
        "required_target_func_names": required_target_func_names,
```

- [ ] **Step 6: 运行 mcp resolver 定向测试**

Run:

```bash
uv run python -m unittest tests.test_ida_mcp_resolver.TestIdaMcpResolver.test_prepare_llm_decompile_request_includes_optional_funcs tests.test_ida_mcp_resolver.TestIdaMcpResolver.test_prepare_llm_decompile_request_deduplicates_optional_funcs -v
```

Expected:

```text
OK
```

- [ ] **Step 7: 提交 Task 2**

```bash
git add ida_mcp_resolver.py tests/test_ida_mcp_resolver.py
git commit -m "feat: 合并LLM可选目标函数"
```

### Task 3: 主函数必需，optional function 可跳过

**Files:**
- Modify: `ida_mcp_resolver.py`
- Test: `tests/test_ida_mcp_resolver.py`

- [ ] **Step 1: 写 optional 缺失仍继续的测试**

在 `TestIdaMcpResolver` 中加入：

```python
    async def test_resolve_symbol_via_llm_decompile_skips_missing_optional_target(
        self,
    ) -> None:
        with (
            patch.object(
                ida_mcp_resolver,
                "_prepare_llm_decompile_request",
                return_value={
                    "prepared": True,
                    "llm_symbol_name": "_HANDLE_TABLE_ENTRY->ObjectPointerBits",
                    "llm_symbol_names": ["_HANDLE_TABLE_ENTRY->ObjectPointerBits"],
                    "target_func_names": [
                        "ObpEnumFindHandleProcedure",
                        "ExGetHandlePointer",
                    ],
                    "required_target_func_names": ["ObpEnumFindHandleProcedure"],
                    "reference_items": [
                        {
                            "func_name": "ObpEnumFindHandleProcedure",
                            "func_va": "0x1406c6cd0",
                            "disasm_code": "reference disasm",
                            "procedure": "",
                        }
                    ],
                    "prompt_template": "{reference_blocks}\n{target_blocks}\n{symbol_name_list}",
                    "prompt_path": "/tmp/prompt.md",
                    "reference_paths": ["/tmp/ref.yaml"],
                    "arch": "amd64",
                },
            ),
            patch.object(
                ida_mcp_resolver,
                "_load_llm_decompile_target_details_via_mcp",
                AsyncMock(
                    return_value=[
                        {
                            "func_name": "ObpEnumFindHandleProcedure",
                            "func_va": "0x1406c6cd0",
                            "disasm_code": "target disasm",
                            "procedure": "",
                        }
                    ]
                ),
            ) as mock_load_targets,
            patch.object(
                ida_mcp_resolver,
                "call_llm_decompile",
                AsyncMock(
                    return_value={
                        "found_call": [],
                        "found_gv": [],
                        "found_struct_offset": [
                            {
                                "insn_va": "0x1406c6ce2",
                                "insn_disasm": "sar r8, 10h",
                                "offset": "0x0",
                                "bit_offset": "20",
                                "struct_name": "_HANDLE_TABLE_ENTRY",
                                "member_name": "ObjectPointerBits",
                            }
                        ],
                    }
                ),
            ) as mock_call,
        ):
            payload = await ida_mcp_resolver.resolve_symbol_via_llm_decompile(
                session=AsyncMock(),
                symbol_name="ObDecodeShift",
                category="struct_offset",
                binary_dir="/tmp/amd64/ntoskrnl",
                image_base=0x140000000,
                llm_decompile_specs=[],
                llm_config={"model": "test-model", "api_key": "test-key"},
                struct_metadata={
                    "struct_name": "_HANDLE_TABLE_ENTRY",
                    "member_name": "ObjectPointerBits",
                    "bits": True,
                },
            )

        self.assertEqual(
            {
                "struct_name": "_HANDLE_TABLE_ENTRY",
                "member_name": "ObjectPointerBits",
                "offset": 0,
                "bit_offset": 20,
            },
            payload,
        )
        self.assertEqual(
            ["ObpEnumFindHandleProcedure", "ExGetHandlePointer"],
            mock_load_targets.await_args.args[1],
        )
        mock_call.assert_awaited_once()
```

- [ ] **Step 2: 写主函数缺失失败的测试**

继续在 `TestIdaMcpResolver` 中加入：

```python
    async def test_resolve_symbol_via_llm_decompile_fails_when_required_target_missing(
        self,
    ) -> None:
        with (
            patch.object(
                ida_mcp_resolver,
                "_prepare_llm_decompile_request",
                return_value={
                    "prepared": True,
                    "llm_symbol_name": "_HANDLE_TABLE_ENTRY->ObjectPointerBits",
                    "llm_symbol_names": ["_HANDLE_TABLE_ENTRY->ObjectPointerBits"],
                    "target_func_names": [
                        "ObpEnumFindHandleProcedure",
                        "ExGetHandlePointer",
                    ],
                    "required_target_func_names": ["ObpEnumFindHandleProcedure"],
                    "reference_items": [],
                    "prompt_template": "{reference_blocks}\n{target_blocks}\n{symbol_name_list}",
                    "prompt_path": "/tmp/prompt.md",
                    "reference_paths": ["/tmp/ref.yaml"],
                    "arch": "amd64",
                },
            ),
            patch.object(
                ida_mcp_resolver,
                "_load_llm_decompile_target_details_via_mcp",
                AsyncMock(
                    return_value=[
                        {
                            "func_name": "ExGetHandlePointer",
                            "func_va": "0x1406c7000",
                            "disasm_code": "helper disasm",
                            "procedure": "",
                        }
                    ]
                ),
            ),
            patch.object(
                ida_mcp_resolver,
                "call_llm_decompile",
                AsyncMock(),
            ) as mock_call,
        ):
            payload = await ida_mcp_resolver.resolve_symbol_via_llm_decompile(
                session=AsyncMock(),
                symbol_name="ObDecodeShift",
                category="struct_offset",
                binary_dir="/tmp/amd64/ntoskrnl",
                image_base=0x140000000,
                llm_decompile_specs=[],
                llm_config={"model": "test-model", "api_key": "test-key"},
                struct_metadata={
                    "struct_name": "_HANDLE_TABLE_ENTRY",
                    "member_name": "ObjectPointerBits",
                    "bits": True,
                },
            )

        self.assertIsNone(payload)
        mock_call.assert_not_awaited()
```

- [ ] **Step 3: 运行测试确认主函数缺失测试失败**

Run:

```bash
uv run python -m unittest tests.test_ida_mcp_resolver.TestIdaMcpResolver.test_resolve_symbol_via_llm_decompile_skips_missing_optional_target tests.test_ida_mcp_resolver.TestIdaMcpResolver.test_resolve_symbol_via_llm_decompile_fails_when_required_target_missing -v
```

Expected:

```text
FAIL: test_resolve_symbol_via_llm_decompile_fails_when_required_target_missing
AssertionError: Expected 'call_llm_decompile' to not have been awaited.
```

- [ ] **Step 4: 新增 required target 检查 helper**

在 `ida_mcp_resolver.py` 中，放在 `_load_llm_decompile_target_details_via_mcp(...)` 后面：

```python
def _has_all_required_target_details(
    target_items: list[dict[str, Any]],
    required_target_func_names: list[str],
) -> bool:
    available_names = {
        str(item.get("func_name", "")).strip()
        for item in target_items
        if str(item.get("func_name", "")).strip()
    }
    return all(name in available_names for name in required_target_func_names)
```

- [ ] **Step 5: 在 resolve_symbol_via_llm_decompile 中检查 required target**

在 `resolve_symbol_via_llm_decompile(...)` 中，`target_items = await _load_llm_decompile_target_details_via_mcp(...)` 后面，替换当前只检查空列表的逻辑为：

```python
        target_func_names = request.get("target_func_names", [])
        required_target_func_names = [
            str(name).strip()
            for name in request.get("required_target_func_names", target_func_names)
            if str(name).strip()
        ]
        if not target_items and target_func_names:
            _debug_log(
                debug,
                f"llm_decompile skipped for {symbol_name}: no target function details",
            )
            return None
        if not _has_all_required_target_details(
            target_items,
            required_target_func_names,
        ):
            _debug_log(
                debug,
                f"llm_decompile skipped for {symbol_name}: missing required target function details",
            )
            return None
```

注意：调用 `_load_llm_decompile_target_details_via_mcp(...)` 时继续传 `request.get("target_func_names", [])`，不要只传 required 列表。

- [ ] **Step 6: 运行 Task 3 定向测试**

Run:

```bash
uv run python -m unittest tests.test_ida_mcp_resolver.TestIdaMcpResolver.test_resolve_symbol_via_llm_decompile_skips_missing_optional_target tests.test_ida_mcp_resolver.TestIdaMcpResolver.test_resolve_symbol_via_llm_decompile_fails_when_required_target_missing -v
```

Expected:

```text
OK
```

- [ ] **Step 7: 提交 Task 3**

```bash
git add ida_mcp_resolver.py tests/test_ida_mcp_resolver.py
git commit -m "fix: 区分LLM必需与可选目标函数"
```

### Task 4: Prompt 中每个反汇编块标注函数名

**Files:**
- Modify: `ida_mcp_resolver.py`
- Test: `tests/test_ida_mcp_resolver.py`

- [ ] **Step 1: 写 prompt 标注测试**

在 `TestIdaMcpResolver` 中加入：

```python
    async def test_call_llm_decompile_labels_each_disassembly_with_func_name(self) -> None:
        prompt_template = (
            ida_mcp_resolver._get_preprocessor_scripts_dir()
            / "prompt"
            / "call_llm_decompile.md"
        ).read_text(encoding="utf-8")
        with patch.object(
            ida_mcp_resolver,
            "call_llm_text",
            AsyncMock(return_value="found_struct_offset: []\n"),
        ) as mock_call:
            await ida_mcp_resolver.call_llm_decompile(
                llm_config={"model": "test-model", "api_key": "test-key"},
                symbol_name_list=["_HANDLE_TABLE_ENTRY->ObjectPointerBits"],
                reference_items=[
                    {
                        "func_name": "ObpEnumFindHandleProcedure",
                        "disasm_code": "reference disasm",
                        "procedure": "reference proc",
                    }
                ],
                target_items=[
                    {
                        "func_name": "ObpEnumFindHandleProcedure",
                        "disasm_code": "target primary disasm",
                        "procedure": "target primary proc",
                    },
                    {
                        "func_name": "ExGetHandlePointer",
                        "disasm_code": "target helper disasm",
                        "procedure": "target helper proc",
                    },
                ],
                prompt_template=prompt_template,
            )

        prompt = mock_call.await_args.kwargs["prompt"]
        self.assertIn("**Disassembly for ObpEnumFindHandleProcedure**", prompt)
        self.assertIn("; Function: ObpEnumFindHandleProcedure", prompt)
        self.assertIn("**Disassembly for ExGetHandlePointer**", prompt)
        self.assertIn("; Function: ExGetHandlePointer", prompt)
        self.assertLess(
            prompt.index("; Function: ObpEnumFindHandleProcedure"),
            prompt.index("target primary disasm"),
        )
        self.assertLess(
            prompt.index("; Function: ExGetHandlePointer"),
            prompt.index("target helper disasm"),
        )
```

- [ ] **Step 2: 运行测试确认当前失败**

Run:

```bash
uv run python -m unittest tests.test_ida_mcp_resolver.TestIdaMcpResolver.test_call_llm_decompile_labels_each_disassembly_with_func_name -v
```

Expected:

```text
FAIL: test_call_llm_decompile_labels_each_disassembly_with_func_name
AssertionError: '**Disassembly for ObpEnumFindHandleProcedure**' not found
```

- [ ] **Step 3: 修改 _render_llm_decompile_blocks**

把 `_render_llm_decompile_blocks(...)` 内部 `_render(...)` 的 return 替换为：

```python
        return (
            f"### {kind} Function: {func_name}\n\n"
            f"**Disassembly for {func_name}**\n\n"
            f"```c\n; Function: {func_name}\n{disasm_code}\n```\n\n"
            f"**Procedure for {func_name}**\n\n"
            f"```c\n{procedure}\n```"
        )
```

- [ ] **Step 4: 运行 prompt 渲染相关测试**

Run:

```bash
uv run python -m unittest tests.test_ida_mcp_resolver.TestIdaMcpResolver.test_call_llm_decompile_uses_cs2_prompt_template tests.test_ida_mcp_resolver.TestIdaMcpResolver.test_call_llm_decompile_debug_prints_prompt_and_raw_response tests.test_ida_mcp_resolver.TestIdaMcpResolver.test_call_llm_decompile_renders_multiple_symbols tests.test_ida_mcp_resolver.TestIdaMcpResolver.test_call_llm_decompile_labels_each_disassembly_with_func_name -v
```

Expected:

```text
OK
```

- [ ] **Step 5: 提交 Task 4**

```bash
git add ida_mcp_resolver.py tests/test_ida_mcp_resolver.py
git commit -m "feat: 标注LLM目标反汇编函数名"
```

### Task 5: 回归验证与收尾

**Files:**
- Verify: `ida_reference_export.py`
- Verify: `ida_mcp_resolver.py`
- Verify: `tests/test_ida_reference_export.py`
- Verify: `tests/test_ida_mcp_resolver.py`

- [ ] **Step 1: 运行相关 unittest**

Run:

```bash
uv run python -m unittest tests.test_ida_reference_export tests.test_ida_mcp_resolver -v
```

Expected:

```text
OK
```

- [ ] **Step 2: 检查目标 reference YAML 不需要修改**

Run:

```bash
git diff -- ida_preprocessor_scripts/find-ObAttributesShift-AND-ObDecodeShift.py ida_preprocessor_scripts/references/ntoskrnl/ObpEnumFindHandleProcedure.amd64.yaml ida_preprocessor_scripts/prompt/call_llm_decompile.md
```

Expected:

```text
```

No output.

- [ ] **Step 3: 检查最终 diff**

Run:

```bash
git diff --stat HEAD
git status --short
```

Expected:

```text
```

No output if each task commit has already been created. If running all tasks without committing between them, expected changed files are only:

```text
ida_reference_export.py
ida_mcp_resolver.py
tests/test_ida_reference_export.py
tests/test_ida_mcp_resolver.py
```

- [ ] **Step 4: 汇总验收点**

在最终回复中明确报告：

```text
已实现：
- reference YAML 合法 optional_funcs 会被保留
- _prepare_llm_decompile_request 会把主函数和 optional_funcs 合并为 target_func_names
- required_target_func_names 只包含主 reference 函数
- optional function 缺失时跳过，主函数缺失时失败
- prompt 中每个函数反汇编块都会标注函数名

验证：
- uv run python -m unittest tests.test_ida_reference_export tests.test_ida_mcp_resolver -v
```

## Self-Review

Spec 覆盖：

- `optional_funcs` schema：Task 1 覆盖。
- 当前 IDB 存在时加入 `{target_blocks}`：Task 2 和 Task 3 覆盖 target list 与导出调用。
- optional 缺失不失败：Task 3 覆盖。
- 主 reference 函数仍为必需：Task 3 覆盖。
- 反汇编块头部标注函数名：Task 4 覆盖。
- 不修改 finder、reference YAML、prompt 模板：Task 5 检查。

占位符扫描：

- 本计划未使用未定义的占位内容。
- 每个实现步骤均列出具体文件、代码片段、命令和预期结果。

类型一致性：

- `validate_reference_yaml_payload(...)` 返回 `dict[str, Any]`，允许 `optional_funcs: list[str]`。
- `_prepare_llm_decompile_request(...)` 返回 `target_func_names` 与 `required_target_func_names`，后续 `resolve_symbol_via_llm_decompile(...)` 读取同名字段。
- Prompt 渲染只改变文本，不改变 target item schema。
