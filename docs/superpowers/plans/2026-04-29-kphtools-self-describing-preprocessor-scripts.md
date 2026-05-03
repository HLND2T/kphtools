# kphtools Self-Describing Preprocessor Scripts Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move all `struct_offset`, `gv`, and `func` locating metadata out of `config.yaml` and into self-describing `find-*.py` preprocessor scripts that call a shared `preprocess_common_skill(...)` interface.

**Architecture:** Keep `dump_symbols.py` and `ida_skill_preprocessor.py` as dispatch layers, add a narrow `ida_preprocessor_common.py` that owns category routing, and demote the current `generic_*` modules into helper-only modules. Preserve the current YAML artifact schema and use script-side `GENERATE_YAML_DESIRED_FIELDS` declarations to make output contracts explicit.

**Tech Stack:** Python 3, `unittest`, `PyYAML`, `ida-pro-mcp`, existing `pdb_resolver.py`, `ida_mcp_resolver.py`, and `symbol_artifacts.py`

---

### Task 1: Tighten Config Contract

**Files:**
- Modify: `config.yaml`
- Modify: `symbol_config.py`
- Test: `tests/test_symbol_config.py`

- [ ] **Step 1: Write the failing config-contract tests**

```python
def test_load_config_reads_minimal_symbol_inventory(self) -> None:
    with TemporaryDirectory() as temp_dir:
        config_path = Path(temp_dir) / "config.yaml"
        config_path.write_text(
            textwrap.dedent(
                """
                modules:
                  - name: ntoskrnl
                    path: [ntoskrnl.exe]
                    skills:
                      - name: find-EgeGuid
                        symbol: EgeGuid
                        expected_output: [EgeGuid.yaml]
                    symbols:
                      - name: EgeGuid
                        category: struct_offset
                        data_type: uint16
                """
            ).strip()
            + "\n",
            encoding="utf-8",
        )

        config = symbol_config.load_config(config_path)

    self.assertEqual("EgeGuid", config.modules[0].skills[0].symbol)
    self.assertEqual("struct_offset", config.modules[0].symbols[0].category)
    self.assertFalse(hasattr(config.modules[0].symbols[0], "symbol_expr"))


def test_load_config_rejects_symbol_locating_fields(self) -> None:
    with TemporaryDirectory() as temp_dir:
        config_path = Path(temp_dir) / "config.yaml"
        config_path.write_text(
            textwrap.dedent(
                """
                modules:
                  - name: ntoskrnl
                    path: [ntoskrnl.exe]
                    skills:
                      - name: find-EgeGuid
                        symbol: EgeGuid
                        expected_output: [EgeGuid.yaml]
                    symbols:
                      - name: EgeGuid
                        category: struct_offset
                        data_type: uint16
                        symbol_expr: _ETW_GUID_ENTRY->Guid
                """
            ).strip()
            + "\n",
            encoding="utf-8",
        )

        with self.assertRaisesRegex(ValueError, "symbol.symbol_expr"):
            symbol_config.load_config(config_path)
```

- [ ] **Step 2: Run the targeted tests to verify they fail**

Run: `uv run python -m unittest tests.test_symbol_config.TestSymbolConfig.test_load_config_reads_minimal_symbol_inventory tests.test_symbol_config.TestSymbolConfig.test_load_config_rejects_symbol_locating_fields -v`

Expected: FAIL because `SymbolSpec` still exposes locating fields and `_load_symbol(...)` still accepts `symbol_expr`.

- [ ] **Step 3: Implement the minimal config changes**

```python
@dataclass(frozen=True)
class SymbolSpec:
    name: str
    category: str
    data_type: str


def _load_symbol(entry: dict[str, Any]) -> SymbolSpec:
    forbidden_fields = (
        "symbol_expr",
        "struct_name",
        "member_name",
        "bits",
        "alias",
    )
    for field_name in forbidden_fields:
        if field_name in entry:
            raise ValueError(f"symbol.{field_name} is not supported; move it to the skill script")

    return SymbolSpec(
        name=_require_non_empty_string(entry, "name", "symbol"),
        category=_require_non_empty_string(entry, "category", "symbol"),
        data_type=_require_non_empty_string(entry, "data_type", "symbol"),
    )
```

```yaml
symbols:
  - name: EgeGuid
    category: struct_offset
    data_type: uint16
  - name: PspCreateProcessNotifyRoutine
    category: gv
    data_type: uint32
  - name: ExReferenceCallBackBlock
    category: func
    data_type: uint32
```

- [ ] **Step 4: Run the targeted tests to verify they pass**

Run: `uv run python -m unittest tests.test_symbol_config.TestSymbolConfig.test_load_config_reads_minimal_symbol_inventory tests.test_symbol_config.TestSymbolConfig.test_load_config_rejects_symbol_locating_fields -v`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add config.yaml symbol_config.py tests/test_symbol_config.py
git commit -m "refactor(config): 收紧符号配置契约"
```

### Task 2: Add the Shared Preprocessor Entry

**Files:**
- Create: `ida_preprocessor_common.py`
- Modify: `ida_preprocessor_scripts/generic_struct_offset.py`
- Modify: `ida_preprocessor_scripts/generic_gv.py`
- Modify: `ida_preprocessor_scripts/generic_func.py`
- Test: `tests/test_ida_preprocessor_common.py`

- [ ] **Step 1: Write the failing shared-entry tests**

```python
class TestIdaPreprocessorCommon(unittest.IsolatedAsyncioTestCase):
    async def test_preprocess_common_skill_uses_struct_script_metadata(self) -> None:
        with TemporaryDirectory() as temp_dir, patch(
            "ida_preprocessor_common.preprocess_struct_symbol",
            new=AsyncMock(
                return_value={
                    "struct_name": "_ETW_GUID_ENTRY",
                    "member_name": "Guid",
                    "offset": 0x10,
                }
            ),
        ):
            status = await ida_preprocessor_common.preprocess_common_skill(
                session=AsyncMock(),
                skill=SimpleNamespace(name="find-EgeGuid", symbol="EgeGuid"),
                symbol=SimpleNamespace(name="EgeGuid", category="struct_offset", data_type="uint16"),
                binary_dir=Path(temp_dir),
                pdb_path=Path(temp_dir) / "ntkrnlmp.pdb",
                debug=False,
                llm_config=None,
                struct_member_names=["EgeGuid"],
                struct_metadata={
                    "EgeGuid": {
                        "symbol_expr": "_ETW_GUID_ENTRY->Guid",
                        "struct_name": "_ETW_GUID_ENTRY",
                        "member_name": "Guid",
                        "bits": False,
                    }
                },
                generate_yaml_desired_fields={
                    "EgeGuid": ["struct_name", "member_name", "offset"]
                },
            )

        self.assertEqual("success", status)

    async def test_preprocess_common_skill_filters_gv_fields(self) -> None:
        with TemporaryDirectory() as temp_dir, patch(
            "ida_preprocessor_common.preprocess_gv_symbol",
            new=AsyncMock(return_value={"gv_name": "PspCreateProcessNotifyRoutine", "gv_rva": 0x45678, "unused": 1}),
        ):
            status = await ida_preprocessor_common.preprocess_common_skill(
                session=AsyncMock(),
                skill=SimpleNamespace(name="find-PspCreateProcessNotifyRoutine", symbol="PspCreateProcessNotifyRoutine"),
                symbol=SimpleNamespace(name="PspCreateProcessNotifyRoutine", category="gv", data_type="uint32"),
                binary_dir=Path(temp_dir),
                pdb_path=Path(temp_dir) / "ntkrnlmp.pdb",
                debug=False,
                llm_config=None,
                gv_names=["PspCreateProcessNotifyRoutine"],
                gv_metadata={"PspCreateProcessNotifyRoutine": {"alias": ["PspCreateProcessNotifyRoutine"]}},
                generate_yaml_desired_fields={
                    "PspCreateProcessNotifyRoutine": ["gv_name", "gv_rva"]
                },
            )

        self.assertEqual("success", status)
        payload = load_artifact(Path(temp_dir) / "PspCreateProcessNotifyRoutine.yaml")
        self.assertEqual({"category", "gv_name", "gv_rva"}, set(payload.keys()))
```

- [ ] **Step 2: Run the targeted tests to verify they fail**

Run: `uv run python -m unittest tests.test_ida_preprocessor_common -v`

Expected: FAIL with `ModuleNotFoundError: No module named 'ida_preprocessor_common'`

- [ ] **Step 3: Implement the shared entry and helper exports**

```python
ALLOWED_FIELDS_BY_CATEGORY = {
    "struct_offset": {"struct_name", "member_name", "offset", "bit_offset"},
    "gv": {"gv_name", "gv_rva"},
    "func": {"func_name", "func_rva"},
}


async def preprocess_common_skill(
    *,
    session,
    skill,
    symbol,
    binary_dir,
    pdb_path,
    debug,
    llm_config,
    struct_member_names=None,
    struct_metadata=None,
    gv_names=None,
    gv_metadata=None,
    func_names=None,
    func_metadata=None,
    generate_yaml_desired_fields=None,
):
    desired_fields = set((generate_yaml_desired_fields or {}).get(skill.symbol, []))
    if skill.symbol != symbol.name:
        return PREPROCESS_STATUS_FAILED

    if symbol.category == "struct_offset":
        metadata = (struct_metadata or {}).get(skill.symbol)
        payload = await preprocess_struct_symbol(
            session=session,
            symbol_name=skill.symbol,
            metadata=metadata,
            binary_dir=binary_dir,
            pdb_path=pdb_path,
            debug=debug,
            llm_config=llm_config,
        )
        write_struct_yaml(artifact_path(binary_dir, skill.symbol), _filter_payload(payload, desired_fields, symbol.category))
        return PREPROCESS_STATUS_SUCCESS

    if symbol.category == "gv":
        metadata = (gv_metadata or {}).get(skill.symbol, {})
        payload = await preprocess_gv_symbol(
            session=session,
            symbol_name=skill.symbol,
            alias_names=metadata.get("alias", [skill.symbol]),
            pdb_path=pdb_path,
        )
        write_gv_yaml(artifact_path(binary_dir, skill.symbol), _filter_payload(payload, desired_fields, symbol.category))
        return PREPROCESS_STATUS_SUCCESS

    if symbol.category == "func":
        metadata = (func_metadata or {}).get(skill.symbol, {})
        payload = await preprocess_func_symbol(
            session=session,
            symbol_name=skill.symbol,
            alias_names=metadata.get("alias", [skill.symbol]),
            pdb_path=pdb_path,
        )
        write_func_yaml(artifact_path(binary_dir, skill.symbol), _filter_payload(payload, desired_fields, symbol.category))
        return PREPROCESS_STATUS_SUCCESS

    return PREPROCESS_STATUS_FAILED
```

```python
async def preprocess_struct_symbol(*, session, symbol_name, metadata, binary_dir, pdb_path, debug, llm_config):
    helper_symbol = SimpleNamespace(
        name=symbol_name,
        category="struct_offset",
        data_type="uint16",
        symbol_expr=metadata["symbol_expr"],
        struct_name=metadata["struct_name"],
        member_name=metadata["member_name"],
        bits=metadata.get("bits", False),
    )
    return await build_struct_payload(
        session=session,
        symbol=helper_symbol,
        pdb_path=pdb_path,
        debug=debug,
        llm_config=llm_config,
    )


async def preprocess_gv_symbol(*, session, symbol_name, alias_names, pdb_path):
    return await build_gv_payload(
        session=session,
        symbol_name=symbol_name,
        alias_names=alias_names,
        pdb_path=pdb_path,
    )


async def preprocess_func_symbol(*, session, symbol_name, alias_names, pdb_path):
    return await build_func_payload(
        session=session,
        symbol_name=symbol_name,
        alias_names=alias_names,
        pdb_path=pdb_path,
    )
```

- [ ] **Step 4: Run the targeted tests to verify they pass**

Run: `uv run python -m unittest tests.test_ida_preprocessor_common -v`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add ida_preprocessor_common.py ida_preprocessor_scripts/generic_struct_offset.py ida_preprocessor_scripts/generic_gv.py ida_preprocessor_scripts/generic_func.py tests/test_ida_preprocessor_common.py
git commit -m "refactor(preprocess): 提取公共预处理入口"
```

### Task 3: Migrate One Script Per Category and Update Dispatch Tests

**Files:**
- Create: `ida_preprocessor_scripts/find-EgeGuid.py`
- Create: `ida_preprocessor_scripts/find-PspCreateProcessNotifyRoutine.py`
- Create: `ida_preprocessor_scripts/find-ExReferenceCallBackBlock.py`
- Modify: `tests/test_ida_skill_preprocessor.py`

- [ ] **Step 1: Write the failing dispatch tests**

```python
async def test_find_EgeGuid_dispatches_through_preprocess_common_skill(self) -> None:
    with TemporaryDirectory() as temp_dir, patch(
        "ida_preprocessor_common.preprocess_common_skill",
        new=AsyncMock(return_value=ida_skill_preprocessor.PREPROCESS_STATUS_SUCCESS),
    ) as mock_common:
        status = await ida_skill_preprocessor.preprocess_single_skill_via_mcp(
            session=AsyncMock(),
            skill=SkillSpec(name="find-EgeGuid", symbol="EgeGuid", expected_output=["EgeGuid.yaml"], expected_input=[]),
            symbol=SymbolSpec(name="EgeGuid", category="struct_offset", data_type="uint16"),
            binary_dir=Path(temp_dir),
            pdb_path=Path(temp_dir) / "ntkrnlmp.pdb",
            debug=False,
            llm_config=None,
        )

    self.assertEqual(ida_skill_preprocessor.PREPROCESS_STATUS_SUCCESS, status)
    self.assertEqual(["EgeGuid"], mock_common.await_args.kwargs["struct_member_names"])
```

- [ ] **Step 2: Run the targeted tests to verify they fail**

Run: `uv run python -m unittest tests.test_ida_skill_preprocessor.TestIdaSkillPreprocessor.test_find_EgeGuid_dispatches_through_preprocess_common_skill -v`

Expected: FAIL because `find-EgeGuid.py` is still a thin wrapper around `generic_struct_offset`

- [ ] **Step 3: Implement the three sample scripts**

```python
import ida_preprocessor_common as preprocessor_common

TARGET_STRUCT_MEMBER_NAMES = ["EgeGuid"]

STRUCT_METADATA = {
    "EgeGuid": {
        "symbol_expr": "_ETW_GUID_ENTRY->Guid",
        "struct_name": "_ETW_GUID_ENTRY",
        "member_name": "Guid",
        "bits": False,
    }
}

GENERATE_YAML_DESIRED_FIELDS = {
    "EgeGuid": ["struct_name", "member_name", "offset", "bit_offset"]
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
        struct_member_names=TARGET_STRUCT_MEMBER_NAMES,
        struct_metadata=STRUCT_METADATA,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
    )
```

```python
import ida_preprocessor_common as preprocessor_common

TARGET_GLOBALVAR_NAMES = ["PspCreateProcessNotifyRoutine"]
GV_METADATA = {
    "PspCreateProcessNotifyRoutine": {"alias": ["PspCreateProcessNotifyRoutine"]}
}
GENERATE_YAML_DESIRED_FIELDS = {
    "PspCreateProcessNotifyRoutine": ["gv_name", "gv_rva"]
}
```

```python
import ida_preprocessor_common as preprocessor_common

TARGET_FUNCTION_NAMES = ["ExReferenceCallBackBlock"]
FUNC_METADATA = {
    "ExReferenceCallBackBlock": {"alias": ["ExReferenceCallBackBlock"]}
}
GENERATE_YAML_DESIRED_FIELDS = {
    "ExReferenceCallBackBlock": ["func_name", "func_rva"]
}
```

- [ ] **Step 4: Run the targeted tests to verify they pass**

Run: `uv run python -m unittest tests.test_ida_skill_preprocessor -v`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add ida_preprocessor_scripts/find-EgeGuid.py ida_preprocessor_scripts/find-PspCreateProcessNotifyRoutine.py ida_preprocessor_scripts/find-ExReferenceCallBackBlock.py tests/test_ida_skill_preprocessor.py
git commit -m "refactor(scripts): 迁移样板预处理脚本"
```

### Task 4: Bulk-Migrate the Remaining Scripts and Structural Smoke Coverage

**Files:**
- Modify: `ida_preprocessor_scripts/find-EpObjectTable.py`
- Modify: `ida_preprocessor_scripts/find-EreGuidEntry.py`
- Modify: `ida_preprocessor_scripts/find-HtHandleContentionEvent.py`
- Modify: `ida_preprocessor_scripts/find-OtName.py`
- Modify: `ida_preprocessor_scripts/find-OtIndex.py`
- Modify: `ida_preprocessor_scripts/find-ObDecodeShift.py`
- Modify: `ida_preprocessor_scripts/find-ObAttributesShift.py`
- Modify: `ida_preprocessor_scripts/find-AlpcCommunicationInfo.py`
- Modify: `ida_preprocessor_scripts/find-AlpcOwnerProcess.py`
- Modify: `ida_preprocessor_scripts/find-AlpcConnectionPort.py`
- Modify: `ida_preprocessor_scripts/find-AlpcServerCommunicationPort.py`
- Modify: `ida_preprocessor_scripts/find-AlpcClientCommunicationPort.py`
- Modify: `ida_preprocessor_scripts/find-AlpcHandleTable.py`
- Modify: `ida_preprocessor_scripts/find-AlpcHandleTableLock.py`
- Modify: `ida_preprocessor_scripts/find-AlpcAttributes.py`
- Modify: `ida_preprocessor_scripts/find-AlpcAttributesFlags.py`
- Modify: `ida_preprocessor_scripts/find-AlpcPortContext.py`
- Modify: `ida_preprocessor_scripts/find-AlpcPortObjectLock.py`
- Modify: `ida_preprocessor_scripts/find-AlpcSequenceNo.py`
- Modify: `ida_preprocessor_scripts/find-AlpcState.py`
- Modify: `ida_preprocessor_scripts/find-KtInitialStack.py`
- Modify: `ida_preprocessor_scripts/find-KtStackLimit.py`
- Modify: `ida_preprocessor_scripts/find-KtStackBase.py`
- Modify: `ida_preprocessor_scripts/find-KtKernelStack.py`
- Modify: `ida_preprocessor_scripts/find-KtReadOperationCount.py`
- Modify: `ida_preprocessor_scripts/find-KtWriteOperationCount.py`
- Modify: `ida_preprocessor_scripts/find-KtOtherOperationCount.py`
- Modify: `ida_preprocessor_scripts/find-KtReadTransferCount.py`
- Modify: `ida_preprocessor_scripts/find-KtWriteTransferCount.py`
- Modify: `ida_preprocessor_scripts/find-KtOtherTransferCount.py`
- Modify: `ida_preprocessor_scripts/find-MmSectionControlArea.py`
- Modify: `ida_preprocessor_scripts/find-MmControlAreaListHead.py`
- Modify: `ida_preprocessor_scripts/find-MmControlAreaLock.py`
- Modify: `ida_preprocessor_scripts/find-EpSectionObject.py`
- Modify: `ida_preprocessor_scripts/find-EpProtection.py`
- Modify: `ida_preprocessor_scripts/find-EpCookie.py`
- Modify: `ida_preprocessor_scripts/find-EpBreakOnTermination.py`
- Modify: `ida_preprocessor_scripts/find-KpDirectoryTableBase.py`
- Modify: `ida_preprocessor_scripts/find-PspLoadImageNotifyRoutine.py`
- Modify: `ida_preprocessor_scripts/find-PspCreateThreadNotifyRoutine.py`
- Modify: `ida_preprocessor_scripts/find-ExDereferenceCallBackBlock.py`
- Modify: `ida_preprocessor_scripts/find-PspEnumerateCallback.py`
- Modify: `ida_preprocessor_scripts/find-CmpEnumerateCallback.py`
- Test: `tests/test_preprocessor_inventory.py`

- [ ] **Step 1: Write the failing structural smoke tests**

```python
class TestPreprocessorInventory(unittest.TestCase):
    def test_every_configured_skill_has_script_and_skill_md(self) -> None:
        config = load_config(Path("config.yaml"))

        for module in config.modules:
            for skill in module.skills:
                script_path = Path("ida_preprocessor_scripts") / f"{skill.name}.py"
                skill_md_path = Path(".claude/skills") / skill.name / "SKILL.md"
                self.assertTrue(script_path.exists(), str(script_path))
                self.assertTrue(skill_md_path.exists(), str(skill_md_path))
```

- [ ] **Step 2: Run the targeted tests to verify they fail**

Run: `uv run python -m unittest tests.test_preprocessor_inventory -v`

Expected: FAIL because the repository still has thin-wrapper scripts and may still be missing force-added `.claude/skills/{name}/SKILL.md` files

- [ ] **Step 3: Migrate the remaining scripts using the exact metadata map below**

```python
STRUCT_SCRIPT_METADATA = {
    "find-EpObjectTable": {"symbol": "EpObjectTable", "symbol_expr": "_EPROCESS->ObjectTable", "struct_name": "_EPROCESS", "member_name": "ObjectTable", "bits": False},
    "find-EreGuidEntry": {"symbol": "EreGuidEntry", "symbol_expr": "_ETW_REG_ENTRY->GuidEntry", "struct_name": "_ETW_REG_ENTRY", "member_name": "GuidEntry", "bits": False},
    "find-HtHandleContentionEvent": {"symbol": "HtHandleContentionEvent", "symbol_expr": "_HANDLE_TABLE->HandleContentionEvent", "struct_name": "_HANDLE_TABLE", "member_name": "HandleContentionEvent", "bits": False},
    "find-OtName": {"symbol": "OtName", "symbol_expr": "_OBJECT_TYPE->Name", "struct_name": "_OBJECT_TYPE", "member_name": "Name", "bits": False},
    "find-OtIndex": {"symbol": "OtIndex", "symbol_expr": "_OBJECT_TYPE->Index", "struct_name": "_OBJECT_TYPE", "member_name": "Index", "bits": False},
    "find-ObDecodeShift": {"symbol": "ObDecodeShift", "symbol_expr": "_HANDLE_TABLE_ENTRY->ObjectPointerBits", "struct_name": "_HANDLE_TABLE_ENTRY", "member_name": "ObjectPointerBits", "bits": True},
    "find-ObAttributesShift": {"symbol": "ObAttributesShift", "symbol_expr": "_HANDLE_TABLE_ENTRY->Attributes", "struct_name": "_HANDLE_TABLE_ENTRY", "member_name": "Attributes", "bits": True},
    "find-AlpcCommunicationInfo": {"symbol": "AlpcCommunicationInfo", "symbol_expr": "_ALPC_PORT->CommunicationInfo", "struct_name": "_ALPC_PORT", "member_name": "CommunicationInfo", "bits": False},
    "find-AlpcOwnerProcess": {"symbol": "AlpcOwnerProcess", "symbol_expr": "_ALPC_PORT->OwnerProcess", "struct_name": "_ALPC_PORT", "member_name": "OwnerProcess", "bits": False},
    "find-AlpcConnectionPort": {"symbol": "AlpcConnectionPort", "symbol_expr": "_ALPC_COMMUNICATION_INFO->ConnectionPort", "struct_name": "_ALPC_COMMUNICATION_INFO", "member_name": "ConnectionPort", "bits": False},
    "find-AlpcServerCommunicationPort": {"symbol": "AlpcServerCommunicationPort", "symbol_expr": "_ALPC_COMMUNICATION_INFO->ServerCommunicationPort", "struct_name": "_ALPC_COMMUNICATION_INFO", "member_name": "ServerCommunicationPort", "bits": False},
    "find-AlpcClientCommunicationPort": {"symbol": "AlpcClientCommunicationPort", "symbol_expr": "_ALPC_COMMUNICATION_INFO->ClientCommunicationPort", "struct_name": "_ALPC_COMMUNICATION_INFO", "member_name": "ClientCommunicationPort", "bits": False},
    "find-AlpcHandleTable": {"symbol": "AlpcHandleTable", "symbol_expr": "_ALPC_COMMUNICATION_INFO->HandleTable", "struct_name": "_ALPC_COMMUNICATION_INFO", "member_name": "HandleTable", "bits": False},
    "find-AlpcHandleTableLock": {"symbol": "AlpcHandleTableLock", "symbol_expr": "_ALPC_HANDLE_TABLE->Lock", "struct_name": "_ALPC_HANDLE_TABLE", "member_name": "Lock", "bits": False},
    "find-AlpcAttributes": {"symbol": "AlpcAttributes", "symbol_expr": "_ALPC_PORT->PortAttributes", "struct_name": "_ALPC_PORT", "member_name": "PortAttributes", "bits": False},
    "find-AlpcAttributesFlags": {"symbol": "AlpcAttributesFlags", "symbol_expr": "_ALPC_PORT_ATTRIBUTES->Flags", "struct_name": "_ALPC_PORT_ATTRIBUTES", "member_name": "Flags", "bits": False},
    "find-AlpcPortContext": {"symbol": "AlpcPortContext", "symbol_expr": "_ALPC_PORT->PortContext", "struct_name": "_ALPC_PORT", "member_name": "PortContext", "bits": False},
    "find-AlpcPortObjectLock": {"symbol": "AlpcPortObjectLock", "symbol_expr": "_ALPC_PORT->PortObjectLock", "struct_name": "_ALPC_PORT", "member_name": "PortObjectLock", "bits": False},
    "find-AlpcSequenceNo": {"symbol": "AlpcSequenceNo", "symbol_expr": "_ALPC_PORT->SequenceNo", "struct_name": "_ALPC_PORT", "member_name": "SequenceNo", "bits": False},
    "find-AlpcState": {"symbol": "AlpcState", "symbol_expr": "_ALPC_PORT->u1.State", "struct_name": "_ALPC_PORT", "member_name": "u1.State", "bits": False},
    "find-KtInitialStack": {"symbol": "KtInitialStack", "symbol_expr": "_KTHREAD->InitialStack", "struct_name": "_KTHREAD", "member_name": "InitialStack", "bits": False},
    "find-KtStackLimit": {"symbol": "KtStackLimit", "symbol_expr": "_KTHREAD->StackLimit", "struct_name": "_KTHREAD", "member_name": "StackLimit", "bits": False},
    "find-KtStackBase": {"symbol": "KtStackBase", "symbol_expr": "_KTHREAD->StackBase", "struct_name": "_KTHREAD", "member_name": "StackBase", "bits": False},
    "find-KtKernelStack": {"symbol": "KtKernelStack", "symbol_expr": "_KTHREAD->KernelStack", "struct_name": "_KTHREAD", "member_name": "KernelStack", "bits": False},
    "find-KtReadOperationCount": {"symbol": "KtReadOperationCount", "symbol_expr": "_KTHREAD->ReadOperationCount", "struct_name": "_KTHREAD", "member_name": "ReadOperationCount", "bits": False},
    "find-KtWriteOperationCount": {"symbol": "KtWriteOperationCount", "symbol_expr": "_KTHREAD->WriteOperationCount", "struct_name": "_KTHREAD", "member_name": "WriteOperationCount", "bits": False},
    "find-KtOtherOperationCount": {"symbol": "KtOtherOperationCount", "symbol_expr": "_KTHREAD->OtherOperationCount", "struct_name": "_KTHREAD", "member_name": "OtherOperationCount", "bits": False},
    "find-KtReadTransferCount": {"symbol": "KtReadTransferCount", "symbol_expr": "_KTHREAD->ReadTransferCount", "struct_name": "_KTHREAD", "member_name": "ReadTransferCount", "bits": False},
    "find-KtWriteTransferCount": {"symbol": "KtWriteTransferCount", "symbol_expr": "_KTHREAD->WriteTransferCount", "struct_name": "_KTHREAD", "member_name": "WriteTransferCount", "bits": False},
    "find-KtOtherTransferCount": {"symbol": "KtOtherTransferCount", "symbol_expr": "_KTHREAD->OtherTransferCount", "struct_name": "_KTHREAD", "member_name": "OtherTransferCount", "bits": False},
    "find-MmSectionControlArea": {"symbol": "MmSectionControlArea", "symbol_expr": "_SECTION->u1.ControlArea,_SECTION_OBJECT->Segment", "struct_name": "_SECTION", "member_name": "u1.ControlArea", "bits": False},
    "find-MmControlAreaListHead": {"symbol": "MmControlAreaListHead", "symbol_expr": "_CONTROL_AREA->ListHead", "struct_name": "_CONTROL_AREA", "member_name": "ListHead", "bits": False},
    "find-MmControlAreaLock": {"symbol": "MmControlAreaLock", "symbol_expr": "_CONTROL_AREA->ControlAreaLock", "struct_name": "_CONTROL_AREA", "member_name": "ControlAreaLock", "bits": False},
    "find-EpSectionObject": {"symbol": "EpSectionObject", "symbol_expr": "_EPROCESS->SectionObject", "struct_name": "_EPROCESS", "member_name": "SectionObject", "bits": False},
    "find-EpProtection": {"symbol": "EpProtection", "symbol_expr": "_EPROCESS->Protection", "struct_name": "_EPROCESS", "member_name": "Protection", "bits": False},
    "find-EpCookie": {"symbol": "EpCookie", "symbol_expr": "_EPROCESS->Cookie", "struct_name": "_EPROCESS", "member_name": "Cookie", "bits": False},
    "find-EpBreakOnTermination": {"symbol": "EpBreakOnTermination", "symbol_expr": "_EPROCESS->BreakOnTermination", "struct_name": "_EPROCESS", "member_name": "BreakOnTermination", "bits": True},
    "find-KpDirectoryTableBase": {"symbol": "KpDirectoryTableBase", "symbol_expr": "_KPROCESS->DirectoryTableBase", "struct_name": "_KPROCESS", "member_name": "DirectoryTableBase", "bits": False},
}

GV_SCRIPT_METADATA = {
    "find-PspLoadImageNotifyRoutine": {"symbol": "PspLoadImageNotifyRoutine", "alias": ["PspLoadImageNotifyRoutine"]},
    "find-PspCreateThreadNotifyRoutine": {"symbol": "PspCreateThreadNotifyRoutine", "alias": ["PspCreateThreadNotifyRoutine"]},
}

FUNC_SCRIPT_METADATA = {
    "find-ExDereferenceCallBackBlock": {"symbol": "ExDereferenceCallBackBlock", "alias": ["ExDereferenceCallBackBlock"]},
    "find-PspEnumerateCallback": {"symbol": "PspEnumerateCallback", "alias": ["PspEnumerateCallback"]},
    "find-CmpEnumerateCallback": {"symbol": "CmpEnumerateCallback", "alias": ["CmpEnumerateCallback"]},
}
```

```python
# struct script template
import ida_preprocessor_common as preprocessor_common

TARGET_STRUCT_MEMBER_NAMES = ["EpObjectTable"]
STRUCT_METADATA = {
    "EpObjectTable": {
        "symbol_expr": "_EPROCESS->ObjectTable",
        "struct_name": "_EPROCESS",
        "member_name": "ObjectTable",
        "bits": False,
    }
}
GENERATE_YAML_DESIRED_FIELDS = {
    "EpObjectTable": ["struct_name", "member_name", "offset", "bit_offset"]
}
```

```markdown
# .claude/skills/find-EpObjectTable/SKILL.md

# find-EpObjectTable

Find kernel struct member `_EPROCESS->ObjectTable` in the current IDA database
and write `EpObjectTable.yaml` with:

- `category: struct_offset`
- `struct_name`
- `member_name`
- `offset`
- `bit_offset` when present
```

```bash
# if .claude is still ignored, create or update matching per-skill fallback docs
git add -f .claude/skills/find-*/SKILL.md
```

- [ ] **Step 4: Run the structural tests to verify they pass**

Run: `uv run python -m unittest tests.test_preprocessor_inventory tests.test_ida_skill_preprocessor -v`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add ida_preprocessor_scripts/find-*.py tests/test_preprocessor_inventory.py tests/test_ida_skill_preprocessor.py
git add -f .claude/skills/find-*/SKILL.md
git commit -m "refactor(scripts): 迁移剩余预处理脚本"
```

### Task 5: Update Workflow Tests and Run Final Regression

**Files:**
- Modify: `tests/test_dump_symbols.py`
- Modify: `tests/test_symbol_config.py`
- Modify: `tests/test_ida_skill_preprocessor.py`

- [ ] **Step 1: Write the failing workflow regression tests**

```python
def test_process_binary_accepts_minimal_symbol_inventory(self) -> None:
    with TemporaryDirectory() as temp_dir:
        binary_dir = Path(temp_dir)
        config = {
            "skills": [{"name": "find-EgeGuid", "symbol": "EgeGuid", "expected_output": ["EgeGuid.yaml"]}],
            "symbols": [{"name": "EgeGuid", "category": "struct_offset", "data_type": "uint16"}],
        }
        with (
            patch.object(dump_symbols, "preprocess_single_skill_via_mcp", new=AsyncMock(return_value=dump_symbols.PREPROCESS_STATUS_SUCCESS)),
            patch.object(dump_symbols, "run_skill", return_value=True),
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
```

- [ ] **Step 2: Run the targeted regression tests to verify they fail**

Run: `uv run python -m unittest tests.test_dump_symbols tests.test_symbol_config tests.test_ida_skill_preprocessor -v`

Expected: FAIL because the existing tests still build symbol fixtures with removed locating fields

- [ ] **Step 3: Update the fixtures and keep the runtime contract unchanged**

```python
symbols = [
    {
        "name": "EgeGuid",
        "category": "struct_offset",
        "data_type": "uint16",
    }
]
```

```python
self.assertEqual("find-EgeGuid", config.modules[0].skills[0].name)
self.assertEqual("struct_offset", config.modules[0].symbols[0].category)
self.assertEqual("uint16", config.modules[0].symbols[0].data_type)
```

- [ ] **Step 4: Run final regression**

Run: `uv run python -m unittest tests.test_ida_preprocessor_common tests.test_preprocessor_inventory tests.test_dump_symbols tests.test_symbol_config tests.test_ida_skill_preprocessor -v`

Expected: PASS

Run: `uv run python -m unittest discover -s tests -v`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add tests/test_dump_symbols.py tests/test_symbol_config.py tests/test_ida_skill_preprocessor.py
git commit -m "test(preprocess): 补充迁移回归覆盖"
```
