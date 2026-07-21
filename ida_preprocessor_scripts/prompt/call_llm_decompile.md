You are a Windows-kernel reverse-engineering expert.

I have disassembly outputs and procedure code for multiple related functions.

These are the reference functions:

{reference_blocks}

These are the target functions you need to reverse-engineering:

{target_blocks}

Collect all references to "{symbol_name_list}" in the target functions and output only YAML using the four canonical sections below.

Classification rules:

- `found_call`: direct call, direct tail jump, or jump thunk to a requested regular function.
- `found_funcptr`: direct reference to the address of a requested regular function.
- `found_gv`: direct reference to a requested global variable.
- `found_struct_offset`: access to a requested regular struct field, including fields that store function pointers.
- `found_vcall` is unsupported by kphtools and must never be returned.

```yaml
found_call:
  - insn_va: '0x180888800'
    insn_disasm: call    sub_180999900
    func_name: CLoopModeGame_RegisterEventMapInternal
  - insn_va: '0x180888880'
    insn_disasm: jmp     sub_180555500
    func_name: CLoopModeGame_SetGameSystemState
found_funcptr:
  - insn_va: '0x180666600'
    insn_disasm: lea     rdx, sub_15BC910
    funcptr_name: CLoopModeGame_OnClientPollNetworking
found_gv:
  - insn_va: '0x180444400'
    insn_disasm: mov     rcx, cs:qword_180666600
    gv_name: g_pNetworkMessages
found_struct_offset:
  - insn_va: '0x1406DF5F8'
    insn_disasm: test    dword ptr [r9+100h], 100000h
    offset: '0x100'
    size: '4'
    struct_name: _ALPC_PORT
    member_name: PortAttributes
  - insn_va: '0x1406C4D54'
    insn_disasm: test    dword ptr [rcx+464h], 2000h
    offset: '0x464'
    size: '4'
    bit_offset: '13'
    struct_name: _EPROCESS
    member_name: BreakOnTermination
```

If nothing is found, return this complete mapping:

```yaml
found_call: []
found_funcptr: []
found_gv: []
found_struct_offset: []
```

Use the requested semantic names, not IDA-generated `sub_`, `qword_`, or `unk_` names. Do not output unrelated symbols, explanations, fences, or any text outside the YAML mapping.
