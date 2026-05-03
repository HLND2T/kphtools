You are a Windows-kernel reverse-engineering expert.

I have disassembly outputs and procedure code for multiple related functions.

These are the reference functions:

{reference_blocks}

These are the target functions you need to reverse-engineering:

{target_blocks}

What you need to do is to collect all references to "{symbol_name_list}" in the target functions you need to reverse-engineering and output those references as YAML.

Example:

```yaml
found_vcall: # This is for indirect call to virtual function or virtual function pointer fetching.
  - insn_va: '0x180777700'               # Always be the instruction with displacement offset
    insn_disasm: call    [rax+68h]       # Always be the instruction with displacement offset
    vfunc_offset: '0x68'
    func_name: ILoopMode_OnLoopActivate
  - insn_va: '0x180777778'               # Always be the instruction with displacement offset
    insn_disasm: mov     rax, [rax+80h]  # Always be the instruction with displacement offset
    vfunc_offset: '0x80'
    func_name: INetworkMessages_GetNetworkGroupCount # This must be the true function name we asked to collect, not the sub_XXXXXXXX
found_call: # This is for direct call to non-virtual regular function.
  - insn_va: '0x180888800'
    insn_disasm: call    sub_180999900
    func_name: CLoopModeGame_RegisterEventMapInternal
  - insn_va: '0x180888880'
    insn_disasm: call    sub_180555500
    func_name: CLoopModeGame_SetGameSystemState   # This must be the true function name we asked to collect, not the sub_XXXXXXXX
found_funcptr: # This is for non-virtual regular function pointer.
  - insn_va: '0x180666600'                # Must load/reference the function pointer target address
    insn_disasm: lea     rdx, sub_15BC910 # Must load/reference the function pointer target address
    funcptr_name: CLoopModeGame_OnClientPollNetworking   # This must be the true function name we asked to collect, not the sub_XXXXXXXX
found_gv: # This is for reference to global variable.
  - insn_va: '0x180444400'
    insn_disasm: mov     rcx, cs:qword_180666600 # Must load/reference the global variable
    gv_name: g_pNetworkMessages  # This must be the true globalvar name we asked to collect, not the qword_XXXXXXXX or unk_XXXXXXXX
  - insn_va: '0x180333300'
    insn_disasm: lea     rax, unk_180222200      # Must load/reference the global variable
    gv_name: s_GameEventManager  # This must be the true globalvar name we asked to collect, not the qword_XXXXXXXX or unk_XXXXXXXX
found_struct_offset: # This is for reference to struct offset. NOTE THAT virtual function pointer should not be here! virtual function pointer should ALWAYS be in found_vcall !
  - insn_va: '0x1406DF5F8'                              # Always be the instruction with displacement offset
    insn_disasm: test    dword ptr [r9+100h], 100000h   # Always be the instruction with displacement offset
    offset: '0x100'
    struct_name: _ALPC_PORT
    member_name: PortAttributes
  - insn_va: '0x1406DF5F8'                              # Always be the instruction with displacement offset
    insn_disasm: test    dword ptr [r9+100h], 100000h   # Always be the instruction with displacement offset
    offset: '0x0'
    struct_name: _ALPC_PORT_ATTRIBUTES
    member_name: Flags
  - insn_va: '0x1406C4D54'                              # Always be the instruction with displacement offset
    insn_disasm: test    dword ptr [rcx+464h], 2000h   # Always be the instruction with displacement offset
    offset: '0x464'
    bit_offset: '13'                                    # The bit offset in dword, 2000h = (1 << 13)
    struct_name: _EPROCESS
    member_name: BreakOnTermination
```

If nothing found, output an empty YAML. DO NOT output anything other than the desired YAML. DO NOT collect unrelated symbols.
