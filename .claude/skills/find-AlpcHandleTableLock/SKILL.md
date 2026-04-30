# find-AlpcHandleTableLock

Find kernel struct member `_ALPC_HANDLE_TABLE->Lock` in the current IDA database and write `AlpcHandleTableLock.yaml` with:

- `category: struct_offset`
- `struct_name`
- `member_name`
- `offset`
- `bit_offset` when the member is a bitfield
