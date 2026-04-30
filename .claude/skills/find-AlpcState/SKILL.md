# find-AlpcState

Find kernel struct member `_ALPC_PORT->u1.State` in the current IDA database and write `AlpcState.yaml` with:

- `category: struct_offset`
- `struct_name`
- `member_name`
- `offset`
- `bit_offset` when the member is a bitfield
