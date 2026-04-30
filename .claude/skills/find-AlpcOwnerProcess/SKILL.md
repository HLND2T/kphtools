# find-AlpcOwnerProcess

Find kernel struct member `_ALPC_PORT->OwnerProcess` in the current IDA database and write `AlpcOwnerProcess.yaml` with:

- `category: struct_offset`
- `struct_name`
- `member_name`
- `offset`
- `bit_offset` when the member is a bitfield
