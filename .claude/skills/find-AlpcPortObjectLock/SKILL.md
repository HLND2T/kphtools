# find-AlpcPortObjectLock

Find kernel struct member `_ALPC_PORT->PortObjectLock` in the current IDA database and write `AlpcPortObjectLock.yaml` with:

- `category: struct_offset`
- `struct_name`
- `member_name`
- `offset`
- `bit_offset` when the member is a bitfield
