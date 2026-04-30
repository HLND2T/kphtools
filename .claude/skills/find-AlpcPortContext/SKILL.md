# find-AlpcPortContext

Find kernel struct member `_ALPC_PORT->PortContext` in the current IDA database and write `AlpcPortContext.yaml` with:

- `category: struct_offset`
- `struct_name`
- `member_name`
- `offset`
- `bit_offset` when the member is a bitfield
