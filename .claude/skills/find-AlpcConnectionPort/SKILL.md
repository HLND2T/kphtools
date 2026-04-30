# find-AlpcConnectionPort

Find kernel struct member `_ALPC_COMMUNICATION_INFO->ConnectionPort` in the current IDA database and write `AlpcConnectionPort.yaml` with:

- `category: struct_offset`
- `struct_name`
- `member_name`
- `offset`
- `bit_offset` when the member is a bitfield
