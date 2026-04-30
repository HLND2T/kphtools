# find-AlpcAttributesFlags

Find kernel struct member `_ALPC_PORT_ATTRIBUTES->Flags` in the current IDA database and write `AlpcAttributesFlags.yaml` with:

- `category: struct_offset`
- `struct_name`
- `member_name`
- `offset`
- `bit_offset` when the member is a bitfield
