# find-AlpcSequenceNo

Find kernel struct member `_ALPC_PORT->SequenceNo` in the current IDA database and write `AlpcSequenceNo.yaml` with:

- `category: struct_offset`
- `struct_name`
- `member_name`
- `offset`
- `bit_offset` when the member is a bitfield
