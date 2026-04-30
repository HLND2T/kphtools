# find-EpBreakOnTermination

Find kernel struct member `_EPROCESS->BreakOnTermination` in the current IDA database and write `EpBreakOnTermination.yaml` with:

- `category: struct_offset`
- `struct_name`
- `member_name`
- `offset`
- `bit_offset` when the member is a bitfield
