# find-EpProtection

Find kernel struct member `_EPROCESS->Protection` in the current IDA database and write `EpProtection.yaml` with:

- `category: struct_offset`
- `struct_name`
- `member_name`
- `offset`
- `bit_offset` when the member is a bitfield
