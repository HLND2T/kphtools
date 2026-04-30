# find-EpObjectTable

Find kernel struct member `_EPROCESS->ObjectTable` in the current IDA database and write `EpObjectTable.yaml` with:

- `category: struct_offset`
- `struct_name`
- `member_name`
- `offset`
- `bit_offset` when the member is a bitfield
