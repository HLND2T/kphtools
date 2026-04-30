# find-EpCookie

Find kernel struct member `_EPROCESS->Cookie` in the current IDA database and write `EpCookie.yaml` with:

- `category: struct_offset`
- `struct_name`
- `member_name`
- `offset`
- `bit_offset` when the member is a bitfield
