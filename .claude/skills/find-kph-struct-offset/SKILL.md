# find-kph-struct-offset

Find the requested kernel struct member offset in the current IDA database and write `{symbol}.yaml` with:

- `category: struct_offset`
- `struct_name`
- `member_name`
- `offset`
- `bit_offset` when the member is a bitfield
