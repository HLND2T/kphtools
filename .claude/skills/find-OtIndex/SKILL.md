# find-OtIndex

Find kernel struct member `_OBJECT_TYPE->Index` in the current IDA database and write `OtIndex.yaml` with:

- `category: struct_offset`
- `struct_name`
- `member_name`
- `offset`
- `bit_offset` when the member is a bitfield
