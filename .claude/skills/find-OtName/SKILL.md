# find-OtName

Find kernel struct member `_OBJECT_TYPE->Name` in the current IDA database and write `OtName.yaml` with:

- `category: struct_offset`
- `struct_name`
- `member_name`
- `offset`
- `bit_offset` when the member is a bitfield
