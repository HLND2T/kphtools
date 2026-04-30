# find-ObAttributesShift

Find kernel struct member `_HANDLE_TABLE_ENTRY->Attributes` in the current IDA database and write `ObAttributesShift.yaml` with:

- `category: struct_offset`
- `struct_name`
- `member_name`
- `offset`
- `bit_offset` when the member is a bitfield
