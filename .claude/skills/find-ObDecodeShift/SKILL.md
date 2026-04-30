# find-ObDecodeShift

Find kernel struct member `_HANDLE_TABLE_ENTRY->ObjectPointerBits` in the current IDA database and write `ObDecodeShift.yaml` with:

- `category: struct_offset`
- `struct_name`
- `member_name`
- `offset`
- `bit_offset` when the member is a bitfield
