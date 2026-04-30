# find-EreGuidEntry

Find kernel struct member `_ETW_REG_ENTRY->GuidEntry` in the current IDA database and write `EreGuidEntry.yaml` with:

- `category: struct_offset`
- `struct_name`
- `member_name`
- `offset`
- `bit_offset` when the member is a bitfield
