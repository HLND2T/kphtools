# find-MmControlAreaListHead

Find kernel struct member `_CONTROL_AREA->ListHead` in the current IDA database and write `MmControlAreaListHead.yaml` with:

- `category: struct_offset`
- `struct_name`
- `member_name`
- `offset`
- `bit_offset` when the member is a bitfield
