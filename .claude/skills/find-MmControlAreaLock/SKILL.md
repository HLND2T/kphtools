# find-MmControlAreaLock

Find kernel struct member `_CONTROL_AREA->ControlAreaLock` in the current IDA database and write `MmControlAreaLock.yaml` with:

- `category: struct_offset`
- `struct_name`
- `member_name`
- `offset`
- `bit_offset` when the member is a bitfield
