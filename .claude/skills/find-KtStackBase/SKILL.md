# find-KtStackBase

Find kernel struct member `_KTHREAD->StackBase` in the current IDA database and write `KtStackBase.yaml` with:

- `category: struct_offset`
- `struct_name`
- `member_name`
- `offset`
- `bit_offset` when the member is a bitfield
