# find-KtStackLimit

Find kernel struct member `_KTHREAD->StackLimit` in the current IDA database and write `KtStackLimit.yaml` with:

- `category: struct_offset`
- `struct_name`
- `member_name`
- `offset`
- `bit_offset` when the member is a bitfield
