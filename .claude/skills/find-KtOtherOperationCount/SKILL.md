# find-KtOtherOperationCount

Find kernel struct member `_KTHREAD->OtherOperationCount` in the current IDA database and write `KtOtherOperationCount.yaml` with:

- `category: struct_offset`
- `struct_name`
- `member_name`
- `offset`
- `bit_offset` when the member is a bitfield
