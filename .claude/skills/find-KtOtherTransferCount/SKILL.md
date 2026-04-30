# find-KtOtherTransferCount

Find kernel struct member `_KTHREAD->OtherTransferCount` in the current IDA database and write `KtOtherTransferCount.yaml` with:

- `category: struct_offset`
- `struct_name`
- `member_name`
- `offset`
- `bit_offset` when the member is a bitfield
