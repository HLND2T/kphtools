# find-KtWriteTransferCount

Find kernel struct member `_KTHREAD->WriteTransferCount` in the current IDA database and write `KtWriteTransferCount.yaml` with:

- `category: struct_offset`
- `struct_name`
- `member_name`
- `offset`
- `bit_offset` when the member is a bitfield
