# find-KtReadTransferCount

Find kernel struct member `_KTHREAD->ReadTransferCount` in the current IDA database and write `KtReadTransferCount.yaml` with:

- `category: struct_offset`
- `struct_name`
- `member_name`
- `offset`
- `bit_offset` when the member is a bitfield
