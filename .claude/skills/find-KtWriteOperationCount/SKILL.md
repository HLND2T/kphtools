# find-KtWriteOperationCount

Find kernel struct member `_KTHREAD->WriteOperationCount` in the current IDA database and write `KtWriteOperationCount.yaml` with:

- `category: struct_offset`
- `struct_name`
- `member_name`
- `offset`
- `bit_offset` when the member is a bitfield
