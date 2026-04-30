# find-KtReadOperationCount

Find kernel struct member `_KTHREAD->ReadOperationCount` in the current IDA database and write `KtReadOperationCount.yaml` with:

- `category: struct_offset`
- `struct_name`
- `member_name`
- `offset`
- `bit_offset` when the member is a bitfield
