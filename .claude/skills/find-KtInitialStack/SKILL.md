# find-KtInitialStack

Find kernel struct member `_KTHREAD->InitialStack` in the current IDA database and write `KtInitialStack.yaml` with:

- `category: struct_offset`
- `struct_name`
- `member_name`
- `offset`
- `bit_offset` when the member is a bitfield
