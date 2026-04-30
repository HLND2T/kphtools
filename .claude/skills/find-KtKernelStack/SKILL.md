# find-KtKernelStack

Find kernel struct member `_KTHREAD->KernelStack` in the current IDA database and write `KtKernelStack.yaml` with:

- `category: struct_offset`
- `struct_name`
- `member_name`
- `offset`
- `bit_offset` when the member is a bitfield
