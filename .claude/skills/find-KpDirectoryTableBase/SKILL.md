# find-KpDirectoryTableBase

Find kernel struct member `_KPROCESS->DirectoryTableBase` in the current IDA database and write `KpDirectoryTableBase.yaml` with:

- `category: struct_offset`
- `struct_name`
- `member_name`
- `offset`
- `bit_offset` when the member is a bitfield
