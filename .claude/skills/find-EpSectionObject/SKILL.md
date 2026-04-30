# find-EpSectionObject

Find kernel struct member `_EPROCESS->SectionObject` in the current IDA database and write `EpSectionObject.yaml` with:

- `category: struct_offset`
- `struct_name`
- `member_name`
- `offset`
- `bit_offset` when the member is a bitfield
