# find-EgeGuid

Find kernel struct member `_ETW_GUID_ENTRY->Guid` in the current IDA database and write `EgeGuid.yaml` with:

- `category: struct_offset`
- `struct_name`
- `member_name`
- `offset`
- `bit_offset` when the member is a bitfield
