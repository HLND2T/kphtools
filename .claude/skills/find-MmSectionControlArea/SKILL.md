# find-MmSectionControlArea

Find kernel struct member `_SECTION->u1.ControlArea,_SECTION_OBJECT->Segment` in the current IDA database and write `MmSectionControlArea.yaml` with:

- `category: struct_offset`
- `struct_name`
- `member_name`
- `offset`
- `bit_offset` when the member is a bitfield
