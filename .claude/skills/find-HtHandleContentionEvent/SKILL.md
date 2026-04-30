# find-HtHandleContentionEvent

Find kernel struct member `_HANDLE_TABLE->HandleContentionEvent` in the current IDA database and write `HtHandleContentionEvent.yaml` with:

- `category: struct_offset`
- `struct_name`
- `member_name`
- `offset`
- `bit_offset` when the member is a bitfield
