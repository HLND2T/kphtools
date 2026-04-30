# find-AlpcCommunicationInfo

Find kernel struct member `_ALPC_PORT->CommunicationInfo` in the current IDA database and write `AlpcCommunicationInfo.yaml` with:

- `category: struct_offset`
- `struct_name`
- `member_name`
- `offset`
- `bit_offset` when the member is a bitfield
