# find-AlpcServerCommunicationPort

Find kernel struct member `_ALPC_COMMUNICATION_INFO->ServerCommunicationPort` in the current IDA database and write `AlpcServerCommunicationPort.yaml` with:

- `category: struct_offset`
- `struct_name`
- `member_name`
- `offset`
- `bit_offset` when the member is a bitfield
