# find-AlpcAttributes-AND-AlpcAttributesFlags-AND-AlpcCommunicationInfo

Find kernel struct members `_ALPC_PORT->PortAttributes`, `_ALPC_PORT_ATTRIBUTES->Flags`, and `_ALPC_PORT->CommunicationInfo` in the current IDA database and write:

- `AlpcAttributes.yaml`
- `AlpcAttributesFlags.yaml`
- `AlpcCommunicationInfo.yaml`

Each YAML contains:

- `category: struct_offset`
- `struct_name`
- `member_name`
- `offset`
- `bit_offset` when the member is a bitfield
