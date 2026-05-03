from __future__ import annotations

import ida_preprocessor_common as preprocessor_common

TARGET_STRUCT_MEMBER_NAMES = [
    "AlpcAttributes",
    "AlpcAttributesFlags",
    "AlpcCommunicationInfo",
    "AlpcOwnerProcess",
    "AlpcConnectionPort",
    "AlpcServerCommunicationPort",
    "AlpcClientCommunicationPort",
]

LLM_DECOMPILE = [
    (
        "AlpcAttributes",
        "_ALPC_PORT->PortAttributes",
        "prompt/call_llm_decompile.md",
        "references/ntoskrnl/AlpcpDeletePort.{arch}.yaml",
    ),
    (
        "AlpcAttributesFlags",
        "_ALPC_PORT_ATTRIBUTES->Flags",
        "prompt/call_llm_decompile.md",
        "references/ntoskrnl/AlpcpDeletePort.{arch}.yaml",
    ),
    (
        "AlpcCommunicationInfo",
        "_ALPC_PORT->CommunicationInfo",
        "prompt/call_llm_decompile.md",
        "references/ntoskrnl/AlpcpDeletePort.{arch}.yaml",
    ),
    (
        "AlpcOwnerProcess",
        "_ALPC_PORT->OwnerProcess",
        "prompt/call_llm_decompile.md",
        "references/ntoskrnl/AlpcpDeletePort.{arch}.yaml",
    ),
    (
        "AlpcConnectionPort",
        "_ALPC_COMMUNICATION_INFO->ConnectionPort",
        "prompt/call_llm_decompile.md",
        "references/ntoskrnl/AlpcpDeletePort.{arch}.yaml",
    ),
    (
        "AlpcServerCommunicationPort",
        "_ALPC_COMMUNICATION_INFO->ServerCommunicationPort",
        "prompt/call_llm_decompile.md",
        "references/ntoskrnl/AlpcpDeletePort.{arch}.yaml",
    ),
    (
        "AlpcClientCommunicationPort",
        "_ALPC_COMMUNICATION_INFO->ClientCommunicationPort",
        "prompt/call_llm_decompile.md",
        "references/ntoskrnl/AlpcpDeletePort.{arch}.yaml",
    ),
]

STRUCT_METADATA = {
    "AlpcAttributes": {
        "symbol_expr": "_ALPC_PORT->PortAttributes",
        "struct_name": "_ALPC_PORT",
        "member_name": "PortAttributes",
        "bits": False,
    },
    "AlpcAttributesFlags": {
        "symbol_expr": "_ALPC_PORT_ATTRIBUTES->Flags",
        "struct_name": "_ALPC_PORT_ATTRIBUTES",
        "member_name": "Flags",
        "bits": False,
    },
    "AlpcCommunicationInfo": {
        "symbol_expr": "_ALPC_PORT->CommunicationInfo",
        "struct_name": "_ALPC_PORT",
        "member_name": "CommunicationInfo",
        "bits": False,
    },
    "AlpcOwnerProcess": {
        "symbol_expr": "_ALPC_PORT->OwnerProcess",
        "struct_name": "_ALPC_PORT",
        "member_name": "OwnerProcess",
        "bits": False,
    },
    "AlpcConnectionPort": {
        "symbol_expr": "_ALPC_COMMUNICATION_INFO->ConnectionPort",
        "struct_name": "_ALPC_COMMUNICATION_INFO",
        "member_name": "ConnectionPort",
        "bits": False,
    },
    "AlpcServerCommunicationPort": {
        "symbol_expr": "_ALPC_COMMUNICATION_INFO->ServerCommunicationPort",
        "struct_name": "_ALPC_COMMUNICATION_INFO",
        "member_name": "ServerCommunicationPort",
        "bits": False,
    },
    "AlpcClientCommunicationPort": {
        "symbol_expr": "_ALPC_COMMUNICATION_INFO->ClientCommunicationPort",
        "struct_name": "_ALPC_COMMUNICATION_INFO",
        "member_name": "ClientCommunicationPort",
        "bits": False,
    },
}

GENERATE_YAML_DESIRED_FIELDS = {
    "AlpcAttributes": ["struct_name", "member_name", "offset"],
    "AlpcAttributesFlags": ["struct_name", "member_name", "offset"],
    "AlpcCommunicationInfo": ["struct_name", "member_name", "offset"],
    "AlpcOwnerProcess": ["struct_name", "member_name", "offset"],
    "AlpcConnectionPort": ["struct_name", "member_name", "offset"],
    "AlpcServerCommunicationPort": ["struct_name", "member_name", "offset"],
    "AlpcClientCommunicationPort": ["struct_name", "member_name", "offset"],
}


async def preprocess_skill(session, skill, symbol, binary_dir, pdb_path, debug, llm_config):
    return await preprocessor_common.preprocess_common_skill(
        session=session,
        skill=skill,
        symbol=symbol,
        binary_dir=binary_dir,
        pdb_path=pdb_path,
        debug=debug,
        llm_config=llm_config,
        struct_member_names=TARGET_STRUCT_MEMBER_NAMES,
        struct_metadata=STRUCT_METADATA,
        llm_decompile_specs=LLM_DECOMPILE,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
    )
