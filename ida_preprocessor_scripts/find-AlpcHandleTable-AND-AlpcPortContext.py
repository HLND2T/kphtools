from __future__ import annotations

import ida_preprocessor_common as preprocessor_common

TARGET_STRUCT_MEMBER_NAMES = ["AlpcHandleTable", "AlpcPortContext"]

LLM_DECOMPILE = [
    (
        "AlpcHandleTable",
        "_ALPC_COMMUNICATION_INFO->HandleTable",
        "prompt/call_llm_decompile.md",
        "references/ntoskrnl/AlpcpCreateClientPort.{arch}.yaml",
    ),
    (
        "AlpcPortContext",
        "_ALPC_PORT->PortContext",
        "prompt/call_llm_decompile.md",
        "references/ntoskrnl/AlpcpCreateClientPort.{arch}.yaml",
    ),
]

STRUCT_METADATA = {
    "AlpcHandleTable": {
        "symbol_expr": "_ALPC_COMMUNICATION_INFO->HandleTable",
        "struct_name": "_ALPC_COMMUNICATION_INFO",
        "member_name": "HandleTable",
        "bits": False,
    },
    "AlpcPortContext": {
        "symbol_expr": "_ALPC_PORT->PortContext",
        "struct_name": "_ALPC_PORT",
        "member_name": "PortContext",
        "bits": False,
    },
}

GENERATE_YAML_DESIRED_FIELDS = {
    "AlpcHandleTable": ["struct_name", "member_name", "offset"],
    "AlpcPortContext": ["struct_name", "member_name", "offset"],
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
