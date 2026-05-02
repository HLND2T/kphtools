from __future__ import annotations

import ida_preprocessor_common as preprocessor_common

TARGET_STRUCT_MEMBER_NAMES = ["AlpcHandleTableLock"]

LLM_DECOMPILE = [
    (
        "AlpcHandleTableLock",
        "_ALPC_HANDLE_TABLE->Lock",
        "prompt/call_llm_decompile.md",
        "references/ntoskrnl/AlpcAddHandleTableEntry.{arch}.yaml",
    ),
]

STRUCT_METADATA = {
    "AlpcHandleTableLock": {
        "symbol_expr": "_ALPC_HANDLE_TABLE->Lock",
        "struct_name": "_ALPC_HANDLE_TABLE",
        "member_name": "Lock",
        "bits": False,
    }
}

GENERATE_YAML_DESIRED_FIELDS = {
    "AlpcHandleTableLock": ['struct_name', 'member_name', 'offset'],
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
