from __future__ import annotations

import ida_preprocessor_common as preprocessor_common

TARGET_STRUCT_MEMBER_NAMES = ["OtTypeLock", "OtCallbackList"]

LLM_DECOMPILE = [
    (
        "OtTypeLock",
        "_OBJECT_TYPE->TypeLock",
        "prompt/call_llm_decompile.md",
        "references/ntoskrnl/ObpCallPreOperationCallbacks.{arch}.yaml",
    ),
    (
        "OtCallbackList",
        "_OBJECT_TYPE->CallbackList",
        "prompt/call_llm_decompile.md",
        "references/ntoskrnl/ObpCallPreOperationCallbacks.{arch}.yaml",
    ),
]

STRUCT_METADATA = {
    "OtTypeLock": {
        "symbol_expr": "_OBJECT_TYPE->TypeLock",
        "struct_name": "_OBJECT_TYPE",
        "member_name": "TypeLock",
        "bits": False,
    },
    "OtCallbackList": {
        "symbol_expr": "_OBJECT_TYPE->CallbackList",
        "struct_name": "_OBJECT_TYPE",
        "member_name": "CallbackList",
        "bits": False,
    },
}

GENERATE_YAML_DESIRED_FIELDS = {
    "OtTypeLock": ["struct_name", "member_name", "offset"],
    "OtCallbackList": ["struct_name", "member_name", "offset"],
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
