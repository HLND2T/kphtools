from __future__ import annotations

import ida_preprocessor_common as preprocessor_common

TARGET_STRUCT_MEMBER_NAMES = ["EgeGuid", "EreGuidEntry"]

LLM_DECOMPILE = [
    (
        "EgeGuid",
        "_ETW_GUID_ENTRY->Guid",
        "prompt/call_llm_decompile.md",
        "references/ntoskrnl/EtwGetProviderIdFromHandle.{arch}.yaml",
    ),
    (
        "EreGuidEntry",
        "_ETW_REG_ENTRY->GuidEntry",
        "prompt/call_llm_decompile.md",
        "references/ntoskrnl/EtwGetProviderIdFromHandle.{arch}.yaml",
    ),
]

STRUCT_METADATA = {
    "EgeGuid": {
        "symbol_expr": "_ETW_GUID_ENTRY->Guid",
        "struct_name": "_ETW_GUID_ENTRY",
        "member_name": "Guid",
        "bits": False,
    },
    "EreGuidEntry": {
        "symbol_expr": "_ETW_REG_ENTRY->GuidEntry",
        "struct_name": "_ETW_REG_ENTRY",
        "member_name": "GuidEntry",
        "bits": False,
    },
}

GENERATE_YAML_DESIRED_FIELDS = {
    "EgeGuid": ["struct_name", "member_name", "offset"],
    "EreGuidEntry": ["struct_name", "member_name", "offset"],
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
