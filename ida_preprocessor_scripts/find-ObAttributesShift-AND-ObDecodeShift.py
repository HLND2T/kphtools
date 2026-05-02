from __future__ import annotations

import ida_preprocessor_common as preprocessor_common

TARGET_STRUCT_MEMBER_NAMES = ["ObAttributesShift", "ObDecodeShift"]

LLM_DECOMPILE = [
    (
        "ObAttributesShift",
        "_HANDLE_TABLE_ENTRY->Attributes",
        "prompt/call_llm_decompile.md",
        "references/ntoskrnl/ObpEnumFindHandleProcedure.{arch}.yaml",
    ),
    (
        "ObDecodeShift",
        "_HANDLE_TABLE_ENTRY->ObjectPointerBits",
        "prompt/call_llm_decompile.md",
        "references/ntoskrnl/ObpEnumFindHandleProcedure.{arch}.yaml",
    ),
]

STRUCT_METADATA = {
    "ObAttributesShift": {
        "symbol_expr": "_HANDLE_TABLE_ENTRY->Attributes",
        "struct_name": "_HANDLE_TABLE_ENTRY",
        "member_name": "Attributes",
        "bits": True,
    },
    "ObDecodeShift": {
        "symbol_expr": "_HANDLE_TABLE_ENTRY->ObjectPointerBits",
        "struct_name": "_HANDLE_TABLE_ENTRY",
        "member_name": "ObjectPointerBits",
        "bits": True,
    },
}

GENERATE_YAML_DESIRED_FIELDS = {
    "ObAttributesShift": ['struct_name', 'member_name', 'offset', 'bit_offset'],
    "ObDecodeShift": ['struct_name', 'member_name', 'offset', 'bit_offset'],
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
