from __future__ import annotations

import ida_preprocessor_common as preprocessor_common

TARGET_STRUCT_MEMBER_NAMES = ["ObAttributesShift", "ObDecodeShift", "HtHandleContentionEvent"]

LLM_DECOMPILE = [
    {
        "symbol_name": "ObAttributesShift",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/ntoskrnl/ObpEnumFindHandleProcedure.{arch}.yaml",
        ],
        "expected_result_sections": ["found_struct_offset"],
        "dependency_policy": {
            "ObpEnumFindHandleProcedure.yaml": "optional",
        },
    },
    {
        "symbol_name": "ObDecodeShift",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/ntoskrnl/ObpEnumFindHandleProcedure.{arch}.yaml",
        ],
        "expected_result_sections": ["found_struct_offset"],
        "dependency_policy": {
            "ObpEnumFindHandleProcedure.yaml": "optional",
        },
    },
    {
        "symbol_name": "HtHandleContentionEvent",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/ntoskrnl/ObpEnumFindHandleProcedure.{arch}.yaml",
        ],
        "expected_result_sections": ["found_struct_offset"],
        "dependency_policy": {
            "ObpEnumFindHandleProcedure.yaml": "optional",
        },
    },
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
    "HtHandleContentionEvent": {
        "symbol_expr": "_HANDLE_TABLE->HandleContentionEvent",
        "struct_name": "_HANDLE_TABLE",
        "member_name": "HandleContentionEvent",
        "bits": False,
    },
}

GENERATE_YAML_DESIRED_FIELDS = {
    "ObAttributesShift": ['struct_name', 'member_name', 'offset', 'bit_offset'],
    "ObDecodeShift": ['struct_name', 'member_name', 'offset', 'bit_offset'],
    "HtHandleContentionEvent": ['struct_name', 'member_name', 'offset'],
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
