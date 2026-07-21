from __future__ import annotations

import ida_preprocessor_common as preprocessor_common

TARGET_STRUCT_MEMBER_NAMES = ["EpBreakOnTermination"]

LLM_DECOMPILE = [
    {
        "symbol_name": "EpBreakOnTermination",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/ntoskrnl/PspTerminateAllThreads.{arch}.yaml",
        ],
        "expected_result_sections": ["found_struct_offset"],
        "dependency_policy": {
            "PspTerminateAllThreads.yaml": "required",
        },
    },
]

STRUCT_METADATA = {
    "EpBreakOnTermination": {
        "symbol_expr": "_EPROCESS->BreakOnTermination",
        "struct_name": "_EPROCESS",
        "member_name": "BreakOnTermination",
        "bits": True,
    }
}

GENERATE_YAML_DESIRED_FIELDS = {
    "EpBreakOnTermination": ['struct_name', 'member_name', 'offset', 'bit_offset'],
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
