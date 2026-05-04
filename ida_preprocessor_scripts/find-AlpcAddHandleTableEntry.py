from __future__ import annotations

import ida_preprocessor_common as preprocessor_common

TARGET_FUNCTION_NAMES = ["AlpcAddHandleTableEntry"]

LLM_DECOMPILE = [
    (
        "AlpcAddHandleTableEntry",
        "AlpcAddHandleTableEntry",
        "prompt/call_llm_decompile.md",
        "references/ntoskrnl/AlpcpCreateSection.{arch}.yaml",
    ),
]

FUNC_METADATA = {
    "AlpcAddHandleTableEntry": {
        "alias": ["AlpcAddHandleTableEntry"],
    }
}

GENERATE_YAML_DESIRED_FIELDS = {
    "AlpcAddHandleTableEntry": ["func_name", "func_rva"],
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
        func_names=TARGET_FUNCTION_NAMES,
        func_metadata=FUNC_METADATA,
        llm_decompile_specs=LLM_DECOMPILE,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
    )
