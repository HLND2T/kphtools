from __future__ import annotations

import ida_preprocessor_common as preprocessor_common

TARGET_FUNCTION_NAMES = ["MiInsertUnusedSegment"]

LLM_DECOMPILE = [
    {
        "symbol_name": "MiInsertUnusedSegment",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/ntoskrnl/MiCheckControlArea.{arch}.yaml",
        ],
        "expected_result_sections": ["found_call", "found_funcptr"],
        "dependency_policy": {
            "MiCheckControlArea.yaml": "required",
        },
    },
]

FUNC_METADATA = {
    "MiInsertUnusedSegment": {
        "alias": ["MiInsertUnusedSegment"],
    }
}

GENERATE_YAML_DESIRED_FIELDS = {
    "MiInsertUnusedSegment": ["func_name", "func_rva"],
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
