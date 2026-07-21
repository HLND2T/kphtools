from __future__ import annotations

import ida_preprocessor_common as preprocessor_common

TARGET_FUNCTION_NAMES = ["EtwGetProviderIdFromHandle"]

LLM_DECOMPILE = [
    {
        "symbol_name": "EtwGetProviderIdFromHandle",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/ntoskrnl/EtwWriteStartScenario.{arch}.yaml",
        ],
        "expected_result_sections": ["found_call", "found_funcptr"],
        "dependency_policy": {
            "EtwWriteStartScenario.yaml": "required",
        },
    },
]

FUNC_METADATA = {
    "EtwGetProviderIdFromHandle": {
        "alias": ["EtwGetProviderIdFromHandle"],
    }
}

GENERATE_YAML_DESIRED_FIELDS = {
    "EtwGetProviderIdFromHandle": ["func_name", "func_rva"],
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
