from __future__ import annotations

import ida_preprocessor_common as preprocessor_common

TARGET_GLOBALVAR_NAMES = [
    "ExpFirmwareTableResource",
    "ExpFirmwareTableProviderListHead",
]

LLM_DECOMPILE = [
    {
        "symbol_name": "ExpFirmwareTableResource",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/ntoskrnl/ExpGetSystemFirmwareTableInformation.{arch}.yaml",
        ],
        "expected_result_sections": ["found_gv"],
        "dependency_policy": {
            "ExpGetSystemFirmwareTableInformation.yaml": "required",
        },
    },
    {
        "symbol_name": "ExpFirmwareTableProviderListHead",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/ntoskrnl/ExpGetSystemFirmwareTableInformation.{arch}.yaml",
        ],
        "expected_result_sections": ["found_gv"],
        "dependency_policy": {
            "ExpGetSystemFirmwareTableInformation.yaml": "required",
        },
    },
]

GV_METADATA = {
    "ExpFirmwareTableResource": {
        "alias": ["ExpFirmwareTableResource"],
    },
    "ExpFirmwareTableProviderListHead": {
        "alias": ["ExpFirmwareTableProviderListHead"],
    },
}

GENERATE_YAML_DESIRED_FIELDS = {
    "ExpFirmwareTableResource": ["gv_name", "gv_rva"],
    "ExpFirmwareTableProviderListHead": ["gv_name", "gv_rva"],
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
        gv_names=TARGET_GLOBALVAR_NAMES,
        gv_metadata=GV_METADATA,
        llm_decompile_specs=LLM_DECOMPILE,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
    )
