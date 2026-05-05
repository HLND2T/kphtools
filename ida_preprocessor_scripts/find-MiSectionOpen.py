from __future__ import annotations

import ida_preprocessor_common as preprocessor_common

MI_SECTION_OPEN_MIN_BUILDNUM = 10074
TARGET_FUNCTION_NAMES = ["MiSectionOpen"]

LLM_DECOMPILE = [
    (
        "MiSectionOpen",
        "MiSectionOpen",
        "prompt/call_llm_decompile.md",
        "references/ntoskrnl/MiSectionInitialization.{arch}.yaml",
    ),
]

FUNC_METADATA = {
    "MiSectionOpen": {
        "alias": ["MiSectionOpen"],
    }
}

GENERATE_YAML_DESIRED_FIELDS = {
    "MiSectionOpen": ["func_name", "func_rva"],
}


async def preprocess_skill(session, skill, symbol, binary_dir, pdb_path, debug, llm_config):
    buildnum = preprocessor_common.buildnum_int_from_binary_dir(binary_dir)
    if buildnum is None:
        return preprocessor_common.PREPROCESS_STATUS_FAILED
    if buildnum < MI_SECTION_OPEN_MIN_BUILDNUM:
        return preprocessor_common.PREPROCESS_STATUS_ABSENT_OK

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
