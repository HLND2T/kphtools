from __future__ import annotations

import ida_preprocessor_common as preprocessor_common

TARGET_GLOBALVAR_NAMES = ["PspLoadImageNotifyRoutine"]

GV_METADATA = {
    "PspLoadImageNotifyRoutine": {
        "alias": ['PspLoadImageNotifyRoutine'],
    }
}

GENERATE_YAML_DESIRED_FIELDS = {
    "PspLoadImageNotifyRoutine": ["gv_name", "gv_rva"],
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
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
    )
