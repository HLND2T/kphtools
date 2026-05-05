from __future__ import annotations

import ida_preprocessor_common as preprocessor_common

TARGET_GLOBALVAR_NAMES = [
    "PspCreateProcessNotifyRoutine",
    "PspCreateThreadNotifyRoutine",
    "PspLoadImageNotifyRoutine",
]

LLM_DECOMPILE = [
    (
        "PspCreateProcessNotifyRoutine",
        "PspCreateProcessNotifyRoutine",
        "prompt/call_llm_decompile.md",
        "references/ntoskrnl/PspEnumerateCallback.{arch}.yaml",
    ),
    (
        "PspCreateThreadNotifyRoutine",
        "PspCreateThreadNotifyRoutine",
        "prompt/call_llm_decompile.md",
        "references/ntoskrnl/PspEnumerateCallback.{arch}.yaml",
    ),
    (
        "PspLoadImageNotifyRoutine",
        "PspLoadImageNotifyRoutine",
        "prompt/call_llm_decompile.md",
        "references/ntoskrnl/PspEnumerateCallback.{arch}.yaml",
    ),
]

GV_METADATA = {
    "PspCreateProcessNotifyRoutine": {
        "alias": ["PspCreateProcessNotifyRoutine"],
    },
    "PspCreateThreadNotifyRoutine": {
        "alias": ["PspCreateThreadNotifyRoutine"],
    },
    "PspLoadImageNotifyRoutine": {
        "alias": ["PspLoadImageNotifyRoutine"],
    },
}

GENERATE_YAML_DESIRED_FIELDS = {
    "PspCreateProcessNotifyRoutine": ["gv_name", "gv_rva"],
    "PspCreateThreadNotifyRoutine": ["gv_name", "gv_rva"],
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
        llm_decompile_specs=LLM_DECOMPILE,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
    )
