from __future__ import annotations

import ida_preprocessor_common as preprocessor_common

TARGET_STRUCT_MEMBER_NAMES = ["KtInitialStack", "KtStackBase", "KtStackLimit"]

LLM_DECOMPILE = [
    (
        "KtInitialStack",
        "_KTHREAD->InitialStack",
        "prompt/call_llm_decompile.md",
        "references/ntoskrnl/KeQueryCurrentStackInformationEx.{arch}.yaml",
    ),
    (
        "KtStackBase",
        "_KTHREAD->StackBase",
        "prompt/call_llm_decompile.md",
        "references/ntoskrnl/KeQueryCurrentStackInformationEx.{arch}.yaml",
    ),
    (
        "KtStackLimit",
        "_KTHREAD->StackLimit",
        "prompt/call_llm_decompile.md",
        "references/ntoskrnl/KeQueryCurrentStackInformationEx.{arch}.yaml",
    ),
]

STRUCT_METADATA = {
    "KtInitialStack": {
        "symbol_expr": "_KTHREAD->InitialStack",
        "struct_name": "_KTHREAD",
        "member_name": "InitialStack",
        "bits": False,
    },
    "KtStackBase": {
        "symbol_expr": "_KTHREAD->StackBase",
        "struct_name": "_KTHREAD",
        "member_name": "StackBase",
        "bits": False,
    },
    "KtStackLimit": {
        "symbol_expr": "_KTHREAD->StackLimit",
        "struct_name": "_KTHREAD",
        "member_name": "StackLimit",
        "bits": False,
    },
}

GENERATE_YAML_DESIRED_FIELDS = {
    "KtInitialStack": ["struct_name", "member_name", "offset"],
    "KtStackBase": ["struct_name", "member_name", "offset"],
    "KtStackLimit": ["struct_name", "member_name", "offset"],
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
