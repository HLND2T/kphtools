from __future__ import annotations

import ida_preprocessor_common as preprocessor_common

TARGET_STRUCT_MEMBER_NAMES = ["KtInitialStack", "KtStackBase", "KtStackLimit"]

PRE_18305_REFERENCE_YAML_PATH = (
    "references/ntoskrnl/KeQueryCurrentStackInformation.{arch}.yaml"
)
POST_18305_REFERENCE_YAML_PATH = (
    "references/ntoskrnl/KeQueryCurrentStackInformationEx.{arch}.yaml"
)

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


def _llm_decompile_specs(binary_dir) -> list[dict[str, object]]:
    has_ex = preprocessor_common.has_current_stack_information_ex(binary_dir)
    if has_ex is None:
        return []
    reference_yaml_path = (
        POST_18305_REFERENCE_YAML_PATH if has_ex else PRE_18305_REFERENCE_YAML_PATH
    )
    target_artifact = (
        "KeQueryCurrentStackInformationEx.yaml"
        if has_ex
        else "KeQueryCurrentStackInformation.yaml"
    )
    return [
        {
            "symbol_name": symbol_name,
            "prompt_path": "prompt/call_llm_decompile.md",
            "reference_yaml_paths": [reference_yaml_path],
            "expected_result_sections": ["found_struct_offset"],
            "dependency_policy": {target_artifact: "required"},
        }
        for symbol_name in TARGET_STRUCT_MEMBER_NAMES
    ]


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
        llm_decompile_specs=_llm_decompile_specs(binary_dir),
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
    )
