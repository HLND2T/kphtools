from __future__ import annotations

import ida_preprocessor_common as preprocessor_common

TARGET_STRUCT_MEMBER_NAMES = ["KtInitialStack", "KtStackBase", "KtStackLimit"]

PRE_18305_REFERENCE_YAML_PATH = (
    "references/ntoskrnl/KeQueryCurrentStackInformation.{arch}.yaml"
)
POST_18305_REFERENCE_YAML_PATH = (
    "references/ntoskrnl/KeQueryCurrentStackInformationEx.{arch}.yaml"
)

LLM_DECOMPILE_TARGETS = [
    (
        "KtInitialStack",
        "_KTHREAD->InitialStack",
        "prompt/call_llm_decompile.md",
    ),
    (
        "KtStackBase",
        "_KTHREAD->StackBase",
        "prompt/call_llm_decompile.md",
    ),
    (
        "KtStackLimit",
        "_KTHREAD->StackLimit",
        "prompt/call_llm_decompile.md",
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


def _llm_decompile_specs(binary_dir) -> list[tuple[str, str, str, str]]:
    has_ex = preprocessor_common.has_current_stack_information_ex(binary_dir)
    if has_ex is None:
        return []
    reference_yaml_path = (
        POST_18305_REFERENCE_YAML_PATH if has_ex else PRE_18305_REFERENCE_YAML_PATH
    )
    return [
        (symbol_name, llm_symbol_name, prompt_path, reference_yaml_path)
        for symbol_name, llm_symbol_name, prompt_path in LLM_DECOMPILE_TARGETS
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
