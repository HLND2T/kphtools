from __future__ import annotations

import ida_preprocessor_common as preprocessor_common

TARGET_STRUCT_MEMBER_NAMES = [
    "KtReadOperationCount",
    "KtWriteOperationCount",
    "KtOtherOperationCount",
    "KtReadTransferCount",
    "KtWriteTransferCount",
    "KtOtherTransferCount",
]

LLM_DECOMPILE = [
    {
        "symbol_name": "KtReadOperationCount",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/ntoskrnl/KeFoldProcessStatisticsThread.{arch}.yaml",
        ],
        "expected_result_sections": ["found_struct_offset"],
        "dependency_policy": {
            "KeFoldProcessStatisticsThread.yaml": "required",
        },
    },
    {
        "symbol_name": "KtWriteOperationCount",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/ntoskrnl/KeFoldProcessStatisticsThread.{arch}.yaml",
        ],
        "expected_result_sections": ["found_struct_offset"],
        "dependency_policy": {
            "KeFoldProcessStatisticsThread.yaml": "required",
        },
    },
    {
        "symbol_name": "KtOtherOperationCount",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/ntoskrnl/KeFoldProcessStatisticsThread.{arch}.yaml",
        ],
        "expected_result_sections": ["found_struct_offset"],
        "dependency_policy": {
            "KeFoldProcessStatisticsThread.yaml": "required",
        },
    },
    {
        "symbol_name": "KtReadTransferCount",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/ntoskrnl/KeFoldProcessStatisticsThread.{arch}.yaml",
        ],
        "expected_result_sections": ["found_struct_offset"],
        "dependency_policy": {
            "KeFoldProcessStatisticsThread.yaml": "required",
        },
    },
    {
        "symbol_name": "KtWriteTransferCount",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/ntoskrnl/KeFoldProcessStatisticsThread.{arch}.yaml",
        ],
        "expected_result_sections": ["found_struct_offset"],
        "dependency_policy": {
            "KeFoldProcessStatisticsThread.yaml": "required",
        },
    },
    {
        "symbol_name": "KtOtherTransferCount",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/ntoskrnl/KeFoldProcessStatisticsThread.{arch}.yaml",
        ],
        "expected_result_sections": ["found_struct_offset"],
        "dependency_policy": {
            "KeFoldProcessStatisticsThread.yaml": "required",
        },
    },
]

STRUCT_METADATA = {
    "KtReadOperationCount": {
        "symbol_expr": "_KTHREAD->ReadOperationCount",
        "struct_name": "_KTHREAD",
        "member_name": "ReadOperationCount",
        "bits": False,
    },
    "KtWriteOperationCount": {
        "symbol_expr": "_KTHREAD->WriteOperationCount",
        "struct_name": "_KTHREAD",
        "member_name": "WriteOperationCount",
        "bits": False,
    },
    "KtOtherOperationCount": {
        "symbol_expr": "_KTHREAD->OtherOperationCount",
        "struct_name": "_KTHREAD",
        "member_name": "OtherOperationCount",
        "bits": False,
    },
    "KtReadTransferCount": {
        "symbol_expr": "_KTHREAD->ReadTransferCount",
        "struct_name": "_KTHREAD",
        "member_name": "ReadTransferCount",
        "bits": False,
    },
    "KtWriteTransferCount": {
        "symbol_expr": "_KTHREAD->WriteTransferCount",
        "struct_name": "_KTHREAD",
        "member_name": "WriteTransferCount",
        "bits": False,
    },
    "KtOtherTransferCount": {
        "symbol_expr": "_KTHREAD->OtherTransferCount",
        "struct_name": "_KTHREAD",
        "member_name": "OtherTransferCount",
        "bits": False,
    },
}

GENERATE_YAML_DESIRED_FIELDS = {
    "KtReadOperationCount": ["struct_name", "member_name", "offset"],
    "KtWriteOperationCount": ["struct_name", "member_name", "offset"],
    "KtOtherOperationCount": ["struct_name", "member_name", "offset"],
    "KtReadTransferCount": ["struct_name", "member_name", "offset"],
    "KtWriteTransferCount": ["struct_name", "member_name", "offset"],
    "KtOtherTransferCount": ["struct_name", "member_name", "offset"],
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
