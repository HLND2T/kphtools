from __future__ import annotations

from pathlib import Path

import ida_preprocessor_common as preprocessor_common

TARGET_FUNCTION_NAMES = ["ExReferenceCallBackBlock", "ExDereferenceCallBackBlock", "PspEnumerateCallback", "CmpEnumerateCallback"]

LLM_DECOMPILE = [
    {
        "symbol_name": "ExReferenceCallBackBlock",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/ntoskrnl/PgInitContext.{buildnum}.{arch}.yaml",
        ],
        "expected_result_sections": ["found_call", "found_funcptr"],
        "dependency_policy": {
            "PgInitContext.yaml": "required",
        },
    },
    {
        "symbol_name": "ExDereferenceCallBackBlock",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/ntoskrnl/PgInitContext.{buildnum}.{arch}.yaml",
        ],
        "expected_result_sections": ["found_call", "found_funcptr"],
        "dependency_policy": {
            "PgInitContext.yaml": "required",
        },
    },
    {
        "symbol_name": "PspEnumerateCallback",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/ntoskrnl/PgInitContext.{buildnum}.{arch}.yaml",
        ],
        "expected_result_sections": ["found_call", "found_funcptr"],
        "dependency_policy": {
            "PgInitContext.yaml": "required",
        },
    },
    {
        "symbol_name": "CmpEnumerateCallback",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/ntoskrnl/PgInitContext.{buildnum}.{arch}.yaml",
        ],
        "expected_result_sections": ["found_call", "found_funcptr"],
        "dependency_policy": {
            "PgInitContext.yaml": "required",
        },
    },
]

FUNC_METADATA = {
    "ExReferenceCallBackBlock": {
        "alias": ["ExReferenceCallBackBlock"],
    },
    "ExDereferenceCallBackBlock": {
        "alias": ["ExDereferenceCallBackBlock"],
    },
    "PspEnumerateCallback": {
        "alias": ["PspEnumerateCallback"],
    },
    "CmpEnumerateCallback": {
        "alias": ["CmpEnumerateCallback"],
    },
}

GENERATE_YAML_DESIRED_FIELDS = {
    "ExReferenceCallBackBlock": ["func_name", "func_rva"],
    "ExDereferenceCallBackBlock": ["func_name", "func_rva"],
    "PspEnumerateCallback": ["func_name", "func_rva"],
    "CmpEnumerateCallback": ["func_name", "func_rva"],
}


def _llm_decompile_specs(binary_dir: str | Path) -> list[dict[str, object]]:
    arch = preprocessor_common.arch_from_binary_dir(binary_dir)
    buildnum = preprocessor_common.buildnum_from_binary_dir(binary_dir)
    if not arch or not buildnum:
        return []
    return [
        {
            **spec,
            "reference_yaml_paths": [
                reference_path.replace("{buildnum}", buildnum)
                for reference_path in spec["reference_yaml_paths"]
            ],
        }
        for spec in LLM_DECOMPILE
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
        func_names=TARGET_FUNCTION_NAMES,
        func_metadata=FUNC_METADATA,
        llm_decompile_specs=_llm_decompile_specs(binary_dir),
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
    )
