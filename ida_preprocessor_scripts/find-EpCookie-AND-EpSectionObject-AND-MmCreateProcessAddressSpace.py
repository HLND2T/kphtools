from __future__ import annotations

import ida_preprocessor_common as preprocessor_common

TARGET_STRUCT_MEMBER_NAMES = ["EpCookie", "EpSectionObject"]

TARGET_FUNCTION_NAMES = ["MmCreateProcessAddressSpace"]

LLM_DECOMPILE = [
    (
        "EpCookie",
        "_EPROCESS->Cookie",
        "prompt/call_llm_decompile.md",
        "references/ntoskrnl/PspAllocateProcess.{arch}.yaml",
    ),
    (
        "EpSectionObject",
        "_EPROCESS->SectionObject",
        "prompt/call_llm_decompile.md",
        "references/ntoskrnl/PspAllocateProcess.{arch}.yaml",
    ),
    (
        "MmCreateProcessAddressSpace",
        "MmCreateProcessAddressSpace",
        "prompt/call_llm_decompile.md",
        "references/ntoskrnl/PspAllocateProcess.{arch}.yaml",
    ),
]

STRUCT_METADATA = {
    "EpCookie": {
        "symbol_expr": "_EPROCESS->Cookie",
        "struct_name": "_EPROCESS",
        "member_name": "Cookie",
        "bits": False,
    },
    "EpSectionObject": {
        "symbol_expr": "_EPROCESS->SectionObject",
        "struct_name": "_EPROCESS",
        "member_name": "SectionObject",
        "bits": False,
    },
}

FUNC_METADATA = {
    "MmCreateProcessAddressSpace": {
        "alias": ["MmCreateProcessAddressSpace"],
    }
}

GENERATE_YAML_DESIRED_FIELDS = {
    "EpCookie": ['struct_name', 'member_name', 'offset'],
    "EpSectionObject": ['struct_name', 'member_name', 'offset'],
    "MmCreateProcessAddressSpace": ["func_name", "func_rva"],
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
        func_names=TARGET_FUNCTION_NAMES,
        func_metadata=FUNC_METADATA,
        llm_decompile_specs=LLM_DECOMPILE,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
    )
