from __future__ import annotations

import ida_preprocessor_common as preprocessor_common

TARGET_STRUCT_MEMBER_NAMES = ["EpObjectTable"]

STRUCT_METADATA = {
    "EpObjectTable": {
        "symbol_expr": "_EPROCESS->ObjectTable",
        "struct_name": "_EPROCESS",
        "member_name": "ObjectTable",
        "bits": False,
    }
}

GENERATE_YAML_DESIRED_FIELDS = {
    "EpObjectTable": ['struct_name', 'member_name', 'offset'],
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
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
    )
