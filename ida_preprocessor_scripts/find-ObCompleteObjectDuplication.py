from __future__ import annotations

import ida_preprocessor_common as preprocessor_common

TARGET_FUNCTION_NAMES = ["ObCompleteObjectDuplication"]

FUNC_XREFS = [
    {
        "func_name": "ObCompleteObjectDuplication",
        "xref_strings": [],
        "xref_unicode_strings": [],
        "xref_gvs": [],
        "xref_signatures": ["BA 4F 62 48 6E"],
        "xref_funcs": ["ObReferenceProcessHandleTable"],
        "exclude_funcs": [],
        "exclude_strings": [],
        "exclude_unicode_strings": [],
        "exclude_gvs": [],
        "exclude_signatures": ["35 02 00 C0"],
    },
]

GENERATE_YAML_DESIRED_FIELDS = {
    "ObCompleteObjectDuplication": ["func_name", "func_rva"],
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
        func_names=TARGET_FUNCTION_NAMES,
        func_xrefs=FUNC_XREFS,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
    )
