from __future__ import annotations

import ida_preprocessor_common as preprocessor_common

TARGET_FUNCTION_NAMES = ["MiCheckControlArea"]

FUNC_XREFS = [
    {
        "func_name": "MiCheckControlArea",
        "xref_strings": [],
        "xref_unicode_strings": [],
        "xref_gvs": [],
        "xref_signatures": ["BA 03 00 00 00", "20 00 02 00"],
        "xref_funcs": ["MiInsertUnusedSegment"],
        "exclude_funcs": [],
        "exclude_strings": [],
        "exclude_unicode_strings": [],
        "exclude_gvs": [],
        "exclude_signatures": [],
    },
]

GENERATE_YAML_DESIRED_FIELDS = {
    "MiCheckControlArea": ["func_name", "func_rva"],
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
