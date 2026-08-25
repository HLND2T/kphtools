from __future__ import annotations

import ida_preprocessor_common as preprocessor_common

TARGET_FUNCTION_NAMES = ["MmPurgeSection"]

FUNC_XREFS = [
    {
        "func_name": "MmPurgeSection",
        "xref_strings": [],
        "xref_unicode_strings": [],
        "xref_gvs": [],
        "xref_signatures": ["B9 DE 00 00 00", "81 ?? ?? 00 80 00 00"],
        "xref_funcs": [],
        "exclude_funcs": [],
        "exclude_strings": [],
        "exclude_unicode_strings": [],
        "exclude_gvs": [],
        "exclude_signatures": [],
    },
]

FUNC_XREFS_ALTERNATIVE = [
    {
        "func_name": "MmPurgeSection",
        "xref_strings": [],
        "xref_unicode_strings": [],
        "xref_gvs": [],
        "xref_signatures": [
            "48 89 5C 24 ?? 55 56 57 41 54 41 55 41 56 41 57 "
            "48 8D 6C 24 ?? 48 81 EC 90 00 00 00 45 33 ED 33 C0"
        ],
        "xref_funcs": [],
        "exclude_funcs": [],
        "exclude_strings": [],
        "exclude_unicode_strings": [],
        "exclude_gvs": [],
        "exclude_signatures": [],
    },
]

GENERATE_YAML_DESIRED_FIELDS = {
    "MmPurgeSection": ["func_name", "func_rva"],
}


async def preprocess_skill(session, skill, symbol, binary_dir, pdb_path, debug, llm_config):
    for strategy_name, func_xrefs in (
        ("primary", FUNC_XREFS),
        ("alternative", FUNC_XREFS_ALTERNATIVE),
    ):
        if debug and strategy_name == "alternative":
            print("    Preprocess: retrying MmPurgeSection with alternative xrefs")
        status = await preprocessor_common.preprocess_common_skill(
            session=session,
            skill=skill,
            symbol=symbol,
            binary_dir=binary_dir,
            pdb_path=pdb_path,
            debug=debug,
            llm_config=llm_config,
            func_names=TARGET_FUNCTION_NAMES,
            func_xrefs=func_xrefs,
            generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        )
        if status != preprocessor_common.PREPROCESS_STATUS_FAILED:
            return status

    return preprocessor_common.PREPROCESS_STATUS_FAILED
