from __future__ import annotations

from importlib import import_module


PREPROCESS_STATUS_SUCCESS = "success"
PREPROCESS_STATUS_FAILED = "failed"
PREPROCESS_STATUS_ABSENT_OK = "absent_ok"


_CATEGORY_MODULE = {
    "struct_offset": "ida_preprocessor_scripts.generic_struct_offset",
    "gv": "ida_preprocessor_scripts.generic_gv",
    "func": "ida_preprocessor_scripts.generic_func",
}


async def preprocess_single_skill_via_mcp(
    session,
    skill,
    symbol,
    binary_dir,
    pdb_path,
    debug: bool,
    llm_config,
):
    module = import_module(_CATEGORY_MODULE[symbol.category])
    return await module.preprocess_skill(
        session=session,
        skill=skill,
        symbol=symbol,
        binary_dir=binary_dir,
        pdb_path=pdb_path,
        debug=debug,
        llm_config=llm_config,
    )
