from __future__ import annotations

from ida_preprocessor_scripts import _extract_ntapi


TARGET_FUNCTION_NAMES = ["NtAlpcCreatePortSection"]

NTAPI_SIGNATURES = {
    "NtAlpcCreatePortSection": ["BE A7 FB 31 06 00 00 00"],
}

GENERATE_YAML_DESIRED_FIELDS = {
    "NtAlpcCreatePortSection": ["func_name", "func_rva"],
}


async def preprocess_skill(session, skill, symbol, binary_dir, pdb_path, debug, llm_config):
    return await _extract_ntapi.preprocess_ntapi_symbols(
        session=session,
        skill=skill,
        symbol=symbol,
        binary_dir=binary_dir,
        pdb_path=pdb_path,
        debug=debug,
        target_function_names=TARGET_FUNCTION_NAMES,
        ntapi_signatures=NTAPI_SIGNATURES,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
    )
