from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import ida_preprocessor_common as preprocessor_common

PRE_18305_FUNCTION_NAME = "KeQueryCurrentStackInformation"
POST_18305_FUNCTION_NAME = "KeQueryCurrentStackInformationEx"

TARGET_FUNCTION_NAMES = [
    PRE_18305_FUNCTION_NAME,
    POST_18305_FUNCTION_NAME,
]

LLM_DECOMPILE_BY_FUNCTION = {
    PRE_18305_FUNCTION_NAME: [
        (
            PRE_18305_FUNCTION_NAME,
            PRE_18305_FUNCTION_NAME,
            "prompt/call_llm_decompile.md",
            "references/ntoskrnl/RtlpGetStackLimits.pre-18305.{arch}.yaml",
        ),
    ],
    POST_18305_FUNCTION_NAME: [
        (
            POST_18305_FUNCTION_NAME,
            POST_18305_FUNCTION_NAME,
            "prompt/call_llm_decompile.md",
            "references/ntoskrnl/RtlpGetStackLimits.post-18305.{arch}.yaml",
        ),
    ],
}

FUNC_METADATA = {
    PRE_18305_FUNCTION_NAME: {
        "alias": [PRE_18305_FUNCTION_NAME],
    },
    POST_18305_FUNCTION_NAME: {
        "alias": [POST_18305_FUNCTION_NAME],
    },
}

GENERATE_YAML_DESIRED_FIELDS = {
    PRE_18305_FUNCTION_NAME: ["func_name", "func_rva"],
    POST_18305_FUNCTION_NAME: ["func_name", "func_rva"],
}


def _symbol_name(symbol: Any) -> str | None:
    if isinstance(symbol, Mapping):
        name = symbol.get("name")
    else:
        name = getattr(symbol, "name", None)
    return name if isinstance(name, str) else None


def _target_function_name(binary_dir) -> str | None:
    has_ex = preprocessor_common.has_current_stack_information_ex(binary_dir)
    if has_ex is None:
        return None
    return POST_18305_FUNCTION_NAME if has_ex else PRE_18305_FUNCTION_NAME


async def preprocess_skill(session, skill, symbol, binary_dir, pdb_path, debug, llm_config):
    selected_function_name = _target_function_name(binary_dir)
    if selected_function_name is None:
        return preprocessor_common.PREPROCESS_STATUS_FAILED

    target_symbol_name = _symbol_name(symbol)
    if target_symbol_name != selected_function_name:
        if target_symbol_name in TARGET_FUNCTION_NAMES:
            return preprocessor_common.PREPROCESS_STATUS_ABSENT_OK
        return preprocessor_common.PREPROCESS_STATUS_FAILED

    return await preprocessor_common.preprocess_common_skill(
        session=session,
        skill=skill,
        symbol=symbol,
        binary_dir=binary_dir,
        pdb_path=pdb_path,
        debug=debug,
        llm_config=llm_config,
        func_names=[selected_function_name],
        func_metadata={selected_function_name: FUNC_METADATA[selected_function_name]},
        llm_decompile_specs=LLM_DECOMPILE_BY_FUNCTION[selected_function_name],
        generate_yaml_desired_fields={
            selected_function_name: GENERATE_YAML_DESIRED_FIELDS[selected_function_name],
        },
    )
