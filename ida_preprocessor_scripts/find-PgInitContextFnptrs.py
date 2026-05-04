from __future__ import annotations

import re
from pathlib import Path

import ida_preprocessor_common as preprocessor_common

TARGET_FUNCTION_NAMES = ["PspEnumerateCallback", "CmpEnumerateCallback"]

LLM_DECOMPILE = [
    (
        "PspEnumerateCallback",
        "PspEnumerateCallback",
        "prompt/call_llm_decompile.md",
        "references/ntoskrnl/PgInitContext.{buildnum}.{arch}.yaml",
    ),
    (
        "CmpEnumerateCallback",
        "CmpEnumerateCallback",
        "prompt/call_llm_decompile.md",
        "references/ntoskrnl/PgInitContext.{buildnum}.{arch}.yaml",
    ),
]

FUNC_METADATA = {
    "PspEnumerateCallback": {
        "alias": ["PspEnumerateCallback"],
    },
    "CmpEnumerateCallback": {
        "alias": ["CmpEnumerateCallback"],
    },
}

GENERATE_YAML_DESIRED_FIELDS = {
    "PspEnumerateCallback": ["func_name", "func_rva"],
    "CmpEnumerateCallback": ["func_name", "func_rva"],
}

_VERSION_DIR_RE = re.compile(r"\.(\d+)\.(\d+)\.(\d+)\.(\d+)$")


def _arch_from_binary_dir(binary_dir: str | Path) -> str | None:
    for part in Path(binary_dir).parts:
        normalized = part.lower()
        if normalized in {"amd64", "arm64"}:
            return normalized
    return None


def _buildnum_from_binary_dir(binary_dir: str | Path) -> str | None:
    for part in Path(binary_dir).parts:
        match = _VERSION_DIR_RE.search(part)
        if match:
            return match.group(3)
    return None


def _llm_decompile_specs(binary_dir: str | Path) -> list[tuple[str, str, str, str]]:
    arch = _arch_from_binary_dir(binary_dir)
    buildnum = _buildnum_from_binary_dir(binary_dir)
    if not arch or not buildnum:
        return []
    return [
        (
            symbol_name,
            llm_symbol_name,
            prompt_path,
            reference_yaml_path.replace("{buildnum}", buildnum),
        )
        for symbol_name, llm_symbol_name, prompt_path, reference_yaml_path
        in LLM_DECOMPILE
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
