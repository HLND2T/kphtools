from __future__ import annotations

from ida_mcp_resolver import resolve_struct_offset_via_llm
from ida_skill_preprocessor import PREPROCESS_STATUS_FAILED, PREPROCESS_STATUS_SUCCESS
from pdb_resolver import resolve_struct_symbol
from symbol_artifacts import artifact_path, write_struct_yaml


async def preprocess_skill(session, skill, symbol, binary_dir, pdb_path, debug, llm_config):
    output_path = artifact_path(binary_dir, symbol.name)
    try:
        payload = resolve_struct_symbol(
            pdb_path,
            symbol.symbol_expr or f"{symbol.struct_name}->{symbol.member_name}",
            bits=symbol.bits,
        )
        write_struct_yaml(output_path, payload)
        return PREPROCESS_STATUS_SUCCESS
    except KeyError:
        if not llm_config:
            return PREPROCESS_STATUS_FAILED

    try:
        payload = await resolve_struct_offset_via_llm(
            llm_config=llm_config,
            reference_blocks=[symbol.struct_name or ""],
            target_blocks=[symbol.member_name or ""],
        )
    except (KeyError, ValueError, TypeError):
        return PREPROCESS_STATUS_FAILED

    if symbol.bits and "bit_offset" not in payload:
        return PREPROCESS_STATUS_FAILED

    write_struct_yaml(
        output_path,
        {
            "struct_name": symbol.struct_name,
            "member_name": symbol.member_name,
            **payload,
        },
    )
    return PREPROCESS_STATUS_SUCCESS
