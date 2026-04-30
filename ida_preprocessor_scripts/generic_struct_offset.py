from __future__ import annotations

from ida_mcp_resolver import resolve_struct_offset_via_llm
from pdb_resolver import resolve_struct_symbol


async def preprocess_struct_symbol(
    *,
    session,
    symbol_name: str,
    metadata: dict,
    pdb_path,
    debug: bool,
    llm_config,
):
    symbol_expr = metadata["symbol_expr"]
    struct_name = metadata["struct_name"]
    member_name = metadata["member_name"]
    bits = bool(metadata.get("bits", False))

    try:
        return resolve_struct_symbol(
            pdb_path,
            symbol_expr,
            bits=bits,
        )
    except KeyError:
        if not llm_config:
            return None

    try:
        payload = await resolve_struct_offset_via_llm(
            llm_config=llm_config,
            reference_blocks=[struct_name],
            target_blocks=[member_name],
        )
    except (KeyError, ValueError, TypeError):
        return None

    if bits and "bit_offset" not in payload:
        return None

    return {
        "struct_name": struct_name,
        "member_name": member_name,
        **payload,
    }
