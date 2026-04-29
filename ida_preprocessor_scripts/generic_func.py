from __future__ import annotations

from ida_mcp_resolver import resolve_public_name_via_mcp
from ida_skill_preprocessor import PREPROCESS_STATUS_FAILED, PREPROCESS_STATUS_SUCCESS
from pdb_resolver import resolve_public_symbol
from symbol_artifacts import artifact_path, write_func_yaml


async def preprocess_skill(session, skill, symbol, binary_dir, pdb_path, debug, llm_config):
    output_path = artifact_path(binary_dir, symbol.name)
    lookup_name = (symbol.alias or [symbol.name])[0]
    try:
        payload = resolve_public_symbol(pdb_path, lookup_name)
    except KeyError:
        try:
            payload = await resolve_public_name_via_mcp(
                session,
                lookup_name,
                image_base=0x140000000,
            )
        except (KeyError, ValueError, TypeError):
            return PREPROCESS_STATUS_FAILED

    write_func_yaml(output_path, {"func_name": symbol.name, "func_rva": payload["rva"]})
    return PREPROCESS_STATUS_SUCCESS
