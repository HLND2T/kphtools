from __future__ import annotations

from pdb_resolver import resolve_public_symbol


async def preprocess_gv_symbol(
    *,
    session,
    symbol_name: str,
    metadata: dict,
    pdb_path,
    debug: bool,
    llm_config,
):
    aliases = metadata.get("alias") or [symbol_name]
    lookup_name = aliases[0]
    try:
        payload = resolve_public_symbol(pdb_path, lookup_name)
    except KeyError:
        return None

    return {"gv_name": symbol_name, "gv_rva": payload["rva"]}
