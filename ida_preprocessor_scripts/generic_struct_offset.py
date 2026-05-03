from __future__ import annotations

from pdb_resolver import resolve_struct_symbol


async def preprocess_struct_symbol(
    *,
    session,
    symbol_name: str,
    metadata: dict,
    pdb_path,
    debug: bool,
    llm_config,
    binary_dir=None,
    image_base: int = 0x140000000,
    llm_decompile_specs=None,
):
    symbol_expr = metadata["symbol_expr"]
    bits = bool(metadata.get("bits", False))

    try:
        return resolve_struct_symbol(
            pdb_path,
            symbol_expr,
            bits=bits,
        )
    except KeyError:
        return None
