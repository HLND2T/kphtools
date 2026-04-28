from __future__ import annotations

import json
from typing import Any

import yaml

from ida_llm_utils import call_llm_text


def _parse_py_eval_result(tool_result: Any) -> dict:
    text = tool_result.content[0].text
    payload = json.loads(text)
    return json.loads(payload["result"])


def _parse_offset_value(value: Any) -> int:
    if isinstance(value, int):
        return value
    return int(str(value), 16)


def _parse_rva_value(payload: dict[str, Any]) -> int:
    if "rva" not in payload:
        raise ValueError("missing rva in py_eval result")

    value = payload["rva"]
    if isinstance(value, int):
        return value
    if not isinstance(value, str):
        raise TypeError("rva must be an int or hex string")
    return int(value, 16)


async def resolve_public_name_via_mcp(
    session,
    symbol_name: str,
    image_base: int,
) -> dict[str, int | str]:
    py_code = (
        "import json\n"
        "import idc\n"
        f"symbol_name = {symbol_name!r}\n"
        f"image_base = {image_base}\n"
        "ea = idc.get_name_ea_simple(symbol_name)\n"
        "if ea == idc.BADADDR:\n"
        "    result = json.dumps({})\n"
        "else:\n"
        "    rva = ea - image_base\n"
        "    result = json.dumps({'rva': hex(rva)})\n"
    )
    tool_result = await session.call_tool("py_eval", {"code": py_code})
    payload = _parse_py_eval_result(tool_result)
    return {"name": symbol_name, "rva": _parse_rva_value(payload)}


async def resolve_struct_offset_via_llm(
    llm_config: dict,
    reference_blocks: list[str],
    target_blocks: list[str],
) -> dict[str, int]:
    prompt = "\n".join(
        [
            "Return YAML with a single key offset.",
            "Reference:",
            *reference_blocks,
            "Target:",
            *target_blocks,
        ]
    )
    raw = await call_llm_text(
        model=llm_config["model"],
        prompt=prompt,
        api_key=llm_config.get("api_key", ""),
        base_url=llm_config.get("base_url"),
        temperature=llm_config.get("temperature"),
    )
    payload = yaml.safe_load(raw) or {}
    return {"offset": _parse_offset_value(payload["offset"])}
