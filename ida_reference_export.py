from __future__ import annotations

import json
import os
import textwrap
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import yaml

from ida_reference_export_template import FUNCTION_DETAIL_EXPORT_TEMPLATE


class ReferenceGenerationError(RuntimeError):
    pass


class LiteralDumper(yaml.SafeDumper):
    pass


def _literal_str_representer(dumper: yaml.Dumper, value: str) -> yaml.Node:
    style = "|" if "\n" in value else None
    return dumper.represent_scalar("tag:yaml.org,2002:str", value, style=style)


LiteralDumper.add_representer(str, _literal_str_representer)


def _normalize_non_empty_text(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    return text or None


def _normalize_address_text(value: Any, *, require_string: bool = False) -> str | None:
    if require_string:
        text = _normalize_non_empty_text(value)
        if text is None:
            return None
        try:
            int(text, 0)
        except (TypeError, ValueError):
            return None
        return text
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            int(text, 0)
        except (TypeError, ValueError):
            return None
        return text
    if isinstance(value, int):
        return hex(value)
    return None


def validate_reference_yaml_payload(payload: Mapping[str, Any]) -> dict[str, str]:
    func_name = _normalize_non_empty_text(payload.get("func_name"))
    func_va = _normalize_address_text(payload.get("func_va"))
    disasm_code = _normalize_non_empty_text(payload.get("disasm_code"))
    procedure_raw = payload.get("procedure", "")
    if func_name is None or func_va is None or disasm_code is None:
        raise ReferenceGenerationError("invalid reference YAML payload")
    if procedure_raw is None:
        procedure = ""
    elif isinstance(procedure_raw, str):
        procedure = procedure_raw
    else:
        raise ReferenceGenerationError("invalid reference YAML payload")
    return {
        "func_name": func_name,
        "func_va": func_va,
        "disasm_code": disasm_code,
        "procedure": procedure,
    }


def build_remote_text_export_py_eval(
    *,
    output_path: str | Path,
    producer_code: str,
    content_var: str = "payload_text",
    format_name: str = "text",
) -> str:
    output_path_str = os.fspath(output_path)
    if not os.path.isabs(output_path_str):
        raise ValueError(f"output_path must be absolute, got {output_path_str!r}")
    if not str(producer_code).strip():
        raise ValueError("producer_code cannot be empty")
    if not str(content_var).strip():
        raise ValueError("content_var cannot be empty")
    producer_block = textwrap.indent(str(producer_code).rstrip(), "    ")
    return (
        "import json, os, traceback\n"
        f"output_path = {output_path_str!r}\n"
        f"format_name = {str(format_name)!r}\n"
        "tmp_path = output_path + '.tmp'\n"
        "def _truncate_text(value, limit=800):\n"
        "    text = '' if value is None else str(value)\n"
        "    return text if len(text) <= limit else text[:limit] + ' [truncated]'\n"
        "try:\n"
        "    if not os.path.isabs(output_path):\n"
        "        raise ValueError(f'output_path must be absolute: {output_path}')\n"
        f"{producer_block}\n"
        f"    payload_text = str({content_var})\n"
        "    parent_dir = os.path.dirname(output_path)\n"
        "    if parent_dir:\n"
        "        os.makedirs(parent_dir, exist_ok=True)\n"
        "    with open(tmp_path, 'w', encoding='utf-8') as handle:\n"
        "        handle.write(payload_text)\n"
        "    os.replace(tmp_path, output_path)\n"
        "    result = json.dumps({\n"
        "        'ok': True,\n"
        "        'output_path': output_path,\n"
        "        'bytes_written': len(payload_text.encode('utf-8')),\n"
        "        'format': format_name,\n"
        "    })\n"
        "except Exception as exc:\n"
        "    try:\n"
        "        if os.path.exists(tmp_path):\n"
        "            os.unlink(tmp_path)\n"
        "    except Exception:\n"
        "        pass\n"
        "    result = json.dumps({\n"
        "        'ok': False,\n"
        "        'output_path': output_path,\n"
        "        'error': _truncate_text(exc),\n"
        "        'traceback': _truncate_text(traceback.format_exc()),\n"
        "    })\n"
    )


def build_function_detail_export_py_eval(func_va_int: int) -> str:
    return FUNCTION_DETAIL_EXPORT_TEMPLATE.replace("__FUNC_VA_INT__", str(func_va_int), 1).strip() + "\n"


def build_reference_yaml_export_py_eval(
    func_va_int: int,
    *,
    output_path: str | Path,
    func_name: str,
) -> str:
    normalized_func_name = str(func_name).strip()
    producer_code = (
        build_function_detail_export_py_eval(func_va_int).rstrip()
        + "\n"
        + "payload = json.loads(result)\n"
        + f"payload['func_name'] = {json.dumps(normalized_func_name)}\n"
        + "import yaml\n"
        + "class LiteralDumper(yaml.SafeDumper):\n"
        + "    pass\n"
        + "def _literal_str_representer(dumper, value):\n"
        + "    style = '|' if '\\n' in value else None\n"
        + "    return dumper.represent_scalar('tag:yaml.org,2002:str', value, style=style)\n"
        + "LiteralDumper.add_representer(str, _literal_str_representer)\n"
        + "payload_text = yaml.dump(\n"
        + "    payload,\n"
        + "    Dumper=LiteralDumper,\n"
        + "    sort_keys=False,\n"
        + "    allow_unicode=True,\n"
        + ")\n"
    )
    return build_remote_text_export_py_eval(
        output_path=output_path,
        producer_code=producer_code,
        content_var="payload_text",
        format_name="yaml",
    )


def _parse_py_eval_result_json(result: Any) -> dict[str, Any] | None:
    content = getattr(result, "content", None)
    if not content:
        return None
    item = content[0]
    raw = getattr(item, "text", None)
    if not isinstance(raw, str):
        raw = str(item)
    try:
        payload = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(payload, dict):
        return None
    result_text = payload.get("result", "")
    if not isinstance(result_text, str) or not result_text:
        return None
    try:
        parsed = json.loads(result_text)
    except (json.JSONDecodeError, TypeError):
        return None
    return parsed if isinstance(parsed, dict) else None


def _is_valid_remote_export_ack(
    export_ack: Any,
    *,
    output_path: str | Path,
    format_name: str,
) -> bool:
    if not isinstance(export_ack, Mapping) or not bool(export_ack.get("ok")):
        return False
    if str(export_ack.get("output_path", "")).strip() != os.fspath(output_path):
        return False
    if str(export_ack.get("format", "")).strip() != format_name:
        return False
    try:
        bytes_written = int(export_ack.get("bytes_written"))
    except (TypeError, ValueError):
        return False
    return bytes_written >= 0


async def export_reference_yaml_via_mcp(
    session: Any,
    *,
    func_name: str,
    func_va: str,
    output_path: str | Path,
    debug: bool = False,
) -> Path:
    del debug
    normalized_func_va = _normalize_address_text(func_va)
    if normalized_func_va is None:
        raise ReferenceGenerationError("unable to export reference YAML via IDA")
    resolved_output_path = Path(output_path).resolve()
    try:
        eval_result = await session.call_tool(
            name="py_eval",
            arguments={
                "code": build_reference_yaml_export_py_eval(
                    int(normalized_func_va, 0),
                    output_path=resolved_output_path,
                    func_name=func_name,
                )
            },
        )
        export_ack = _parse_py_eval_result_json(eval_result)
        if not _is_valid_remote_export_ack(
            export_ack,
            output_path=resolved_output_path,
            format_name="yaml",
        ):
            raise ReferenceGenerationError("unable to export reference YAML via IDA")
        payload = yaml.safe_load(resolved_output_path.read_text(encoding="utf-8")) or {}
        validate_reference_yaml_payload(payload)
    except ReferenceGenerationError:
        raise
    except Exception as exc:
        raise ReferenceGenerationError("unable to export reference YAML via IDA") from exc
    return resolved_output_path
