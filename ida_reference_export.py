from __future__ import annotations

import base64
import json
import os
import textwrap
import zlib
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import yaml


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


_FUNCTION_DETAIL_EXPORT_TEMPLATE_B85 = """
c-qxjOLN;c5We$Qu)2tBRE?dqIjHd=P2!nea>%5a%%m9(EJ89J3S>dhu}9<o-rWU20wgHObq_5M5+93wKR%FAv8yYo;v#3+)xF})f=)NBSew(b5cY1vw>vHrU9_qw>GpaN-!zqol)PU>F&qxZYknu$eG~D!HLq3tj{b^D7{Z<+zKGvff=3Yw&NzeXEW7;U{hRF5>+JXUAG0iqa=wW(R@YqQ+4{N_-!jR>mM6|RDAXt>6>wO@NXJ>KWp&!&VQD~0Ayi^7(~dwdHIEG+dKfkY56M+4g|=(cOL%2?^@OgvOKnb)jI>UTz3Zwh`C7RKHwik)*yY{_eZPDiTU&@i6|Bs{q<Cy9Ir1AU>%zQzgG;sCW#_G40v@5rgd_(d6m$(af4uxi6l&HqHU^?n9><<avEq<BJnsc>bW94xB~#$Oi@t1@l*8WROzD_;Os1{)ha%Du1LFmcaM^J5{=r~QDL^$k5a81k4M{}8n2CHKdQ->-^c)NOeqEG2{wP}>R)m5D3i#~kZourRd<+r>6Jjw*y5))~C3V+X#B=Mx`GSm2PhY9C|M0r7ZNab#eiwADJ+35Y-=fo!??{2zsE4a-%KKv{$6gMa%VARpG=>qU<0U^dCc)0`m%t+K?%5`+P1dbFZeXhMJc07@Mo!nNH$`VK_H;DJqtnVv_1du7-YB_<g9F7;Q9p8()>D=AE1Ikj{vesq(X2gckz4K736<P2m9adRyg>nmB|rz$zzm33LOH-`VnYq*nP59UrlNCt2EN~><P+e=%ZA7ExvTJIwzq5^R(tT#+4;-Q4>Pkuv!`W1*gdu0fjWX|yF;lO^SH`$0eWHN(=LdT*PJPK1$_&`mz*u)bEo=7Bg3#J^VVe6dZ);xJ)`u*^6Yte4cQieemYztR3X})SV6lmz9wszifuE=chxN*D$OB<+K@%<G*~QrTt}T9Pf#9Mj}G$X;hiO9L4ss{G2a)w)XSsD^u-J=BtwsYO14iDw48fSZL_rX?k|OG#HS-n)`bkxnctzlx*`2^jzK#yYMv;H8*w{5WCQ>I4};~@33Y*Wm2&{_EN_x0H@X90Tw?<u_(9jsZ?E6Je*5+V*)`b^gOF`gvTbAhNSht1L%N#`N6v9{<_}ck@t!rbTXaxD>;rRId)9R8gKFbsH`@^~pRUmBNeDteLG@0I?`8<2eL@rH6mF!fS!MD@f~Jr;dC{<D*ELw{7`pC32Ih{=79a^EiEFVLHJPcAzy$L4IkuvK_racT4_$9&p9XWo756X#S--}6!|!3%%XN&Ns$xA91Y$YvI*EdOmSPm<^I(lT#81(D@9?p@o3T3oQ_Pn)RUr~$*=s?O#S+qMlfiBRp_I34p=yJ(L6L(IL^{#Gama`Ex(D{gT0ASuE4Bvg!jRm7ZzhGDG&`lOrKt-uUG9?_d*zIAD8$yN^JNS`dw_jgG@wv!HRtZ$&R9M9)F=;Tv^2O%E)rMSo_5FXvPSV5xeV9+82=nUi=Y4U(s^m3DbJ!oXLjwvo~#L9_3T&U-hjqC>y~u|`Q&%8Lt8=<gGWHx<2~!K1H#ec^rk;88d&L6bYg#K{pgXij%ImCUoUqisdNCJUBu^ODLcV;;2`Q(wS+K202-0uZ7M0#r^@O(mw}zR<Qq!<@U|9`0tmu;UJbc7{%a|4^#|a1DXSd?{*nQ@pWHKt(#6UgB+ZD$*C_Z(0{2BUbdKzl9yQZDKD5{A<+$%wXdB~<=_r&?6fE4F%%Lv<cE&$p{x|qvnEUvj+mpZOM5q_|e_awmn?IjFHl1~<T*UL6T|HkN3##O|TsF|4F+~o%#sJ2+!eH5>#S&<~b|g-w+ChtSyKcT0>N=U<OgZJhY1mUh-eKo>jookx>oD5e{9DR}6&ouR9;C~*&H;K&OiKGgBm`m&uJE{}r+qC5GxSyHFjn30Hm_*93~-j&cGyoT2Vm6r+dx0S%<?6^b+;E;UA9}meQEG*lVM1{bg-UflyiW>H4O0q+&k(O!`JSRk@XbK2%!eSHQrd_kA{4N!*M4{@N3{(e4V!~t1Fl!NoupAtk!g$>JL<5P-{M2rBM*iN>)I}{=~|bzmu|(fXFX_2pypDB*3nG74N}&9Vf)$`imHO&}6a?8Y95;ZHdqDE8H?~cXgv*bniQ#&4>rS{+g`<n(KFKy&Rh2n_1IdW&8f_>hr^FF<^PifMKVxUhL4Av_`)IowHF0lh?9Z^SqUo*on$$!9$cre*=?nNO=
"""


def build_function_detail_export_py_eval(func_va_int: int) -> str:
    return (
        zlib.decompress(
            base64.b85decode(_FUNCTION_DETAIL_EXPORT_TEMPLATE_B85.replace("\n", ""))
        )
        .decode("utf-8")
        .replace("__FUNC_VA_INT__", str(func_va_int), 1)
        .strip()
        + "\n"
    )


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


def _parse_py_eval_json_result(result: Any) -> dict[str, Any] | None:
    content = getattr(result, "content", None)
    if not content:
        return None
    item = content[0]
    raw = getattr(item, "text", None)
    if not isinstance(raw, str):
        raw = str(item)
    try:
        payload = json.loads(raw)
        result_text = payload.get("result", "") if isinstance(payload, dict) else ""
        parsed = json.loads(result_text) if isinstance(result_text, str) and result_text else None
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
        export_ack = _parse_py_eval_json_result(eval_result)
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
