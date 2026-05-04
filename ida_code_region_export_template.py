CODE_REGION_EXPORT_TEMPLATE = r"""
import ida_bytes, ida_lines, ida_segment, idc, json

code_start = __CODE_VA_INT__
code_size = __CODE_SIZE_INT__

def _format_address(ea):
    seg = ida_segment.getseg(ea)
    seg_name = ida_segment.get_segm_name(seg) if seg else ""
    return f"{seg_name}:{ea:016X}" if seg_name else f"{ea:016X}"

def _iter_comment_lines(ea):
    seen = set()
    for repeatable in (0, 1):
        try:
            comment = idc.get_cmt(ea, repeatable)
        except Exception:
            comment = None
        if not comment:
            continue
        text = ida_lines.tag_remove(comment).strip()
        if text and text not in seen:
            seen.add(text)
            yield text

    get_extra_cmt = getattr(idc, "get_extra_cmt", None)
    if get_extra_cmt is None:
        return

    for index in range(-10, 11):
        try:
            comment = get_extra_cmt(ea, index)
        except Exception:
            continue
        if not comment:
            continue
        text = ida_lines.tag_remove(comment).strip()
        if text and text not in seen:
            seen.add(text)
            yield text

def get_code_region_disasm(start_ea, size):
    if size <= 0:
        return ""
    end_ea = start_ea + size
    lines = []
    ea = int(start_ea)
    while ea != idc.BADADDR and ea < end_ea:
        try:
            flags = ida_bytes.get_flags(ea)
        except Exception:
            break
        if ida_bytes.is_code(flags):
            address_text = _format_address(ea)
            for comment in _iter_comment_lines(ea):
                lines.append(f"{address_text}                 ; {comment}")
            disasm_line = ida_lines.tag_remove(
                idc.generate_disasm_line(ea, 0) or ""
            ).strip()
            if disasm_line:
                lines.append(f"{address_text}                 {disasm_line}")
        try:
            next_ea = idc.next_head(ea, end_ea)
        except Exception:
            break
        if next_ea == idc.BADADDR or next_ea <= ea:
            break
        ea = int(next_ea)
    return "\n".join(lines).strip()

result = json.dumps(
    {
        'func_name': "__CODE_NAME__",
        'func_va': hex(code_start),
        'disasm_code': get_code_region_disasm(code_start, code_size),
    }
)
"""
