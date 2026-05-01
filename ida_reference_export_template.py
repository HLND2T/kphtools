FUNCTION_DETAIL_EXPORT_TEMPLATE = r"""
import ida_bytes, ida_funcs, ida_lines, ida_segment, idautils, idc, json
try:
    import ida_hexrays
except Exception:
    ida_hexrays = None

func_ea = __FUNC_VA_INT__

def _append_chunk_range(chunk_ranges, start_ea, end_ea):
    try:
        start_ea = int(start_ea)
        end_ea = int(end_ea)
    except Exception:
        return
    if start_ea < end_ea:
        chunk_ranges.append((start_ea, end_ea))

def _collect_chunk_ranges(func):
    chunk_ranges = []
    try:
        initial_chunk_ranges = []
        for start_ea, end_ea in idautils.Chunks(func.start_ea):
            _append_chunk_range(initial_chunk_ranges, start_ea, end_ea)
        chunk_ranges = initial_chunk_ranges
    except Exception:
        pass
    if not chunk_ranges:
        tail_chunk_ranges = []
        try:
            try:
                tail_iterator = ida_funcs.func_tail_iterator_t(func)
            except Exception:
                tail_iterator = ida_funcs.func_tail_iterator_t()
                if not tail_iterator.set_ea(func.start_ea):
                    tail_iterator = None
            if tail_iterator is not None and tail_iterator.first():
                while True:
                    chunk = tail_iterator.chunk()
                    _append_chunk_range(
                        tail_chunk_ranges,
                        getattr(chunk, "start_ea", None),
                        getattr(chunk, "end_ea", None),
                    )
                    if not tail_iterator.next():
                        break
        except Exception:
            tail_chunk_ranges = []
        if tail_chunk_ranges:
            _append_chunk_range(
                tail_chunk_ranges,
                func.start_ea,
                func.end_ea,
            )
            chunk_ranges = tail_chunk_ranges
    if not chunk_ranges:
        chunk_ranges = [(int(func.start_ea), int(func.end_ea))]
    return sorted(set(chunk_ranges))

def _find_chunk_end(ea, chunk_ranges):
    for start_ea, end_ea in chunk_ranges:
        if start_ea <= ea < end_ea:
            return end_ea
    return None

def _is_in_chunk_ranges(ea, chunk_ranges):
    return _find_chunk_end(ea, chunk_ranges) is not None

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

def _iter_chunk_code_heads(chunk_ranges):
    for start_ea, end_ea in chunk_ranges:
        ea = int(start_ea)
        while ea != idc.BADADDR and ea < end_ea:
            try:
                flags = ida_bytes.get_flags(ea)
            except Exception:
                break
            if ida_bytes.is_code(flags):
                yield ea
            try:
                next_ea = idc.next_head(ea, end_ea)
            except Exception:
                break
            if next_ea == idc.BADADDR or next_ea <= ea:
                break
            ea = next_ea

def _render_disasm_lines(eas):
    lines = []
    for ea in eas:
        ea = int(ea)
        address_text = _format_address(ea)
        for comment in _iter_comment_lines(ea):
            lines.append(f"{address_text}                 ; {comment}")
        disasm_line = ida_lines.tag_remove(idc.generate_disasm_line(ea, 0) or "").strip()
        if disasm_line:
            lines.append(f"{address_text}                 {disasm_line}")
    return "\n".join(lines).strip()

def get_disasm(start_ea):
    func = ida_funcs.get_func(start_ea)
    if func is None:
        return ""

    chunk_ranges = _collect_chunk_ranges(func)
    fallback_eas = sorted(set(int(ea) for ea in _iter_chunk_code_heads(chunk_ranges)))
    if not fallback_eas:
        return ""

    try:
        pending_eas = [int(func.start_ea)]
        visited_eas = set()
        collected_eas = set()
        code_head_count = len(fallback_eas)
        max_steps = code_head_count * 4 + 256
        steps = 0

        while pending_eas and steps < max_steps:
            ea = int(pending_eas.pop())
            while True:
                if not _is_in_chunk_ranges(ea, chunk_ranges):
                    break
                flags = ida_bytes.get_flags(ea)
                if not ida_bytes.is_code(flags):
                    break
                if ea in visited_eas:
                    break

                visited_eas.add(ea)
                collected_eas.add(ea)
                steps += 1

                mnem = (idc.print_insn_mnem(ea) or "").lower()
                refs = [
                    int(ref)
                    for ref in idautils.CodeRefsFrom(ea, False)
                    if _is_in_chunk_ranges(int(ref), chunk_ranges)
                ]
                chunk_end = _find_chunk_end(ea, chunk_ranges)
                next_ea = idc.next_head(ea, chunk_end) if chunk_end is not None else idc.BADADDR

                if mnem in ("ret", "retn", "retf", "iret", "iretd", "iretq", "int3", "hlt", "ud2"):
                    break
                if mnem == "jmp":
                    for ref in reversed(refs):
                        if ref not in visited_eas:
                            pending_eas.append(ref)
                    break
                if mnem.startswith("j"):
                    for ref in reversed(refs):
                        if ref not in visited_eas:
                            pending_eas.append(ref)
                    if next_ea == idc.BADADDR or next_ea <= ea:
                        break
                    ea = int(next_ea)
                    continue
                if next_ea == idc.BADADDR or next_ea <= ea:
                    break
                ea = int(next_ea)

        collected_eas.update(fallback_eas)
        return _render_disasm_lines(sorted(collected_eas))
    except Exception:
        return _render_disasm_lines(fallback_eas)

def get_pseudocode(start_ea):
    if ida_hexrays is None:
        return ""
    try:
        if not ida_hexrays.init_hexrays_plugin():
            return ""
        cfunc = ida_hexrays.decompile(start_ea)
    except Exception:
        return ""
    if not cfunc:
        return ""
    return "\n".join(ida_lines.tag_remove(line.line) for line in cfunc.get_pseudocode())

globals().update(locals())

func = ida_funcs.get_func(func_ea)
if func is None:
    raise ValueError(f"Function not found: {hex(func_ea)}")

func_start = int(func.start_ea)
result = json.dumps(
    {
        "func_name": ida_funcs.get_func_name(func_start) or f"sub_{func_start:X}",
        "func_va": hex(func_start),
        "disasm_code": get_disasm(func_start),
        "procedure": get_pseudocode(func_start),
    }
)
"""
