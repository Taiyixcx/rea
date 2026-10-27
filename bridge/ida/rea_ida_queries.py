"""Closed read-only IDAPython queries for the REA Hex-Rays MCP profile.

The caller supplies JSON data, never Python source. No target program is run.
"""
import hashlib
import importlib.metadata
import re

import ida_auto
import ida_bytes
import ida_funcs
import ida_ida
import ida_idaapi
import ida_lines
import ida_loader
import ida_name
import ida_nalt
import ida_segment
import ida_xref
import idaapi
import idautils


class _ReaIdentityError(Exception):
    pass


def _rea_hex(ea):
    return hex(int(ea))


def _rea_function(ea):
    fn = ida_funcs.get_func(ea)
    if fn is None:
        return None
    return {"address": _rea_hex(fn.start_ea), "name": ida_funcs.get_func_name(fn.start_ea),
            "size": str(ida_funcs.calc_func_size(fn))}


def _rea_page(items, args):
    offset = args.get("offset", 0)
    if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0 or offset > len(items):
        raise ValueError("invalid page offset")
    end = min(offset + 100, len(items))
    return {"items": items[offset:end], "next_offset": end if end < len(items) else None,
            "total": len(items)}


def _rea_metadata():
    versions = {}
    for name in ("ida-domain", "ida-nexus", "idapro"):
        try:
            versions[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            versions[name] = None
    original = ida_nalt.retrieve_input_file_sha256()
    return {"input_path": ida_nalt.get_input_file_path(),
            "idb_path": ida_loader.get_path(ida_loader.PATH_TYPE_IDB),
            "sha256": original.hex() if original else None,
            "processor": ida_ida.inf_get_procname(), "imagebase": _rea_hex(ida_nalt.get_imagebase()),
            "kernel_version": idaapi.get_kernel_version(), "sdk_version": idaapi.IDA_SDK_VERSION,
            "auto_analysis_ready": bool(ida_auto.auto_is_ok()), "package_versions": versions}


def _rea_resolve(query):
    if re.fullmatch(r"0[xX][0-9a-fA-F]+", query):
        ea = int(query, 16)
    else:
        ea = ida_name.get_name_ea(ida_idaapi.BADADDR, query)
    return None if ea == ida_idaapi.BADADDR else _rea_function(ea)


def _rea_attest(args):
    ranges = []
    previous = None
    gaps_empty = True
    for region in args["ranges"]:
        start, end = int(region["start"], 16), int(region["end"], 16)
        if start < 0 or end <= start or end > 0x100000:
            raise ValueError("invalid RL78 source range")
        if previous is not None:
            if start < previous:
                raise ValueError("source ranges are not ordered")
            if any(ida_bytes.is_loaded(ea) for ea in range(previous, start)):
                gaps_empty = False
        h = hashlib.sha256()
        for ea in range(start, end, 4096):
            data = ida_bytes.get_bytes(ea, min(4096, end - ea))
            if data is None:
                raise ValueError("source data was not loaded at " + hex(ea))
            h.update(data)
        ranges.append({"start": _rea_hex(start), "end": _rea_hex(end), "sha256": h.hexdigest()})
        previous = end
    segments = []
    seg = ida_segment.get_first_seg()
    while seg is not None:
        segments.append({"start": _rea_hex(seg.start_ea), "end": _rea_hex(seg.end_ea)})
        seg = ida_segment.get_next_seg(seg.start_ea)
    return {"ranges": ranges, "gaps_empty": gaps_empty, "engine_segments": segments}


def rea_query(request):
    """Versioned query envelope; stdout/stderr remain producer-owned MCP fields."""
    operation, args = request["operation"], request["parameters"]
    response = {"version": 1, "request_id": request["request_id"],
                "operation": operation, "status": "ok", "result": None, "reason": None}
    try:
        if operation == "metadata":
            response["result"] = _rea_metadata()
        elif operation == "attest":
            response["result"] = _rea_attest(args)
        elif operation == "functions":
            response["result"] = _rea_page([_rea_function(ea) for ea in idautils.Functions()], args)
        elif operation == "strings":
            response["result"] = _rea_page([{"address": _rea_hex(item.ea), "value": str(item)}
                                           for item in idautils.Strings()], args)
        elif operation == "resolve":
            fn = _rea_resolve(args["query"])
            if fn is None:
                response.update(status="missing", reason="Not a function")
            else:
                response["result"] = fn
        elif operation == "contains":
            ea = int(args["address"], 16)
            fn = _rea_function(ea)
            response["result"] = {"function": fn, "in_segment": ida_segment.getseg(ea) is not None}
        elif operation == "xrefs":
            refs = sorted({(xref.frm, xref.type) for xref in idautils.XrefsTo(int(args["address"], 16), 0)})
            response["result"] = _rea_page([{"address": _rea_hex(ea), "type": kind} for ea, kind in refs], args)
        elif operation in ("assembly", "callees", "pseudocode"):
            entry = int(args["entry"], 16)
            fn = ida_funcs.get_func(entry)
            if fn is None or fn.start_ea != entry:
                raise _ReaIdentityError("resolved function entry is no longer present")
            if operation == "assembly":
                rows = []
                for ea in idautils.FuncItems(entry):
                    if ida_bytes.is_code(ida_bytes.get_full_flags(ea)):
                        text = ida_lines.generate_disasm_line(ea, 0)
                        if text is None:
                            raise ValueError("instruction rendering unavailable at " + hex(ea))
                        rows.append({"address": _rea_hex(ea), "instruction": ida_lines.tag_remove(text)})
                response["result"] = {**_rea_page(rows, args), "function": _rea_function(entry)}
            elif operation == "callees":
                targets = {}
                for ea in idautils.FuncItems(entry):
                    for xref in idautils.XrefsFrom(ea, 0):
                        if xref.type not in (ida_xref.fl_CN, ida_xref.fl_CF):
                            continue
                        target = _rea_function(xref.to)
                        if target is not None:
                            targets[target["address"]] = target
                rows = sorted(targets.values(), key=lambda item: int(item["address"], 16))
                response["result"] = _rea_page(rows, args)
            else:
                try:
                    import ida_hexrays
                    if not ida_hexrays.init_hexrays_plugin():
                        response.update(status="unavailable", reason="Hex-Rays decompiler is unavailable for the loaded processor")
                    else:
                        try:
                            cfunc = ida_hexrays.decompile(entry)
                            if cfunc is None:
                                response.update(status="unavailable", reason="IDA did not produce pseudocode for this function")
                            else:
                                if cfunc.entry_ea != entry:
                                    raise _ReaIdentityError("decompiler returned another function")
                                rows = [ida_lines.tag_remove(line.line) for line in cfunc.get_pseudocode()]
                                response["result"] = _rea_page(rows, args)
                        except ida_hexrays.DecompilationFailure as exc:
                            response.update(status="unavailable", reason="Function decompilation failed: " + str(exc))
                except ImportError:
                    response.update(status="unavailable", reason="Hex-Rays decompiler module is not installed")
        else:
            raise ValueError("unsupported closed REA query")
    except _ReaIdentityError as exc:
        response.update(status="identity_error", reason=str(exc))
    except Exception as exc:
        response.update(status="error", reason=type(exc).__name__ + ": " + str(exc))
    return response
