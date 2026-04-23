"""Signature maker API — generate and search binary pattern signatures.

Wraps the vendored sigmaker core (``.vendor.sigmaker``) as MCP tools so an
LLM can create unique code signatures (IDA / x64Dbg / masked-bytes / bitmask
formats), walk xrefs and pick the shortest unique signature per caller,
signature an explicit address range, and search the loaded binary for a
pattern in any supported input format.
"""

from __future__ import annotations

from typing import Annotated

from .rpc import tool
from .sync import idasync, IDAError
from .utils import parse_address
from .vendor import sigmaker as _sigmaker


_SUPPORTED_FORMATS = {
    "ida": _sigmaker.SignatureType.IDA,
    "x64dbg": _sigmaker.SignatureType.x64Dbg,
    "mask": _sigmaker.SignatureType.Mask,
    "bitmask": _sigmaker.SignatureType.BitMask,
}


def _resolve_format(name: str) -> _sigmaker.SignatureType:
    key = (name or "ida").strip().lower()
    if key not in _SUPPORTED_FORMATS:
        raise IDAError(
            f"Unknown signature format: {name!r}. "
            f"Supported: {sorted(_SUPPORTED_FORMATS)}"
        )
    return _SUPPORTED_FORMATS[key]


def _make_config(
    *,
    sig_type: _sigmaker.SignatureType,
    wildcard_operands: bool,
    continue_outside_function: bool,
    wildcard_optimized: bool,
    max_single_signature_length: int,
    max_xref_signature_length: int,
    print_top_x: int,
) -> _sigmaker.SigMakerConfig:
    return _sigmaker.SigMakerConfig(
        output_format=sig_type,
        wildcard_operands=wildcard_operands,
        continue_outside_of_function=continue_outside_function,
        wildcard_optimized=wildcard_optimized,
        # MCP callers are headless — never show the "continue?" dialog or the
        # "signature already N bytes" prompt. Length limits are enforced by
        # returning Unexpected instead.
        enable_continue_prompt=False,
        ask_longer_signature=False,
        print_top_x=print_top_x,
        max_single_signature_length=max_single_signature_length,
        max_xref_signature_length=max_xref_signature_length,
    )


def _format_signature(
    sig: _sigmaker.Signature, sig_type: _sigmaker.SignatureType
) -> str:
    return format(sig, sig_type.value)


@tool
@idasync
def make_signature(
    ea: Annotated[str, "Starting address (hex, decimal, or symbol name)"],
    sig_type: Annotated[
        str, "Output format: ida | x64dbg | mask | bitmask"
    ] = "ida",
    wildcard_operands: Annotated[
        bool, "Replace operand bytes with wildcards for version resilience"
    ] = True,
    continue_outside_function: Annotated[
        bool,
        "Continue walking instructions past the end of the enclosing function",
    ] = False,
    wildcard_optimized: Annotated[
        bool,
        "Also wildcard operands whose byte offset inside the instruction is 0",
    ] = False,
    max_length: Annotated[
        int, "Give up if the signature grows beyond this many bytes"
    ] = 100,
) -> dict:
    """Generate a unique byte signature starting at an address.

    Walks instructions forward from ``ea`` until the accumulated pattern is
    unique in the loaded binary, then returns it in the requested format.
    """
    start_ea = parse_address(ea)
    sig_kind = _resolve_format(sig_type)
    cfg = _make_config(
        sig_type=sig_kind,
        wildcard_operands=wildcard_operands,
        continue_outside_function=continue_outside_function,
        wildcard_optimized=wildcard_optimized,
        max_single_signature_length=max_length,
        max_xref_signature_length=max_length,
        print_top_x=1,
    )

    try:
        result = _sigmaker.SignatureMaker().make_signature(start_ea, cfg)
    except _sigmaker.Unexpected as exc:
        raise IDAError(str(exc))
    except _sigmaker.UserCanceledError as exc:
        raise IDAError(f"Canceled: {exc}")

    addr = result.address
    return {
        "address": hex(int(addr)) if addr is not None else hex(start_ea),
        "signature": _format_signature(result.signature, sig_kind),
        "bytes": len(result.signature),
        "format": sig_kind.value,
    }


@tool
@idasync
def make_xref_signatures(
    ea: Annotated[str, "Address that xrefs point to (hex, decimal, or name)"],
    sig_type: Annotated[str, "Output format: ida | x64dbg | mask | bitmask"] = "ida",
    wildcard_operands: Annotated[bool, "Wildcard operand bytes"] = True,
    continue_outside_function: Annotated[
        bool, "Continue past caller function boundaries"
    ] = False,
    wildcard_optimized: Annotated[
        bool, "Also wildcard zero-offset operands"
    ] = False,
    top_n: Annotated[
        int, "Return at most N shortest signatures (0 = return all)"
    ] = 5,
    max_length: Annotated[
        int, "Give up a candidate xref if its signature exceeds this many bytes"
    ] = 250,
) -> dict:
    """Generate a signature for each code xref that targets an address.

    Useful for signatureing a function by its callers when the function itself
    is too generic (e.g. a tiny getter). Signatures are sorted shortest-first.
    """
    target_ea = parse_address(ea)
    sig_kind = _resolve_format(sig_type)
    cfg = _make_config(
        sig_type=sig_kind,
        wildcard_operands=wildcard_operands,
        continue_outside_function=continue_outside_function,
        wildcard_optimized=wildcard_optimized,
        max_single_signature_length=max_length,
        max_xref_signature_length=max_length,
        print_top_x=max(1, top_n) if top_n > 0 else 1,
    )

    try:
        result = _sigmaker.XrefFinder().find_xrefs(target_ea, cfg)
    except _sigmaker.UserCanceledError as exc:
        raise IDAError(f"Canceled: {exc}")

    picked = result.signatures if top_n <= 0 else result.signatures[:top_n]
    return {
        "target": hex(target_ea),
        "xref_count": len(result.signatures),
        "format": sig_kind.value,
        "signatures": [
            {
                "xref": hex(int(gs.address)) if gs.address is not None else None,
                "signature": _format_signature(gs.signature, sig_kind),
                "bytes": len(gs.signature),
            }
            for gs in picked
        ],
    }


@tool
@idasync
def make_range_signature(
    start_ea: Annotated[str, "Range start address (inclusive)"],
    end_ea: Annotated[str, "Range end address (exclusive)"],
    sig_type: Annotated[str, "Output format: ida | x64dbg | mask | bitmask"] = "ida",
    wildcard_operands: Annotated[bool, "Wildcard operand bytes"] = True,
    wildcard_optimized: Annotated[
        bool, "Also wildcard zero-offset operands"
    ] = False,
) -> dict:
    """Generate a signature covering an exact address range.

    Unlike :func:`make_signature`, the output is not required to be unique —
    it simply encodes every byte between ``start_ea`` and ``end_ea`` (with
    operand wildcarding applied per instruction when requested).
    """
    start = parse_address(start_ea)
    end = parse_address(end_ea)
    if end <= start:
        raise IDAError("end_ea must be greater than start_ea")

    sig_kind = _resolve_format(sig_type)
    cfg = _make_config(
        sig_type=sig_kind,
        wildcard_operands=wildcard_operands,
        continue_outside_function=True,
        wildcard_optimized=wildcard_optimized,
        max_single_signature_length=0x7FFFFFFF,
        max_xref_signature_length=0x7FFFFFFF,
        print_top_x=1,
    )

    try:
        result = _sigmaker.SignatureMaker().make_signature(start, cfg, end)
    except _sigmaker.Unexpected as exc:
        raise IDAError(str(exc))
    except _sigmaker.UserCanceledError as exc:
        raise IDAError(f"Canceled: {exc}")

    return {
        "start_ea": hex(start),
        "end_ea": hex(end),
        "signature": _format_signature(result.signature, sig_kind),
        "bytes": len(result.signature),
        "format": sig_kind.value,
    }


_MAX_SEARCH_MATCHES = 1000


@tool
@idasync
def search_signature(
    signature: Annotated[
        str,
        "Signature string in any supported format "
        "(IDA, x64Dbg, masked bytes + 'xxxx?x', or C array + '0b1101')",
    ],
    max_matches: Annotated[
        int,
        f"Stop after this many matches (clamped to {_MAX_SEARCH_MATCHES})",
    ] = 100,
) -> dict:
    """Search the loaded binary for a signature and return matching addresses.

    Accepts signatures in any of the four output formats plus loose hex with
    ``?`` / ``??`` wildcards; the input format is auto-detected. If the
    ``sigmaker`` SIMD speedup package is installed in IDA's Python, the scan
    uses its AVX2 / NEON / SSE2 implementation automatically.
    """
    if not signature or not signature.strip():
        raise IDAError("Empty signature")

    limit = max(1, min(int(max_matches), _MAX_SEARCH_MATCHES))

    try:
        result = _sigmaker.SignatureSearcher.from_signature(signature).search()
    except ValueError as exc:
        raise IDAError(f"Invalid signature: {exc}")

    if not result.signature_str:
        raise IDAError("Unrecognized signature format")

    # Reject patterns with no fixed bytes — otherwise a scan would either
    # match everywhere or (in the SIMD path) silently return [min_ea].
    _, parsed_bytes = _sigmaker.SigText.normalize(result.signature_str)
    if not any(not wild for _val, wild in parsed_bytes):
        raise IDAError("Signature has no fixed bytes (all wildcards)")

    # Resolve function names (best-effort).
    import idaapi

    matches = []
    for m in result.matches[:limit]:
        ea = int(m)
        func_name = None
        try:
            func_name = idaapi.get_func_name(ea) or None
        except Exception:
            func_name = None
        matches.append(
            {
                "address": hex(ea),
                "function": func_name,
            }
        )

    return {
        "normalized_signature": result.signature_str,
        "match_count": len(result.matches),
        "returned": len(matches),
        "truncated": len(result.matches) > limit,
        "simd": _sigmaker.SIMD_SPEEDUP_AVAILABLE,
        "matches": matches,
    }
