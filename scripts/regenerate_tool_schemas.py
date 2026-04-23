"""Regenerate ``src/ida_multi_mcp/ida_tool_schemas.json`` from the live tool registry.

The aggregator server serves this JSON before any IDA instance is connected,
so it must stay in sync with the ``@tool`` decorators in
``src/ida_multi_mcp/ida_mcp/api_*.py``.

Usage:
    python scripts/regenerate_tool_schemas.py [--dry-run] [--out PATH]

Approach: stub IDA modules (we never *call* tools here — we only introspect
their signatures via ``get_type_hints``), import ``ida_multi_mcp.ida_mcp``
which triggers all ``@tool`` registrations against ``MCP_SERVER``, then call
``MCP_SERVER.registry.methods["tools/list"]()`` and write the resulting list.

The default tools/list call uses an empty ``_enabled_extensions`` set, which
matches the existing snapshot (debugger tools under ``@ext("dbg")`` stay
hidden). Resources registered via ``@resource`` are not included, which also
matches the existing snapshot.
"""

from __future__ import annotations

import argparse
import enum
import json
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_ROOT = REPO_ROOT / "src"
DEFAULT_OUT = SRC_ROOT / "ida_multi_mcp" / "ida_tool_schemas.json"


# ---------------------------------------------------------------------------
# IDA module stubs
# ---------------------------------------------------------------------------
#
# We only need enough shape for the import-time code paths of ``ida_mcp/*``,
# ``sync.py``, ``compat.py``, and ``vendor/sigmaker.py`` to succeed. Any
# attribute we don't pre-populate falls through to MagicMock's auto-attrs.


class _IdaapiStub(MagicMock):
    # WildcardPolicy IntEnums expect concrete ints:
    o_void = 0
    o_reg = 1
    o_mem = 2
    o_phrase = 3
    o_displ = 4
    o_imm = 5
    o_far = 6
    o_near = 7
    o_idpspec0 = 8
    o_idpspec1 = 9
    o_idpspec2 = 10
    o_idpspec3 = 11
    o_idpspec4 = 12
    o_idpspec5 = 13

    PLFM_386 = 1
    PLFM_ARM = 2
    PLFM_MIPS = 3
    PLFM_PPC = 4

    BADADDR = 0xFFFFFFFFFFFFFFFF
    IDA_SDK_VERSION = 900
    MFF_WRITE = 2
    MFF_READ = 1
    ASKBTN_YES = 1
    ASKBTN_NO = 0
    ASKBTN_CANCEL = -1
    SEGPERM_EXEC = 1
    XREF_ALL = 0

    BIN_SEARCH_NOCASE = 1
    BIN_SEARCH_FORWARD = 2

    NN_call = 0
    NN_callfi = 1
    NN_callni = 2

    PLUGIN_FIX = 8


def _make_ida_modules() -> dict[str, object]:
    idaapi = _IdaapiStub()
    idaapi.get_kernel_version = lambda: "9.0"
    idaapi.user_cancelled = lambda: False
    idaapi.get_root_filename = lambda: ""
    idaapi.ph_get_id = lambda: _IdaapiStub.PLFM_386
    idaapi.get_imagebase = lambda: 0
    idaapi.retrieve_input_file_size = lambda: 0
    idaapi.get_input_file_path = lambda: ""
    idaapi.get_flags = lambda ea: 0
    idaapi.is_code = lambda flags: False
    idaapi.get_first_seg = lambda: None
    idaapi.get_next_seg = lambda ea: None
    idaapi.get_bytes = lambda ea, n: b""
    idaapi.get_byte = lambda ea: 0
    idaapi.inf_get_min_ea = lambda: 0
    idaapi.inf_get_max_ea = lambda: 0
    # CRITICAL: http.py registers idasync-wrapped helpers at import time, and
    # the idasync decorator schedules work via idaapi.execute_sync(fn, mode)
    # and then blocks on a queue.Queue.get(). If execute_sync is a MagicMock
    # no-op, the queue never gets populated and the import hangs forever.
    # Make execute_sync run the callable synchronously in-thread.
    idaapi.execute_sync = lambda fn, mode=0: (fn(), 0)[1]
    # insn_t / xrefblk_t / compiled_binpat_vec_t are used but not called at
    # import time — leave them as MagicMock auto-attrs.

    modules: dict[str, object] = {"idaapi": idaapi}
    for name in (
        "ida_auto", "ida_bytes", "ida_dbg", "ida_dirtree", "ida_entry",
        "ida_frame", "ida_funcs", "ida_hexrays", "ida_ida", "ida_idaapi",
        "ida_idd", "ida_kernwin", "ida_lines", "ida_loader", "ida_nalt",
        "ida_name", "ida_netnode", "ida_segment", "ida_typeinf", "ida_ua",
        "ida_xref", "idautils", "idc",
    ):
        modules[name] = MagicMock()

    # idc.batch must be callable returning an int (used by sync_wrapper at
    # runtime, not at import — but be safe).
    modules["idc"].batch = lambda mode=0: 0

    # ida_ida.inf_is_64bit is probed by compat.py via hasattr; make sure it
    # exists as a callable so the fast path is taken.
    modules["ida_ida"].inf_is_64bit = lambda: False

    # ida_entry attributes probed by compat.py
    modules["ida_entry"].get_entry_qty = lambda: 0
    modules["ida_entry"].get_entry_ordinal = lambda i: 0
    modules["ida_entry"].get_entry = lambda o: 0
    modules["ida_entry"].get_entry_name = lambda o: ""

    return modules


def _install_stubs() -> None:
    for name, mod in _make_ida_modules().items():
        sys.modules[name] = mod  # overwrite if already present


def _restore_module(name: str, saved: object | None) -> None:
    if saved is None:
        sys.modules.pop(name, None)
    else:
        sys.modules[name] = saved


# ---------------------------------------------------------------------------
# Tool-list generation
# ---------------------------------------------------------------------------


def regenerate_tool_list(verbose: bool = False) -> list[dict]:
    def _log(msg: str) -> None:
        if verbose:
            print(f"[trace] {msg}", flush=True)

    _log("install stubs")
    sys.path.insert(0, str(SRC_ROOT))
    _install_stubs()

    _log("purge prior imports")
    for name in list(sys.modules):
        if name == "ida_multi_mcp" or name.startswith("ida_multi_mcp."):
            sys.modules.pop(name, None)

    _log("import ida_multi_mcp.ida_mcp")
    import ida_multi_mcp.ida_mcp  # noqa: F401 — registers all @tool decorators

    _log("import MCP_SERVER")
    from ida_multi_mcp.ida_mcp.rpc import MCP_SERVER

    _log("call tools/list")
    response = MCP_SERVER.registry.methods["tools/list"]()

    _log(f"got {len(response['tools'])} tools")
    return response["tools"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out",
        type=Path,
        default=DEFAULT_OUT,
        help=f"Output path (default: {DEFAULT_OUT.relative_to(REPO_ROOT)})",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print diff summary; do not write the file.",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Print trace messages during import/registration.",
    )
    args = parser.parse_args()

    tools = regenerate_tool_list(verbose=args.verbose)
    serialized = json.dumps(tools, indent=2)

    existing = None
    if args.out.exists():
        existing = args.out.read_text(encoding="utf-8")

    if existing == serialized:
        print(f"No changes — {len(tools)} tools; {args.out} already up to date.")
        return 0

    old_names = set()
    if existing:
        try:
            old_names = {t["name"] for t in json.loads(existing)}
        except Exception:
            pass
    new_names = {t["name"] for t in tools}
    added = sorted(new_names - old_names)
    removed = sorted(old_names - new_names)

    print(f"Regenerated schema: {len(tools)} tools")
    if added:
        print(f"  Added ({len(added)}): {', '.join(added)}")
    if removed:
        print(f"  Removed ({len(removed)}): {', '.join(removed)}")
    if not added and not removed:
        print("  (schema changes without name-level changes)")

    if args.dry_run:
        print("Dry run — not writing file.")
        return 0

    args.out.write_text(serialized, encoding="utf-8")
    print(f"Wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
