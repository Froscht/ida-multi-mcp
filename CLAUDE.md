# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

Python 3.11+. No runtime dependencies (pure stdlib); `pytest>=7.0` is the only dev dep.

```bash
# Editable install with dev extras
pip install -e .[dev]

# Run full test suite
pytest

# Run a single test file / single test
pytest tests/test_router.py
pytest tests/test_router.py::test_name

# Reinstall the IDA plugin + (re)write MCP client configs after code changes
ida-multi-mcp --install                 # --ida-dir "C:\Program Files\IDA Pro 9.0" on Windows custom path
ida-multi-mcp --uninstall
ida-multi-mcp --list                    # show registered IDA instances
ida-multi-mcp --config                  # dump the MCP client JSON

# Run the MCP server directly (stdio; normally invoked by an MCP client)
ida-multi-mcp                           # optional: --idalib-python /path/to/py3.11

# Benchmarking
python scripts/benchmark.py
```

`pytest.ini` excludes `references/`, `dist/`, `.factory/`, `.omd/`, `.omc/` — these are vendored/reference trees and must not be run as tests.

## Architecture

### Layered model (big picture)

```
MCP Client ──stdio──▶ server.py (aggregator) ──▶ router.py ──HTTP JSON-RPC──▶ IDA instance(s)
                         │                          │
                         │                          ├─▶ registry.py (~/.ida-mcp/instances.json, file-locked)
                         │                          └─▶ health.py (liveness, binary-change verification)
                         │
                         └─▶ idalib_manager.py ──spawn──▶ idalib_worker.py (headless subprocess per binary)
```

The IDA side lives in `src/ida_multi_mcp/ida_mcp/` and is a bundled fork of the original `ida-pro-mcp` tool layer — it runs **inside** IDA (GUI plugin) or inside an idalib subprocess, exposing ~80 tools over HTTP JSON-RPC. The multi-instance aggregator is the code in `src/ida_multi_mcp/` *outside* `ida_mcp/`.

### Two processes you may be editing
1. **Aggregator / CLI** (runs in the MCP client's Python): `server.py`, `router.py`, `registry.py`, `health.py`, `cache.py`, `idalib_manager.py`, `__main__.py`, `tools/`.
2. **In-IDA plugin / idalib worker** (runs inside IDA's Python or an idalib subprocess): `plugin/*`, `ida_mcp/*`, `idalib_worker.py`. Uses `idaapi`, `ida_kernwin`, etc. — these imports only resolve inside IDA, so don't run this code from the regular test runner.

`plugin/ida_multi_mcp_loader.py` is the shim copied into IDA's plugins directory by `--install`; the real plugin body lives in `plugin/ida_multi_mcp.py`.

### Tool federation (critical to get right)

Tools come from two sources and are merged in `server.py`:
- **Static schemas**: `src/ida_multi_mcp/ida_tool_schemas.json` — bundled snapshot of all IDA tool schemas, loaded at import. This is what the client sees when **no** IDA instance is running.
- **Dynamic schemas**: on first tool-call and on `refresh_tools()`, the server hits each live instance's HTTP endpoint and overlays real schemas on top of the static ones.

If you add/modify an IDA tool in `ida_mcp/api_*.py`, regenerate `ida_tool_schemas.json` with `python scripts/regenerate_tool_schemas.py` (add `-v` for trace output, `--dry-run` to preview added/removed tool names). The script stubs all IDA modules, imports `ida_mcp` to trigger every `@tool` registration, then serializes the `tools/list` response. Management tools in `tools/management.py` and idalib lifecycle tools in `tools/idalib.py` are registered separately (not from the static JSON).

### Routing contract (the non-negotiable rule)

Every proxied IDA tool call **must** carry an `instance_id`. `router.py` enforces this:
- 1 instance registered → auto-selected.
- 0 or 2+ instances → return an error with `available_instances` and a hint; **do not pick one silently.**

Instance IDs are deterministic 4-char base36 strings derived from `(pid, port, idb_path)` — same binary reopened = same ID. Expired IDs return a helpful "replaced by X" error (`router._handle_expired_instance`). The authoritative rules live in `docs/.ssot/contracts/routing_contract.md` and `registry_contract.md` — see "Documentation governance" below.

### Binary-change detection (dual strategy)

1. **Primary**: IDA `IDB_Hooks.closebase` + `UI_Hooks.database_inited` in the plugin mark the old registry entry expired and re-register under a new ID.
2. **Fallback**: every request in `router.py` verifies the binary path hasn't changed via `health.query_binary_metadata` (5 s cache). This covers the case where hooks fail or a crash left a stale entry.

Don't remove the fallback when touching the router — it's load-bearing, not redundant.

### Registry

File-backed at `~/.ida-mcp/instances.json` with a sibling `.lock` (see `filelock.py`). Entries are validated by schema (`registry._validate_instance_entry`) and hosts are restricted to loopback (`_is_loopback_host`) to prevent SSRF via registry manipulation. Heartbeats are written every 60 s; entries older than ~2 min are reaped on server start (`health.cleanup_stale_instances`).

### idalib (headless) model

`idalib_manager.py` spawns one `idalib_worker.py` subprocess **per binary** — no in-process DB switching. Each worker opens the binary via the `idapro` package, starts the same HTTP tool server as the GUI plugin, and registers itself in the same JSON registry, so GUI and headless instances are indistinguishable from the router's perspective. `idapro` is an optional dep (`pip install -e .[idalib]`) and is only importable on machines with an IDA Pro license.

### IDA version compatibility

`ida_mcp/compat.py` is the single place that absorbs API differences between IDA 8.3, 9.0, and 9.3 (entry-point APIs moved from `ida_nalt` to `ida_entry`, `inf_is_64bit` moved from `idaapi` to `ida_ida`, etc.). Import from `compat.py` rather than the version-specific `ida_*` modules when touching `ida_mcp/`.

### Vendored third-party tools

`ida_mcp/vendor/` holds copies of external MIT-licensed projects whose non-UI cores are re-exposed as MCP tools:

- `vendor/sigmaker.py` — signature generation / search core from [ida-sigmaker](https://github.com/mahmoudimus/ida-sigmaker) (Qt forms + plugin shell stripped). Wrapped by `api_sigmaker.py` (`make_signature`, `make_xref_signatures`, `make_range_signature`, `search_signature`). Transparently picks up the `sigmaker._speedups.simd_scan` SIMD scanner if the upstream `sigmaker` package is also `pip install`ed in IDA's Python; otherwise falls back to `idaapi.bin_search`.

When updating vendored code, re-strip the UI layer (no Qt forms, no action handlers, no plugin `PLUGIN_ENTRY`) and replace wait-box / clipboard helpers with no-ops — MCP callers are headless and return structured data instead of printing to IDA's output window.

### MCP transport

Uses a vendored MCP implementation at `src/ida_multi_mcp/vendor/zeromcp/` — do not introduce the `mcp`/`modelcontextprotocol` PyPI SDK as a dependency. The package is stdlib-only by design.

Two transports are wired up in `__main__.py` / `server.py:run()`:

- **stdio** (default) — the aggregator is spawned as a child of the MCP client, JSON-RPC over stdin/stdout. Matches every MCP client.
- **HTTP + SSE** (opt-in via `--http`) — the aggregator binds a TCP port and serves Streamable-HTTP at `/mcp` and SSE at `/sse`. Use this when IDA lives on a workstation separate from the MCP client (e.g. `ida-multi-mcp --http --host 0.0.0.0 --port 8765`). No authentication is built in; this mode is designed for trusted LAN / VPN use. For internet exposure, front it with a reverse proxy that handles TLS+auth.

The `zeromcp` handler's `_check_host_header` enforces DNS-rebinding protection; bind address selects the policy:
- loopback bind → loopback-only Host headers (existing default)
- specific LAN IP → allow that IP + loopback
- `0.0.0.0` / `::` → disabled (operator opted into LAN trust)

`_host_allowlist` on the `McpServer` carries that state — set by `serve()` from the bind address.

## Documentation governance

This repo uses an SSOT (Single Source of Truth) discipline — read `AGENTS.md` before editing docs. Summary:

- **Authority order**: `docs/.ssot/contracts/*` > `docs/.ssot/PRD.md` > `docs/.ssot/decisions/*` > `docs/.ssot/architectures/*` > `docs/plans/_completed/*` > `docs/ops/*`.
- Contracts are the source of truth for routing, registry, and tool semantics — **never redefine contract semantics in architecture/README/code comments.** Link to them instead.
- When you change architecture or behavior, update the relevant `docs/.ssot/architectures/NN_*.md` doc and bump its `Last updated:` date to the real absolute date (not "today"/"now").
- Read order when starting a non-trivial change: `docs/README.md` → `docs/.ssot/PRD.md` → `docs/.ssot/contracts/*` → target architecture doc.

## Installer behavior to keep in mind

`__main__.py` auto-configures ~25 MCP clients by editing their config files (JSON and TOML). When changing install logic:
- Writes are atomic (temp file + `os.replace`) with a Windows fallback that copies in-place if `os.replace` hits `WinError 5` on a locked settings file.
- Skips symlinks on overwrite (anti-symlink-attack).
- Migrates legacy `ida-pro-mcp` / `github.com/mrexodia/ida-pro-mcp` entries to `ida-multi-mcp` automatically.
- VS Code / Visual Studio 2022 / Factory Droid use non-default JSON structures — see `special_json_structures` and the `include_type` flag.
- Uninstall only removes **known** registry files (`instances.json`, `instances.json.lock`) and an empty `~/.ida-mcp/`; it will not recursively delete arbitrary contents.

`--install` has three mutually-exclusive modes handled in `cmd_install`:
- **default** — plugin + local stdio client configs (single-machine setup).
- **`--plugin-only`** — only the IDA plugin; leaves client configs untouched. Use on the workstation where IDA lives if it doesn't also run your MCP client.
- **`--remote URL`** — only client configs, written as HTTP transport (`{"type": "http", "url": URL}`). Skips the plugin. Use on the laptop/client machine. `URL` is validated (`_validate_remote_url`) to require an `http://` or `https://` scheme and non-empty host.

The split worker helpers are `_install_ida_plugin(ida_dir)` and `_uninstall_ida_plugin(ida_dir)`; `generate_mcp_config(*, include_type, remote_url)` emits the right shape for each mode.
