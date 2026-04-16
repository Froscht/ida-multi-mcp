"""Pure tests for lazy cache initialization in ida_mcp api_core/api_modify."""

from __future__ import annotations

import importlib
import sys
import types
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
IDA_MCP_ROOT = SRC_ROOT / "ida_multi_mcp" / "ida_mcp"


class _FakeString:
    def __init__(self, ea: int, text: str):
        self.ea = ea
        self._text = text

    def __str__(self) -> str:
        return self._text


@pytest.fixture
def ida_mcp_modules(monkeypatch):
    """Load api_core/api_modify with IDA modules stubbed out."""
    import ida_multi_mcp

    # Remove any prior imports so this fixture gets a clean module state.
    for name in list(sys.modules):
        if name == "ida_multi_mcp.ida_mcp" or name.startswith("ida_multi_mcp.ida_mcp."):
            sys.modules.pop(name, None)

    pkg = types.ModuleType("ida_multi_mcp.ida_mcp")
    pkg.__path__ = [str(IDA_MCP_ROOT)]
    monkeypatch.setitem(sys.modules, "ida_multi_mcp.ida_mcp", pkg)
    monkeypatch.setattr(ida_multi_mcp, "ida_mcp", pkg, raising=False)

    ida_module_names = [
        "ida_auto",
        "ida_funcs",
        "ida_hexrays",
        "ida_loader",
        "idaapi",
        "idautils",
        "ida_nalt",
        "ida_typeinf",
        "ida_segment",
        "idc",
        "ida_bytes",
        "ida_dirtree",
        "ida_frame",
        "ida_ua",
    ]
    for name in ida_module_names:
        monkeypatch.setitem(sys.modules, name, MagicMock())

    rpc = types.ModuleType("ida_multi_mcp.ida_mcp.rpc")
    rpc.tool = lambda func: func
    monkeypatch.setitem(sys.modules, "ida_multi_mcp.ida_mcp.rpc", rpc)

    sync = types.ModuleType("ida_multi_mcp.ida_mcp.sync")

    class IDAError(Exception):
        pass

    sync.IDAError = IDAError
    sync.idasync = lambda func: func
    monkeypatch.setitem(sys.modules, "ida_multi_mcp.ida_mcp.sync", sync)

    utils = types.ModuleType("ida_multi_mcp.ida_mcp.utils")
    utils.Metadata = dict
    utils.Function = dict
    utils.ConvertedNumber = dict
    utils.Global = dict
    utils.Import = dict
    utils.String = dict
    utils.Segment = dict
    utils.Page = dict
    utils.NumberConversion = dict
    utils.ListQuery = dict
    utils.CommentOp = dict
    utils.CommentAppendOp = dict
    utils.AsmPatchOp = dict
    utils.DefineOp = dict
    utils.UndefineOp = dict
    utils.FunctionRename = dict
    utils.GlobalRename = dict
    utils.LocalRename = dict
    utils.StackRename = dict
    utils.RenameBatch = dict
    utils.get_image_size = lambda *_args, **_kwargs: 0
    utils.parse_address = lambda value: int(value, 0) if isinstance(value, str) and value else value
    utils.normalize_list_input = lambda value, max_items=500: value
    utils.normalize_dict_list = (
        lambda value, str_to_dict=None, max_items=500:
        value if isinstance(value, list) else [value if not isinstance(value, str) else str_to_dict(value)]
    )
    utils.get_function = lambda addr: {"addr": hex(addr), "name": f"sub_{addr:x}"}
    utils.paginate = lambda data, offset, count: {
        "data": data[offset:] if count == 0 else data[offset:offset + count],
        "next_offset": None,
    }
    utils.pattern_filter = lambda data, _pattern, _field: data
    utils.decompile_checked = lambda _ea: None
    utils.refresh_decompiler_ctext = lambda _ea: None
    monkeypatch.setitem(sys.modules, "ida_multi_mcp.ida_mcp.utils", utils)

    api_core = importlib.import_module("ida_multi_mcp.ida_mcp.api_core")
    api_modify = importlib.import_module("ida_multi_mcp.ida_mcp.api_modify")
    return api_core, api_modify


class TestApiCoreLazyCaches:
    def test_list_funcs_builds_cache_once(self, ida_mcp_modules):
        api_core, _ = ida_mcp_modules
        api_core._funcs_cache = None
        api_core.idautils.Functions.return_value = [0x1000, 0x2000]

        first = api_core.list_funcs({"offset": 0, "count": 50, "filter": ""})
        second = api_core.list_funcs({"offset": 0, "count": 50, "filter": ""})

        assert api_core.idautils.Functions.call_count == 1
        assert first == second
        assert [item["name"] for item in first[0]["data"]] == ["sub_1000", "sub_2000"]

    def test_list_globals_builds_cache_once(self, ida_mcp_modules):
        api_core, _ = ida_mcp_modules
        api_core._globals_cache = None
        api_core.idautils.Names.return_value = [
            (0x1000, "sub_1000"),
            (0x2000, "g_data"),
            (0x3000, None),
        ]
        api_core.idaapi.get_func.side_effect = lambda ea: object() if ea == 0x1000 else None

        first = api_core.list_globals({"offset": 0, "count": 50, "filter": ""})
        second = api_core.list_globals({"offset": 0, "count": 50, "filter": ""})

        assert api_core.idautils.Names.call_count == 1
        assert first == second
        assert first[0]["data"] == [{"addr": "0x2000", "name": "g_data"}]

    def test_refresh_caches_rebuilds_all_caches(self, ida_mcp_modules):
        api_core, _ = ida_mcp_modules
        api_core._strings_cache = [("stale", "value")]
        api_core._funcs_cache = [{"addr": "0xdead", "name": "stale_func"}]
        api_core._globals_cache = [{"addr": "0xbeef", "name": "stale_global"}]

        api_core.idautils.Strings.return_value = [
            _FakeString(0x10, "a"),
            _FakeString(0x20, "b"),
        ]
        api_core.idautils.Functions.return_value = [0x1000]
        api_core.idautils.Names.return_value = [(0x2000, "g_value")]
        api_core.idaapi.get_func.return_value = None

        result = api_core.refresh_caches()

        assert result["strings"] == 2
        assert result["functions"] == 1
        assert result["globals"] == 1
        assert result["time_ms"] >= 0


class TestApiModifyCacheInvalidation:
    def test_rename_invalidates_relevant_caches(self, ida_mcp_modules):
        _, api_modify = ida_mcp_modules
        api_modify.invalidate_funcs_cache = MagicMock()
        api_modify.invalidate_globals_cache = MagicMock()
        api_modify.parse_address = lambda _value: 0x1000
        api_modify.refresh_decompiler_ctext = MagicMock()
        api_modify.idaapi.SN_CHECK = 0
        api_modify.idaapi.BADADDR = -1
        api_modify.idaapi.get_flags.return_value = 0
        api_modify.idaapi.has_user_name.return_value = True
        api_modify.idaapi.set_name.return_value = True
        api_modify.idaapi.get_func.return_value = SimpleNamespace(start_ea=0x1000)
        api_modify.idaapi.get_name_ea.return_value = 0x2000

        result = api_modify.rename(
            {
                "func": {"addr": "0x1000", "name": "main"},
                "data": {"old": "g_old", "new": "g_new"},
            }
        )

        assert result["func"][0]["ok"] is True
        assert result["data"][0]["ok"] is True
        api_modify.invalidate_funcs_cache.assert_called_once()
        api_modify.invalidate_globals_cache.assert_called_once()

    def test_define_func_invalidates_caches_on_success(self, ida_mcp_modules):
        _, api_modify = ida_mcp_modules
        api_modify.invalidate_funcs_cache = MagicMock()
        api_modify.invalidate_globals_cache = MagicMock()
        api_modify.idaapi.BADADDR = -1
        api_modify.idaapi.is_loaded.return_value = True
        api_modify.parse_address = lambda value: -1 if value == "" else int(value, 0)
        api_modify.idaapi.get_func.side_effect = [
            None,
            SimpleNamespace(start_ea=0x1000, end_ea=0x1010),
        ]
        api_modify.ida_funcs.add_func.return_value = True

        result = api_modify.define_func({"addr": "0x1000"})

        assert result[0]["start"] == "0x1000"
        assert result[0]["end"] == "0x1010"
        api_modify.invalidate_funcs_cache.assert_called_once()
        api_modify.invalidate_globals_cache.assert_called_once()
