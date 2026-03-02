"""Tests for vendor/zeromcp/jsonrpc.py — JSON-RPC 2.0 dispatch."""

import pytest

from ida_multi_mcp.vendor.zeromcp.jsonrpc import (
    JsonRpcRegistry,
    JsonRpcException,
    register_pending_request,
    unregister_pending_request,
    cancel_request,
)


@pytest.fixture
def rpc():
    reg = JsonRpcRegistry()
    reg.redact_exceptions = True

    def add(a: int, b: int) -> int:
        return a + b

    def greet(name: str, title: str = "Mr") -> str:
        return f"Hello, {title} {name}"

    def typed_float(x: float) -> float:
        return x * 2

    def optional_param(x: int, y: int | None = None) -> int:
        return x + (y or 0)

    reg.method(add)
    reg.method(greet)
    reg.method(typed_float)
    reg.method(optional_param)
    return reg


# ---------------------------------------------------------------------------
# Parsing errors
# ---------------------------------------------------------------------------

class TestParsing:
    def test_invalid_json(self, rpc):
        resp = rpc.dispatch(b"not json{{{")
        assert resp["error"]["code"] == -32700

    def test_non_object(self, rpc):
        resp = rpc.dispatch(b"42")
        assert resp["error"]["code"] == -32600

    def test_missing_jsonrpc(self, rpc):
        resp = rpc.dispatch({"method": "add", "id": 1})
        assert resp["error"]["code"] == -32600

    def test_missing_method(self, rpc):
        resp = rpc.dispatch({"jsonrpc": "2.0", "id": 1})
        assert resp["error"]["code"] == -32600


# ---------------------------------------------------------------------------
# Method dispatch
# ---------------------------------------------------------------------------

class TestMethod:
    def test_unknown_method(self, rpc):
        resp = rpc.dispatch({"jsonrpc": "2.0", "method": "nope", "id": 1})
        assert resp["error"]["code"] == -32601


# ---------------------------------------------------------------------------
# Parameter handling
# ---------------------------------------------------------------------------

class TestParams:
    def test_dict_params(self, rpc):
        resp = rpc.dispatch({
            "jsonrpc": "2.0", "method": "add",
            "params": {"a": 1, "b": 2}, "id": 1
        })
        assert resp["result"] == 3

    def test_list_params(self, rpc):
        resp = rpc.dispatch({
            "jsonrpc": "2.0", "method": "add",
            "params": [10, 20], "id": 1
        })
        assert resp["result"] == 30

    def test_missing_required(self, rpc):
        resp = rpc.dispatch({
            "jsonrpc": "2.0", "method": "add",
            "params": {"a": 1}, "id": 1
        })
        assert resp["error"]["code"] == -32602

    def test_extra_params(self, rpc):
        resp = rpc.dispatch({
            "jsonrpc": "2.0", "method": "add",
            "params": {"a": 1, "b": 2, "c": 3}, "id": 1
        })
        assert resp["error"]["code"] == -32602

    def test_null_params_no_required(self, rpc):
        """Method with all-optional params should accept null params."""
        # Register a no-args method
        rpc.method(lambda: 42, name="no_args")
        resp = rpc.dispatch({
            "jsonrpc": "2.0", "method": "no_args",
            "params": None, "id": 1
        })
        assert resp["result"] == 42


# ---------------------------------------------------------------------------
# Type handling
# ---------------------------------------------------------------------------

class TestTypes:
    def test_type_mismatch(self, rpc):
        resp = rpc.dispatch({
            "jsonrpc": "2.0", "method": "add",
            "params": {"a": "not_int", "b": 2}, "id": 1
        })
        assert resp["error"]["code"] == -32602

    def test_int_to_float_coercion(self, rpc):
        resp = rpc.dispatch({
            "jsonrpc": "2.0", "method": "typed_float",
            "params": {"x": 5}, "id": 1
        })
        assert resp["result"] == 10.0

    def test_union_allows_none(self, rpc):
        resp = rpc.dispatch({
            "jsonrpc": "2.0", "method": "optional_param",
            "params": {"x": 10, "y": None}, "id": 1
        })
        assert resp["result"] == 10


# ---------------------------------------------------------------------------
# Notifications
# ---------------------------------------------------------------------------

class TestNotifications:
    def test_no_id_returns_none(self, rpc):
        resp = rpc.dispatch({
            "jsonrpc": "2.0", "method": "add",
            "params": {"a": 1, "b": 2}
            # no "id" field
        })
        assert resp is None


# ---------------------------------------------------------------------------
# Error redaction
# ---------------------------------------------------------------------------

class TestErrors:
    def test_redact_exceptions(self, rpc):
        def boom():
            raise ValueError("secret info")
        rpc.method(boom)
        resp = rpc.dispatch({"jsonrpc": "2.0", "method": "boom", "id": 1})
        assert resp["error"]["code"] == -32603
        assert "ValueError" in resp["error"]["message"]
        assert "secret info" not in resp["error"]["message"]

    def test_unredacted_exceptions(self, rpc):
        rpc.redact_exceptions = False

        def boom2():
            raise ValueError("visible error detail")
        rpc.method(boom2, name="boom2")
        resp = rpc.dispatch({"jsonrpc": "2.0", "method": "boom2", "id": 1})
        assert "visible error detail" in resp["error"]["message"]


# ---------------------------------------------------------------------------
# Cancellation
# ---------------------------------------------------------------------------

class TestCancellation:
    def test_register_unregister_cancel(self):
        event = register_pending_request(42)
        assert not event.is_set()
        assert cancel_request(42) is True
        assert event.is_set()
        unregister_pending_request(42)
        assert cancel_request(42) is False
