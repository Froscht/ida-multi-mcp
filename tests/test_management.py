"""Tests for tools/management.py — Management tool functions."""

import pytest

from ida_multi_mcp.tools import management


class _DummyRegistry:
    """Minimal registry stub for management tests."""
    def __init__(self, instances=None):
        self._instances = instances or {}

    def list_instances(self):
        return dict(self._instances)


class TestListInstances:
    def test_with_data(self):
        reg = _DummyRegistry({
            "abc": {
                "binary_name": "test.exe", "binary_path": "/test.exe",
                "arch": "x64", "host": "127.0.0.1", "port": 5000,
                "pid": 100, "registered_at": "2024-01-01T00:00:00Z",
            }
        })
        management.set_registry(reg)
        result = management.list_instances()
        assert result["count"] == 1
        assert result["instances"][0]["id"] == "abc"

    def test_empty_registry(self):
        management.set_registry(_DummyRegistry())
        result = management.list_instances()
        assert result["count"] == 0
        assert result["instances"] == []


class TestRefreshTools:
    def test_with_callback(self):
        management.set_refresh_callback(lambda: 42)
        result = management.refresh_tools()
        assert result["refreshed"] is True
        assert result["tools_count"] == 42

    def test_without_callback(self):
        management.set_refresh_callback(None)
        result = management.refresh_tools()
        assert result["refreshed"] is False


class TestRegistryLifecycle:
    def test_set_get_registry(self):
        reg = _DummyRegistry()
        management.set_registry(reg)
        assert management._get_registry() is reg

    def test_get_registry_uninitialized(self):
        management.set_registry(None)
        with pytest.raises(RuntimeError, match="not initialized"):
            management._get_registry()
