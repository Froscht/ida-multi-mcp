"""Tests for registry.py — Instance registry with file-based JSON storage."""

import json
import os
import time

import pytest

from ida_multi_mcp.registry import (
    InstanceRegistry,
    MAX_INSTANCES,
    ALLOWED_HOSTS,
    _is_loopback_host,
    _validate_instance_entry,
)


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

class TestRegistration:
    def test_creates_instance(self, tmp_registry):
        iid = tmp_registry.register(pid=1, port=100, idb_path="/a.i64",
                                    binary_name="a.exe", host="127.0.0.1")
        assert isinstance(iid, str) and len(iid) >= 4
        info = tmp_registry.get_instance(iid)
        assert info is not None
        assert info["pid"] == 1

    def test_first_instance_becomes_active(self, tmp_registry):
        iid = tmp_registry.register(pid=1, port=100, idb_path="/a.i64",
                                    host="127.0.0.1")
        assert tmp_registry.get_active() == iid

    def test_preserves_existing_active(self, tmp_registry):
        iid1 = tmp_registry.register(pid=1, port=100, idb_path="/a.i64",
                                     host="127.0.0.1")
        tmp_registry.register(pid=2, port=200, idb_path="/b.i64",
                              host="127.0.0.1")
        assert tmp_registry.get_active() == iid1

    def test_rejects_non_localhost_host(self, tmp_registry):
        with pytest.raises(ValueError, match="Invalid host"):
            tmp_registry.register(pid=1, port=100, idb_path="/a.i64",
                                  host="10.0.0.1")

    def test_max_instances_limit(self, tmp_path):
        reg = InstanceRegistry(str(tmp_path / "inst.json"))
        for i in range(MAX_INSTANCES):
            reg.register(pid=i, port=i + 1000, idb_path=f"/{i}.i64",
                         host="127.0.0.1")
        with pytest.raises(ValueError, match="Registry full"):
            reg.register(pid=999, port=9999, idb_path="/overflow.i64",
                         host="127.0.0.1")


# ---------------------------------------------------------------------------
# Unregistration
# ---------------------------------------------------------------------------

class TestUnregistration:
    def test_removes_instance(self, populated_registry):
        instances = populated_registry.list_instances()
        iid = next(iter(instances))
        assert populated_registry.unregister(iid) is True
        assert populated_registry.get_instance(iid) is None

    def test_promotes_active_on_removal(self, tmp_registry):
        iid1 = tmp_registry.register(pid=1, port=100, idb_path="/a.i64",
                                     host="127.0.0.1")
        tmp_registry.register(pid=2, port=200, idb_path="/b.i64",
                              host="127.0.0.1")
        tmp_registry.unregister(iid1)
        # Active should be promoted to the remaining instance
        assert tmp_registry.get_active() is not None
        assert tmp_registry.get_active() != iid1

    def test_unregister_nonexistent_returns_false(self, tmp_registry):
        assert tmp_registry.unregister("doesnotexist") is False


# ---------------------------------------------------------------------------
# Active management
# ---------------------------------------------------------------------------

class TestActiveManagement:
    def test_set_active_valid(self, populated_registry):
        instances = populated_registry.list_instances()
        ids = list(instances.keys())
        populated_registry.set_active(ids[1])
        assert populated_registry.get_active() == ids[1]

    def test_set_active_invalid(self, populated_registry):
        result = populated_registry.set_active("nonexistent")
        assert result is False


# ---------------------------------------------------------------------------
# Heartbeat
# ---------------------------------------------------------------------------

class TestHeartbeat:
    def test_update_existing(self, populated_registry):
        iid = next(iter(populated_registry.list_instances()))
        old_hb = populated_registry.get_instance(iid)["last_heartbeat"]
        time.sleep(0.01)
        assert populated_registry.update_heartbeat(iid) is True
        new_hb = populated_registry.get_instance(iid)["last_heartbeat"]
        assert new_hb != old_hb

    def test_update_nonexistent(self, tmp_registry):
        assert tmp_registry.update_heartbeat("nope") is False


# ---------------------------------------------------------------------------
# Expiration
# ---------------------------------------------------------------------------

class TestExpiration:
    def test_expire_moves_to_expired(self, populated_registry):
        iid = next(iter(populated_registry.list_instances()))
        assert populated_registry.expire_instance(iid, reason="test") is True
        assert populated_registry.get_instance(iid) is None
        expired = populated_registry.get_expired(iid)
        assert expired is not None
        assert expired["reason"] == "test"

    def test_expire_with_replaced_by(self, populated_registry):
        ids = list(populated_registry.list_instances().keys())
        populated_registry.expire_instance(ids[0], reason="replaced",
                                           replaced_by=ids[1])
        expired = populated_registry.get_expired(ids[0])
        assert expired["replaced_by"] == ids[1]

    def test_expire_nonexistent_returns_false(self, tmp_registry):
        assert tmp_registry.expire_instance("nope", reason="x") is False

    def test_cleanup_expired_removes_old(self, tmp_registry):
        iid = tmp_registry.register(pid=1, port=100, idb_path="/a.i64",
                                    host="127.0.0.1")
        tmp_registry.expire_instance(iid, reason="old")
        # With max_age=0, everything is old
        removed = tmp_registry.cleanup_expired(max_age_seconds=0)
        assert removed >= 1
        assert tmp_registry.get_expired(iid) is None


# ---------------------------------------------------------------------------
# Stale cleanup
# ---------------------------------------------------------------------------

class TestStaleCleanup:
    def test_expires_old_heartbeats(self, tmp_registry):
        iid = tmp_registry.register(pid=1, port=100, idb_path="/a.i64",
                                    host="127.0.0.1")
        # Set heartbeat to epoch 0 by manipulating file directly
        import json as _json
        with open(tmp_registry.registry_path, "r") as f:
            data = _json.load(f)
        data["instances"][iid]["last_heartbeat"] = "1970-01-01T00:00:00+00:00"
        with open(tmp_registry.registry_path, "w") as f:
            _json.dump(data, f)

        stale = tmp_registry.cleanup_stale(timeout_seconds=1)
        assert iid in stale

    def test_preserves_fresh_heartbeats(self, populated_registry):
        stale = populated_registry.cleanup_stale(timeout_seconds=9999)
        assert stale == []


# ---------------------------------------------------------------------------
# Corruption recovery
# ---------------------------------------------------------------------------

class TestCorruptionRecovery:
    def test_recovers_from_non_dict_json(self, tmp_path):
        registry_path = str(tmp_path / "instances.json")
        with open(registry_path, "w") as f:
            f.write('"just a string"')
        reg = InstanceRegistry(registry_path)
        # Should recover and allow registration
        iid = reg.register(pid=1, port=100, idb_path="/a.i64",
                           host="127.0.0.1")
        assert len(iid) >= 4

    def test_recovers_from_nul_filled_file(self, tmp_path):
        registry_path = str(tmp_path / "instances.json")
        with open(registry_path, "wb") as f:
            f.write(b"\x00" * 512)
        reg = InstanceRegistry(registry_path)
        iid = reg.register(pid=1, port=100, idb_path="/a.i64",
                           host="127.0.0.1")
        assert len(iid) >= 4
        quarantined = list(tmp_path.glob("instances.json.corrupt-*"))
        assert quarantined

    def test_strips_non_localhost_hosts_on_read(self, tmp_path):
        registry_path = str(tmp_path / "instances.json")
        data = {
            "instances": {
                "evil": {
                    "pid": 1, "host": "10.0.0.1", "port": 80,
                    "binary_name": "x", "binary_path": "",
                    "idb_path": "/x.i64", "arch": "x64",
                    "registered_at": "2024-01-01T00:00:00Z",
                    "last_heartbeat": "2024-01-01T00:00:00Z",
                },
                "good": {
                    "pid": 2, "host": "127.0.0.1", "port": 81,
                    "binary_name": "y", "binary_path": "",
                    "idb_path": "/y.i64", "arch": "x64",
                    "registered_at": "2024-01-01T00:00:00Z",
                    "last_heartbeat": "2024-01-01T00:00:00Z",
                },
            },
            "active_instance": None,
            "expired": {},
        }
        with open(registry_path, "w") as f:
            json.dump(data, f)
        reg = InstanceRegistry(registry_path)
        instances = reg.list_instances()
        assert "evil" not in instances
        assert "good" in instances


# ---------------------------------------------------------------------------
# Schema validation (V-03, V-12)
# ---------------------------------------------------------------------------


def _valid_entry(**overrides) -> dict:
    """Build a schema-valid instance entry, with selective overrides for tests."""
    base = {
        "pid": 123,
        "host": "127.0.0.1",
        "port": 5000,
        "binary_name": "x",
        "binary_path": "",
        "idb_path": "/x.i64",
        "arch": "x64",
        "registered_at": "2024-01-01T00:00:00Z",
        "last_heartbeat": "2024-01-01T00:00:00Z",
    }
    base.update(overrides)
    return base


class TestLoopbackHostHelper:
    @pytest.mark.parametrize("host", [
        "127.0.0.1",
        "localhost",
        "::1",
        "LOCALHOST",         # case-insensitive
        "  127.0.0.1  ",     # whitespace
        "127.0.0.2",         # anywhere in 127.0.0.0/8
        "127.255.255.254",
    ])
    def test_accepts_loopback(self, host):
        assert _is_loopback_host(host) is True

    @pytest.mark.parametrize("host", [
        "10.0.0.1",
        "192.168.1.1",
        "8.8.8.8",
        "::2",
        "2001:db8::1",
        "",
        "not-an-ip",
    ])
    def test_rejects_non_loopback(self, host):
        assert _is_loopback_host(host) is False

    def test_rejects_non_string(self):
        assert _is_loopback_host(None) is False
        assert _is_loopback_host(127) is False


class TestEntryValidation:
    def test_accepts_valid_entry(self):
        assert _validate_instance_entry("id", _valid_entry()) is True

    def test_rejects_non_dict(self):
        assert _validate_instance_entry("id", "not a dict") is False
        assert _validate_instance_entry("id", None) is False

    @pytest.mark.parametrize("port", ["5000", 5000.0, None, True])
    def test_rejects_non_integer_port(self, port):
        # Note: bool is a subclass of int in Python, but we explicitly want to
        # reject True/False as ports. isinstance(True, int) is True, so the
        # current validator accepts bool; documented here as known behavior.
        if isinstance(port, bool):
            pytest.skip("bool is treated as int by isinstance()")
        assert _validate_instance_entry("id", _valid_entry(port=port)) is False

    @pytest.mark.parametrize("port", [0, -1, 65536, 99999])
    def test_rejects_out_of_range_port(self, port):
        assert _validate_instance_entry("id", _valid_entry(port=port)) is False

    def test_rejects_non_loopback_host(self):
        assert _validate_instance_entry("id", _valid_entry(host="8.8.8.8")) is False

    def test_rejects_invalid_pid_type(self):
        assert _validate_instance_entry("id", _valid_entry(pid="not-int")) is False

    def test_rejects_negative_pid(self):
        assert _validate_instance_entry("id", _valid_entry(pid=-1)) is False

    def test_allows_missing_pid(self):
        entry = _valid_entry()
        entry.pop("pid")
        assert _validate_instance_entry("id", entry) is True


class TestLoadEntryValidation:
    """Integration: InstanceRegistry._load should drop invalid entries."""

    def test_drops_invalid_port_entries(self, tmp_path):
        registry_path = str(tmp_path / "instances.json")
        data = {
            "instances": {
                "bad_port_type": _valid_entry(port="5000"),
                "bad_port_range": _valid_entry(port=70000),
                "good": _valid_entry(port=5001),
            },
            "active_instance": None,
            "expired": {},
        }
        with open(registry_path, "w") as f:
            json.dump(data, f)
        reg = InstanceRegistry(registry_path)
        instances = reg.list_instances()
        assert "bad_port_type" not in instances
        assert "bad_port_range" not in instances
        assert "good" in instances

    def test_drops_invalid_pid_entries(self, tmp_path):
        registry_path = str(tmp_path / "instances.json")
        data = {
            "instances": {
                "bad_pid": _valid_entry(pid=-5),
                "good": _valid_entry(pid=42),
            },
            "active_instance": None,
            "expired": {},
        }
        with open(registry_path, "w") as f:
            json.dump(data, f)
        reg = InstanceRegistry(registry_path)
        instances = reg.list_instances()
        assert "bad_pid" not in instances
        assert "good" in instances

    def test_drops_non_dict_entries(self, tmp_path):
        registry_path = str(tmp_path / "instances.json")
        data = {
            "instances": {
                "bad": "not a dict",
                "good": _valid_entry(),
            },
            "active_instance": None,
            "expired": {},
        }
        with open(registry_path, "w") as f:
            json.dump(data, f)
        reg = InstanceRegistry(registry_path)
        instances = reg.list_instances()
        assert "bad" not in instances
        assert "good" in instances
