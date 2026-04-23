"""Tests for --install --remote / --plugin-only client-side setup modes."""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
sys.path.insert(0, str(SRC_ROOT))


class TestGenerateMcpConfig(unittest.TestCase):
    def test_stdio_default_shape(self):
        from ida_multi_mcp.__main__ import generate_mcp_config

        cfg = generate_mcp_config()
        self.assertIn("command", cfg)
        self.assertEqual(cfg["args"], ["-m", "ida_multi_mcp"])
        self.assertNotIn("url", cfg)

    def test_stdio_with_include_type_sets_type(self):
        from ida_multi_mcp.__main__ import generate_mcp_config

        cfg = generate_mcp_config(include_type=True)
        self.assertEqual(cfg["type"], "stdio")

    def test_remote_shape_is_http(self):
        from ida_multi_mcp.__main__ import generate_mcp_config

        cfg = generate_mcp_config(remote_url="http://host:1234/mcp")
        self.assertEqual(cfg, {"type": "http", "url": "http://host:1234/mcp"})
        # No command/args/env in remote mode.
        self.assertNotIn("command", cfg)
        self.assertNotIn("args", cfg)
        self.assertNotIn("env", cfg)


class TestValidateRemoteUrl(unittest.TestCase):
    def test_accepts_http_and_https(self):
        from ida_multi_mcp.__main__ import _validate_remote_url

        self.assertEqual(
            _validate_remote_url("http://host:1/mcp"), "http://host:1/mcp"
        )
        self.assertEqual(
            _validate_remote_url("https://host:1/mcp"), "https://host:1/mcp"
        )

    def test_rejects_missing_scheme(self):
        from ida_multi_mcp.__main__ import _validate_remote_url

        with self.assertRaises(ValueError):
            _validate_remote_url("host:1/mcp")

    def test_rejects_wrong_scheme(self):
        from ida_multi_mcp.__main__ import _validate_remote_url

        with self.assertRaises(ValueError):
            _validate_remote_url("ftp://host/mcp")

    def test_rejects_empty(self):
        from ida_multi_mcp.__main__ import _validate_remote_url

        with self.assertRaises(ValueError):
            _validate_remote_url("")

    def test_rejects_missing_host(self):
        from ida_multi_mcp.__main__ import _validate_remote_url

        with self.assertRaises(ValueError):
            _validate_remote_url("http:///mcp")


class TestInstallMcpServersRemote(unittest.TestCase):
    def test_remote_url_written_to_factory_droid_config(self):
        from ida_multi_mcp.__main__ import SERVER_NAME, install_mcp_servers

        with tempfile.TemporaryDirectory() as td:
            home = Path(td)
            (home / ".factory").mkdir(parents=True, exist_ok=True)

            old_env = dict(os.environ)
            try:
                os.environ["HOME"] = str(home)
                os.environ["USERPROFILE"] = str(home)
                os.environ["APPDATA"] = str(home / "AppData" / "Roaming")

                with mock.patch(
                    "ida_multi_mcp.__main__.os.path.expanduser",
                    return_value=str(home),
                ):
                    install_mcp_servers(
                        quiet=True, remote_url="http://workstation:8765/mcp"
                    )

                config_path = home / ".factory" / "mcp.json"
                self.assertTrue(config_path.exists())
                config = json.loads(config_path.read_text(encoding="utf-8"))
                entry = config["mcpServers"][SERVER_NAME]

                # Remote mode writes HTTP transport, NOT stdio.
                self.assertEqual(entry["type"], "http")
                self.assertEqual(entry["url"], "http://workstation:8765/mcp")
                self.assertNotIn("command", entry)
                self.assertNotIn("args", entry)

                # Round-trip uninstall should cleanly remove the entry.
                with mock.patch(
                    "ida_multi_mcp.__main__.os.path.expanduser",
                    return_value=str(home),
                ):
                    install_mcp_servers(
                        uninstall=True, quiet=True,
                        remote_url="http://workstation:8765/mcp",
                    )

                config = json.loads(config_path.read_text(encoding="utf-8"))
                self.assertNotIn(SERVER_NAME, config["mcpServers"])
            finally:
                os.environ.clear()
                os.environ.update(old_env)


class TestCmdInstallModes(unittest.TestCase):
    """Exercise the install-command branch selection without actually touching
    the filesystem. We patch the worker helpers and verify the right ones get
    called for each flag combination.
    """

    def _make_args(self, **overrides):
        base = dict(
            install=True,
            uninstall=False,
            list=False,
            config=False,
            ida_dir=None,
            registry=None,
            idalib_python=None,
            remote=None,
            plugin_only=False,
            http=False,
            host="127.0.0.1",
            port=8765,
        )
        base.update(overrides)
        return type("Args", (), base)()

    def test_remote_skips_plugin_and_calls_install_mcp_servers_with_url(self):
        from ida_multi_mcp import __main__ as cli

        with mock.patch.object(cli, "_install_ida_plugin") as plug, \
             mock.patch.object(cli, "install_mcp_servers") as inst:
            rc = cli.cmd_install(
                self._make_args(remote="http://host:8765/mcp")
            )

        self.assertEqual(rc, 0)
        plug.assert_not_called()
        inst.assert_called_once_with(remote_url="http://host:8765/mcp")

    def test_plugin_only_calls_plugin_install_and_skips_mcp_servers(self):
        from ida_multi_mcp import __main__ as cli

        with mock.patch.object(cli, "_install_ida_plugin", return_value=0) as plug, \
             mock.patch.object(cli, "install_mcp_servers") as inst:
            rc = cli.cmd_install(self._make_args(plugin_only=True))

        self.assertEqual(rc, 0)
        plug.assert_called_once_with(None)
        inst.assert_not_called()

    def test_default_calls_both(self):
        from ida_multi_mcp import __main__ as cli

        with mock.patch.object(cli, "_install_ida_plugin", return_value=0) as plug, \
             mock.patch.object(cli, "install_mcp_servers") as inst:
            rc = cli.cmd_install(self._make_args())

        self.assertEqual(rc, 0)
        plug.assert_called_once_with(None)
        inst.assert_called_once_with()

    def test_mutex_remote_and_plugin_only(self):
        from ida_multi_mcp import __main__ as cli

        with mock.patch.object(cli, "_install_ida_plugin") as plug, \
             mock.patch.object(cli, "install_mcp_servers") as inst:
            rc = cli.cmd_install(
                self._make_args(remote="http://h:1/m", plugin_only=True)
            )

        self.assertEqual(rc, 2)
        plug.assert_not_called()
        inst.assert_not_called()

    def test_invalid_remote_url_returns_error(self):
        from ida_multi_mcp import __main__ as cli

        with mock.patch.object(cli, "_install_ida_plugin") as plug, \
             mock.patch.object(cli, "install_mcp_servers") as inst:
            rc = cli.cmd_install(self._make_args(remote="not-a-url"))

        self.assertEqual(rc, 2)
        plug.assert_not_called()
        inst.assert_not_called()


class TestCmdUninstallModes(unittest.TestCase):
    def _make_args(self, **overrides):
        base = dict(
            ida_dir=None, remote=None, plugin_only=False,
        )
        base.update(overrides)
        return type("Args", (), base)()

    def test_remote_uninstall_skips_plugin_teardown(self):
        from ida_multi_mcp import __main__ as cli

        with mock.patch.object(cli, "_uninstall_ida_plugin") as un, \
             mock.patch.object(cli, "install_mcp_servers") as inst:
            rc = cli.cmd_uninstall(
                self._make_args(remote="http://host:8765/mcp")
            )

        self.assertEqual(rc, 0)
        un.assert_not_called()
        inst.assert_called_once_with(
            uninstall=True, remote_url="http://host:8765/mcp"
        )

    def test_plugin_only_uninstall_leaves_client_configs_alone(self):
        from ida_multi_mcp import __main__ as cli

        with mock.patch.object(cli, "_uninstall_ida_plugin") as un, \
             mock.patch.object(cli, "install_mcp_servers") as inst:
            rc = cli.cmd_uninstall(self._make_args(plugin_only=True))

        self.assertEqual(rc, 0)
        un.assert_called_once_with(None)
        inst.assert_not_called()


if __name__ == "__main__":
    unittest.main()
