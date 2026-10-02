"""Frozen-bundle behavior, simulated: self-relaunch, MCP commands, hub spawn, launcher."""

import io
import os
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from serial_deck import flash, launcher, mcp_status, runtime
from serial_deck.hub_client import HubProcessManager


class FrozenSelfCommandTest(unittest.TestCase):
    def frozen(self, exe, **env):
        return [patch.object(sys, "frozen", True, create=True),
                patch.object(sys, "executable", exe),
                patch.dict(os.environ, env, clear=False)]

    def test_not_frozen_has_no_console_executable(self):
        with patch.object(sys, "frozen", False, create=True):
            self.assertIsNone(runtime.console_executable())
            with self.assertRaises(RuntimeError):
                runtime.self_command("hub")

    def test_frozen_prefers_the_sibling_console_executable(self):
        suffix = ".exe" if os.name == "nt" else ""
        gui = str(Path("/opt/app") / f"serial-deck{suffix}")
        with patch.object(sys, "frozen", True, create=True), patch.object(sys, "executable", gui), \
                patch.object(Path, "is_file", return_value=True), patch.dict(os.environ, {}, clear=False):
            os.environ.pop("APPIMAGE", None)
            command = runtime.self_command("hub", "--baud", "115200")
        self.assertTrue(command[0].endswith(f"serial-deck-cli{suffix}"), command)
        self.assertEqual(command[1:], ["hub", "--baud", "115200"])

    @unittest.skipUnless(sys.platform.startswith("linux"), "AppImage is Linux-only")
    def test_appimage_relaunch_uses_the_stable_path_and_keeps_no_fuse_mode(self):
        with patch.object(sys, "frozen", True, create=True), \
                patch.object(sys, "executable", "/tmp/.mount_x/usr/lib/serial-deck/serial-deck"), \
                patch.dict(os.environ, {"APPIMAGE": "/home/u/SerialDeck.AppImage"}):
            os.environ.pop("APPIMAGE_EXTRACT_AND_RUN", None)
            self.assertEqual(runtime.self_command("mcp"), ["/home/u/SerialDeck.AppImage", "mcp"])
            os.environ["APPIMAGE_EXTRACT_AND_RUN"] = "1"
            self.assertEqual(runtime.self_command("mcp"),
                             ["/home/u/SerialDeck.AppImage", "--appimage-extract-and-run", "mcp"])
            # The flag form is stripped by the runtime; the extraction dir still tells.
            os.environ.pop("APPIMAGE_EXTRACT_AND_RUN")
            os.environ["APPDIR"] = "/tmp/appimage_extracted_0123abcd"
            self.assertIn("--appimage-extract-and-run", runtime.self_command("hub"))
            os.environ["APPDIR"] = "/tmp/.mount_SerialXy"
            self.assertNotIn("--appimage-extract-and-run", runtime.self_command("hub"))

    def test_host_env_restores_the_loader_path(self):
        env = {"LD_LIBRARY_PATH": "/bundle/_internal", "LD_LIBRARY_PATH_ORIG": "/usr/local/lib",
               "DYLD_LIBRARY_PATH": "/bundle", "_MEIPASS2": "/bundle"}
        with patch.object(sys, "frozen", True, create=True), patch.dict(os.environ, env):
            clean = runtime.host_env()
        self.assertEqual(clean["LD_LIBRARY_PATH"], "/usr/local/lib")
        self.assertNotIn("DYLD_LIBRARY_PATH", clean)
        self.assertNotIn("_MEIPASS2", clean)

    def test_host_env_is_a_plain_copy_for_pip_installs(self):
        with patch.object(sys, "frozen", False, create=True), \
                patch.dict(os.environ, {"LD_LIBRARY_PATH": "/x"}):
            self.assertEqual(runtime.host_env()["LD_LIBRARY_PATH"], "/x")


class FrozenIntegrationTest(unittest.TestCase):
    def test_hub_is_spawned_through_the_bundle_when_frozen(self):
        manager = HubProcessManager(socket_path="/tmp/sd-frozen-test.sock")
        with patch("serial_deck.runtime.frozen", return_value=True), \
                patch("serial_deck.runtime.self_command", side_effect=lambda *a: ["BUNDLE", *a]), \
                patch.object(manager, "socket_ready", side_effect=[False, True]), \
                patch("serial_deck.hub_client.find_existing_hub", return_value=None), \
                patch("subprocess.Popen") as popen:
            popen.return_value.poll.return_value = None
            self.assertTrue(manager.ensure_started())
        argv = popen.call_args.args[0]
        self.assertEqual(argv[:2], ["BUNDLE", "hub"])
        self.assertIn("--socket", argv)

    def test_hub_is_spawned_as_a_module_from_a_pip_install(self):
        manager = HubProcessManager(socket_path="/tmp/sd-pip-test.sock")
        with patch("serial_deck.runtime.frozen", return_value=False), \
                patch.object(manager, "socket_ready", side_effect=[False, True]), \
                patch("serial_deck.hub_client.find_existing_hub", return_value=None), \
                patch("subprocess.Popen") as popen:
            popen.return_value.poll.return_value = None
            manager.ensure_started()
        self.assertEqual(popen.call_args.args[0][:3], [sys.executable, "-m", "serial_deck.hub"])

    def test_mcp_commands_point_at_the_bundle(self):
        with patch("serial_deck.runtime.frozen", return_value=True), \
                patch("serial_deck.runtime.self_command", side_effect=lambda *a: ["/Apps/serial-deck-cli", *a]):
            commands = mcp_status.install_commands("interact")
        self.assertIn("/Apps/serial-deck-cli mcp --allow interact", commands["claude"])
        self.assertEqual(commands["pip"], "")
        self.assertIn('"command": "/Apps/serial-deck-cli"', commands["json"])

    def test_frozen_flash_command_is_runnable_serial_deck_syntax(self):
        build = Path(__file__).resolve().parent / "fixtures"
        with patch("serial_deck.runtime.frozen", return_value=True), \
                patch("serial_deck.runtime.self_command", side_effect=lambda *a: ["sd-cli", *a]), \
                patch("serial_deck.flash.esptool_args", return_value=["--chip", "esp32"]):
            command = flash.build_flash_command("COM5", str(build), 921600)
        self.assertEqual(command[:2], ["sd-cli", "flash"])
        self.assertEqual(command[command.index("--port") + 1], "COM5")
        self.assertIn("--yes", command)


class LauncherTest(unittest.TestCase):
    def test_no_subcommand_opens_the_app(self):
        with patch("serial_deck.app.main", return_value=0) as app_main:
            self.assertEqual(launcher.main([]), 0)
        app_main.assert_called_once_with([])

    def test_subcommands_dispatch_with_their_arguments(self):
        with patch("serial_deck.hub.main", return_value=3) as hub_main:
            self.assertEqual(launcher.main(["hub", "--status"]), 3)
        hub_main.assert_called_once_with(["--status"])

    def test_appimage_and_finder_arguments_are_dropped(self):
        with patch("serial_deck.web.main", return_value=0) as web_main:
            launcher.main(["--appimage-extract-and-run", "web", "--port-web", "1"])
        web_main.assert_called_once_with(["--port-web", "1"])

    def test_version_and_help(self):
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(launcher.main(["--version"]), 0)
            self.assertEqual(launcher.main(["--help"]), 0)
        self.assertIn("serial-deck 0.2.0", out.getvalue())
        self.assertIn("console", out.getvalue())


class FlashSelfTest(unittest.TestCase):
    def test_bundled_stubs_decode(self):
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(flash.main(["--self-test"]), 0)
        self.assertIn("stub files OK", out.getvalue())


if __name__ == "__main__":
    unittest.main()
