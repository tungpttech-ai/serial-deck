"""Frozen-bundle behavior, simulated: self-relaunch, MCP commands, hub spawn, launcher."""

import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import serial_deck
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


class SelfCommandEnvTest(unittest.TestCase):
    def test_appimage_relaunch_gets_the_host_loader_path(self):
        env = {"APPIMAGE": "/home/u/SerialDeck.AppImage", "LD_LIBRARY_PATH": "/tmp/.mount_x/usr/lib/serial-deck/_internal"}
        with patch.object(sys, "frozen", True, create=True), patch.dict(os.environ, env):
            os.environ.pop("LD_LIBRARY_PATH_ORIG", None)
            child = runtime.self_command_env()
        self.assertIsNotNone(child)
        self.assertNotIn("LD_LIBRARY_PATH", child)  # the AppRun shell must use host libraries
        self.assertEqual(child["APPIMAGE"], "/home/u/SerialDeck.AppImage")

    def test_plain_bundles_and_pip_installs_inherit(self):
        with patch.object(sys, "frozen", True, create=True), patch.dict(os.environ, {}, clear=False):
            os.environ.pop("APPIMAGE", None)
            self.assertIsNone(runtime.self_command_env())
        with patch.object(sys, "frozen", False, create=True):
            self.assertIsNone(runtime.self_command_env())


class HostExecTest(unittest.TestCase):
    def test_windows_bundle_launches_host_programs_through_host_exec(self):
        with patch.object(runtime, "frozen", return_value=True), patch.object(runtime.os, "name", "nt"), \
                patch.object(runtime, "console_executable", return_value=r"C:\App\serial-deck-cli.exe"), \
                patch("subprocess.Popen") as popen:
            runtime.popen_host(["addr2line", "-e", "app.elf"])
        argv = popen.call_args.args[0]
        self.assertEqual(argv[:3], [r"C:\App\serial-deck-cli.exe", "host-exec", "--"])
        self.assertEqual(argv[3:], ["addr2line", "-e", "app.elf"])

    def test_host_exec_runs_the_program_and_relays_its_exit_code(self):
        code = runtime.host_exec(["--", sys.executable, "-c", "raise SystemExit(7)"])
        self.assertEqual(code, 7)
        self.assertEqual(runtime.host_exec([]), 2)

    @unittest.skipIf(os.name == "nt", "POSIX process groups")
    def test_run_host_timeout_kills_the_whole_tree_promptly(self):
        import subprocess
        import time
        script = ("import subprocess, sys, time; "
                  "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)']); time.sleep(30)")
        started = time.monotonic()
        with self.assertRaises(subprocess.TimeoutExpired):
            runtime.run_host([sys.executable, "-c", script], timeout=0.5, capture_output=True)
        self.assertLess(time.monotonic() - started, 4.0)

    def test_run_host_accepts_subprocess_run_arguments(self):
        import subprocess
        ok = runtime.run_host([sys.executable, "-c", "print('hi')"], capture_output=True, text=True,
                              timeout=30, check=False)
        self.assertEqual((ok.returncode, ok.stdout.strip()), (0, "hi"))
        with self.assertRaises(subprocess.CalledProcessError):
            runtime.run_host([sys.executable, "-c", "raise SystemExit(3)"], capture_output=True, check=True)

    def test_symbolizer_runs_addr2line_through_run_host(self):
        from serial_deck.web import ElfSymbolizer
        with tempfile.TemporaryDirectory() as temp:
            elf = Path(temp) / "app.elf"
            elf.write_bytes(b"\x7fELF" + b"\x00" * 60)
            tool = Path(temp) / "addr2line.py"
            tool.write_text("import sys\nprint('app_main at main.c:12')\n", encoding="utf-8")
            symbolizer = ElfSymbolizer(str(elf), tool_path=sys.executable)
            with patch.object(runtime, "run_host", wraps=runtime.run_host) as spy, \
                    patch.object(symbolizer, "tool_path", sys.executable):
                # Run "python addr2line.py ..." in place of the real tool.
                original = runtime.popen_host
                with patch.object(runtime, "popen_host",
                                  side_effect=lambda a, **k: original([a[0], str(tool), *a[1:]], **k)):
                    lines = symbolizer.decode("Backtrace: 0x42001234")
            self.assertTrue(spy.called)
            self.assertEqual(lines, ["0x42001234: app_main at main.c:12"])

    def test_launcher_routes_host_exec(self):
        with patch.object(runtime, "host_exec", return_value=5) as host_exec:
            self.assertEqual(launcher.main(["host-exec", "--", "x"]), 5)
        host_exec.assert_called_once_with(["--", "x"])


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

    def test_appimage_hub_spawn_drops_the_bundle_loader_path(self):
        manager = HubProcessManager(socket_path="/tmp/sd-appimage-test.sock")
        bundle_env = {"APPIMAGE": "/home/u/SerialDeck.AppImage",
                      "LD_LIBRARY_PATH": "/tmp/.mount_x/usr/lib/serial-deck/_internal"}
        with patch.object(sys, "frozen", True, create=True), patch.dict(os.environ, bundle_env), \
                patch("serial_deck.runtime.self_command", side_effect=lambda *a: ["/home/u/SerialDeck.AppImage", *a]), \
                patch.object(manager, "socket_ready", side_effect=[False, True]), \
                patch("serial_deck.hub_client.find_existing_hub", return_value=None), \
                patch("subprocess.Popen") as popen:
            os.environ.pop("LD_LIBRARY_PATH_ORIG", None)
            popen.return_value.poll.return_value = None
            manager.ensure_started()
        env = popen.call_args.kwargs["env"]
        self.assertIsNotNone(env)
        self.assertNotIn("LD_LIBRARY_PATH", env)

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
        self.assertIn(f"serial-deck {serial_deck.__version__}", out.getvalue())
        self.assertIn("console", out.getvalue())


class FlashSelfTest(unittest.TestCase):
    def test_bundled_stubs_decode(self):
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(flash.main(["--self-test"]), 0)
        self.assertIn("stub files OK", out.getvalue())


if __name__ == "__main__":
    unittest.main()
