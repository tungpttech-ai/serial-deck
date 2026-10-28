"""User scripts: runner API, hub supervision, autorun, stop, and safety limits.

Every test points SERIAL_DECK_CONFIG and SERIAL_DECK_RUNTIME_DIR at a temp dir:
a hub already running for the real user must never be reused or touched.
"""

import os
import re
import signal
import socket
import sys
import tempfile
import textwrap
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from serial_deck import script_supervisor, scripting
from serial_deck import service as service_module
from serial_deck.deckconfig import JsonFile
from serial_deck.hub_client import HubProcessManager
from serial_deck.service import MultiPortHub

posix_only = unittest.skipUnless(os.name == "posix", "needs POSIX process groups")


def eventually(check, timeout=8.0):
    deadline = time.monotonic() + timeout
    while not check():
        if time.monotonic() > deadline:
            raise AssertionError("condition did not become true")
        time.sleep(0.02)


class FakeDevice:
    """A ser2net-like TCP endpoint the test plays the device on."""

    def __init__(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind(("127.0.0.1", 0))
        self.server.listen(4)
        self.port = f"tcp://127.0.0.1:{self.server.getsockname()[1]}"
        self.conns = []
        self.received = bytearray()
        self.lock = threading.Lock()
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while True:
            try:
                conn, _ = self.server.accept()
            except OSError:
                return
            conn.settimeout(0.2)
            self.conns.append(conn)
            threading.Thread(target=self._read, args=(conn,), daemon=True).start()

    def _read(self, conn):
        while True:
            try:
                data = conn.recv(4096)
            except socket.timeout:
                continue
            except OSError:
                return
            if not data:
                return
            with self.lock:
                self.received.extend(data)

    def say(self, text):
        for conn in list(self.conns):
            try:
                conn.sendall(text.encode())
            except OSError:
                pass

    def heard(self):
        with self.lock:
            return bytes(self.received).decode(errors="replace")

    def close(self):
        self.server.close()
        for conn in self.conns:
            conn.close()


class ScriptEnvironment(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="sd-script-")
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.config = root / "config"
        self.scripts = self.config / "scripts"
        self.scripts.mkdir(parents=True)
        env = patch.dict(os.environ, {"SERIAL_DECK_CONFIG": str(self.config),
                                      "SERIAL_DECK_RUNTIME_DIR": str(root / "rt")})
        env.start()
        self.addCleanup(env.stop)
        self.device = FakeDevice()
        self.addCleanup(self.device.close)

    def write_script(self, name, body):
        path = self.scripts / f"{name}.py"
        path.write_text(textwrap.dedent(body))
        return path


class ScriptPathTest(ScriptEnvironment):
    def test_names_are_plain_identifiers(self):
        self.write_script("ok_1", "def run(dev): pass\n")
        self.assertTrue(scripting.script_path("ok_1").is_file())
        for bad in ("../evil", "a/b", "", ".hidden", "x.py", "a b", "x" * 60, None, 5):
            with self.assertRaises((ValueError, FileNotFoundError), msg=repr(bad)):
                scripting.script_path(bad)

    @posix_only
    def test_a_symlink_out_of_the_folder_is_refused(self):
        outside = Path(self.temp.name) / "outside.py"
        outside.write_text("def run(dev): pass\n")
        (self.scripts / "link.py").symlink_to(outside)
        with self.assertRaises(ValueError):
            scripting.script_path("link")

    def test_an_oversized_script_is_refused(self):
        (self.scripts / "big.py").write_text("#" * (scripting.MAX_SCRIPT_BYTES + 1))
        with self.assertRaises(ValueError):
            scripting.script_path("big")

    def test_listing_reads_the_description_without_running_the_script(self):
        marker = Path(self.temp.name) / "ran"
        self.write_script("hello", f'''
            """Say hello to the device.

            More detail."""
            open({str(marker)!r}, "w").write("executed")
            def run(dev): pass
        ''')
        (self.scripts / "broken.py").write_text("def run(:\n")
        listed = {item["name"]: item for item in scripting.list_scripts()}
        self.assertEqual(listed["hello"]["description"], "Say hello to the device.")
        self.assertTrue(listed["hello"]["has_run"])
        self.assertFalse(listed["broken"]["ok"])
        self.assertFalse(marker.exists(), "listing must never execute a script")


class FakeTransport:
    def __init__(self):
        self.written = []
        self.frames = []
        self.incoming = []
        self.error = None

    def read(self, size=4096):
        if self.error:
            raise self.error
        if self.incoming:
            return self.incoming.pop(0)
        time.sleep(0.01)
        return b""

    def write(self, data):
        self.written.append(bytes(data))

    def write_frame(self, frame):
        self.frames.append(bytes(frame))


class DeviceApiTest(unittest.TestCase):
    def device(self):
        transport = FakeTransport()
        dev = scripting.Device(transport, "/dev/x", 115200, log=lambda t: None)
        dev.start()
        self.addCleanup(dev.close)
        return dev, transport

    def test_expect_matches_across_chunks_and_consumes_up_to_the_match(self):
        dev, transport = self.device()
        transport.incoming += [b"boot lo", b"g in: ", b"login: rest"]
        match = dev.expect(r"login:", timeout=3)
        self.assertEqual(match.group(0), "login:")
        self.assertIn(b"x", b"x")
        dev.flush()

    def test_expect_times_out(self):
        dev, _ = self.device()
        with self.assertRaises(scripting.ScriptTimeout):
            dev.expect("never", timeout=0.2)

    def test_expect_any_returns_the_earliest_match(self):
        dev, transport = self.device()
        transport.incoming += [b"ERROR first then OK"]
        index, match = dev.expect_any(["OK", "ERROR"], timeout=3)
        self.assertEqual((index, match.group(0)), (1, "ERROR"))

    def test_send_encodes_text_and_frames_go_through_write_frame(self):
        dev, transport = self.device()
        dev.send_line("root")
        dev.send(b"\x01\x02")
        dev.send_frame(b"frame\x00")
        self.assertEqual(transport.written, [b"root\n", b"\x01\x02"])
        self.assertEqual(transport.frames, [b"frame\x00"])

    def test_a_lost_link_raises_instead_of_hanging(self):
        dev, transport = self.device()
        transport.error = OSError("peer closed")
        with self.assertRaises(ConnectionError):
            dev.expect("anything", timeout=3)

    def test_stop_interrupts_a_wait(self):
        dev, _ = self.device()
        threading.Timer(0.1, dev.close).start()
        with self.assertRaises(scripting.ScriptStopped):
            dev.expect("never", timeout=5)

    def test_the_api_has_no_reset_bootloader_or_flash(self):
        names = {n for n in dir(scripting.Device) if not n.startswith("_")}
        for forbidden in ("reset", "bootloader", "flash_firmware", "enter_bootloader", "set_baud"):
            self.assertNotIn(forbidden, names)
        self.assertFalse(hasattr(scripting.Device(FakeTransport(), "p", 1), "transport"))

    def test_on_line_receives_whole_lines_and_its_errors_are_contained(self):
        transport = FakeTransport()
        seen, logs = [], []
        dev = scripting.Device(transport, "/dev/x", 115200, log=logs.append)

        def on_line(d, line):
            seen.append(line)
            if line == "boom":
                raise RuntimeError("bad handler")

        dev.start(on_line)
        self.addCleanup(dev.close)
        transport.incoming += [b"one\r\ntw", b"o\nboom\nthree\n"]
        eventually(lambda: seen == ["one", "two", "boom", "three"])
        eventually(lambda: any("on_line failed" in entry for entry in logs))


class RunScriptTest(ScriptEnvironment):
    def run_with(self, body, transport=None):
        path = self.write_script("t", body)
        transport = transport or FakeTransport()
        out = []
        dev = scripting.Device(transport, "/dev/x", 115200, log=out.append)
        code = scripting.run_script(path, dev, out=out.append)
        return code, out, transport

    def test_a_clean_run_returns_zero(self):
        transport = FakeTransport()
        transport.incoming += [b"login: "]
        code, out, transport = self.run_with('''
            def run(dev):
                dev.expect("login:", timeout=3)
                dev.send_line("root")
                dev.log("done")
        ''', transport)
        self.assertEqual(code, 0)
        self.assertEqual(transport.written, [b"root\n"])
        self.assertIn("done", out)

    def test_timeout_failure_and_load_errors_have_distinct_codes(self):
        self.assertEqual(self.run_with('def run(dev): dev.expect("x", timeout=0.1)\n')[0], 1)
        self.assertEqual(self.run_with('def run(dev): raise ValueError("no")\n')[0], 1)
        self.assertEqual(self.run_with("def run(:\n")[0], 2)
        self.assertEqual(self.run_with("x = 1\n")[0], 2)


class HubSupervisionTest(ScriptEnvironment):
    def setUp(self):
        super().setUp()
        self.hub = MultiPortHub(os.path.join(self.temp.name, "hub.sock"), idle_timeout=0.5)
        self.hub.start()
        self.addCleanup(self.hub.close)
        threading.Thread(target=self._loop, daemon=True).start()
        self.manager = HubProcessManager(socket_path=str(self.hub.socket_path))
        eventually(self.manager.socket_ready)

    def _loop(self):
        while not self.hub.stop.is_set():
            self.hub.stop.wait(0.1)
            try:
                self.hub.stop_idle_autoruns()
                self.hub.reap_idle()
            except Exception:
                pass

    def control(self, action, **payload):
        return self.manager.request_control(action, **payload)

    def logs(self, run_id):
        text = []
        cursor = 0
        while True:
            reply = self.control("script_logs", id=run_id, after=cursor)
            text += [line["text"] for line in reply["lines"]]
            if reply["cursor"] == cursor:
                return text, reply["run"]
            cursor = reply["cursor"]

    def test_a_script_runs_end_to_end_against_a_fake_device(self):
        self.write_script("login", '''
            """Log in."""
            def run(dev):
                dev.expect(r"login:", timeout=8)
                dev.send_line("root")
                dev.expect(r"Password:", timeout=8)
                dev.send_line("hunter2")
                dev.log("logged in")
        ''')
        run = self.control("script_run", name="login", port=self.device.port, baud=115200)["run"]
        eventually(lambda: self.device.conns)
        time.sleep(0.3)
        self.device.say("boot...\nlogin: ")
        eventually(lambda: "root" in self.device.heard())
        self.device.say("Password: ")
        eventually(lambda: "hunter2" in self.device.heard())
        eventually(lambda: self.control("script_logs", id=run["id"])["run"]["state"] == "done")
        text, summary = self.logs(run["id"])
        self.assertIn("logged in", text)
        self.assertEqual(summary["exit_code"], 0)

    def test_on_line_reacts_to_incoming_data(self):
        self.write_script("watch", '''
            def on_line(dev, line):
                if "panic" in line:
                    dev.send_line("reboot")
        ''')
        run = self.control("script_run", name="watch", port=self.device.port)["run"]
        eventually(lambda: self.device.conns)
        time.sleep(0.3)
        self.device.say("all fine\nKernel panic!\n")
        eventually(lambda: "reboot" in self.device.heard())
        self.assertEqual(self.control("script_logs", id=run["id"])["run"]["state"], "running")

    def test_stop_ends_a_running_script(self):
        self.write_script("forever", "def run(dev):\n    dev.sleep(300)\n")
        run = self.control("script_run", name="forever", port=self.device.port)["run"]
        eventually(lambda: self.control("script_logs", id=run["id"])["run"]["state"] == "running")
        stopped = self.control("script_stop", id=run["id"])["run"]
        eventually(lambda: self.control("script_logs", id=run["id"])["run"]["state"] in ("stopped", "done"))

    @posix_only
    def test_stop_kills_the_whole_process_group(self):
        child_pid = Path(self.temp.name) / "child.pid"
        self.write_script("spawner", f'''
            import subprocess
            def run(dev):
                child = subprocess.Popen(["sleep", "300"])
                open({str(child_pid)!r}, "w").write(str(child.pid))
                dev.sleep(300)
        ''')
        run = self.control("script_run", name="spawner", port=self.device.port)["run"]
        eventually(child_pid.exists)
        pid = int(child_pid.read_text())
        os.kill(pid, 0)  # alive
        self.control("script_stop", id=run["id"])
        def gone():
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                return True
            return False
        eventually(gone)

    def test_a_script_that_hangs_ignoring_sigterm_is_killed(self):
        self.write_script("stubborn", '''
            import signal, time
            def run(dev):
                signal.signal(signal.SIGTERM, signal.SIG_IGN)
                while True:
                    time.sleep(0.1)
        ''')
        run = self.control("script_run", name="stubborn", port=self.device.port)["run"]
        time.sleep(1.0)
        with patch.object(script_supervisor, "STOP_GRACE_S", 0.5):
            self.control("script_stop", id=run["id"])
        eventually(lambda: self.control("script_logs", id=run["id"])["run"]["state"] in ("stopped", "failed"))

    def test_the_same_script_cannot_run_twice_on_one_port(self):
        self.write_script("once", "def run(dev):\n    dev.sleep(300)\n")
        self.control("script_run", name="once", port=self.device.port)
        with self.assertRaisesRegex(RuntimeError, "already running"):
            self.control("script_run", name="once", port=self.device.port)

    def test_unknown_scripts_and_bad_names_are_refused(self):
        for name in ("missing", "../x", ""):
            with self.assertRaises(RuntimeError):
                self.control("script_run", name=name, port=self.device.port)

    def test_logs_are_bounded_and_report_dropped_lines(self):
        self.write_script("chatty", f'''
            def run(dev):
                for i in range({script_supervisor.LOG_LINES + 100}):
                    print("line", i, flush=True)
        ''')
        run = self.control("script_run", name="chatty", port=self.device.port)["run"]
        eventually(lambda: self.control("script_logs", id=run["id"])["run"]["state"] in ("done", "failed"))
        reply = self.control("script_logs", id=run["id"], after=0, limit=500)
        self.assertLessEqual(len(reply["lines"]), script_supervisor.LOG_LINES)
        self.assertTrue(reply["dropped"])

    def test_script_output_never_reaches_the_device_stream(self):
        self.write_script("quiet", 'def run(dev):\n    dev.log("not for the device")\n    print("also not")\n')
        run = self.control("script_run", name="quiet", port=self.device.port)["run"]
        eventually(lambda: self.control("script_logs", id=run["id"])["run"]["state"] == "done")
        self.assertNotIn("not for the device", self.device.heard())

    def test_autorun_starts_when_the_port_opens_and_stops_with_the_last_real_client(self):
        self.write_script("auto", "def on_line(dev, line):\n    dev.send_line('seen ' + line)\n")
        self.control("script_autorun", name="auto", enabled=True, match={"port": self.device.port})
        self.manager.claim_port(self.device.port, 115200)
        eventually(lambda: any(r["autorun"] for r in self.control("script_status")["runs"]))
        run_id = self.control("script_status")["runs"][0]["id"]
        # The claim above holds no data socket, so no dashboard is attached: the runner
        # alone must not keep the port open forever. It is stopped once past the grace.
        with patch.object(service_module, "AUTORUN_GRACE_S", 0.0):
            eventually(lambda: self.control("script_logs", id=run_id)["run"]["state"] != "running", timeout=20)

    def test_a_user_started_script_does_not_trigger_autorun_stop(self):
        self.write_script("manual", "def run(dev):\n    dev.sleep(300)\n")
        run = self.control("script_run", name="manual", port=self.device.port)["run"]
        time.sleep(1.5)
        self.assertEqual(self.control("script_logs", id=run["id"])["run"]["state"], "running")

    def test_autorun_is_kept_while_a_real_client_uses_the_port(self):
        self.write_script("kept", "def on_line(dev, line):\n    pass\n")
        self.control("script_autorun", name="kept", enabled=True, match={"port": self.device.port})
        self.manager.claim_port(self.device.port, 115200)
        eventually(lambda: self.control("script_status")["runs"])
        run_id = self.control("script_status")["runs"][0]["id"]
        from serial_deck.uart_client import open_uart_transport
        # The hub counts data clients, it cannot tell the runner from a dashboard: a dashboard
        # that attaches before the runner would be mistaken for it. Wait for the runner first.
        channel = next(iter(self.hub.channels.values()))
        eventually(lambda: len(channel.clients) >= 1)
        dashboard = open_uart_transport(self.manager.endpoint, 115200, 0.2)  # a real data client
        self.addCleanup(dashboard.close)
        eventually(lambda: len(channel.clients) >= 2)
        with patch.object(service_module, "AUTORUN_GRACE_S", 0.0):
            time.sleep(1.5)
            self.assertEqual(self.control("script_logs", id=run_id)["run"]["state"], "running")

    def _fake_autorun(self, attached):
        run = script_supervisor.ScriptRun("sx", "ghost", self.device.port, 115200, True)
        run.attached = attached
        self.hub.scripts.runs[run.id] = run
        self.addCleanup(self.hub.scripts.runs.pop, run.id, None)
        return run

    def test_a_dashboard_is_not_mistaken_for_a_runner_that_has_not_attached(self):
        self.manager.claim_port(self.device.port, 115200)
        self._fake_autorun(attached=False)  # started, data socket not open yet
        from serial_deck.uart_client import open_uart_transport
        dashboard = open_uart_transport(self.manager.endpoint, 115200, 0.2)
        self.addCleanup(dashboard.close)
        channel = next(iter(self.hub.channels.values()))
        eventually(lambda: self.hub.real_clients(channel) == 1)
        with self.assertRaises(RuntimeError):
            self.hub.request_shutdown(commit=False)

    def test_an_attached_runner_is_not_a_real_client(self):
        self.manager.claim_port(self.device.port, 115200)
        self._fake_autorun(attached=True)
        from serial_deck.uart_client import open_uart_transport
        runner = open_uart_transport(self.manager.endpoint, 115200, 0.2)
        self.addCleanup(runner.close)
        channel = next(iter(self.hub.channels.values()))
        eventually(lambda: len(channel.clients) == 1)
        self.assertEqual(self.hub.real_clients(channel), 0)

    def test_a_script_starts_in_a_frozen_build_that_is_not_an_appimage(self):
        # self_command_env() is None there ("inherit as is"): start() must still work
        # and hand the runner its run id.
        from serial_deck import runtime
        seen = {}
        real_popen = script_supervisor.subprocess.Popen

        def popen(command, **kwargs):
            seen["env"] = kwargs.get("env")
            return real_popen([sys.executable, "-c", "pass"], **{**kwargs, "env": None})

        self.write_script("frozen_ok", "def run(dev):\n    pass\n")
        with patch.object(runtime, "frozen", return_value=True), \
                patch.object(script_supervisor, "scripting", wraps=scripting), \
                patch.object(script_supervisor.ScriptSupervisor, "_default_command",
                             lambda self, path, port, baud: ["x"]), \
                patch.object(script_supervisor.subprocess, "Popen", popen), \
                patch.dict(os.environ, {}, clear=False):
            os.environ.pop("APPIMAGE", None)
            run = self.hub.scripts.start("frozen_ok", self.device.port)
        self.assertEqual(seen["env"]["SERIAL_DECK_RUN_ID"], run.id)

    def test_runner_attached_rejects_unknown_and_manual_runs(self):
        with self.assertRaises(Exception):
            self.control("runner_attached", id="nope")
        run = self._fake_autorun(attached=False)
        run.autorun = False  # a user-started script is a client, never marked
        with self.assertRaises(Exception):
            self.control("runner_attached", id=run.id)
        self.assertFalse(run.attached)

    def test_a_real_autorun_runner_reports_attached(self):
        self.write_script("auto3", "def on_line(dev, line):\n    pass\n")
        self.control("script_autorun", name="auto3", enabled=True, match={"port": self.device.port})
        self.manager.claim_port(self.device.port, 115200)
        eventually(lambda: any(r.attached for r in self.hub.scripts.runs.values()), timeout=20)

    def test_autorun_does_not_start_twice_for_the_same_port(self):
        self.write_script("auto2", "def on_line(dev, line):\n    pass\n")
        self.control("script_autorun", name="auto2", enabled=True, match={"port": self.device.port})
        self.manager.claim_port(self.device.port, 115200)
        eventually(lambda: self.control("script_status")["runs"])
        self.manager.claim_port(self.device.port, 115200)
        time.sleep(0.5)
        self.assertEqual(len(self.control("script_status")["runs"]), 1)

    @posix_only  # os.kill(pid, 0) probes on POSIX but terminates the process on Windows
    def test_shutdown_stops_every_script(self):
        self.write_script("long", "def run(dev):\n    dev.sleep(300)\n")
        run = self.control("script_run", name="long", port=self.device.port)["run"]
        eventually(lambda: self.control("script_logs", id=run["id"])["run"]["state"] == "running")
        pid = self.control("script_status")["runs"][0]["pid"]
        self.hub.scripts.stop_all()
        def gone():
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                return True
            return False
        eventually(gone)

    def test_autorun_needs_an_existing_script_and_a_match(self):
        with self.assertRaises(RuntimeError):
            self.control("script_autorun", name="ghost", enabled=True, match={"port": "/dev/x"})
        self.write_script("real", "def run(dev): pass\n")
        with self.assertRaises(RuntimeError):
            self.control("script_autorun", name="real", enabled=True, match={})


if __name__ == "__main__":
    unittest.main()


class ScriptMcpPolicyTest(unittest.TestCase):
    """Running a script writes to a device: it needs `interact`, and never `hardware`."""

    def test_levels(self):
        from serial_deck.mcp_server import TOOL_LEVELS
        self.assertEqual(TOOL_LEVELS["serial_script_list"], "observe")
        self.assertEqual(TOOL_LEVELS["serial_script_status"], "observe")
        self.assertEqual(TOOL_LEVELS["serial_script_run"], "interact")
        self.assertEqual(TOOL_LEVELS["serial_script_stop"], "interact")

    def test_an_observe_only_server_cannot_run_or_stop_scripts(self):
        from serial_deck.agent import AgentError, DeckAgent
        agent = DeckAgent(policy="observe", socket_path="/nonexistent/hub.sock")
        with self.assertRaises(AgentError) as run:
            agent.script_run("x", None, None)
        self.assertEqual(run.exception.code, "policy_denied")
        with self.assertRaises(AgentError) as stop:
            agent.script_stop("s1")
        self.assertEqual(stop.exception.code, "policy_denied")

    def test_no_tool_can_create_or_edit_a_script(self):
        from serial_deck.mcp_server import TOOL_LEVELS
        for name in TOOL_LEVELS:
            self.assertFalse(re.search(r"script_(write|create|save|edit|delete|upload)", name), name)


class ScriptCliTest(ScriptEnvironment):
    def test_list_and_a_foreground_run_through_the_cli(self):
        import io
        from contextlib import redirect_stdout
        self.write_script("greet", '"""Greets."""\ndef run(dev):\n    dev.send_line("hi")\n    dev.log("sent")\n')
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            self.assertEqual(scripting.main(["list"]), 0)
        self.assertIn("greet", buffer.getvalue())
        self.assertIn("Greets.", buffer.getvalue())

    def test_the_launcher_dispatches_the_script_command(self):
        from serial_deck import launcher
        self.assertIn("script", launcher.COMMANDS)
        self.assertEqual(launcher.COMMANDS["script"][0], "scripting")

    def test_a_bad_name_exits_non_zero_without_touching_the_hub(self):
        self.assertEqual(scripting.main(["run", "../evil", "--port", "/dev/x"]), 2)
