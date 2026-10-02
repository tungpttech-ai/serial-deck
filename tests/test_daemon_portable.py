"""The real daemon end to end on every OS: a fake device behind a tcp:// UART bridge.

Unlike the PTY suites this runs natively on Windows, so CI exercises the
loopback-TCP hub transport, msvcrt locking and process spawning there.
"""

import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

from serial_deck.hub_client import HubProcessManager
from serial_deck.uart_client import open_uart_transport

ROOT = Path(__file__).resolve().parents[1]
HUB = str(ROOT / "serial_deck" / "hub.py")


def eventually(check, timeout=5.0):
    deadline = time.monotonic() + timeout
    while not check():
        if time.monotonic() > deadline:
            raise AssertionError("condition did not become true")
        time.sleep(0.02)


class FakeBridge:
    """A ser2net-like TCP endpoint: the hub connects, the test plays the device."""

    def __init__(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind(("127.0.0.1", 0))
        self.server.listen(1)
        self.port = f"tcp://127.0.0.1:{self.server.getsockname()[1]}"
        self.device = None
        self.accepted = threading.Event()
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        try:
            self.device, _ = self.server.accept()
        except OSError:
            return
        self.device.settimeout(3)
        self.accepted.set()

    def close(self):
        if self.device is not None:
            self.device.close()
        self.server.close()


class PortableDaemonTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="sd-e2e-")
        self.addCleanup(self.temp.cleanup)
        runtime = Path(self.temp.name) / "rt"
        self.env = {**os.environ, "SERIAL_DECK_RUNTIME_DIR": str(runtime)}
        self.path = str(runtime / "hub.sock")
        self.bridge = FakeBridge()
        self.addCleanup(self.bridge.close)
        self.manager = HubProcessManager(socket_path=self.path, hub_script=HUB)
        self.addCleanup(self._stop_daemon)
        self.process = None

    def _stop_daemon(self):
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            self.process.wait(timeout=10)

    def start_daemon(self):
        self.process = subprocess.Popen(
            [sys.executable, HUB, "--socket", self.path, "--port-idle-timeout", "0.5"],
            cwd=str(ROOT), env=self.env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        eventually(self.manager.socket_ready, timeout=15)

    def test_claim_stream_write_subscribe_and_shutdown(self):
        self.start_daemon()
        self.manager.claim_port(self.bridge.port, 115200)
        self.assertTrue(self.bridge.accepted.wait(5))
        events = []
        self.manager.subscribe(events.append)
        self.addCleanup(self.manager.unsubscribe)
        data = open_uart_transport(self.manager.endpoint, 115200, 0.2)
        try:
            eventually(lambda: self.manager.get_status()["client_count"] == 1)
            self.bridge.device.sendall(b"boot ok\r\n")
            received = b""
            deadline = time.monotonic() + 5
            while b"boot ok" not in received and time.monotonic() < deadline:
                received += data.read()
            self.assertIn(b"boot ok", received)
            data.write(b"help\n")
            self.assertEqual(self.bridge.device.recv(64), b"help\n")
            eventually(lambda: any(e.get("port") == self.bridge.port for e in events))
            with self.assertRaisesRegex(RuntimeError, "clients or flash"):
                self.manager.shutdown()  # refused while a data client is attached
        finally:
            data.close()
        eventually(lambda: self.manager.get_status()["client_count"] == 0)
        self.manager.unsubscribe()
        self.manager.request_control("shutdown")
        self.process.wait(timeout=10)
        self.assertFalse(self.manager.socket_ready())

    def test_second_daemon_on_the_same_path_is_refused(self):
        self.start_daemon()
        second = subprocess.run(
            [sys.executable, HUB, "--socket", self.path], cwd=str(ROOT), env=self.env,
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30)
        self.assertNotEqual(second.returncode, 0)
        self.assertTrue(self.manager.socket_ready())  # the first one is untouched

    def test_manager_starts_a_detached_daemon_and_finds_it_again(self):
        started = self.manager.ensure_started(timeout=15)
        self.process = self.manager.process
        self.assertTrue(started)
        again = HubProcessManager(socket_path=self.path, hub_script=HUB)
        self.assertFalse(again.ensure_started(timeout=15))  # attached, not spawned
        self.assertTrue(self.manager.socket_ready())


if __name__ == "__main__":
    unittest.main()
