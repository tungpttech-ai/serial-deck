"""Discovery uses private fake control sockets; no physical UART access."""

import json
import os
import socket
import tempfile
import threading
import time
import unittest
try:
    import pty
    import tty
except ImportError:  # Windows: no pseudo-terminals
    pty = tty = None
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from serial_deck import hub_client as hub
from serial_deck import ipc
from serial_deck import web as web


class HubDiscoveryTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="sd-discovery-")
        self.addCleanup(self.temp.cleanup)
        self.requests = []
        self.status = {"ok": True, "event": "status", "state": "ready",
                       "port": "/dev/ttyFAKE3", "baud": 1500000,
                       "client_count": 1, "flash": {"active": False}}

    def serve(self, name, status):
        path = str(Path(self.temp.name) / name)
        data = ipc.listen(path)
        control = ipc.listen(path + ".ctl")
        control.settimeout(0.1)
        stop = threading.Event()

        def respond():
            while not stop.is_set():
                try:
                    client, _ = control.accept()
                except socket.timeout:
                    continue
                with client:
                    self.requests.append(json.loads(ipc.read_line(client, timeout=1)))
                    client.sendall(json.dumps(status).encode() + b"\n")

        thread = threading.Thread(target=respond, daemon=True)
        thread.start()

        def cleanup():
            stop.set()
            thread.join(2)
            control.close()
            data.close()

        self.addCleanup(cleanup)
        return path

    def test_registry_discovers_custom_path_and_prunes_stale_entries(self):
        with patch.dict(os.environ, {"SERIAL_DECK_RUNTIME_DIR": str(Path(self.temp.name) / "rt")}):
            path = self.serve("custom-board-console", self.status)
            ipc.register(path)
            stale = str(Path(self.temp.name) / "gone.sock")
            ipc.register(stale)
            self.assertIn(path, hub.hub_socket_paths())
            self.assertNotIn(stale, hub.hub_socket_paths())
            self.assertEqual(len(list((Path(self.temp.name) / "rt" / "registry").iterdir())), 1)

    def test_matching_hub_keeps_baud_and_is_not_owned(self):
        path = self.serve("custom-console", self.status)
        with patch.object(hub, "hub_socket_paths", return_value=[path]):
            manager = hub.find_existing_hub("/dev/ttyFAKE3")
        self.assertEqual(manager.socket_path, path)
        self.assertEqual(manager.baud, 1500000)
        self.assertFalse(manager.owns_process)
        self.assertFalse(manager.owns_port)
        self.assertEqual(self.requests, [{"action": "status"}])

    def test_dead_socket_and_unrelated_protocol_are_ignored(self):
        dead = str(Path(self.temp.name) / "missing")
        wrong = self.serve("wrong", {"ok": True, "port": "/dev/ttyFAKE3", "baud": 1500000})
        live = self.serve("right", self.status)
        with patch.object(hub, "hub_socket_paths", return_value=[dead, wrong, live]):
            self.assertEqual(hub.find_existing_hub("/dev/ttyFAKE3").socket_path, live)

    def test_complete_status_with_unknown_protocol_is_never_reused(self):
        other = self.serve("other-tool", {**self.status, "protocol": "someone-else-v9"})
        with patch.object(hub, "hub_socket_paths", return_value=[other]):
            self.assertIsNone(hub.find_existing_hub("/dev/ttyFAKE3"))
            self.assertIsNone(hub.find_existing_hub())

    def test_other_device_is_never_selected_for_requested_port(self):
        path = self.serve("other", self.status)
        with patch.object(hub, "hub_socket_paths", return_value=[path]):
            self.assertIsNone(hub.find_existing_hub("/dev/ttyFAKE0"))

    def test_startup_prefers_claimed_hub_and_can_reuse_idle(self):
        idle = self.serve("idle", {**self.status, "port": None, "state": "idle"})
        live = self.serve("live", self.status)
        with patch.object(hub, "hub_socket_paths", return_value=[idle, live]):
            self.assertEqual(hub.find_existing_hub().socket_path, live)
            self.assertEqual(hub.find_existing_hub(exclude=(live,)).socket_path, idle)
            self.assertEqual(hub.find_existing_hub("/dev/ttyFAKE0", allow_idle=True).socket_path, idle)

    def test_discovery_skips_channel_socket_and_prefers_multiport_root(self):
        legacy = self.serve("legacy", self.status)
        root = self.serve("root", {**self.status, "protocol": hub.MULTIPORT_PROTOCOL,
                                   "port": None, "channels": []})
        channel = self.serve("channel", {**self.status, "protocol": hub.MULTIPORT_PROTOCOL,
                                         "channel_socket": "channel", "service_socket": root})
        with patch.object(hub, "hub_socket_paths", return_value=[channel, legacy, root]):
            manager = hub.find_existing_hub()
        self.assertEqual(manager.socket_path, root)
        self.assertTrue(manager.multiport)


@unittest.skipIf(pty is None, "needs POSIX pseudo-terminals")
class SharedHubIntegrationTest(unittest.TestCase):
    def test_simultaneous_app_start_creates_only_one_idle_hub(self):
        with tempfile.TemporaryDirectory(prefix="sd-concurrent-") as tmp:
            script = str(Path(__file__).resolve().parents[1] / "serial_deck" / "hub.py")
            barrier = threading.Barrier(2)
            backends = []

            def start(i):
                barrier.wait(timeout=3)
                return web.WebBackend(
                    "127.0.0.1", 0, socket_path=str(Path(tmp) / f"app-{i}"),
                    hub_manager_factory=lambda port, baud, path: hub.HubProcessManager(
                        port, baud, path, hub_script=script))

            try:
                with patch.object(hub, "hub_socket_paths", side_effect=lambda: [
                        str(p)[:-4] for p in Path(tmp).glob("*.ctl")]), \
                        patch.object(hub.subprocess, "Popen", wraps=hub.subprocess.Popen) as spawn, \
                        ThreadPoolExecutor(max_workers=2) as pool:
                    futures = [pool.submit(start, i) for i in range(2)]
                    for future in futures:
                        backends.append(future.result(timeout=10))
                    self.assertEqual(spawn.call_count, 1)
                    self.assertEqual(backends[0].hub_manager.socket_path, backends[1].hub_manager.socket_path)
            finally:
                # Detach the subscriber before stopping the process owner.
                for backend in sorted(backends, key=lambda b: b.hub_manager.owns_process):
                    backend.close()
                for backend in backends:
                    if backend.hub_manager.owns_process:
                        backend.hub_manager.shutdown()

    def test_two_backends_reuse_custom_hub_and_preserve_other_clients(self):
        with tempfile.TemporaryDirectory(prefix="sd-shared-") as tmp:
            master, slave = pty.openpty()
            tty.setraw(master)
            tty.setraw(slave)
            port = os.ttyname(slave)
            root = Path(__file__).resolve().parents[1]
            wrapper = Path(tmp) / "hub_wrapper.py"
            wrapper.write_text(
                f"import sys\nsys.path.insert(0, {str(root)!r})\n"
                f"from serial_deck import hub as h\nh.discover_serial_ports=lambda: [{port!r}]\n"
                "raise SystemExit(h.main())\n", encoding="utf-8")
            owner = hub.HubProcessManager(socket_path=str(Path(tmp) / "custom-console"),
                                          hub_script=str(wrapper))
            backends = []
            try:
                with patch.object(hub, "hub_socket_paths", return_value=[]):
                    owner.ensure_started()
                owner.claim_port(port, 57600)
                with patch.object(hub, "hub_socket_paths", return_value=[owner.socket_path]), \
                        patch.object(hub.subprocess, "Popen", side_effect=AssertionError("must reuse existing hub")):
                    for i in range(2):
                        backend = web.WebBackend("127.0.0.1", 0, socket_path=str(Path(tmp) / f"unused-{i}"))
                        backends.append(backend)
                        self.assertEqual(backend.hub_manager.socket_path, owner.socket_path)
                        status = backend.connections.get("default").connect(port, 19200, "linux")
                        self.assertEqual(status["baud"], 57600)
                deadline = time.monotonic() + 3
                while owner.get_status()["client_count"] != 2 and time.monotonic() < deadline:
                    time.sleep(0.02)
                self.assertEqual(owner.get_status()["client_count"], 2)
                os.write(master, b"SHARED_DEVICE_DATA\n")
                for backend in backends:
                    bridge = backend.connections.get("default")
                    deadline = time.monotonic() + 3
                    while b"SHARED_DEVICE_DATA" not in bridge.raw_history and time.monotonic() < deadline:
                        time.sleep(0.02)
                    self.assertIn(b"SHARED_DEVICE_DATA", bridge.raw_history)
                backends[0].close()
                owner.stop()  # Even the original owner must preserve remaining clients.
                self.assertIsNone(owner.process.poll())
                self.assertTrue(owner.socket_ready())
                backends[1].close()
                deadline = time.monotonic() + 3
                while owner.get_status()["client_count"] and time.monotonic() < deadline:
                    time.sleep(0.02)
                owner.stop()
                self.assertTrue(owner.socket_ready())
                owner.shutdown()
                self.assertFalse(owner.socket_ready())
            finally:
                for backend in backends:
                    backend.close()
                if owner.socket_ready():
                    owner.shutdown()
                os.close(master)
                os.close(slave)


if __name__ == "__main__":
    unittest.main()
