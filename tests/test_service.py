"""Multi-port daemon acceptance with real PTYs and hub sockets, no hardware."""

import base64
import os
import select
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
from pathlib import Path
from unittest.mock import patch

from serial_deck import hub as uart
from serial_deck.hub_client import BaudConflictError, HubProcessManager, HubRegistry
from serial_deck.service import MultiPortHub
from serial_deck.uart_client import (
    FRAME_COMMAND, FrameDispatchUnknown, HubRefused, decode_frame, encode_json_frame,
    open_uart_transport)


def eventually(check, timeout=3):
    deadline = time.monotonic() + timeout
    while not check():
        if time.monotonic() > deadline:
            raise AssertionError("condition did not become true")
        time.sleep(0.02)


@unittest.skipIf(pty is None, "needs POSIX pseudo-terminals")
class MultiPortServiceTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="pk-multi-")
        self.pairs = [pty.openpty(), pty.openpty()]
        for master, slave in self.pairs:
            tty.setraw(master)
            tty.setraw(slave)
        self.ports = [os.ttyname(slave) for _, slave in self.pairs]
        self.scan = patch.object(uart, "discover_serial_ports", return_value=self.ports)
        self.scan.start()
        self.path = str(Path(self.temp.name) / "hub.sock")
        self.service = MultiPortHub(self.path, idle_timeout=0.3)
        self.service.start()
        self.root = HubProcessManager(socket_path=self.path)
        self.transports = []
        self.managers = []

    def tearDown(self):
        for transport in self.transports:
            transport.close()
        for manager in self.managers:
            manager.unsubscribe()
        self.service.close()
        self.scan.stop()
        for master, slave in self.pairs:
            os.close(master)
            os.close(slave)
        self.temp.cleanup()

    def attach(self, index, baud=115200):
        manager = HubProcessManager(socket_path=self.path)
        manager.claim_port(self.ports[index], baud)
        self.managers.append(manager)
        transport = open_uart_transport(manager.endpoint, manager.baud, 0.1)
        self.transports.append(transport)
        return manager, transport

    def test_two_ports_one_pid_and_no_rx_tx_crosstalk(self):
        first, a = self.attach(0, 115200)
        second, b = self.attach(1, 230400)
        _, shared = self.attach(0, 19200)
        eventually(lambda: self.root.get_status()["client_count"] == 3)
        status = self.root.get_status()
        self.assertEqual(len(status["channels"]), 2)
        self.assertEqual({c["pid"] for c in status["channels"]}, {status["pid"]})
        self.assertEqual({c["baud"] for c in status["channels"]}, {115200, 230400})
        os.write(self.pairs[0][0], b"FROM_A\n")
        self.assertEqual(a.read(), b"FROM_A\n")
        self.assertEqual(shared.read(), b"FROM_A\n")
        self.assertEqual(b.read(), b"")
        b.write(b"TO_B\n")
        self.assertTrue(select.select([self.pairs[1][0]], [], [], 2)[0])
        self.assertEqual(os.read(self.pairs[1][0], 1024), b"TO_B\n")
        self.assertEqual(select.select([self.pairs[0][0]], [], [], 0.1)[0], [])
        self.assertNotEqual(first.endpoint, second.endpoint)
        self.assertEqual(first.socket_path, second.socket_path)

    def read_master(self, index, size, timeout=2):
        data, deadline = b"", time.monotonic() + timeout
        while len(data) < size and time.monotonic() < deadline:
            if select.select([self.pairs[index][0]], [], [], 0.1)[0]:
                data += os.read(self.pairs[index][0], 65536)
        return data

    def test_write_frame_writes_whole_frames_from_racing_clients(self):
        manager, a = self.attach(0)
        _, b = self.attach(0)
        self.assertIn("write_frame", manager.get_status()["features"])
        frames = [encode_json_frame(FRAME_COMMAND, n, {"pad": "x" * 900, "n": n}) for n in range(40)]
        barrier = threading.Barrier(2)

        def send(transport, items):
            barrier.wait()
            for frame in items:
                transport.write_frame(frame)

        threads = [threading.Thread(target=send, args=(a, frames[0::2])),
                   threading.Thread(target=send, args=(b, frames[1::2]))]
        for thread in threads:
            thread.start()
        data = self.read_master(0, sum(map(len, frames)), timeout=5)
        for thread in threads:
            thread.join()
        decoded = sorted(decode_frame(part + b"\0")[2] for part in data.split(b"\0") if part)
        self.assertEqual(decoded, list(range(40)))

    def test_write_frame_validation_and_raw_path_unchanged(self):
        manager, transport = self.attach(0)
        for bad in (b"", b"no-terminator", b"a\0b\0", b"x" * 3000 + b"\0"):
            with self.assertRaisesRegex(RuntimeError, "write_frame"):
                manager.request_control("write_frame", data=base64.b64encode(bad).decode())
        with self.assertRaisesRegex(RuntimeError, "base64"):
            manager.request_control("write_frame", data="@@@")
        raw = bytes(range(256)) * 4
        transport.write(raw)
        self.assertEqual(self.read_master(0, len(raw)), raw)

    def test_write_frame_falls_back_on_legacy_hub(self):
        _, transport = self.attach(0)
        calls = []
        def legacy_control(request):
            calls.append(request["action"])
            raise HubRefused("unknown control action: write_frame")

        transport._control = legacy_control
        frame = encode_json_frame(FRAME_COMMAND, 1, {"n": 1})
        transport.write_frame(frame)
        transport.write_frame(frame)
        self.assertEqual(calls, ["write_frame"])
        self.assertEqual(self.read_master(0, 2 * len(frame)), frame * 2)

    def test_write_frame_uart_failure_reports_unknown_dispatch(self):
        manager, transport = self.attach(0)
        channel = next(iter(self.service.channels.values()))

        class Broken:
            def write(self, frame):
                raise OSError("EIO after partial write")

            def read(self, size=4096):
                time.sleep(0.05)
                return b""

            def close(self):
                pass

        real = channel.serial
        channel.serial = Broken()
        try:
            with self.assertRaises(FrameDispatchUnknown):
                transport.write_frame(encode_json_frame(FRAME_COMMAND, 1, {"n": 1}))
        finally:
            channel.serial = real

    def test_write_frame_without_verdict_never_falls_back(self):
        _, transport = self.attach(0)

        def lost_reply(_request):
            raise TimeoutError("timed out")

        transport._control = lost_reply
        with self.assertRaises(FrameDispatchUnknown):
            transport.write_frame(encode_json_frame(FRAME_COMMAND, 1, {"n": 1}))
        self.assertEqual(self.read_master(0, 1, timeout=0.3), b"")  # not re-sent on the data socket

    def test_alias_reuses_live_channel_and_baud(self):
        first, _ = self.attach(0, 57600)
        alias = Path(self.temp.name) / "by-id"
        alias.symlink_to(self.ports[0])
        second = HubProcessManager(socket_path=self.path)
        second.claim_port(str(alias), 19200)
        self.assertEqual(second.endpoint, first.endpoint)
        self.assertEqual(second.baud, 57600)
        self.assertEqual(len(self.service.channels), 1)

    def test_reconnect_after_disconnect_applies_new_baud(self):
        first, a = self.attach(0, 115200)
        eventually(lambda: self.root.get_status()["client_count"] == 1)
        a.close()
        self.transports.remove(a)
        eventually(lambda: self.root.get_status()["client_count"] == 0)
        second = HubProcessManager(socket_path=self.path)
        second.claim_port(self.ports[0], 38400, "error")  # before the idle reap closes the channel
        self.managers.append(second)
        b = open_uart_transport(second.endpoint, second.baud, 0.1)
        self.transports.append(b)
        self.assertEqual(second.baud, 38400)
        self.assertEqual(second.endpoint, first.endpoint)
        self.assertEqual(self.service.channels[os.path.realpath(self.ports[0])].baud, 38400)
        eventually(lambda: self.root.get_status()["client_count"] == 1)  # attach is async over TCP
        os.write(self.pairs[0][0], b"AFTER\n")
        self.assertEqual(b.read(), b"AFTER\n")

    def test_baud_conflict_join_error_and_retime_in_place(self):
        first, a = self.attach(0, 115200)
        eventually(lambda: self.root.get_status()["client_count"] == 1)
        serial = self.service.channels[os.path.realpath(self.ports[0])].serial
        events = []
        first.subscribe(events.append)

        joiner = HubProcessManager(socket_path=self.path)
        joiner.claim_port(self.ports[0], 38400)  # default keeps the live baud
        self.assertEqual(joiner.baud, 115200)

        asker = HubProcessManager(socket_path=self.path)
        with self.assertRaises(BaudConflictError) as caught:
            asker.claim_port(self.ports[0], 38400, "error")
        self.assertEqual((caught.exception.live_baud, caught.exception.requested_baud,
                          caught.exception.client_count), (115200, 38400, 1))

        asker.claim_port(self.ports[0], 38400, "retime")
        self.assertEqual(asker.baud, 38400)
        channel = self.service.channels[os.path.realpath(self.ports[0])]
        self.assertIs(channel.serial, serial)  # retimed, never reopened
        eventually(lambda: any(e.get("baud") == 38400 for e in events))
        os.write(self.pairs[0][0], b"STILL_HERE\n")
        self.assertEqual(a.read(), b"STILL_HERE\n")  # the first client kept streaming

    def test_web_bridges_ask_then_retime_shared_port(self):
        from serial_deck.web import DeckWebBridge
        registry = HubRegistry(default_manager=self.root, reuse_live_baud=True)
        first = DeckWebBridge(hub_registry=registry)
        second = DeckWebBridge(hub_registry=registry)
        try:
            first.connect(self.ports[0], 115200, "linux")
            eventually(lambda: self.root.get_status()["client_count"] == 1)
            with self.assertRaises(BaudConflictError):
                second.connect(self.ports[0], 38400, "linux", "error")
            self.assertFalse(second.connected)
            status = second.connect(self.ports[0], 38400, "linux", "retime")
            self.assertEqual(status["baud"], 38400)
            eventually(lambda: first.get_status()["baud"] == 38400)
            self.assertTrue(first.connected)
        finally:
            second.disconnect()
            first.disconnect()

    def test_registry_only_creates_channel_clients_not_processes(self):
        registry = HubRegistry(default_manager=self.root)
        with patch("subprocess.Popen", side_effect=AssertionError("unexpected process")):
            a = registry.acquire(self.ports[0], 115200)
            b = registry.acquire(self.ports[1], 230400)
            self.assertEqual(a.get_status()["pid"], b.get_status()["pid"])
            registry.release(self.ports[0], a)
            registry.release(self.ports[1], b)
        self.assertTrue(self.root.socket_ready())

    def test_idle_channel_cleanup_removes_sockets_and_retains_active_port(self):
        first, a = self.attach(0)
        _, b = self.attach(1)
        eventually(lambda: self.root.get_status()["client_count"] == 2)
        a.close()
        eventually(lambda: first.get_status()["client_count"] == 0)
        time.sleep(0.35)
        self.service.reap_idle()
        self.assertFalse(Path(first.channel_socket).exists())
        self.assertFalse(Path(first.channel_socket + ".ctl").exists())
        self.assertEqual(len(self.service.channels), 1)
        os.write(self.pairs[1][0], b"STILL_ALIVE\n")
        self.assertEqual(b.read(), b"STILL_ALIVE\n")
        self.assertTrue(self.root.socket_ready())

    def test_shutdown_refuses_active_clients_and_flash(self):
        manager, transport = self.attach(0)
        eventually(lambda: manager.get_status()["client_count"] == 1)
        with self.assertRaisesRegex(RuntimeError, "clients or flash"):
            self.root.shutdown()
        transport.close()
        eventually(lambda: manager.get_status()["client_count"] == 0)
        channel = next(iter(self.service.channels.values()))
        channel.flashing = True
        try:
            with self.assertRaisesRegex(RuntimeError, "clients or flash"):
                self.root.shutdown()
        finally:
            channel.flashing = False

    def test_flash_isolated_other_port_streams_and_channel_is_not_reaped(self):
        first, a = self.attach(0)
        second, b = self.attach(1)
        entered, finish = threading.Event(), threading.Event()

        def fake_flash(*args, **kwargs):
            entered.set()
            finish.wait(5)
            return 0

        with patch.object(uart, "build_flash_command", return_value=["esptool", "fake"]), \
                patch.object(uart, "flash_build_in_process", side_effect=fake_flash):
            first.start_flash("/fake-build", 3000000)
            try:
                self.assertTrue(entered.wait(2))
                self.assertTrue(first.get_status()["flash"]["active"])
                self.assertFalse(second.get_status()["flash"]["active"])
                self.assertTrue(self.root.get_status()["flash"]["active"])
                with self.assertRaisesRegex(RuntimeError, "another port is flashing"):
                    second.start_flash("/fake-build", 3000000)
                a.close()
                time.sleep(0.35)
                self.service.reap_idle()
                self.assertEqual(len(self.service.channels), 2)
                os.write(self.pairs[1][0], b"DURING_FLASH\n")
                self.assertEqual(b.read(), b"DURING_FLASH\n")
            finally:
                finish.set()
                eventually(lambda: not first.get_status()["flash"]["active"])
                eventually(lambda: not self.service.flash_lock.locked())
        self.assertEqual(first.get_status()["flash"]["exit_code"], 0)

    def test_accepted_shutdown_refuses_new_flash_and_claims(self):
        manager, transport = self.attach(0)
        transport.close()
        self.transports.remove(transport)
        eventually(lambda: manager.get_status()["client_count"] == 0)
        self.service.request_shutdown(commit=False)  # accepted, reply not yet sent
        with patch.object(uart, "flash_build_in_process", side_effect=AssertionError("flash started")), \
                self.assertRaisesRegex(RuntimeError, "shutting down"):
            manager.start_flash("/fake-build", 115200)
        with self.assertRaisesRegex(RuntimeError, "shutting down"):
            self.root.claim_port(self.ports[1], 115200)
        self.assertFalse(any(c.flashing for c in self.service.channels.values()))
        self.assertEqual(manager.get_status()["port"], self.ports[0])  # status still answers

    def test_duplicate_daemon_cannot_unlink_live_socket(self):
        other = MultiPortHub(self.path)
        with self.assertRaises((OSError, RuntimeError)):
            other.start()
        self.assertTrue(self.root.socket_ready())

    def test_status_subscription_is_scoped_to_selected_port(self):
        first, _ = self.attach(0)
        second, _ = self.attach(1)
        events = []
        first.subscribe(events.append)
        eventually(lambda: bool(events))
        second_status = second.get_status()
        self.assertTrue(all(e["port"] == self.ports[0] for e in events))
        self.assertEqual(second_status["port"], self.ports[1])
        first.unsubscribe()
        channel = self.service.channels[os.path.realpath(self.ports[0])]
        eventually(lambda: not channel.status_clients)

    def test_failed_claim_does_not_leave_channel_or_socket(self):
        with self.assertRaises(RuntimeError):
            self.root.claim_port("/dev/does-not-exist", 115200)
        self.assertEqual(self.service.channels, {})
        self.assertEqual(list(self.service.channel_dir.iterdir()), [])

    def test_repeated_connect_disconnect_does_not_accumulate_threads_or_sockets(self):
        baseline = threading.active_count()
        self.service.idle_timeout = 0.01
        for _ in range(8):
            manager, transport = self.attach(0)
            events = []
            manager.subscribe(events.append)
            eventually(lambda: bool(events))
            transport.close()
            manager.unsubscribe()
            eventually(lambda: manager.get_status()["client_count"] == 0)
            time.sleep(0.02)
            self.service.reap_idle()
            self.assertEqual(self.service.channels, {})
        eventually(lambda: threading.active_count() <= baseline)
        self.assertEqual(list(self.service.channel_dir.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
