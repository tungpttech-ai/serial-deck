import json
import socket
import threading
import time
import unittest
from unittest.mock import patch

from serial_deck.hub import UartHub


class FakeSerial:
    def __init__(self):
        self.dtr = False
        self.rts = False

    def set_modem_lines(self, dtr=None, rts=None):
        if dtr is not None:
            self.dtr = dtr
        if rts is not None:
            self.rts = rts

    def get_modem_lines(self):
        return self.dtr, self.rts

    def hard_reset(self):
        self.rts = True
        self.rts = False

    def enter_bootloader(self):
        self.dtr = True
        self.rts = True
        self.dtr = False
        self.rts = False

    def close(self):
        pass


class FakeFanoutClient:
    def __init__(self, sent_bytes=None, error=None):
        self.sent_bytes = sent_bytes
        self.error = error
        self.calls = []
        self.closed = False

    def send(self, data, flags=0):
        self.calls.append((data, flags))
        if self.error is not None:
            raise self.error
        return len(data) if self.sent_bytes is None else self.sent_bytes

    def shutdown(self, how):
        self.shut_down = True

    def close(self):
        self.closed = True


class HubControlTest(unittest.TestCase):
    def setUp(self):
        self.hub = UartHub.__new__(UartHub)
        self.hub.port = "/dev/ttyACM0"
        self.hub.baud = 115200
        self.hub.serial = FakeSerial()
        self.hub.serial_lock = threading.Lock()
        self.hub.serial_read_lock = threading.Lock()
        self.hub.clients = set()
        self.hub.clients_lock = threading.Lock()
        self.hub.status_clients = set()
        self.hub.status_clients_lock = threading.Lock()
        self.hub.status_lock = threading.Lock()
        self.hub.revision = 0
        self.hub.flashing = False
        self.hub.flash_id = 0
        self.hub.flash_progress = 0
        self.hub.flash_step = "Idle"
        self.hub.flash_line = ""
        self.hub.flash_build_dir = ""
        self.hub.flash_baud = 0
        self.hub.flash_exit_code = None
        self.hub.flash_error = ""
        self.hub.stop = threading.Event()

    def request(self, action, **kwargs):
        client, server = socket.socketpair()
        request = {"action": action, **kwargs}
        client.sendall(json.dumps(request).encode("utf-8") + b"\n")  # requests are newline-framed
        worker = threading.Thread(target=self.hub._handle_control, args=(server,))
        worker.start()
        response = json.loads(client.recv(1024).decode("utf-8"))
        worker.join(timeout=1)
        client.close()
        return response

    def test_lines_response_contains_resulting_state(self):
        self.assertEqual(self.request("lines", dtr=True, rts=False),
                         {"ok": True, "dtr": True, "rts": False})

    def test_reset_response_contains_released_lines(self):
        self.assertEqual(self.request("reset"),
                         {"ok": True, "dtr": False, "rts": False})

    def test_scan_response_contains_ports_and_hub_port(self):
        with patch(
                "serial_deck.hub.discover_serial_ports",
                return_value=["/dev/ttyACM0", "/dev/ttyUSB0"],
        ):
            self.assertEqual(
                self.request("scan"),
                {
                    "ok": True,
                    "ports": ["/dev/ttyACM0", "/dev/ttyUSB0"],
                    "hub_port": "/dev/ttyACM0",
                },
            )

    def test_claim_opens_requested_port_only_when_idle(self):
        self.hub.serial = None
        self.hub.port = ""
        self.hub.baud = 115200
        opened = FakeSerial()
        with patch(
                "serial_deck.hub.discover_serial_ports",
                return_value=["/dev/ttyACM1"],
        ), patch(
                "serial_deck.hub.open_device_transport",
                return_value=opened,
        ) as serial_factory:
            response = self.request("claim", port="/dev/ttyACM1", baud=230400)
        self.assertEqual(response, {
            "ok": True,
            "claimed": True,
            "port": "/dev/ttyACM1",
            "baud": 230400,
        })
        serial_factory.assert_called_once_with("/dev/ttyACM1", 230400, 0.1)
        self.assertIs(self.hub.serial, opened)

    def test_claim_accepts_network_endpoint_without_serial_scan(self):
        self.hub.serial = None
        self.hub.port = ""
        opened = FakeSerial()
        with patch(
                "serial_deck.hub.discover_serial_ports",
                return_value=[],
        ) as scan, patch(
                "serial_deck.hub.open_device_transport",
                return_value=opened,
        ) as factory:
            response = self.request("claim", port="tcp://192.168.1.50:23", baud=115200)
        self.assertTrue(response["ok"], response)
        self.assertEqual(response["port"], "tcp://192.168.1.50:23")
        scan.assert_not_called()
        factory.assert_called_once_with("tcp://192.168.1.50:23", 115200, 0.1)

        flash = self.request("flash_preview", build_dir="build", flash_baud=3000000)
        self.assertFalse(flash["ok"])
        self.assertIn("physical UART", flash["error"])

    def test_claim_rejects_different_port_when_already_claimed(self):
        response = self.request("claim", port="/dev/ttyUSB0", baud=115200)
        self.assertFalse(response["ok"])
        self.assertIn("already claimed", response["error"])

    def test_release_returns_hub_to_idle(self):
        self.hub.clients = set()
        response = self.request("release")
        self.assertEqual(response, {"ok": True, "released": True})
        self.assertIsNone(self.hub.serial)
        self.assertEqual(self.hub.port, "")

    def test_broadcast_drops_slow_client_without_blocking_healthy_client(self):
        healthy = FakeFanoutClient()
        slow = FakeFanoutClient(error=BlockingIOError())
        self.hub.clients = {healthy, slow}

        self.hub.broadcast(b"uart-data")

        self.assertEqual(healthy.calls[0][0], b"uart-data")
        self.assertIn(healthy, self.hub.clients)
        self.assertNotIn(slow, self.hub.clients)
        self.assertTrue(slow.closed)

    def test_broadcast_drops_client_after_partial_write(self):
        partial = FakeFanoutClient(sent_bytes=3)
        self.hub.clients = {partial}

        self.hub.broadcast(b"uart-data")

        self.assertNotIn(partial, self.hub.clients)
        self.assertTrue(partial.closed)

    def test_lost_serial_drops_port_and_disconnects_clients(self):
        lost_serial = self.hub.serial
        client_a = FakeFanoutClient()
        client_b = FakeFanoutClient()
        self.hub.clients = {client_a, client_b}

        self.hub._handle_serial_lost(lost_serial, OSError(19, "No such device"))

        self.assertIsNone(self.hub.serial)
        self.assertEqual(self.hub.port, "")
        self.assertEqual(self.hub.clients, set())
        self.assertTrue(client_a.closed)
        self.assertTrue(client_b.closed)

    def test_lost_serial_is_a_noop_if_hub_already_moved_to_a_different_port(self):
        stale_serial = self.hub.serial
        replacement = FakeSerial()
        self.hub.serial = replacement
        self.hub.port = "/dev/ttyACM1"

        self.hub._handle_serial_lost(stale_serial, OSError(19, "No such device"))

        self.assertIs(self.hub.serial, replacement)
        self.assertEqual(self.hub.port, "/dev/ttyACM1")

    def test_status_reports_flash_state(self):
        self.hub.flashing = True
        self.hub.flash_id = 7
        self.hub.flash_progress = 42
        self.hub.flash_step = "Writing"
        status = self.hub._status_payload()
        self.assertEqual(status["state"], "flashing")
        self.assertEqual(status["flash"]["id"], 7)
        self.assertEqual(status["flash"]["progress"], 42)

    def test_flash_output_parses_decimal_percent_and_strips_ansi(self):
        self.hub._set_flash_output("\x1b[KWriting at 0x0034ed24 ... 66.8%\x1b[K")
        self.assertEqual(self.hub.flash_progress, 66.8)
        self.assertEqual(self.hub.flash_step, "Writing")
        self.assertNotIn("\x1b", self.hub.flash_line)

    def test_flash_runs_in_hub_and_reopens_uart(self):
        opened = FakeSerial()
        with patch(
                "serial_deck.hub.build_flash_command",
                return_value=["esptool", "--port", "/dev/ttyACM0"],
        ), patch(
                "serial_deck.hub.SerialTransport",
                return_value=opened,
        ), patch(
                "serial_deck.hub.flash_build_in_process",
                side_effect=lambda port, build, baud, output: (output("Writing (42 %)") or 0),
        ):
            response = self.request("flash", build_dir="build", flash_baud=460800)
            self.assertTrue(response["accepted"])
            deadline = time.monotonic() + 1.0
            while self.hub.flash_exit_code is None and time.monotonic() < deadline:
                time.sleep(0.01)
        self.assertFalse(self.hub.flashing)
        self.assertEqual(self.hub.flash_progress, 100)
        self.assertIs(self.hub.serial, opened)


if __name__ == "__main__":
    unittest.main()
