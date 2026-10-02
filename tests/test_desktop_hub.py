import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from serial_deck.desktop_hub import (
    HubProcessManager,
    HubControlDeck,
)


class HubProcessManagerTest(unittest.TestCase):
    def setUp(self):
        discovery = patch("serial_deck.hub_client.find_existing_hub", return_value=None)
        discovery.start()
        self.addCleanup(discovery.stop)

    def test_endpoint_uses_unix_scheme(self):
        manager = HubProcessManager("/dev/ttyACM0", 115200, "/tmp/serial-deck-test.sock")
        self.assertEqual(manager.endpoint, "hub://" + manager.socket_path)
        self.assertTrue(manager.socket_path.endswith("serial-deck-test.sock"))

    def test_rejects_hub_endpoint_as_physical_uart(self):
        with self.assertRaises(ValueError):
            HubProcessManager("hub:///tmp/other.sock", 115200, "/tmp/serial-deck-test.sock")

    def test_existing_hub_is_attached_not_owned(self):
        manager = HubProcessManager("/dev/ttyACM0", 115200, "/tmp/serial-deck-test.sock")
        status = {"ok": True, "event": "status", "state": "idle", "port": None, "baud": 115200, "flash": {"active": False}, "protocol": "serial-deck-multiport-v1"}
        with patch.object(manager, "socket_ready", return_value=True), \
                patch.object(manager, "request_control", return_value=status):
            self.assertFalse(manager.ensure_started())
        self.assertFalse(manager.owns_process)
        self.assertTrue(manager.multiport)
        self.assertIsNone(manager.process)

    def test_endpoint_with_unknown_protocol_is_refused(self):
        manager = HubProcessManager("/dev/ttyACM0", 115200, "/tmp/serial-deck-test.sock")
        status = {"ok": True, "event": "status", "state": "idle", "port": None, "baud": 115200, "flash": {"active": False}, "protocol": "someone-else-v9"}
        with patch.object(manager, "socket_ready", return_value=True), \
                patch.object(manager, "request_control", return_value=status), \
                self.assertRaisesRegex(RuntimeError, "not a serial-deck hub"):
            manager.ensure_started()

    def test_endpoint_answering_bare_ok_is_not_a_hub(self):
        manager = HubProcessManager("/dev/ttyACM0", 115200, "/tmp/serial-deck-test.sock")
        with patch.object(manager, "socket_ready", return_value=True), \
                patch.object(manager, "request_control", return_value={"ok": True}), \
                self.assertRaisesRegex(RuntimeError, "not a serial-deck hub"):
            manager.ensure_started()

    def test_idle_hub_start_does_not_open_a_uart(self):
        manager = HubProcessManager("/dev/ttyACM0", 115200, "/tmp/serial-deck-test.sock")
        with patch.object(manager, "socket_ready", side_effect=(False, True)), \
             patch("serial_deck.desktop_hub.subprocess.Popen") as popen:
            self.assertTrue(manager.ensure_started())
        command = popen.call_args.args[0]
        self.assertNotIn("--port", command)

    def test_claim_port_sends_selection_and_baud_to_hub(self):
        manager = HubProcessManager("", 115200, "/tmp/serial-deck-test.sock")
        with patch.object(
                manager, "request_control",
                return_value={"ok": True, "claimed": True, "port": "/dev/ttyACM1", "baud": 230400},
        ) as request:
            manager.claim_port("/dev/ttyACM1", 230400)
        request.assert_called_once_with("claim", port="/dev/ttyACM1", baud=230400)
        self.assertTrue(manager.owns_port)
        self.assertEqual(manager.uart_port, "/dev/ttyACM1")
        self.assertEqual(manager.baud, 230400)

    def test_missing_hub_script_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            missing = Path(tmpdir) / "missing.py"
            manager = HubProcessManager(
                "/dev/ttyACM0", 115200, "/tmp/serial-deck-test.sock", str(missing))
            with patch.object(manager, "socket_ready", return_value=False):
                with self.assertRaises(RuntimeError):
                    manager.ensure_started()

    def test_scan_ports_comes_from_hub_control(self):
        manager = HubProcessManager("/dev/ttyACM0", 115200, "/tmp/serial-deck-test.sock")
        with patch.object(
                manager, "request_control",
                return_value={"ok": True, "ports": ["/dev/ttyACM0", "/dev/ttyUSB0"]},
        ) as request:
            self.assertEqual(manager.scan_ports(), ["/dev/ttyACM0", "/dev/ttyUSB0"])
        request.assert_called_once_with("scan")

    def test_scan_ports_rejects_invalid_hub_response(self):
        manager = HubProcessManager("/dev/ttyACM0", 115200, "/tmp/serial-deck-test.sock")
        with patch.object(manager, "request_control", return_value={"ok": True, "ports": [1]}):
            with self.assertRaisesRegex(RuntimeError, "invalid port list"):
                manager.scan_ports()


class HubDeckLifecycleTest(unittest.TestCase):
    def test_scan_log_is_deferred_until_log_widget_exists(self):
        deck = HubControlDeck.__new__(HubControlDeck)
        deck._pending_hub_logs = []

        deck._append_hub_log("[hub] initial scan", "elf")

        self.assertEqual(deck._pending_hub_logs, [("[hub] initial scan", "elf")])


class HubStatusPortLossTest(unittest.TestCase):
    def test_queued_status_from_old_channel_does_not_disconnect_new_port(self):
        deck = HubControlDeck.__new__(HubControlDeck)
        deck.transport = object()
        deck.hub_manager = MagicMock(channel_socket="/tmp/new-channel.sock")
        deck.disconnect = MagicMock()
        deck._handle_hub_status({
            "channel_socket": "/tmp/expired-channel.sock", "port": None,
            "flash": {"active": False},
        })
        deck.disconnect.assert_not_called()

    def test_lost_port_triggers_immediate_disconnect(self):
        # UartHub._handle_serial_lost force-drops a physically lost UART and
        # its status payload then carries port=None while a client is still
        # attached (a normal `release` action refuses that). The deck must
        # reflect the disconnect right away instead of waiting for its own
        # data socket to notice the closed connection.
        deck = HubControlDeck.__new__(HubControlDeck)
        deck.transport = object()
        deck.hub_manager = MagicMock()
        deck.disconnect = MagicMock()
        deck._append_log_record = MagicMock()

        deck._handle_hub_status({
            "state": "idle",
            "port": None,
            "flash": {"active": False, "id": 0, "progress": 0, "step": "Idle", "exit_code": None, "line": ""},
        })

        deck.disconnect.assert_called_once()
        deck._append_log_record.assert_called_once_with("[hub] physical UART was lost", "error")

    def test_lost_port_is_a_noop_when_already_disconnected(self):
        deck = HubControlDeck.__new__(HubControlDeck)
        deck.transport = None
        deck.hub_manager = MagicMock()
        deck.disconnect = MagicMock()
        deck._append_log_record = MagicMock()
        deck.flash_button = MagicMock()
        deck.flash_progress_var = MagicMock()
        deck.flash_status_var = MagicMock()
        deck._last_flash_line = ""
        deck._last_flash_done_id = 0

        deck._handle_hub_status({
            "state": "idle",
            "port": None,
            "flash": {"active": False, "id": 0, "progress": 0, "step": "Idle", "exit_code": None, "line": ""},
        })

        deck.disconnect.assert_not_called()


if __name__ == "__main__":
    unittest.main()

    def test_live_baud_change_updates_picker_and_logs(self):
        deck = HubControlDeck.__new__(HubControlDeck)
        deck.transport = object()
        deck.hub_manager = MagicMock(channel_socket="/tmp/ch.sock", baud=115200)
        deck.baud_var = MagicMock()
        deck._append_log_record = MagicMock()
        deck._handle_hub_status({"channel_socket": "/tmp/ch.sock", "port": "/dev/ttyACM0",
                                 "baud": 921600})
        deck.baud_var.set.assert_called_once_with("921600")
        self.assertEqual(deck.hub_manager.baud, 921600)
        deck._append_log_record.assert_called_once_with(
            "[hub] UART baud changed 115200 -> 921600", "warning")
