import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from serial_deck.web import (
    HTML_PAGE,
    DeckWebBridge,
    auto_find_elf,
    parse_flash_progress,
    parse_log_level,
    parse_tx_payload,
    should_symbolize_log,
)


class DeckWebTest(unittest.TestCase):
    def test_log_level_parsing(self):
        self.assertEqual(parse_log_level("E (123) panic: failed"), "error")
        self.assertEqual(parse_log_level("W (123) wifi: retry"), "warning")
        self.assertEqual(parse_log_level("I (123) app: ready"), "info")
        self.assertEqual(parse_log_level("D (123) app: debug info"), "debug")
        self.assertEqual(parse_log_level("V (123) app: verbose trace"), "verbose")
        self.assertEqual(parse_log_level("plain raw output"), "plain")

    def test_web_exposes_raw_filter_enabled_by_default(self):
        self.assertIn('id="lvl-plain"', HTML_PAGE)
        self.assertIn('id="lvl-elf"', HTML_PAGE)
        self.assertIn("new Set(['E', 'W', 'I', 'D', 'elf', 'tx', 'plain'])", HTML_PAGE)
        self.assertIn("if (!enabledLevels.has(lvlKey)) return false;", HTML_PAGE)

    def test_tx_payload_parsing(self):
        self.assertEqual(parse_tx_payload("help", "ascii", "lf"), b"help\n")
        self.assertEqual(parse_tx_payload("AT", "ascii", "crlf"), b"AT\r\n")
        self.assertEqual(parse_tx_payload("50 03 0xff,0A", "hex"), b"\x50\x03\xff\x0a")
        with self.assertRaises(ValueError):
            parse_tx_payload("5", "hex")
        with self.assertRaises(ValueError):
            parse_tx_payload("zz", "hex")

    def test_send_raw_writes_bytes_and_echoes_tx_log(self):
        bridge = DeckWebBridge()
        bridge.transport = MagicMock()
        bridge.connected = True
        self.assertEqual(bridge.send_raw("ping", "ascii", "lf"), 5)
        bridge.transport.write.assert_called_once_with(b"ping\n")
        self.assertEqual(bridge.history_logs[-1]["level"], "tx")
        self.assertEqual(bridge.history_logs[-1]["text"], "TX> ping\\n")

    def test_send_raw_requires_connection(self):
        with self.assertRaises(RuntimeError):
            DeckWebBridge().send_raw("ping")

    def test_linux_mode_streams_raw_bytes_and_skips_control_frames(self):
        bridge = DeckWebBridge()
        bridge.set_console_mode("linux")
        bridge.transport = MagicMock()
        bridge.connected = True
        with self.assertRaises(RuntimeError):
            bridge.send_button("ENTER")
        bridge.transport.write.assert_not_called()

        events = []
        bridge.broadcast = events.append
        bridge._broadcast_raw(b"\x1b[32mroot@board\x1b[0m:~# ")
        self.assertEqual(events[-1]["type"], "raw")
        self.assertEqual(json.loads(json.dumps(events[-1]))["data"],
                         "G1szMm1yb290QGJvYXJkG1swbTp+IyA=")
        self.assertEqual(bytes(bridge.raw_history), b"\x1b[32mroot@board\x1b[0m:~# ")

        bridge.send_term_input(b"\x03")
        bridge.transport.write.assert_called_once_with(b"\x03")

    def test_unknown_console_mode_is_rejected(self):
        with self.assertRaises(ValueError):
            DeckWebBridge().set_console_mode("windows")

    def test_flash_progress_parsing(self):
        pct, step = parse_flash_progress("Writing at 0x00010000... (45 %)")
        self.assertEqual(pct, 45)
        self.assertEqual(step, "Writing")

        pct, step = parse_flash_progress("\x1b[KWriting at 0x0034ed24 ... 66.8%\x1b[K")
        self.assertEqual(pct, 66.8)
        self.assertEqual(step, "Writing")

        pct, step = parse_flash_progress("Erasing flash (this may take a while)...")
        self.assertIsNone(pct)
        self.assertEqual(step, "Erasing")

        pct, step = parse_flash_progress("Hash of data verified.")
        self.assertEqual(step, "Hash of data verified")

    def test_symbolizer_only_runs_for_crash_logs(self):
        self.assertFalse(should_symbolize_log('{"tag":"ws_rx","payload":{"hex":"5003"}}'))
        self.assertTrue(should_symbolize_log("assert failed: Backtrace: 0x40001234"))

    def test_auto_find_elf(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            elf1 = tmp / "firmware.elf"
            elf1.touch()
            self.assertEqual(auto_find_elf(str(tmp)), str(elf1.resolve()))

            non_existent = tmp / "missing_dir"
            self.assertEqual(auto_find_elf(str(non_existent)), "")

    def test_bridge_status_and_telemetry(self):
        bridge = DeckWebBridge(default_port="/dev/ttyMock", default_baud=115200)
        status = bridge.get_status()
        self.assertFalse(status["connected"])
        self.assertEqual(status["port"], "/dev/ttyMock")
        self.assertEqual(status["baud"], 115200)
        self.assertEqual(status["fsm"], "UNKNOWN")

        # Simulate frame telemetry update
        bridge._update_telemetry(1, {"commands": ["input.button", "query"], "target": "demo-board", "baud": 115200})
        status = bridge.get_status()
        self.assertIn("demo-board", status["device"])

        bridge._update_telemetry(3, {"result": {"state": "VOICE_ACTIVE", "heap_free": 123456}})
        status = bridge.get_status()
        self.assertEqual(status["fsm"], "VOICE_ACTIVE")
        self.assertEqual(status["telemetry"].get("heap_free"), 123456)

    def test_bridge_flash_is_delegated_to_hub(self):
        hub = MagicMock()
        hub.endpoint = "hub:///tmp/serial-deck-test.sock"
        bridge = DeckWebBridge(default_port="/dev/ttyMock", hub_manager=hub)

        bridge.start_flash("build", 460800)

        hub.preview_flash.assert_called_once_with("build", 460800)
        hub.start_flash.assert_called_once_with("build", 460800)

    def test_hub_status_is_rebroadcast_to_web_clients(self):
        hub = MagicMock()
        bridge = DeckWebBridge(default_port="/dev/ttyMock", hub_manager=hub)
        client = bridge.register_client()

        bridge._handle_hub_status({
            "state": "flashing",
            "port": "/dev/ttyACM0",
            "flash": {"active": True, "id": 3, "progress": 55, "step": "Writing", "exit_code": None, "line": "Writing"},
        })

        events = [client.get_nowait() for _ in range(3)]
        self.assertEqual(events[0]["type"], "flash")
        self.assertEqual(events[0]["percent"], 55)
        self.assertEqual(events[1]["type"], "status")
        self.assertEqual(events[2]["type"], "log")
        self.assertIn("[hub flash] Writing", events[2]["text"])

        bridge._handle_hub_status({
            "state": "flashing",
            "port": "/dev/ttyACM0",
            "flash": {"active": True, "id": 3, "progress": 55, "step": "Writing", "exit_code": None, "line": "Writing"},
        })
        self.assertEqual(client.qsize(), 2)

    def test_hub_status_reports_lost_port_as_immediate_disconnect(self):
        # UartHub._handle_serial_lost force-drops a physically lost UART and
        # its status payload then carries port=None while a data client is
        # still attached (a normal `release` action refuses that). The
        # bridge must reflect the disconnect right away instead of waiting
        # for its own data socket to notice the closed connection.
        hub = MagicMock()
        bridge = DeckWebBridge(default_port="/dev/ttyACM0", hub_manager=hub)
        bridge.connected = True
        bridge.port = "/dev/ttyACM0"
        client = bridge.register_client()

        bridge._handle_hub_status({
            "state": "idle",
            "port": None,
            "flash": {"active": False, "id": 0, "progress": 0, "step": "Idle", "exit_code": None, "line": ""},
        })

        self.assertFalse(bridge.connected)
        hub.release_port.assert_called_once()
        events = [client.get_nowait() for _ in range(2)]
        self.assertEqual(events[0]["type"], "log")
        self.assertEqual(events[0]["level"], "error")
        self.assertIn("physical UART was lost", events[0]["text"])
        self.assertEqual(events[1]["type"], "status")
        self.assertFalse(events[1]["connected"])
        self.assertTrue(client.empty())

    def test_hub_status_with_no_port_is_a_noop_when_already_disconnected(self):
        hub = MagicMock()
        bridge = DeckWebBridge(default_port="/dev/ttyACM0", hub_manager=hub)
        client = bridge.register_client()

        bridge._handle_hub_status({
            "state": "idle",
            "port": None,
            "flash": {"active": False, "id": 0, "progress": 0, "step": "Idle", "exit_code": None, "line": ""},
        })

        hub.release_port.assert_not_called()
        self.assertEqual(client.qsize(), 2)  # flash + status broadcast, no extra [hub] log


if __name__ == "__main__":
    unittest.main()
