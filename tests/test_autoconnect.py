"""Auto-reconnect: a lost device comes back by itself, a user disconnect stays off."""

import os
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from serial_deck import uart_client as uart
from serial_deck.web import DeckWebBridge


def eventually(check, timeout=5.0):
    deadline = time.monotonic() + timeout
    while not check():
        if time.monotonic() > deadline:
            raise AssertionError("condition did not become true")
        time.sleep(0.01)


class FindPortByUsbTest(unittest.TestCase):
    """A replug can bring a board back under another path."""

    def identities(self, table):
        return patch.object(uart, "usb_identity", lambda device: table.get(device, {}))

    def test_follows_the_device_to_its_new_path(self):
        table = {"/dev/ttyACM1": {"usb_vid_pid": "303a:1001", "usb_serial": "AA"},
                 "/dev/ttyUSB0": {"usb_vid_pid": "10c4:ea60", "usb_serial": "BB"}}
        with self.identities(table):
            self.assertEqual(uart.find_port_by_usb("303a:1001", "AA", list(table)), "/dev/ttyACM1")

    def test_serial_number_tells_identical_boards_apart(self):
        table = {"/dev/ttyACM0": {"usb_vid_pid": "303a:1001", "usb_serial": "AA"},
                 "/dev/ttyACM1": {"usb_vid_pid": "303a:1001", "usb_serial": "BB"}}
        with self.identities(table):
            self.assertEqual(uart.find_port_by_usb("303a:1001", "BB", list(table)), "/dev/ttyACM1")

    def test_refuses_to_guess_between_identical_boards_without_a_serial(self):
        table = {"/dev/ttyACM0": {"usb_vid_pid": "303a:1001", "usb_serial": ""},
                 "/dev/ttyACM1": {"usb_vid_pid": "303a:1001", "usb_serial": ""}}
        with self.identities(table):
            self.assertIsNone(uart.find_port_by_usb("303a:1001", "", list(table)))

    def test_absent_device_is_none(self):
        with self.identities({}):
            self.assertIsNone(uart.find_port_by_usb("303a:1001", "AA", ["/dev/ttyACM0"]))

    # Two boards of one model, each a composite device with two CDC-ACM ttys
    # (interface 00 = console, 02 = second port): same vid:pid and serial per board.
    TWO_BOARDS = {
        "/dev/ttyACM0": {"usb_vid_pid": "1a86:55d2", "usb_serial": "AA", "usb_interface": "00"},
        "/dev/ttyACM1": {"usb_vid_pid": "1a86:55d2", "usb_serial": "AA", "usb_interface": "02"},
        "/dev/ttyACM2": {"usb_vid_pid": "1a86:55d2", "usb_serial": "BB", "usb_interface": "00"},
        "/dev/ttyACM3": {"usb_vid_pid": "1a86:55d2", "usb_serial": "BB", "usb_interface": "02"},
    }

    def test_interface_tells_the_ports_of_one_board_apart(self):
        with self.identities(self.TWO_BOARDS):
            ports = list(self.TWO_BOARDS)
            self.assertEqual(uart.find_port_by_usb("1a86:55d2", "BB", ports, "00"), "/dev/ttyACM2")
            self.assertEqual(uart.find_port_by_usb("1a86:55d2", "BB", ports, "02"), "/dev/ttyACM3")
            # An older saved identity has no interface: still ambiguous, still refused.
            self.assertIsNone(uart.find_port_by_usb("1a86:55d2", "BB", ports))

    def test_it_follows_the_interface_after_the_numbers_change(self):
        renumbered = {"/dev/ttyACM4": self.TWO_BOARDS["/dev/ttyACM2"],
                      "/dev/ttyACM5": self.TWO_BOARDS["/dev/ttyACM3"],
                      "/dev/ttyACM6": self.TWO_BOARDS["/dev/ttyACM0"],
                      "/dev/ttyACM7": self.TWO_BOARDS["/dev/ttyACM1"]}
        with self.identities(renumbered):
            self.assertEqual(uart.find_port_by_usb("1a86:55d2", "BB", list(renumbered), "00"), "/dev/ttyACM4")
            self.assertEqual(uart.find_port_by_usb("1a86:55d2", "AA", list(renumbered), "02"), "/dev/ttyACM7")

    def test_an_unreadable_interface_never_matches_a_saved_one(self):
        table = {"/dev/ttyACM0": {"usb_vid_pid": "1a86:55d2", "usb_serial": "AA", "usb_interface": ""}}
        with self.identities(table):
            self.assertIsNone(uart.find_port_by_usb("1a86:55d2", "AA", list(table), "00"))

    def test_aliases_of_one_tty_count_once(self):
        with tempfile.TemporaryDirectory() as directory:
            real = Path(directory) / "ttyACM9"
            real.touch()
            alias = Path(directory) / "by-id-link"
            alias.symlink_to(real)
            same = {"usb_vid_pid": "303a:1001", "usb_serial": "AA", "usb_interface": "00"}
            table = {str(real): same, str(alias): same}
            with self.identities(table):
                self.assertEqual(uart.find_port_by_usb("303a:1001", "AA", list(table), "00"), str(real))

    def test_usb_identity_reads_the_nearest_interface_from_sysfs(self):
        with tempfile.TemporaryDirectory() as directory:
            usb = Path(directory) / "sys" / "usb1" / "1-2"
            interface = usb / "1-2:1.2"
            tty = interface / "tty" / "ttyACM9"
            tty.mkdir(parents=True)
            (usb / "idVendor").write_text("1a86\n")
            (usb / "idProduct").write_text("55d2\n")
            (usb / "serial").write_text("AA\n")
            (interface / "bInterfaceNumber").write_text("02\n")
            class_dir = Path(directory) / "class" / "ttyACM9"
            class_dir.mkdir(parents=True)
            (class_dir / "device").symlink_to(interface)
            with patch.object(uart, "SYS_CLASS_TTY", Path(directory) / "class"):
                identity = uart.usb_identity("/dev/ttyACM9")
        self.assertEqual(identity, {"usb_vid_pid": "1a86:55d2", "usb_serial": "AA", "usb_interface": "02"})


class FakeSerialDeck(DeckWebBridge):
    """A bridge whose connect is scripted: no hub, no sockets."""

    RECONNECT_BACKOFF = (0.01,)

    def __init__(self, ports):
        super().__init__(default_port="/dev/ttyACM0", hub_manager=MagicMock())
        self.ports = ports
        self.connects = []
        self.fail_next = 0

    def list_ports(self):
        return list(self.ports)

    def _connect(self, port, baud, mode=None, on_baud_conflict="join", passphrase=""):
        self.connects.append(port)
        if self.fail_next:
            self.fail_next -= 1
            raise RuntimeError("busy")
        self.port, self.baud, self.connected = port, baud, True
        if mode:
            self.console_mode = mode
        self._remembered = {"port": port, "baud": baud, "mode": self.console_mode,
                            "usb_vid_pid": "", "usb_serial": ""}
        return self.get_status()


class AutoReconnectTest(unittest.TestCase):
    def deck(self, ports=("/dev/ttyACM0",)):
        deck = FakeSerialDeck(list(ports))
        self.addCleanup(deck.close)
        deck.connect("/dev/ttyACM0", 115200, "control")
        deck.set_auto_reconnect(True)
        return deck

    def test_a_lost_device_reconnects_with_its_port_baud_and_mode(self):
        deck = self.deck()
        deck._lost()
        eventually(lambda: deck.connected)
        self.assertEqual(deck.connects, ["/dev/ttyACM0", "/dev/ttyACM0"])
        self.assertEqual((deck.baud, deck.console_mode), (115200, "control"))
        self.assertFalse(deck.reconnecting)

    def test_it_waits_while_the_device_is_unplugged(self):
        deck = self.deck(ports=())
        deck._lost()
        time.sleep(0.15)
        self.assertFalse(deck.connected)
        self.assertTrue(deck.reconnecting)
        deck.ports.append("/dev/ttyACM0")
        eventually(lambda: deck.connected)

    def test_it_follows_a_usb_device_to_a_new_path(self):
        deck = self.deck(ports=())
        deck._remembered.update(usb_vid_pid="303a:1001", usb_serial="AA")
        table = {"/dev/ttyACM3": {"usb_vid_pid": "303a:1001", "usb_serial": "AA"}}
        with patch.object(uart, "usb_identity", lambda device: table.get(device, {})):
            deck._lost()
            deck.ports.append("/dev/ttyACM3")
            eventually(lambda: deck.connected, timeout=8)
        self.assertEqual(deck.port, "/dev/ttyACM3")

    def test_a_user_disconnect_is_never_undone(self):
        deck = self.deck()
        deck.disconnect()
        time.sleep(0.15)
        self.assertFalse(deck.connected)
        self.assertEqual(len(deck.connects), 1)

    def test_a_user_disconnect_while_a_retry_is_opening_wins(self):
        """Disconnect arrives while the retry is already inside _connect (it passed the
        generation check): the connection that finishes afterwards must not survive."""
        deck = self.deck(ports=())
        entered, release = threading.Event(), threading.Event()
        original = deck._connect

        def slow_connect(*args, **kwargs):
            entered.set()
            release.wait(5)
            return original(*args, **kwargs)
        deck._connect = slow_connect
        deck._lost()
        deck.ports.append("/dev/ttyACM0")
        self.assertTrue(entered.wait(5))
        threading.Thread(target=lambda: (time.sleep(0.1), release.set()), daemon=True).start()
        deck.disconnect()  # returns only after the in-flight connect has settled
        time.sleep(0.3)
        self.assertFalse(deck.connected)
        self.assertFalse(deck.reconnecting)

    def test_a_user_disconnect_during_a_retry_stops_it(self):
        deck = self.deck(ports=())
        deck._lost()
        eventually(lambda: deck.reconnecting)
        deck.disconnect()
        deck.ports.append("/dev/ttyACM0")
        time.sleep(0.15)
        self.assertFalse(deck.connected)
        self.assertFalse(deck.reconnecting)

    def test_turning_it_off_cancels_a_pending_retry(self):
        deck = self.deck(ports=())
        deck._lost()
        eventually(lambda: deck.reconnecting)
        deck.set_auto_reconnect(False)
        deck.ports.append("/dev/ttyACM0")
        time.sleep(0.15)
        self.assertFalse(deck.connected)

    def test_off_by_default_so_a_lost_device_stays_lost(self):
        deck = FakeSerialDeck(["/dev/ttyACM0"])
        self.addCleanup(deck.close)
        deck.connect("/dev/ttyACM0", 115200)
        deck._lost()
        time.sleep(0.1)
        self.assertFalse(deck.connected)
        self.assertFalse(deck.reconnecting)

    def test_a_failed_attempt_is_retried(self):
        deck = self.deck()
        deck.fail_next = 2
        deck._lost()
        eventually(lambda: deck.connected)
        self.assertEqual(len(deck.connects), 4)

    def test_it_does_not_reconnect_during_a_flash(self):
        deck = self.deck()
        deck.flashing = True
        deck._lost()
        time.sleep(0.15)
        self.assertFalse(deck.connected)

    def test_a_new_user_connect_replaces_a_pending_retry(self):
        deck = self.deck(ports=())
        deck._lost()
        eventually(lambda: deck.reconnecting)
        deck.connect("/dev/ttyUSB0", 9600)
        time.sleep(0.1)
        self.assertEqual(deck.port, "/dev/ttyUSB0")
        self.assertEqual(deck.connects.count("/dev/ttyACM0"), 1)

    def test_closing_the_bridge_ends_the_retry(self):
        deck = self.deck(ports=())
        deck._lost()
        eventually(lambda: deck.reconnecting)
        deck.close()
        deck.ports.append("/dev/ttyACM0")
        time.sleep(0.1)
        self.assertFalse(deck.connected)

    def test_status_reports_the_reconnect_state_for_the_ui(self):
        deck = self.deck(ports=())
        deck._lost()
        eventually(lambda: deck.reconnecting)
        status = deck.get_status()
        self.assertTrue(status["auto_reconnect"])
        self.assertTrue(status["reconnecting"])
        self.assertFalse(status["connected"])


if __name__ == "__main__":
    unittest.main()
