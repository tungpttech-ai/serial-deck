import os
import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from serial_deck import uart_client as uart


class SerialPortDetailsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.addCleanup(patch.stopall)
        patch.object(uart.sys, "platform", "linux").start()
        patch.object(uart.os, "access", return_value=True).start()
        self.stat = patch.object(Path, "stat", return_value=SimpleNamespace(st_mode=stat.S_IFCHR)).start()

    def details(self, device, **kwargs):
        return uart.serial_port_details(device, sysfs_root=self.root, **kwargs)

    def test_phantom_uart_is_hidden_but_configured_uart_remains(self):
        tty = self.root / "ttyS0"
        tty.mkdir()
        (tty / "type").write_text("0\n")
        self.assertIsNone(self.details("/dev/ttyS0"))
        (tty / "type").write_text("4\n")
        self.assertEqual(self.details("/dev/ttyS0")["device"], "/dev/ttyS0")

    @unittest.skipIf(os.name == "nt", "POSIX device paths")
    def test_missing_noncharacter_and_inaccessible_devices_are_hidden(self):
        self.stat.side_effect = FileNotFoundError()
        self.assertIsNone(self.details("/dev/ttyUSB0"))
        self.stat.side_effect = None
        self.stat.return_value = SimpleNamespace(st_mode=stat.S_IFREG)
        self.assertIsNone(self.details("/dev/ttyUSB0"))
        self.stat.return_value = SimpleNamespace(st_mode=stat.S_IFCHR)
        with patch.object(uart.os, "access", return_value=False):
            self.assertIsNone(self.details("/dev/ttyUSB0"))

    def test_usb_description_includes_interface_and_path_without_opening_uart(self):
        interface = self.root / "ttyACM0" / "device"
        interface.mkdir(parents=True)
        (interface / "bInterfaceNumber").write_text("02\n")
        with patch.object(uart, "open_device_transport", side_effect=AssertionError("UART opened")):
            detail = self.details("/dev/ttyACM0", description="USB Dual Serial", manufacturer="WCH")
        self.assertEqual(detail["label"], "/dev/ttyACM0 - USB Dual Serial - WCH - Interface 02")

    def test_missing_metadata_keeps_accessible_candidate(self):
        self.assertEqual(self.details("/dev/ttyUSB8", description="n/a")["label"],
                         "/dev/ttyUSB8 - Serial port")

    def test_missing_pyserial_falls_back_to_device_scan(self):
        with patch.dict("sys.modules", {"serial.tools": None}), \
             patch.object(uart, "discover_serial_ports", return_value=["/dev/ttyUSB1"]), \
             patch.object(uart, "serial_port_details", return_value={"device": "/dev/ttyUSB1"}) as inspect:
            self.assertEqual(uart.discover_serial_port_details(), [{"device": "/dev/ttyUSB1"}])
            inspect.assert_called_once_with("/dev/ttyUSB1", "", "", "")


if __name__ == "__main__":
    unittest.main()
