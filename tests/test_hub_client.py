import unittest
from unittest.mock import MagicMock, patch

import os
import tempfile
from pathlib import Path

from serial_deck import ipc
from serial_deck.hub_client import (
    DEFAULT_SOCKET,
    HubProcessManager,
    HubRegistry,
)
from serial_deck.uart_client import is_device_port, port_identity

class DefaultSocketPathTest(unittest.TestCase):
    def test_default_hub_lives_in_a_private_per_user_directory(self):
        self.assertEqual(Path(DEFAULT_SOCKET).name, "hub.sock")
        self.assertEqual(Path(DEFAULT_SOCKET).parent, ipc.runtime_dir())
        if os.name != "nt":
            self.assertEqual(ipc.runtime_dir().stat().st_mode & 0o077, 0)

    def test_runtime_dir_override_is_created_private(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "rt"
            with patch.dict(os.environ, {"SERIAL_DECK_RUNTIME_DIR": str(target)}):
                self.assertEqual(ipc.runtime_dir(), target)
            if os.name != "nt":
                self.assertEqual(target.stat().st_mode & 0o777, 0o700)

class PortNameTest(unittest.TestCase):
    def test_windows_com_names_are_devices_and_normalized(self):
        for name in ("COM3", "com3", "\\\\.\\COM3"):
            self.assertTrue(is_device_port(name), name)
            self.assertEqual(port_identity(name), "COM3")
        self.assertTrue(is_device_port("/dev/ttyUSB0"))
        for name in ("COMX", "tcp://10.0.0.2:23", "hub://x", "ttyUSB0"):
            self.assertFalse(is_device_port(name), name)


class HubRegistryTest(unittest.TestCase):
    def setUp(self):
        discovery = patch("serial_deck.hub_client.find_existing_hub", return_value=None)
        discovery.start()
        self.addCleanup(discovery.stop)

    @unittest.skipIf(os.name == "nt", "POSIX device paths")
    def test_same_port_shares_client_different_ports_share_daemon(self):
        root = MagicMock(socket_path="/tmp/shared.sock")
        root.get_status.return_value = {"protocol": "serial-deck-multiport-v1"}
        created = []
        def ctor(**kwargs):
            manager = MagicMock(**kwargs)
            created.append(manager)
            return manager
        with patch("serial_deck.hub_client.HubProcessManager", side_effect=ctor):
            registry = HubRegistry(default_manager=root)
            first = registry.acquire("/dev/ttyACM0", 115200)
            second = registry.acquire("/dev/ttyACM0", 115200)
            third = registry.acquire("/dev/ttyACM1", 115200)
        self.assertIs(first, second)
        self.assertIsNot(first, third)
        self.assertEqual(len(created), 2)
        self.assertEqual(first.socket_path, third.socket_path)
        for manager in created:
            manager.ensure_started.assert_not_called()
        registry.release("/dev/ttyACM0", first)
        first.stop.assert_not_called()
        registry.release("/dev/ttyACM0", second)
        first.stop.assert_called_once()  # detaches a multiport client; never kills daemon
        root.stop.assert_not_called()
        self.assertEqual(registry.claimed_ports(), ["/dev/ttyACM1"])

    def test_failed_claim_leaves_no_channel_reference(self):
        root = MagicMock(socket_path="/tmp/shared.sock")
        root.get_status.return_value = {"protocol": "serial-deck-multiport-v1"}
        channel = MagicMock()
        channel.claim_port.side_effect = RuntimeError("not available")
        with patch("serial_deck.hub_client.HubProcessManager", return_value=channel):
            registry = HubRegistry(default_manager=root)
            with self.assertRaises(RuntimeError):
                registry.acquire("/dev/ttyACM0", 115200)
        self.assertEqual(registry.claimed_ports(), [])
        channel.unsubscribe.assert_called_once()
        root.stop.assert_not_called()

    def test_pin_lets_acquire_reuse_an_externally_owned_manager(self):
        external = MagicMock()
        registry = HubRegistry(baud=115200)
        registry.pin("/dev/ttyACM0", external)

        with patch("serial_deck.hub_client.HubProcessManager") as ctor:
            reused = registry.acquire("/dev/ttyACM0", 115200)

        ctor.assert_not_called()
        self.assertIs(reused, external)
        external.claim_port.assert_called_once_with("/dev/ttyACM0", 115200)


class MultiCallbackSubscribeTest(unittest.TestCase):
    def setUp(self):
        self.manager = HubProcessManager("/dev/ttyACM0", 115200, "/tmp/serial-deck-hub-client-test.sock")

    @staticmethod
    def _fake_socket():
        # recv() returns EOF immediately so the background reader thread
        # exits on its own instead of spinning forever on a mocked socket
        # that can't reproduce a real settimeout()-bounded blocking read.
        fake_socket = MagicMock()
        fake_socket.recv.return_value = b""
        return fake_socket

    def test_second_callback_reuses_the_shared_subscriber_connection(self):
        fake_socket = self._fake_socket()
        with patch("serial_deck.ipc.connect", return_value=fake_socket) as connect:
            self.manager.subscribe(lambda event: None)
            first_socket = self.manager._subscriber
            self.manager.subscribe(lambda event: None)
        self.assertIs(self.manager._subscriber, first_socket)
        connect.assert_called_once()

    def test_unsubscribe_one_callback_keeps_shared_connection_for_the_other(self):
        fake_socket = self._fake_socket()
        cb_a = lambda event: None
        cb_b = lambda event: None
        with patch("serial_deck.ipc.connect", return_value=fake_socket) as connect:
            self.manager.subscribe(cb_a)
            self.manager.subscribe(cb_b)
            self.manager.unsubscribe(cb_a)
        self.assertIsNotNone(self.manager._subscriber)
        self.assertEqual(self.manager._callbacks, [cb_b])
        fake_socket.close.assert_not_called()

    def test_unsubscribe_with_no_argument_tears_down_everything(self):
        fake_socket = self._fake_socket()
        with patch("serial_deck.ipc.connect", return_value=fake_socket) as connect:
            self.manager.subscribe(lambda event: None)
            self.manager.subscribe(lambda event: None)
            self.manager.unsubscribe()
        self.assertIsNone(self.manager._subscriber)
        self.assertEqual(self.manager._callbacks, [])
        fake_socket.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
