"""Port routing regressions; all managers/transports are fake (no UART access)."""

import os
import unittest
from unittest.mock import MagicMock, patch

from serial_deck import hub_client as hub
from serial_deck import web as web


def manager_for(port, baud=1500000):
    manager = MagicMock()
    manager.baud = baud
    manager.socket_path = "/tmp/fake-routing.sock"
    manager.endpoint = "hub:///tmp/fake-routing.sock"
    manager.get_status.return_value = {"port": port, "baud": baud}
    manager.request_control.return_value = {"flash": {"active": False}}

    def claim(selected, requested):
        current = manager.get_status.return_value["port"]
        if current and (current != selected or manager.baud != requested):
            raise RuntimeError("UART already claimed")
        manager.baud = requested
        manager.get_status.return_value = {"port": selected, "baud": requested}

    manager.claim_port.side_effect = claim
    return manager


@unittest.skipIf(os.name == "nt", "POSIX device paths")
class PortRoutingTest(unittest.TestCase):
    def setUp(self):
        discovery = patch.object(hub, "find_existing_hub", return_value=None)
        self.discovery = discovery.start()
        self.addCleanup(discovery.stop)
        self.default = manager_for("/dev/ttyACM3")
        self.registry = hub.HubRegistry(default_manager=self.default, reuse_live_baud=True)

    def test_device_aliases_share_one_registry_entry(self):
        realpath = hub.os.path.realpath
        with patch.object(hub.os.path, "realpath", side_effect=lambda p: "/dev/ttyACM3" if p == "/dev/serial/by-id/board" else realpath(p)):
            first = self.registry.acquire("/dev/serial/by-id/board", 2000000)
            second = self.registry.acquire("/dev/ttyACM3", 2000000)
            self.assertIs(first, second)
            self.assertEqual(self.registry.claimed_ports(), ["/dev/ttyACM3"])
            first.claim_port.assert_called_with("/dev/ttyACM3", 1500000)
            self.registry.release("/dev/serial/by-id/board", first)
            self.registry.release("/dev/ttyACM3", second)
        self.assertEqual(self.registry.claimed_ports(), [])

    def test_legacy_hub_never_spawns_another_for_different_port(self):
        with patch.object(hub, "HubProcessManager") as ctor:
            with self.assertRaisesRegex(RuntimeError, "Legacy single-port"):
                self.registry.acquire("/dev/ttyACM0", 2000000)
        ctor.assert_not_called()
        self.default.claim_port.assert_not_called()
        self.default.stop.assert_not_called()

    def test_default_and_extra_tab_share_live_baud_and_preserve_hub(self):
        with patch.object(hub, "HubProcessManager") as ctor:
            first = self.registry.acquire("/dev/ttyACM3", 2000000)
            second = self.registry.acquire("/dev/ttyACM3", 115200)
        ctor.assert_not_called()
        self.assertIs(first, self.default)
        self.assertIs(second, first)
        self.assertEqual([c.args for c in first.claim_port.call_args_list],
                         [("/dev/ttyACM3", 1500000)] * 2)
        self.registry.release("/dev/ttyACM3", first)
        self.assertEqual(self.registry.claimed_ports(), ["/dev/ttyACM3"])
        self.registry.release("/dev/ttyACM3", second)
        self.assertEqual(self.registry.claimed_ports(), [])
        first.release_port.assert_not_called()
        first.stop.assert_not_called()

    def test_idle_legacy_default_can_claim_one_port(self):
        self.default.get_status.return_value["port"] = None
        with patch.object(hub, "HubProcessManager") as ctor:
            self.assertIs(self.registry.acquire("/dev/ttyACM0", 115200), self.default)
        ctor.assert_not_called()

    def test_legacy_external_retarget_is_not_overridden(self):
        manager = self.registry.acquire("/dev/ttyACM3", 2000000)
        self.registry.release("/dev/ttyACM3", manager)
        self.default.get_status.return_value["port"] = "/dev/ttyACM2"
        with self.assertRaisesRegex(RuntimeError, "Legacy single-port"):
            self.registry.acquire("/dev/ttyACM3", 2000000)

    def test_failed_default_claim_leaves_no_reservation(self):
        self.default.claim_port.side_effect = RuntimeError("disconnected")
        with self.assertRaisesRegex(RuntimeError, "disconnected"):
            self.registry.acquire("/dev/ttyACM3", 2000000)
        self.assertEqual(self.registry.claimed_ports(), [])
        self.default.stop.assert_not_called()

    def test_bridge_uses_live_baud_and_releases_original_registry_key(self):
        bridge = web.DeckWebBridge(hub_manager=self.default, hub_registry=self.registry)
        with patch.object(web, "open_uart_transport", return_value=MagicMock()) as transport, \
                patch.object(bridge, "_reader_loop"), patch.object(bridge, "_send_hello"):
            status = bridge.connect("/dev/ttyACM3", 2000000, "linux")
            self.assertEqual((status["port"], status["baud"]), ("/dev/ttyACM3", 1500000))
            transport.assert_called_once_with(self.default.endpoint, 1500000, 0.1)
            bridge.port = "/dev/changed-by-status"
            bridge.disconnect()
        self.assertEqual(self.registry.claimed_ports(), [])
        self.default.stop.assert_not_called()

    def test_transport_failure_releases_registry_reference(self):
        bridge = web.DeckWebBridge(hub_manager=self.default, hub_registry=self.registry)
        with patch.object(web, "open_uart_transport", side_effect=OSError("socket vanished")):
            with self.assertRaisesRegex(RuntimeError, "Connection failed"):
                bridge.connect("/dev/ttyACM3", 2000000, "linux")
        self.assertFalse(bridge.connected)
        self.assertIsNone(bridge.hub_manager)
        self.assertEqual(self.registry.claimed_ports(), [])
        self.default.stop.assert_not_called()

    def test_flash_check_includes_default_after_bridge_moves_away(self):
        bridge = web.DeckWebBridge(hub_manager=manager_for("/dev/ttyACM0"))
        connections = web.ConnectionManager(bridge, self.registry, 2000000, "")
        connections.lifecycle_hubs.append(self.default)
        self.default.request_control.return_value = {"flash": {"active": True}}
        self.assertEqual(connections.flash_check().active, [self.default.socket_path])


if __name__ == "__main__":
    unittest.main()
