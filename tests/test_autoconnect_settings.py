"""Restore-on-start and device rules: opt-in, matched by USB identity, once per plug."""

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from serial_deck import autoconnect as ac
from serial_deck import uart_client
from serial_deck.deckconfig import JsonFile
from serial_deck.web import ConnectionManager, DeckWebBridge


class SettingsTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.settings = ac.Settings(JsonFile("settings.json", ac.DEFAULTS, Path(self.dir.name)))

    def test_everything_is_off_by_default(self):
        data = self.settings.get()
        self.assertFalse(data["restore_on_start"])
        self.assertEqual(data["rules"], [])

    def test_rules_round_trip_and_are_normalised(self):
        saved = self.settings.update(rules=[{"usb_vid_pid": "303A:1001", "usb_serial": "AA",
                                             "baud": 2000000, "mode": "control", "label": " P4 "}])
        rule = saved["rules"][0]
        self.assertEqual((rule["usb_vid_pid"], rule["label"], rule["port"]), ("303a:1001", "P4", ""))
        self.assertEqual(self.settings.get()["rules"], saved["rules"])

    def test_invalid_rules_are_refused(self):
        for bad in ({"usb_vid_pid": "nope", "baud": 115200}, {"baud": 115200}, {"port": "/dev/x", "baud": 5},
                    {"port": "/dev/x", "baud": 115200, "mode": "evil"}, "not a dict",
                    {"port": "/dev/x\n", "baud": 115200}):
            with self.assertRaises(ac.SettingsError, msg=str(bad)):
                self.settings.update(rules=[bad])

    def test_too_many_rules_are_refused(self):
        with self.assertRaises(ac.SettingsError):
            self.settings.update(rules=[{"port": f"/dev/ttyUSB{i}", "baud": 9600} for i in range(40)])

    def test_a_corrupt_or_hand_edited_file_never_breaks_loading(self):
        path = Path(self.dir.name) / "settings.json"
        path.write_text("{ not json")
        self.assertEqual(self.settings.get()["rules"], [])
        path.write_text('{"rules": [{"usb_vid_pid": "zzzz"}, {"port": "/dev/ttyUSB0", "baud": 9600}]}')
        self.assertEqual([r["port"] for r in self.settings.get()["rules"]], ["/dev/ttyUSB0"])

    def test_the_settings_file_is_private(self):
        self.settings.update(restore_on_start=True)
        if os.name == "posix":
            self.assertEqual((Path(self.dir.name) / "settings.json").stat().st_mode & 0o077, 0)


class RuleMatchTest(unittest.TestCase):
    def test_matches_by_vid_pid_and_serial_not_by_path(self):
        rule = ac.clean_rule({"usb_vid_pid": "303a:1001", "usb_serial": "AA", "baud": 115200})
        self.assertTrue(ac.rule_matches(rule, "/dev/ttyACM7", {"usb_vid_pid": "303a:1001", "usb_serial": "AA"}))
        self.assertFalse(ac.rule_matches(rule, "/dev/ttyACM7", {"usb_vid_pid": "303a:1001", "usb_serial": "BB"}))
        self.assertFalse(ac.rule_matches(rule, "/dev/ttyACM7", {"usb_vid_pid": "10c4:ea60", "usb_serial": "AA"}))

    def test_a_rule_without_a_serial_matches_any_board_of_that_model(self):
        rule = ac.clean_rule({"usb_vid_pid": "303a:1001", "baud": 115200})
        self.assertTrue(ac.rule_matches(rule, "/dev/ttyACM0", {"usb_vid_pid": "303a:1001", "usb_serial": "ZZ"}))

    def test_a_rule_with_an_interface_opens_only_that_port_of_a_composite_board(self):
        rule = ac.clean_rule({"usb_vid_pid": "1a86:55d2", "usb_serial": "AA", "usb_interface": "00",
                              "baud": 2000000})
        self.assertEqual(rule["usb_interface"], "00")
        board = {"usb_vid_pid": "1a86:55d2", "usb_serial": "AA"}
        self.assertTrue(ac.rule_matches(rule, "/dev/ttyACM0", {**board, "usb_interface": "00"}))
        self.assertFalse(ac.rule_matches(rule, "/dev/ttyACM1", {**board, "usb_interface": "02"}))
        self.assertFalse(ac.rule_matches(rule, "/dev/ttyACM1", board))  # interface unreadable
        # A rule saved before interfaces existed keeps matching every port of the board.
        old = ac.clean_rule({"usb_vid_pid": "1a86:55d2", "usb_serial": "AA", "baud": 2000000})
        self.assertEqual(old["usb_interface"], "")
        self.assertTrue(ac.rule_matches(old, "/dev/ttyACM1", {**board, "usb_interface": "02"}))

    def test_an_interface_needs_a_usb_identity_and_two_hex_digits(self):
        for bad in ({"usb_interface": "00", "port": "/dev/ttyS3"}, {"usb_vid_pid": "1a86:55d2", "usb_interface": "zz"},
                    {"usb_vid_pid": "1a86:55d2", "usb_interface": "0"}):
            with self.assertRaises(ac.SettingsError, msg=str(bad)):
                ac.clean_rule({"baud": 115200, **bad})

    def test_a_path_rule_is_only_for_devices_without_usb_identity(self):
        rule = ac.clean_rule({"port": "/dev/ttyS3", "baud": 9600})
        self.assertTrue(ac.rule_matches(rule, "/dev/ttyS3", {}))
        self.assertFalse(ac.rule_matches(rule, "/dev/ttyS4", {}))

    def test_a_disabled_rule_never_matches(self):
        rule = ac.clean_rule({"port": "/dev/ttyS3", "baud": 9600, "enabled": False})
        self.assertFalse(ac.rule_matches(rule, "/dev/ttyS3", {}))


class RuleWatcherTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.settings = ac.Settings(JsonFile("settings.json", ac.DEFAULTS, Path(self.dir.name)))
        self.settings.update(rules=[{"usb_vid_pid": "303a:1001", "baud": 2000000, "mode": "control"}])
        self.present = []
        self.opened = set()
        self.connected = []
        self.identities = {"/dev/ttyACM0": {"usb_vid_pid": "303a:1001", "usb_serial": "AA"},
                           "/dev/ttyUSB0": {"usb_vid_pid": "10c4:ea60", "usb_serial": "BB"}}
        self.watcher = ac.RuleWatcher(
            self.settings, lambda: list(self.present), lambda p: self.identities.get(p, {}),
            lambda p: p in self.opened, lambda p, rule: self.connected.append((p, rule["baud"], rule["mode"])))

    def test_connects_a_matching_device_with_the_rule_settings(self):
        self.present = ["/dev/ttyACM0", "/dev/ttyUSB0"]
        self.assertEqual(self.watcher.poll(), ["/dev/ttyACM0"])
        self.assertEqual(self.connected, [("/dev/ttyACM0", 2000000, "control")])

    def test_acts_once_per_plug_so_disconnect_is_not_fought(self):
        self.present = ["/dev/ttyACM0"]
        self.watcher.poll()
        self.watcher.poll()
        self.watcher.poll()
        self.assertEqual(len(self.connected), 1)

    def test_a_replug_is_eligible_again(self):
        self.present = ["/dev/ttyACM0"]
        self.watcher.poll()
        self.present = []
        for _ in range(ac.EMPTY_POLLS_BEFORE_FORGET):  # a single empty listing could be a glitch
            self.watcher.poll()
        self.present = ["/dev/ttyACM0"]
        self.watcher.poll()
        self.assertEqual(len(self.connected), 2)

    def test_a_port_already_open_is_left_alone(self):
        self.present = ["/dev/ttyACM0"]
        self.opened.add("/dev/ttyACM0")
        self.assertEqual(self.watcher.poll(), [])

    def test_no_rules_means_nothing_is_opened(self):
        self.settings.update(rules=[])
        self.present = ["/dev/ttyACM0"]
        self.assertEqual(self.watcher.poll(), [])
        self.assertEqual(self.connected, [])

    def test_a_failing_connect_does_not_stop_the_watcher(self):
        def boom(port, rule):
            raise RuntimeError("busy")
        self.watcher.connect = boom
        self.present = ["/dev/ttyACM0"]
        self.assertEqual(self.watcher.poll(), [])

    def test_a_busy_port_is_retried_a_few_times_then_left_alone(self):
        attempts = []

        def busy(port, rule):
            attempts.append(port)
            raise RuntimeError("busy")
        self.watcher.connect = busy
        self.present = ["/dev/ttyACM0"]
        for _ in range(10):
            self.watcher.poll()
        self.assertEqual(len(attempts), ac.MAX_OPEN_ATTEMPTS)  # each open may reset the board
        self.present = []
        for _ in range(ac.EMPTY_POLLS_BEFORE_FORGET):
            self.watcher.poll()
        self.present = ["/dev/ttyACM0"]  # unplugged and back: a fresh start
        self.watcher.poll()
        self.assertEqual(len(attempts), ac.MAX_OPEN_ATTEMPTS + 1)

    def test_an_empty_listing_between_failures_does_not_refill_the_retry_budget(self):
        attempts = []

        def busy(port, rule):
            attempts.append(port)
            raise RuntimeError("busy")
        self.watcher.connect = busy
        for _ in range(6):  # two failed opens, one glitchy empty listing, repeat
            self.present = ["/dev/ttyACM0"]
            self.watcher.poll()
            self.watcher.poll()
            self.present = []
            self.watcher.poll()
        self.assertLessEqual(len(attempts), ac.MAX_OPEN_ATTEMPTS)

    def test_a_later_success_after_a_busy_open_is_acted_on_once(self):
        outcomes = [RuntimeError("busy"), None]

        def flaky(port, rule):
            outcome = outcomes.pop(0)
            if outcome:
                raise outcome
            self.connected.append(port)
        self.watcher.connect = flaky
        self.present = ["/dev/ttyACM0"]
        self.assertEqual(self.watcher.poll(), [])
        self.assertEqual(self.watcher.poll(), ["/dev/ttyACM0"])
        self.assertEqual(self.watcher.poll(), [])

    def test_a_port_opened_by_someone_else_is_not_reopened_after_their_disconnect(self):
        self.present = ["/dev/ttyACM0"]
        self.opened.add("/dev/ttyACM0")  # user connected it by hand
        self.watcher.poll()
        self.opened.discard("/dev/ttyACM0")  # ... and pressed Disconnect
        self.assertEqual(self.watcher.poll(), [])
        self.assertEqual(self.connected, [])

    def test_one_empty_listing_does_not_forget_what_was_handled(self):
        self.present = ["/dev/ttyACM0"]
        self.watcher.poll()
        self.present = []  # a failed enumeration, not an unplug
        self.watcher.poll()
        self.present = ["/dev/ttyACM0"]
        self.watcher.poll()
        self.assertEqual(len(self.connected), 1)

    def test_a_real_unplug_is_noticed_after_consecutive_empty_listings(self):
        self.present = ["/dev/ttyACM0"]
        self.watcher.poll()
        self.present = []
        for _ in range(ac.EMPTY_POLLS_BEFORE_FORGET):
            self.watcher.poll()
        self.present = ["/dev/ttyACM0"]
        self.watcher.poll()
        self.assertEqual(len(self.connected), 2)

class RestoreTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        patcher = patch.dict(os.environ, {"SERIAL_DECK_CONFIG": self.dir.name})
        patcher.start()
        self.addCleanup(patcher.stop)

    def manager(self, ports):
        bridge = DeckWebBridge(default_port="", hub_manager=MagicMock())
        bridge.list_ports = lambda: list(ports)
        calls = []
        bridge.connect = lambda port, baud, mode=None, *a, **k: (calls.append((port, baud, mode)), setattr(bridge, "connected", True), setattr(bridge, "port", port))
        manager = ConnectionManager(bridge, MagicMock(), 115200, "")
        return manager, calls

    def test_restore_is_off_by_default_even_with_remembered_ports(self):
        manager, calls = self.manager(["/dev/ttyACM0"])
        manager.settings.update(last_ports=[{"port": "/dev/ttyACM0", "baud": 9600, "mode": "linux"}])
        self.assertEqual(manager.restore_last_session(), [])
        self.assertEqual(calls, [])

    def test_restore_reopens_the_remembered_ports_when_opted_in(self):
        manager, calls = self.manager(["/dev/ttyACM0"])
        manager.settings.update(restore_on_start=True,
                                last_ports=[{"port": "/dev/ttyACM0", "baud": 9600, "mode": "control"}])
        self.assertEqual(manager.restore_last_session(), ["/dev/ttyACM0"])
        self.assertEqual(calls, [("/dev/ttyACM0", 9600, "control")])

    def test_restore_skips_a_port_that_is_gone_without_failing(self):
        manager, calls = self.manager([])
        manager.settings.update(restore_on_start=True,
                                last_ports=[{"port": "/dev/ttyACM0", "baud": 9600, "mode": "linux"}])
        self.assertEqual(manager.restore_last_session(), [])

    def test_restore_keeps_a_board_that_is_not_plugged_in_yet(self):
        manager, calls = self.manager(["/dev/ttyACM0"])
        here = {"port": "/dev/ttyACM0", "baud": 9600, "mode": "linux"}
        away = {"port": "/dev/ttyACM5", "baud": 2000000, "mode": "control",
                "usb_vid_pid": "1a86:55d2", "usb_serial": "BB", "usb_interface": "00"}
        manager.settings.update(restore_on_start=True, last_ports=[here, away])
        bridge = manager.get("default")
        with patch.object(DeckWebBridge, "_remember_device", lambda self_, port, baud: setattr(
                self_, "_remembered", {**here, "usb_vid_pid": "", "usb_serial": "", "usb_interface": ""})):
            bridge.connect = lambda port, baud, mode=None, *a, **k: (
                calls.append(port), setattr(bridge, "connected", True), setattr(bridge, "port", port),
                bridge._remember_device(port, baud), bridge._session_changed())
            self.assertEqual(manager.restore_last_session(), ["/dev/ttyACM0"])
        saved = manager.settings.get()["last_ports"]
        self.assertEqual([item["port"] for item in saved], ["/dev/ttyACM0", "/dev/ttyACM5"])  # not forgotten

    def open_one(self, manager, bridge, identity):
        """Make `bridge` look like it just connected a port with this USB identity."""
        def connect(port, baud, mode=None, *a, **k):
            bridge.connected, bridge.port = True, port
            bridge._remembered = {"port": port, "baud": baud, "mode": mode or "linux", **identity}
            bridge._session_changed()
        bridge.connect = connect

    def test_a_legacy_entry_is_not_duplicated_by_its_restored_twin(self):
        saved = [{"port": f"/dev/ttyACM{i}", "baud": 9600, "mode": "linux", "usb_vid_pid": "1a86:55d2",
                  "usb_serial": f"S{i}", "usb_interface": ""} for i in range(8)]
        manager, _ = self.manager(["/dev/ttyACM0"])
        bridge = manager.get("default")
        manager.settings.update(restore_on_start=True, last_ports=saved)
        self.open_one(manager, bridge, {"usb_vid_pid": "1a86:55d2", "usb_serial": "S0", "usb_interface": "00"})
        table = {"/dev/ttyACM0": {"usb_vid_pid": "1a86:55d2", "usb_serial": "S0", "usb_interface": "00"}}
        with patch.object(uart_client, "usb_identity", lambda d: table.get(d, {})):
            self.assertEqual(manager.restore_last_session(), ["/dev/ttyACM0"])
        serials = [item["usb_serial"] for item in manager.settings.get()["last_ports"]]
        self.assertEqual(serials, [f"S{i}" for i in range(8)])  # one entry per board, none dropped

    def test_a_board_not_restored_survives_later_connects_and_disconnects(self):
        away = {"port": "/dev/ttyACM5", "baud": 9600, "mode": "linux", "usb_vid_pid": "1a86:55d2",
                "usb_serial": "BB", "usb_interface": "00"}
        manager, _ = self.manager([])
        bridge = manager.get("default")
        manager.settings.update(restore_on_start=True, last_ports=[away])
        manager.restore_last_session()
        self.open_one(manager, bridge, {"usb_vid_pid": "", "usb_serial": "", "usb_interface": ""})
        bridge.connect("/dev/ttyUSB0", 115200, "linux")  # an unrelated connection
        self.assertIn("BB", [i["usb_serial"] for i in manager.settings.get()["last_ports"]])
        bridge.connected = False  # ... and its Disconnect
        manager.remember_session()
        self.assertEqual([i["usb_serial"] for i in manager.settings.get()["last_ports"]], ["BB"])

    def test_a_disconnect_right_after_a_restore_is_not_brought_back(self):
        saved = {"port": "/dev/ttyACM0", "baud": 9600, "mode": "linux", "usb_vid_pid": "",
                 "usb_serial": "", "usb_interface": ""}
        manager, _ = self.manager(["/dev/ttyACM0"])
        bridge = manager.get("default")
        manager.settings.update(restore_on_start=True, last_ports=[saved])
        self.open_one(manager, bridge, {"usb_vid_pid": "", "usb_serial": "", "usb_interface": ""})
        manager.restore_last_session()
        bridge.connected = False  # the user presses Disconnect
        manager.remember_session()
        self.assertEqual(manager.settings.get()["last_ports"], [])

    def test_restore_follows_the_saved_interface_to_its_new_tty(self):
        table = {"/dev/ttyACM4": {"usb_vid_pid": "1a86:55d2", "usb_serial": "BB", "usb_interface": "00"},
                 "/dev/ttyACM5": {"usb_vid_pid": "1a86:55d2", "usb_serial": "BB", "usb_interface": "02"}}
        manager, calls = self.manager(list(table))
        saved = {"port": "/dev/ttyACM2", "baud": 2000000, "mode": "control",
                 "usb_vid_pid": "1a86:55d2", "usb_serial": "BB", "usb_interface": "02"}
        manager.settings.update(restore_on_start=True, last_ports=[saved])
        with patch.object(uart_client, "usb_identity", lambda device: table.get(device, {})):
            self.assertEqual(manager.restore_last_session(), ["/dev/ttyACM5"])
        self.assertEqual(calls, [("/dev/ttyACM5", 2000000, "control")])

    def test_the_open_ports_are_remembered_and_a_user_close_forgets_them(self):
        manager, _ = self.manager(["/dev/ttyACM0"])
        bridge = manager.get("default")
        bridge.connected = True
        bridge._remembered = {"port": "/dev/ttyACM0", "baud": 9600, "mode": "linux",
                              "usb_vid_pid": "", "usb_serial": ""}
        manager.remember_session()
        self.assertEqual(manager.settings.get()["last_ports"][0]["port"], "/dev/ttyACM0")
        bridge.connected = False
        manager.remember_session()
        self.assertEqual(manager.settings.get()["last_ports"], [])


if __name__ == "__main__":
    unittest.main()


class SettingsEndpointTest(unittest.TestCase):
    """The settings POST starts connecting devices: it needs the page's token."""

    def test_saving_settings_needs_the_dashboard_token(self):
        from serial_deck import web
        handler = type("H", (), {"headers": {"X-Deck-Action": ""}, "action_token": "tok"})()
        self.assertFalse(web.DeckHttpHandler._action_token_ok(handler))
        handler.headers = {"X-Deck-Action": "tok"}
        self.assertTrue(web.DeckHttpHandler._action_token_ok(handler))
