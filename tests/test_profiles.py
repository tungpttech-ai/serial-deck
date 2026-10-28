"""Device profiles: JSON presets for SSH devices, data only."""

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from serial_deck import profiles
from serial_deck.mcp_server import build_server, main as mcp_main

GOOD = {"label": "My board", "remote_socket": "/run/svc.sock.stream", "control_socket": "/run/svc.sock",
        "screen_path": "/api/screen?format=jpeg", "restart_args": ["a", "b"],
        "follow_socket_suffix": ".stream", "screen_revision_header": "X-Rev",
        "mcp_tool_prefix": "board", "default_baud": 2000000, "default_mode": "control"}


class ProfileTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        env = patch.dict(os.environ, {"SERIAL_DECK_PROFILE_DIR": self.dir.name})
        env.start()
        self.addCleanup(env.stop)

    def write(self, name, data):
        text = data if isinstance(data, str) else json.dumps(data)
        (Path(self.dir.name) / f"{name}.json").write_text(text)

    def test_a_good_profile_loads_with_its_name_and_label(self):
        self.write("board", GOOD)
        found, problems = profiles.load_all()
        self.assertEqual(problems, {})
        self.assertEqual(found["board"]["label"], "My board")
        self.assertEqual(found["board"]["default_mode"], "control")
        self.assertEqual(found["board"]["restart_args"], ["a", "b"])

    def test_the_default_directory_is_under_the_config_dir(self):
        with patch.dict(os.environ, {"SERIAL_DECK_PROFILE_DIR": "", "SERIAL_DECK_CONFIG": "/x/cfg"}):
            self.assertEqual(profiles.profile_dir(), Path("/x/cfg/profiles"))

    def test_a_missing_directory_is_just_empty(self):
        with patch.dict(os.environ, {"SERIAL_DECK_PROFILE_DIR": self.dir.name + "/nope"}):
            self.assertEqual(profiles.load_all(), ({}, {}))

    def test_unknown_keys_are_refused_not_ignored(self):
        self.write("typo", {**GOOD, "restart_cmd": "rm -rf /"})  # a command must never ride in a profile
        found, problems = profiles.load_all()
        self.assertEqual(found, {})
        self.assertIn("unknown profile keys: restart_cmd", problems["typo.json"])

    def test_values_go_through_the_pairing_validation(self):
        for bad in ({"remote_socket": "relative"}, {"screen_path": "http://x/"}, {"restart_args": ["a b"]},
                    {"follow_socket_suffix": "stream"}, {"mcp_tool_prefix": "Bad-Prefix"},
                    {"default_baud": 5}, {"default_mode": "windows"}, {"label": "a\nb"}, {"user": "Root!"}):
            with self.assertRaises(profiles.ProfileError, msg=str(bad)):
                profiles.clean("p", {**GOOD, **bad})
        with self.assertRaises(profiles.ProfileError):
            profiles.clean("p", [])
        with self.assertRaises(profiles.ProfileError):
            profiles.clean("../x", GOOD)

    def test_a_broken_file_does_not_hide_the_others(self):
        self.write("good", GOOD)
        self.write("broken", "{not json")
        self.write("huge", {"label": "x" * (profiles.MAX_BYTES + 10)})
        found, problems = profiles.load_all()
        self.assertEqual(list(found), ["good"])
        self.assertEqual(sorted(problems), ["broken.json", "huge.json"])

    def test_a_profile_without_a_socket_is_allowed_for_prefix_and_defaults_only(self):
        self.write("prefix-only", {"mcp_tool_prefix": "board"})
        self.assertIn("prefix-only", profiles.load_all()[0])


class ProfileHubTest(unittest.TestCase):
    def test_the_hub_lists_profiles_and_their_problems(self):
        from serial_deck.service import MultiPortHub
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "board.json").write_text(json.dumps(GOOD))
            (Path(directory) / "bad.json").write_text("{}x")
            with patch.dict(os.environ, {"SERIAL_DECK_PROFILE_DIR": directory,
                                         "SERIAL_DECK_CONFIG": directory,
                                         "SERIAL_DECK_RUNTIME_DIR": directory}):
                hub = MultiPortHub(str(Path(directory) / "hub.sock"))
                result = hub._ssh_action("ssh_profiles", {})
        self.assertTrue(result["ok"])
        self.assertEqual([p["name"] for p in result["profiles"]], ["board"])
        self.assertEqual(list(result["problems"]), ["bad.json"])


class McpProfileTest(unittest.TestCase):
    def run_main(self, args, directory):
        seen = []
        with patch.dict(os.environ, {"SERIAL_DECK_PROFILE_DIR": directory}), \
                patch("serial_deck.mcp_server.build_server", lambda agent, prefix="serial": (
                    seen.append(prefix), type("S", (), {"run": lambda self, mode: None})())[1]), \
                patch("serial_deck.mcp_server.DeckAgent"):
            code = mcp_main(args)
        return code, seen

    def test_the_profile_supplies_the_tool_prefix_unless_one_is_given(self):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "board.json").write_text(json.dumps(GOOD))
            self.assertEqual(self.run_main(["--profile", "board", "--no-activity"], directory), (0, ["board"]))
            self.assertEqual(self.run_main(["--profile", "board", "--tool-prefix", "x", "--no-activity"],
                                           directory), (0, ["x"]))
            with self.assertRaises(SystemExit):
                self.run_main(["--profile", "missing", "--no-activity"], directory)


if __name__ == "__main__":
    unittest.main()
