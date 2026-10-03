"""Regression checks for executable identity in the bundle smoke test."""

import importlib.util
import tempfile
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "serial_deck_smoke_test", Path(__file__).resolve().parents[1] / "packaging" / "smoke_test.py")
smoke = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(smoke)


class McpExecutableTest(unittest.TestCase):
    def test_flag_wrapper_registration_uses_the_appimage(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wrapper = root / "sd-flagged"
            appimage = root / "SerialDeck-0.2.1-x86_64.AppImage"
            command = [str(appimage), "--appimage-extract-and-run", "mcp", "--allow", "observe"]
            with self.assertRaises(AssertionError):
                smoke.assert_mcp_executable(command, str(wrapper))
            smoke.assert_mcp_executable(command, str(appimage))
            self.assertEqual(command[1:], ["--appimage-extract-and-run", "mcp", "--allow", "observe"])

    def test_direct_bundles_and_sibling_console_executables(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, console in (("serial-deck", "serial-deck-cli"),
                                  ("serial-deck.exe", "serial-deck-cli.exe")):
                with self.subTest(name=name):
                    smoke.assert_mcp_executable([str(root / name), "mcp"], str(root / name))
                    smoke.assert_mcp_executable([str(root / console), "mcp"], str(root / name))
                    smoke.assert_mcp_executable([str(root / console), "mcp"], str(root / console))

    def test_rejects_interpreters_and_other_bundles(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            expected = root / "SerialDeck.AppImage"
            for executable in (root / "python3", root / "other" / expected.name,
                               root / "other" / "serial-deck-cli", root / "serial-deck-cli-unrelated"):
                with self.subTest(executable=executable), self.assertRaises(AssertionError):
                    smoke.assert_mcp_executable([str(executable), "mcp"], str(expected))


if __name__ == "__main__":
    unittest.main()
