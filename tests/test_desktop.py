import tempfile
import unittest
from pathlib import Path

from serial_deck.desktop import (
    ElfSymbolizer,
    ControlDeck,
    auto_find_elf,
    log_filter_key,
    parse_flash_progress,
    should_symbolize_log,
)


class DesktopMonitorTest(unittest.TestCase):
    def test_log_level_colors(self):
        self.assertEqual(ControlDeck._log_tag("E (123) panic: failed"), "error")
        self.assertEqual(ControlDeck._log_tag("W (123) wifi: retry"), "warning")
        self.assertEqual(ControlDeck._log_tag("I (123) app: ready"), "info")
        self.assertEqual(ControlDeck._log_tag("D (123) app: state"), "debug")
        self.assertEqual(ControlDeck._log_tag("V (123) app: verbose"), "verbose")
        self.assertIsNone(ControlDeck._log_tag("plain console text"))
        self.assertEqual(log_filter_key(None), "plain")
        self.assertEqual(log_filter_key("error"), "error")

    def test_flash_progress_parsing(self):
        pct, step = parse_flash_progress("Writing at 0x00010000... (68 %)")
        self.assertEqual(pct, 68)
        self.assertEqual(step, "Writing")

        pct, step = parse_flash_progress("\x1b[KWriting at 0x0034ed24 ... 66.8%\x1b[K")
        self.assertEqual(pct, 66.8)
        self.assertEqual(step, "Writing")

        pct, step = parse_flash_progress("Connecting....")
        self.assertIsNone(pct)
        self.assertEqual(step, "Connecting")

    def test_symbolizer_only_runs_for_crash_logs(self):
        self.assertFalse(should_symbolize_log('{"tag":"ws_rx","payload":{"hex":"5003"}}'))
        self.assertTrue(should_symbolize_log("Guru Meditation Error: Backtrace: 0x40001234"))

    def test_auto_find_elf(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            elf_file = tmp / "app.elf"
            elf_file.touch()
            self.assertEqual(auto_find_elf(str(tmp)), str(elf_file.resolve()))

    def test_missing_elf_is_rejected(self):
        with self.assertRaises(ValueError):
            ElfSymbolizer("/tmp/serial-deck-missing.elf")


if __name__ == "__main__":
    unittest.main()
