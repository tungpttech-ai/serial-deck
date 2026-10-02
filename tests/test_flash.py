import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from serial_deck.flash import build_flash_command


class FlashCommandTest(unittest.TestCase):
    def test_manifest_and_selected_baud_build_command(self):
        with tempfile.TemporaryDirectory() as directory:
            build = Path(directory)
            (build / "app.bin").write_bytes(b"app")
            (build / "boot.bin").write_bytes(b"boot")
            (build / "flasher_args.json").write_text(json.dumps({
                "flash_settings": {"flash_mode": "dio", "flash_freq": "80m", "flash_size": "16MB"},
                "flash_files": {"0x10000": "app.bin", "0x2000": "boot.bin"},
                "extra_esptool_args": {"chip": "esp32s3"},
            }), encoding="utf-8")
            with patch("serial_deck.flash.find_esptool", return_value="/fake/esptool"):
                command = build_flash_command("/dev/ttyACM0", directory, 921600)
        self.assertIn("921600", command)
        self.assertEqual(command[command.index("--chip") + 1], "esp32s3")  # from the manifest
        self.assertLess(command.index("0x2000"), command.index("0x10000"))

    def test_manifest_without_esp32_chip_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            build = Path(directory)
            (build / "app.bin").write_bytes(b"app")
            (build / "flasher_args.json").write_text(json.dumps({
                "flash_files": {"0x10000": "app.bin"}, "extra_esptool_args": {"chip": "rp2040"},
            }), encoding="utf-8")
            with patch("serial_deck.flash.find_esptool", return_value="/fake/esptool"), \
                    self.assertRaisesRegex(ValueError, "no ESP32 chip"):
                build_flash_command("/dev/ttyACM0", directory, 921600)


if __name__ == "__main__":
    unittest.main()
