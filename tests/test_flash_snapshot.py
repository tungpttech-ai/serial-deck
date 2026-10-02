"""Flash snapshot policy: immutable copies and region rules, no hardware."""

import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from serial_deck import flash
from serial_deck import flash_snapshot as snap

TABLE = Path(__file__).with_name("fixtures") / "esp_partitions" / "partition-table.bin"

def write_build(root: Path, files=None, chip="esp32p4") -> Path:
    """An ESP-IDF build with a typical OTA partition table (nvs 0x9000, ota_0 0x10000)."""
    build = root / "build"
    (build / "bootloader").mkdir(parents=True)
    (build / "partition_table").mkdir()
    (build / "bootloader" / "bootloader.bin").write_bytes(b"B" * 23088)
    (build / "partition_table" / "partition-table.bin").write_bytes(TABLE.read_bytes())
    (build / "ota_data_initial.bin").write_bytes(b"\xff" * 8192)
    (build / "app.bin").write_bytes(b"A" * 4096)
    manifest = {
        "flash_settings": {"flash_mode": "dio", "flash_size": "16MB", "flash_freq": "80m"},
        "flash_files": files or {
            "0x2000": "bootloader/bootloader.bin",
            "0x8000": "partition_table/partition-table.bin",
            "0xd000": "ota_data_initial.bin",
            "0x10000": "app.bin",
        },
        "bootloader": {"offset": "0x2000", "file": "bootloader/bootloader.bin", "encrypted": "false"},
        "partition-table": {"offset": "0x8000", "file": "partition_table/partition-table.bin",
                            "encrypted": "false"},
        "otadata": {"offset": "0xd000", "file": "ota_data_initial.bin", "encrypted": "false"},
        "app": {"offset": "0x10000", "file": "app.bin", "encrypted": "false"},
        "extra_esptool_args": {"chip": chip, "stub": True},
    }
    (build / "flasher_args.json").write_text(json.dumps(manifest))
    (build / "project_description.json").write_text(json.dumps(
        {"project_name": "demo", "project_version": "1.2.3", "target": "esp32p4"}))
    return build

class PartitionTableTest(unittest.TestCase):
    def test_parses_real_esp_idf_table(self):
        parts = {p.name: p for p in snap.parse_partition_table(TABLE.read_bytes())}
        self.assertEqual(parts["nvs"].offset, 0x9000)
        self.assertEqual(parts["nvs"].kind, "data")
        self.assertEqual(parts["otadata"].kind, "ota_data")
        self.assertEqual((parts["ota_0"].offset, parts["ota_0"].kind), (0x10000, "app"))
        self.assertEqual(parts["coredump"].size, 0x80000)

    def test_rejects_bad_magic(self):
        data = bytearray(TABLE.read_bytes())
        data[0:2] = b"\x50\xaa"  # big-endian magic is not a valid entry
        with self.assertRaises(snap.FlashPolicyError):
            snap.parse_partition_table(bytes(data))

class SnapshotTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="pk-snap-")
        self.root = Path(self.temp.name)
        self.store = self.root / "store"
        self.store.mkdir(mode=0o700)

    def tearDown(self):
        self.temp.cleanup()

    def test_snapshot_copies_images_and_rewrites_manifest(self):
        build = write_build(self.root)
        snapshot = snap.prepare_snapshot(str(build), root=self.store)
        roles = [image.role for image in snapshot.images]
        self.assertEqual(roles, ["bootloader", "partition-table", "ota_data:otadata", "app:ota_0"])
        self.assertEqual(snapshot.project["project_version"], "1.2.3")
        self.assertEqual(snapshot.state()["state"], "prepared")
        manifest = json.loads((snapshot.directory / "flasher_args.json").read_text())
        self.assertTrue(all(path.startswith("images/") for path in manifest["flash_files"].values()))
        with patch.object(flash.shutil, "which", return_value="/usr/bin/esptool"):
            command = flash.build_flash_command("/dev/ttyACM0", str(snapshot.directory))
        self.assertTrue(snap.command_paths_inside(command, snapshot.directory))
        # Editing the build afterwards cannot change what would be written.
        (build / "app.bin").write_bytes(b"EVIL")
        snapshot.verify()
        self.assertEqual(Path(snapshot.images[-1].path).read_bytes(), b"A" * 4096)
        Path(snapshot.images[-1].path).write_bytes(b"EVIL")
        with self.assertRaisesRegex(snap.FlashPolicyError, "changed"):
            snapshot.verify()

    def test_refuses_nvs_absolute_paths_escapes_and_other_chips(self):
        cases = {
            "nvs": {"0x9000": "app.bin"},
            "coredump": {"0xf80000": "app.bin"},
            "unmapped": {"0x1000000": "app.bin"},
            "overflow": {"0x0fff000": "app.bin"},
        }
        for name, files in cases.items():
            with self.subTest(name), tempfile.TemporaryDirectory() as temp:
                build = write_build(Path(temp), files={"0x8000": "partition_table/partition-table.bin", **files})
                with self.assertRaisesRegex(snap.FlashPolicyError, "refusing|lands"):
                    snap.prepare_snapshot(str(build), root=self.store)
        with tempfile.TemporaryDirectory() as temp:
            outside = Path(temp) / "outside.bin"
            outside.write_bytes(b"X")
            build = write_build(Path(temp), files={"0x10000": str(outside)})
            with self.assertRaisesRegex(snap.FlashPolicyError, "inside build_dir"):
                snap.prepare_snapshot(str(build), root=self.store)
            build2 = write_build(Path(temp) / "b2", files={"0x10000": "../../outside.bin"})
            with self.assertRaisesRegex(snap.FlashPolicyError, "inside build_dir"):
                snap.prepare_snapshot(str(build2), root=self.store)
        with tempfile.TemporaryDirectory() as temp:
            build = write_build(Path(temp), chip="stm32f4")
            with self.assertRaisesRegex(snap.FlashPolicyError, "ESP32-family"):
                snap.prepare_snapshot(str(build), root=self.store)
        with self.assertRaisesRegex(snap.FlashPolicyError, "absolute"):
            snap.prepare_snapshot("relative/build", root=self.store)
        self.assertEqual(list(self.store.iterdir()), [])

    def test_refuses_overlapping_images(self):
        build = write_build(self.root, files={"0x10000": "app.bin", "0x10800": "app.bin",
                                              "0x8000": "partition_table/partition-table.bin"})
        with self.assertRaisesRegex(snap.FlashPolicyError, "overlaps"):
            snap.prepare_snapshot(str(build), root=self.store)

class SnapshotCollectionTest(unittest.TestCase):
    def status(self, active=False, flash_id=3, channel="/c.sock", pid=None):
        return {"pid": pid or os.getpid(), "channels": [
            {"channel_socket": channel, "flash": {"active": active, "id": flash_id}}]}

    def state(self, kind, **extra):
        return {"state": kind, "hub_pid": os.getpid(), "hub_socket": "/h.sock",
                "channel_socket": "/c.sock", "updated": time.time(), **extra}

    def test_prepared_only_after_expiry(self):
        self.assertFalse(snap.snapshot_collectable({"state": "prepared", "expires": time.time() + 60},
                                                   lambda _: None))
        self.assertTrue(snap.snapshot_collectable({"state": "prepared", "expires": time.time() - 1},
                                                  lambda _: None))

    def test_in_use_waits_for_hub_evidence(self):
        state = self.state("in_use", flash_id=3)
        self.assertFalse(snap.snapshot_collectable(state, lambda _: self.status(active=True)))
        self.assertFalse(snap.snapshot_collectable(state, lambda _: None))
        self.assertTrue(snap.snapshot_collectable(state, lambda _: self.status(active=False)))
        self.assertTrue(snap.snapshot_collectable(state, lambda _: self.status(channel="/other")))
        self.assertTrue(snap.snapshot_collectable({**state, "hub_pid": 2 ** 22 + 7}, lambda _: None))

    def test_sending_with_lost_reply_is_kept_until_id_moves(self):
        state = self.state("sending", flash_id_before=2)
        self.assertFalse(snap.snapshot_collectable(state, lambda _: self.status(active=True, flash_id=3)))
        self.assertFalse(snap.snapshot_collectable(state, lambda _: self.status(flash_id=2)))
        self.assertTrue(snap.snapshot_collectable(state, lambda _: self.status(flash_id=3)))
        old = {**state, "updated": time.time() - snap.UNACCEPTED_GRACE - 1}
        self.assertTrue(snap.snapshot_collectable(old, lambda _: self.status(flash_id=2)))

    def test_stateless_directory_is_kept(self):
        self.assertFalse(snap.snapshot_collectable({}, lambda _: None))

if __name__ == "__main__":
    unittest.main()
