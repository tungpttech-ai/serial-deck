#!/usr/bin/env python3
"""Immutable, policy-checked flash snapshots for agent-driven flashing.

An agent previews a build, the build is copied into a private snapshot whose
manifest points only at those copies, and the hub later flashes exactly that
snapshot. Only the bootloader, the partition table, OTA data and app images
may be written; NVS, PHY, storage, coredump and unmapped regions are refused.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shutil
import struct
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

try:
    from . import ipc
except ImportError:
    import ipc

ESP_PARTITION_MAGIC = 0x50AA  # stored little-endian: b"\xaa\x50"
PARTITION_ENTRY = struct.Struct("<HBBII16sI")
PARTITION_MD5_MAGIC = b"\xeb\xeb"
PARTITION_END = b"\xff\xff"
PARTITION_TABLE_MAX = 0x1000
TYPE_APP = 0x00
TYPE_DATA = 0x01
SUBTYPE_DATA_OTA = 0x00
SNAPSHOT_TTL = 600.0
# A request the hub never accepted leaves its flash id unchanged; the hub
# accepts synchronously, so this is ample before declaring it unused.
UNACCEPTED_GRACE = 60.0
STATE_FILE = "state.json"


class FlashPolicyError(ValueError):
    """The build cannot be flashed by an agent."""


@dataclass(frozen=True)
class Partition:
    name: str
    type: int
    subtype: int
    offset: int
    size: int

    @property
    def end(self) -> int:
        return self.offset + self.size

    @property
    def kind(self) -> str:
        if self.type == TYPE_APP:
            return "app"
        if self.type == TYPE_DATA and self.subtype == SUBTYPE_DATA_OTA:
            return "ota_data"
        return "data"


def parse_partition_table(data: bytes) -> list[Partition]:
    """Parse an ESP-IDF binary partition table (32-byte little-endian entries)."""
    partitions = []
    for index in range(0, len(data) - PARTITION_ENTRY.size + 1, PARTITION_ENTRY.size):
        entry = data[index:index + PARTITION_ENTRY.size]
        if entry[:2] == PARTITION_END:
            break
        if entry[:2] == PARTITION_MD5_MAGIC:
            continue
        magic, ptype, subtype, offset, size, name, _flags = PARTITION_ENTRY.unpack(entry)
        if magic != ESP_PARTITION_MAGIC:
            raise FlashPolicyError(f"invalid partition entry at byte {index}")
        partitions.append(Partition(name.rstrip(b"\0").decode("ascii", "replace"),
                                    ptype, subtype, offset, size))
    if not partitions:
        raise FlashPolicyError("partition table has no entries")
    return partitions


def _offset(value: Any) -> int:
    try:
        return int(str(value), 0)
    except ValueError:
        raise FlashPolicyError(f"invalid flash offset: {value!r}") from None


@dataclass
class FlashImage:
    offset: int
    role: str
    source: str
    path: str
    size: int
    sha256: str
    partition: str = ""

    def summary(self) -> dict[str, Any]:
        return {"offset": hex(self.offset), "role": self.role, "partition": self.partition,
                "file": Path(self.source).name, "size": self.size, "sha256": self.sha256}


def classify_images(manifest: dict[str, Any], images: list[tuple[int, str, int]],
                    partitions: list[Partition]) -> list[str]:
    """Label each `(offset, file name, size)` image, or raise when a write is not allowed."""
    def section(name: str) -> tuple[int | None, str]:
        info = manifest.get(name)
        if not isinstance(info, dict):
            return None, ""
        if str(info.get("encrypted", "false")).lower() == "true":
            raise FlashPolicyError(f"encrypted {name} images are not supported")
        return _offset(info["offset"]) if "offset" in info else None, str(info.get("file", ""))

    table_offset, table_file = section("partition-table")
    if table_offset is None:
        raise FlashPolicyError("manifest has no partition-table offset")
    boot_offset, boot_file = section("bootloader")
    for name in ("app", "otadata"):
        section(name)
    labels = []
    spans = []
    for offset, relative, size in images:
        end = offset + size
        if boot_offset == offset and Path(boot_file).name == relative:
            if end > table_offset:
                raise FlashPolicyError("bootloader image overlaps the partition table")
            label = "bootloader"
        elif offset == table_offset and Path(table_file).name == relative:
            if size > PARTITION_TABLE_MAX:
                raise FlashPolicyError("partition table image is too large")
            label = "partition-table"
        else:
            owner = next((p for p in partitions if p.offset <= offset and end <= p.end), None)
            if owner is None or owner.kind not in ("app", "ota_data"):
                where = f"partition '{owner.name}'" if owner else "an unmapped region"
                raise FlashPolicyError(
                    f"refusing to write {relative} at {hex(offset)}: it lands in {where}; "
                    "only bootloader, partition table, OTA data and app partitions are allowed")
            label = f"{owner.kind}:{owner.name}"
        for other_start, other_end, other in spans:
            if offset < other_end and other_start < end:
                raise FlashPolicyError(f"{relative} overlaps {other}")
        spans.append((offset, end, relative))
        labels.append(label)
    return labels


def snapshot_root() -> Path:
    # Every process of this user (MCP servers get a minimal environment) must
    # agree on the path, and nobody else may swap images in it.
    return ipc.private_dir(ipc.runtime_dir() / "flash-snapshots")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


@dataclass
class FlashSnapshot:
    token: str
    directory: Path
    build_dir: str
    images: list[FlashImage]
    project: dict[str, Any]
    created: float
    expires: float
    binding: dict[str, Any] = field(default_factory=dict)

    def state(self) -> dict[str, Any]:
        return read_state(self.directory)

    def set_state(self, state: str, **info: Any) -> None:
        write_state(self.directory, {**self.state(), **info, "state": state,
                                     "updated": time.time()})

    def verify(self) -> None:
        for image in self.images:
            path = Path(image.path)
            if not path.is_file() or _sha256(path) != image.sha256:
                raise FlashPolicyError(f"snapshot image changed: {path.name}")

    def remove(self) -> None:
        shutil.rmtree(self.directory, ignore_errors=True)


def read_state(directory: Path) -> dict[str, Any]:
    try:
        state = json.loads((directory / STATE_FILE).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return state if isinstance(state, dict) else {}


def write_state(directory: Path, state: dict[str, Any]) -> None:
    temp = directory / f".{STATE_FILE}.tmp"
    temp.write_text(json.dumps(state), encoding="utf-8")
    os.replace(temp, directory / STATE_FILE)


def prepare_snapshot(build_dir: str, root: Path | None = None,
                     ttl: float = SNAPSHOT_TTL) -> FlashSnapshot:
    build = Path(build_dir).expanduser()
    if not build.is_absolute():
        raise FlashPolicyError("build_dir must be an absolute path")
    build = build.resolve()
    try:
        manifest = json.loads((build / "flasher_args.json").read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise FlashPolicyError(f"missing ESP-IDF flash manifest: {build / 'flasher_args.json'}") from None
    except json.JSONDecodeError as exc:
        raise FlashPolicyError(f"invalid flash manifest: {exc}") from None
    chip = (manifest.get("extra_esptool_args") or {}).get("chip")
    if not isinstance(chip, str) or not re.fullmatch(r"esp32[a-z0-9]*", chip):
        raise FlashPolicyError(f"manifest chip is {chip!r}; an ESP32-family chip is required")
    files = manifest.get("flash_files")
    if not isinstance(files, dict) or not files:
        raise FlashPolicyError("flash manifest contains no flash files")

    sources = []
    for offset, relative in sorted(files.items(), key=lambda item: _offset(item[0])):
        relative_path = Path(str(relative))
        source = (build / relative_path).resolve()
        if relative_path.is_absolute() or not source.is_relative_to(build) or not source.is_file():
            raise FlashPolicyError(f"flash image must be a file inside build_dir: {relative}")
        sources.append((_offset(offset), source))
    table_info = manifest.get("partition-table") or {}
    table_source = (build / str(table_info.get("file", ""))).resolve()
    if not table_info.get("file") or not table_source.is_relative_to(build) or not table_source.is_file():
        raise FlashPolicyError("manifest partition table image is missing")

    token = secrets.token_urlsafe(18)
    directory = (root or snapshot_root()) / token
    (directory / "images").mkdir(mode=0o700, parents=True)
    created = time.time()
    # Written first so a concurrent collector never sees a stateless directory.
    write_state(directory, {"state": "prepared", "token": token, "created": created,
                            "expires": created + ttl, "build_dir": str(build)})
    try:
        copies = []
        for index, (offset, source) in enumerate(sources):
            target = directory / "images" / f"{index}-{source.name}"
            shutil.copyfile(source, target)
            copies.append((offset, source, target))
        table_copy = next((t for _, s, t in copies if s == table_source), None)
        if table_copy is None:
            table_copy = directory / "partition-table.bin"
            shutil.copyfile(table_source, table_copy)
        partitions = parse_partition_table(table_copy.read_bytes())
        labels = classify_images(manifest, [(offset, source.name, target.stat().st_size)
                                            for offset, source, target in copies], partitions)
        images = [FlashImage(offset, label, str(source), str(target), target.stat().st_size,
                             _sha256(target), label.split(":", 1)[-1] if ":" in label else "")
                  for (offset, source, target), label in zip(copies, labels)]
        rewritten = {**manifest,
                     "flash_files": {hex(image.offset): f"images/{Path(image.path).name}"
                                     for image in images}}
        (directory / "flasher_args.json").write_text(json.dumps(rewritten, indent=2), encoding="utf-8")
        description = build / "project_description.json"
        project: dict[str, Any] = {}
        if description.is_file():
            shutil.copyfile(description, directory / "project_description.json")
            try:
                data = json.loads(description.read_text(encoding="utf-8"))
                project = {key: data.get(key) for key in
                           ("project_name", "project_version", "target", "idf_ver") if key in data}
            except json.JSONDecodeError:
                pass
    except Exception:
        shutil.rmtree(directory, ignore_errors=True)
        raise
    return FlashSnapshot(token, directory, str(build), images, project, created, created + ttl)


def command_paths_inside(command: list[str], directory: Path) -> bool:
    """True when every image argument of an esptool command is inside `directory`."""
    try:
        start = command.index("write-flash") + 1
    except ValueError:
        return False
    args = command[start:]
    images = [arg for index, arg in enumerate(args)
              if index > 0 and args[index - 1].startswith("0x")]
    root = directory.resolve()
    return bool(images) and all(Path(arg).resolve().is_relative_to(root) for arg in images)


def _pid_alive(pid: Any) -> bool:
    return ipc.pid_alive(pid)


def snapshot_collectable(state: dict[str, Any], hub_status: Callable[[str], dict[str, Any] | None],
                         now: float | None = None) -> bool:
    """Decide from evidence (never age alone) whether the hub may still read a snapshot."""
    now = time.time() if now is None else now
    kind = state.get("state")
    if kind == "done":
        return True
    if kind == "prepared":
        return now > float(state.get("expires", 0))
    if kind not in ("sending", "in_use"):
        return False
    if not _pid_alive(state.get("hub_pid")):
        return True  # The process that could be flashing no longer exists.
    try:
        status = hub_status(str(state.get("hub_socket", "")))
    except (OSError, RuntimeError, ValueError):
        return False
    if not status or status.get("pid") != state.get("hub_pid"):
        return False
    channel = next((c for c in status.get("channels", [])
                    if c.get("channel_socket") == state.get("channel_socket")), None)
    if channel is None:
        return True  # Channels flashing are never reaped, so none is using it.
    flash = channel.get("flash") or {}
    if flash.get("active"):
        return False
    current = flash.get("id", 0)
    if kind == "in_use":
        return current >= int(state.get("flash_id", 0))
    before = int(state.get("flash_id_before", 0))
    return current > before or now - float(state.get("updated", now)) > UNACCEPTED_GRACE


def collect_snapshots(hub_status: Callable[[str], dict[str, Any] | None],
                      root: Path | None = None, keep: set[str] = frozenset()) -> list[str]:
    """Remove snapshots that are provably unused; return removed tokens."""
    try:
        root = root or snapshot_root()
    except (OSError, RuntimeError):
        return []
    removed = []
    for directory in root.iterdir():
        if not directory.is_dir() or directory.name in keep:
            continue
        if snapshot_collectable(read_state(directory), hub_status):
            shutil.rmtree(directory, ignore_errors=True)
            removed.append(directory.name)
    return removed
