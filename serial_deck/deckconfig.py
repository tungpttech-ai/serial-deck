"""Per-user Serial Deck configuration: one private directory, atomic 0600 files."""

from __future__ import annotations

import json
import os
import tempfile
import threading
from pathlib import Path
from typing import Any


def config_dir() -> Path:
    base = os.environ.get("SERIAL_DECK_CONFIG") or os.path.join(
        os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config"), "serial-deck")
    return Path(base)


def private_dir(path: Path) -> Path:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.name == "posix":
        os.chmod(path, 0o700)
    return path


def write_private(path: Path, text: str) -> None:
    """Atomic owner-only write next to `path`."""
    private_dir(path.parent)
    fd, temp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
        if os.name == "posix":
            os.chmod(temp, 0o600)
        os.replace(temp, path)
    except BaseException:
        try:
            os.unlink(temp)
        except FileNotFoundError:
            pass
        raise


class JsonFile:
    """A small versioned JSON document (`{"version": 1, ...}`) with a lock.

    A missing or unreadable file reads as `default`: a corrupt settings file must
    never stop the app from starting, and is replaced on the next save.
    """

    def __init__(self, name: str, default: dict[str, Any], root: Path | None = None) -> None:
        self.name = name
        self.default = default
        self._root = root
        self.lock = threading.RLock()

    @property
    def path(self) -> Path:
        return (self._root or config_dir()) / self.name

    def load(self) -> dict[str, Any]:
        with self.lock:
            try:
                data = json.loads(self.path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                return json.loads(json.dumps(self.default))
            return data if isinstance(data, dict) else json.loads(json.dumps(self.default))

    def save(self, data: dict[str, Any]) -> None:
        with self.lock:
            write_private(self.path, json.dumps({"version": 1, **data}, indent=2) + "\n")
