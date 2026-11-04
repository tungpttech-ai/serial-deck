"""Byte-bounded hot log cache backed by a private, shared SQLite archive.

Budgets cover cached records per process (RAM) and all streams in this directory
(disk), not the Python/browser heaps. Settings changes apply after restart.
"""
from __future__ import annotations

import atexit
import json
import logging
import os
import sqlite3
import threading
import time
import uuid
from collections import OrderedDict
from pathlib import Path

try:
    from .deckconfig import private_dir
except ImportError:
    from deckconfig import private_dir

MIB = 1024 * 1024
RETENTION_S = 48 * 3600
DEFAULTS = {"directory": "", "ram_mib": 64, "disk_mib": 1024}


def clean_settings(raw):
    if not isinstance(raw, dict):
        raise ValueError("log_cache must be an object")
    data = {**DEFAULTS, **raw}
    directory = data["directory"]
    if not isinstance(directory, str) or len(directory) > 4096 or any(ord(c) < 32 or ord(c) == 127 for c in directory):
        raise ValueError("cache directory must be a path without control characters")
    if directory and not Path(directory).expanduser().is_absolute():
        raise ValueError("cache directory must be absolute (or start with ~)")
    for name, low, high in (("ram_mib", 1, 4096), ("disk_mib", 16, 1048576)):
        if type(data[name]) is not int or not low <= data[name] <= high:
            raise ValueError(f"{name} must be {low}..{high}")
    return {key: data[key] for key in DEFAULTS}


SQLITE_FULL = 13  # sqlite3.SQLITE_FULL and exc.sqlite_errorcode need Python 3.11


def is_disk_full(exc):
    code = getattr(exc, "sqlite_errorcode", None)
    return code == SQLITE_FULL if code is not None else "database or disk is full" in str(exc)


def default_directory():
    return Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache") / "serial-deck" / "logs"


class LogCache:
    def __init__(self, settings=None):
        self.settings = clean_settings(settings or {})
        self.directory = Path(self.settings["directory"]).expanduser() if self.settings["directory"] else default_directory()
        self.ram_limit = self.settings["ram_mib"] * MIB
        self.disk_limit = self.settings["disk_mib"] * MIB
        self.lock = threading.RLock()
        self.hot = OrderedDict()
        self.hot_bytes = 0
        self.pending = OrderedDict()
        self.lost_records = 0
        self.error = ""
        self.db = None
        self.last_prune = 0.0

    def _open(self):
        if self.db is None:
            private_dir(self.directory)
            path = self.directory / "logs.sqlite3"
            fd = os.open(path, os.O_CREAT | os.O_WRONLY, 0o600)
            os.close(fd)
            if os.name == "posix":
                os.chmod(path, 0o600)
            db = sqlite3.connect(path, timeout=5, check_same_thread=False)
            try:
                db.execute("PRAGMA auto_vacuum=INCREMENTAL")
                db.execute("PRAGMA journal_mode=WAL")
                db.execute("PRAGMA synchronous=NORMAL")
                db.execute("PRAGMA cache_size=-1024")
                db.execute("PRAGMA wal_autocheckpoint=64")
                db.execute("PRAGMA journal_size_limit=0")
                # Leave room for bounded WAL transactions and SQLite bookkeeping.
                page_size = db.execute("PRAGMA page_size").fetchone()[0]
                self.max_pages = int(self.disk_limit * 0.85) // page_size
                db.execute(f"PRAGMA max_page_count={self.max_pages}")
                db.execute("CREATE TABLE IF NOT EXISTS logs (id INTEGER PRIMARY KEY, stream TEXT NOT NULL, "
                           "seq INTEGER NOT NULL, created REAL NOT NULL, label TEXT NOT NULL, data BLOB NOT NULL)")
                db.execute("CREATE UNIQUE INDEX IF NOT EXISTS stream_seq ON logs(stream, seq)")
                db.execute("CREATE INDEX IF NOT EXISTS log_age ON logs(created)")
                db.commit()
            except BaseException:
                db.close()
                raise
            self.db = db
        return self.db

    def _failed(self, exc):
        message = str(exc)
        if message != self.error:
            logging.getLogger(__name__).error("Log archive unavailable; keeping recent logs in RAM: %s", message)
        self.error = message

    def _prune(self, force=False):
        db = self._open()
        now = time.time()
        if not force and now - self.last_prune < 1:
            return
        # Small committed batches keep WAL growth bounded even after a long idle.
        while True:
            deleted = db.execute("DELETE FROM logs WHERE id IN (SELECT id FROM logs WHERE created < ? LIMIT 256)",
                                 (now - RETENTION_S,)).rowcount
            db.commit()
            if deleted < 256:
                break
        target = int(self.max_pages * (0.80 if force else 0.95))
        while True:
            pages = db.execute("PRAGMA page_count").fetchone()[0]
            free = db.execute("PRAGMA freelist_count").fetchone()[0]
            if pages - free <= target:
                break
            used = pages - free
            count = db.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
            batch = min(256, max(1, (count * (used - target) + used - 1) // used))
            deleted = db.execute("DELETE FROM logs WHERE id IN (SELECT id FROM logs ORDER BY created LIMIT ?)", (batch,)).rowcount
            db.commit()
            if not deleted:
                break
        # Incremental vacuum also lets a smaller configured quota reclaim old files.
        while db.execute("PRAGMA page_count").fetchone()[0] > self.max_pages:
            if not db.execute("PRAGMA freelist_count").fetchone()[0]:
                break
            db.execute("PRAGMA incremental_vacuum(256)").fetchall()
            db.commit()
        db.execute(f"PRAGMA max_page_count={self.max_pages}")
        db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        self.last_prune = now

    def append(self, stream, seq, label, record):
        now = time.time()
        payload = json.dumps({"created_at": now, **record}, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        with self.lock:
            # ponytail: conservative serialized-record accounting, not a process RSS
            # limit. A hard process heap cap needs process isolation.
            charge = len(payload) + len(stream) + len(label) + 512
            self.hot[(stream, seq)] = (now, payload, charge)
            self.hot_bytes += charge
            self.pending[(stream, seq)] = label
            try:
                db = self._open()
                self._prune()
                # Retry RAM-held writes after transient disk failures, in arrival order.
                while self.pending:
                    key, saved_label = next(iter(self.pending.items()))
                    saved_time, saved_payload, _ = self.hot[key]
                    if saved_time < now - RETENTION_S:
                        del self.pending[key]
                        continue
                    values = (*key, saved_time, saved_label, saved_payload)
                    try:
                        db.execute("INSERT OR IGNORE INTO logs(stream,seq,created,label,data) VALUES (?,?,?,?,?)", values)
                        db.commit()
                    except sqlite3.OperationalError as exc:
                        db.rollback()
                        if not is_disk_full(exc):
                            raise
                        self._prune(force=True)
                        db.execute("INSERT OR IGNORE INTO logs(stream,seq,created,label,data) VALUES (?,?,?,?,?)", values)
                        db.commit()
                    del self.pending[key]
                self.error = f"{self.lost_records} records lost before archiving during disk failure" if self.lost_records else ""
            except (OSError, sqlite3.Error) as exc:
                if self.db is not None:
                    self.db.rollback()
                self._failed(exc)
            finally:
                while self.hot and (self.hot_bytes > self.ram_limit or next(iter(self.hot.values()))[0] < now - RETENTION_S):
                    key, value = self.hot.popitem(last=False)
                    self.hot_bytes -= value[2]
                    if key in self.pending:
                        del self.pending[key]
                        if value[0] >= now - RETENTION_S:
                            self.lost_records += 1

    def rows(self, stream, cursor=0, reverse=False, limit=None, before=None):
        count = 0
        position = before if reverse and before is not None else (2**63 - 1 if reverse else cursor - 1)
        while limit is None or count < limit:
            size = min(128, limit - count) if limit is not None else 128
            with self.lock:
                try:
                    db = self._open()
                    op, order = ("<", "DESC") if reverse else (">", "ASC")
                    batch = db.execute(f"SELECT seq,data FROM logs WHERE stream=? AND seq {op} ? "
                                       f"AND seq>=? AND seq<? AND created>=? ORDER BY seq {order} LIMIT ?",
                                       (stream, position, cursor, before if before is not None else 2**63 - 1, time.time() - RETENTION_S, size)).fetchall()
                except (OSError, sqlite3.Error) as exc:
                    self._failed(exc)
                    batch = []
                # Merge RAM-only records after disk errors; preserve seq order.
                hot = [(seq, value[1]) for (sid, seq), value in self.hot.items()
                       if sid == stream and value[0] >= time.time() - RETENTION_S and seq >= cursor
                       and (before is None or seq < before)
                       and (seq < position if reverse else seq > position)] if self.error else []
                if hot:
                    batch = sorted(dict([*batch, *hot]).items(), reverse=reverse)[:size]
            if not batch:
                break
            for seq, payload in batch:
                yield json.loads(payload)
                count += 1
            position = batch[-1][0]

    def archives(self):
        with self.lock:
            try:
                self._prune()
                return [{"stream": stream, "label": label, "first": first, "last": last, "records": count}
                        for stream, label, first, last, count in self._open().execute(
                            "SELECT stream,label,MIN(created),MAX(created),COUNT(*) FROM logs "
                            "WHERE created>=? GROUP BY stream ORDER BY MAX(created) DESC", (time.time() - RETENTION_S,))]
            except (OSError, sqlite3.Error) as exc:
                self._failed(exc)
                return []

    def status(self):
        with self.lock:
            return {"directory": str(self.directory), **{k: self.settings[k] for k in ("ram_mib", "disk_mib")},
                    "retention_hours": 48, "ram_used_bytes": self.hot_bytes,
                    "pending_records": len(self.pending), "lost_records": self.lost_records, "error": self.error}

    def close(self):
        with self.lock:
            if self.db is not None:
                self.db.close()
                self.db = None


_shared = None
_shared_lock = threading.Lock()


def shared_cache():
    global _shared
    with _shared_lock:
        if _shared is None:
            try:
                from .autoconnect import Settings
            except ImportError:
                from autoconnect import Settings
            _shared = LogCache(Settings().get()["log_cache"])
            atexit.register(_shared.close)
        return _shared


class CachedRecords:
    """A session's records; lazy iteration reads archived pages, not a full list."""
    def __init__(self, label, cache=None, stream=None):
        self.cache = cache or shared_cache()
        self.stream = stream or uuid.uuid4().hex
        self.label = label
        self.seq = 0

    def append(self, record):
        self.seq = record.get("seq", self.seq + 1)
        self.cache.append(self.stream, self.seq, self.label, {"seq": self.seq, **record})

    def iter_records(self, cursor=0, reverse=False, limit=None, before=None):
        return self.cache.rows(self.stream, cursor, reverse, limit, before)

    def __iter__(self):
        return self.iter_records()

    def __bool__(self):
        return next(self.iter_records(limit=1), None) is not None

    def __getitem__(self, index):
        if isinstance(index, slice) and index.start is not None and index.start < 0 and index.stop is None:
            return list(reversed(list(self.iter_records(reverse=True, limit=-index.start))))
        if index in (0, -1):
            row = next(self.iter_records(reverse=index == -1, limit=1), None)
            if row is None:
                raise IndexError(index)
            return row
        raise IndexError(index)
