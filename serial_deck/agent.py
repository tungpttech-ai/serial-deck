#!/usr/bin/env python3
"""Agent-facing control core used by the MCP server.

Every operation goes through the shared multi-port hub; this module never
opens a physical UART. It keeps per-port sessions with a bounded record ring,
correlates firmware requests by `request_id`, and drives hub-owned flashing
of immutable snapshots. It is synchronous and thread-safe so it can be tested
without an MCP runtime.
"""

from __future__ import annotations

import datetime
import json
import os
import re
import secrets
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

try:
    from . import flash_snapshot as snapshots
    from . import mcp_status as mcp_status
    from .hub_client import (
        DEFAULT_SOCKET, MULTIPORT_PROTOCOL, BaudConflictError, HubProcessManager, port_identity)
    from .uart_client import (
        FRAME_COMMAND, FRAME_ERROR, FRAME_EVENT, FRAME_HELLO, FRAME_NAMES, FRAME_RESPONSE,
        PROTOCOL_VERSION, FrameDispatchUnknown, UartReader, discover_serial_port_details, encode_json_frame,
        is_device_port, is_network_port, make_request, open_uart_transport, send_frame)
except ImportError:
    import flash_snapshot as snapshots
    import mcp_status as mcp_status
    from hub_client import (
        DEFAULT_SOCKET, MULTIPORT_PROTOCOL, BaudConflictError, HubProcessManager, port_identity)
    from uart_client import (
        FRAME_COMMAND, FRAME_ERROR, FRAME_EVENT, FRAME_HELLO, FRAME_NAMES, FRAME_RESPONSE,
        PROTOCOL_VERSION, FrameDispatchUnknown, UartReader, discover_serial_port_details, encode_json_frame,
        is_device_port, is_network_port, make_request, open_uart_transport, send_frame)

POLICIES = ("observe", "interact", "hardware")
TERMINAL_STATUSES = {"succeeded", "failed", "cancelled", "expired", "rejected"}
LIFECYCLE_RANK = {"accepted": 0, "running": 1, **{status: 2 for status in TERMINAL_STATUSES}}
BUTTONS = ("HOME", "LEFT", "RIGHT", "ENTER", "ONOFF")
BUTTON_ACTIONS = ("press", "release", "long_press")
QUERY_KINDS = ("capabilities", "identity", "fsm", "snapshot")
RING_RECORDS = 5000
LINE_CHARS = 2000
RESPONSE_RECORDS = 500
RESPONSE_BYTES = 48 * 1024
MAX_SESSIONS = 4
MAX_WAITERS = 32
MAX_WAIT_S = 120.0
MAX_FLASH_WAIT_S = 60.0
LOG_LEVEL_RE = re.compile(r"(?:^|\s)([EWIDV])\s+\(")
LEVELS = {"E": "error", "W": "warning", "I": "info", "D": "debug", "V": "verbose"}
ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
SECRET_KEY = (r"password|passwd|pass|psk|token|secret|api[_-]?key|authorization|auth_tag"
              r"|bearer|cookie|session(?:_id|id)?|credential|challenge|private[_-]?key")
REDACTIONS = (
    (re.compile(r"\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{8,}", re.I), r"\1 [redacted]"),
    (re.compile(rf'("(?:[\w-]*(?:{SECRET_KEY})[\w-]*)"\s*:\s*)"(?:[^"\\]|\\.)*"', re.I), r'\1"[redacted]"'),
    (re.compile(rf"\b([\w-]*(?:{SECRET_KEY})[\w-]*)(\s*[=:]\s*)(?!\[redacted\]|(?:Bearer|Basic)\s)([^\s,;&\"']+)", re.I),
     r"\1\2[redacted]"),
    (re.compile(r"\b([a-z][a-z0-9+.-]*://)[^/\s:@]+:[^/\s@]+@", re.I), r"\1[redacted]@"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"), "[redacted-jwt]"),
)
IDENTITY_KEYS = re.compile(r"serial|mac|uuid|device_id|chip_id|imei|sn$|key", re.I)
FLASH_VERIFIED_RE = re.compile(r"Hash of data verified", re.I)


ACTIVITY_LIMIT = 200
ACTIVITY_FLUSH_S = 0.5


def activity_dir() -> Path:
    """Per-user directory where each MCP process publishes what it is doing."""
    root = mcp_status.activity_dir()
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    return root


class ActivityLog:
    """Bounded record of tool calls, written atomically for dashboards to read.

    Only metadata leaves the process (tool name, redacted arguments, outcome,
    duration); dashboards read it from a private per-user directory.
    """

    def __init__(self, policy: str, socket_path: str, directory: Path | None = None,
                 client: str = "") -> None:
        self.lock = threading.Lock()
        self.entries: deque[dict[str, Any]] = deque(maxlen=ACTIVITY_LIMIT)
        self.next_id = 1
        self.info = {"pid": os.getpid(), "policy": policy, "hub_socket": socket_path,
                     "client": client, "started": time.time()}
        self.sessions: list[dict[str, Any]] = []
        self.flash_jobs: list[dict[str, Any]] = []
        try:
            self.path: Path | None = (directory or activity_dir()) / f"{os.getpid()}.json"
        except OSError:
            self.path = None
        self._last_flush = 0.0
        self.flush(force=True)

    def begin(self, tool: str, args: dict[str, Any]) -> int:
        with self.lock:
            entry_id = self.next_id
            self.next_id += 1
            self.entries.append({"id": entry_id, "tool": tool, "args": redact_value(args),
                                 "started": time.time(), "state": "running"})
        self.flush(force=True)
        return entry_id

    def end(self, entry_id: int, outcome: str, summary: str = "") -> None:
        with self.lock:
            for entry in reversed(self.entries):
                if entry["id"] == entry_id:
                    entry.update(state=outcome, ended=time.time(), summary=redact(summary)[:300],
                                 duration_ms=int((time.time() - entry["started"]) * 1000))
                    break
        self.flush(force=True)

    def update_state(self, sessions: list[dict[str, Any]], flash_jobs: list[dict[str, Any]]) -> None:
        with self.lock:
            self.sessions = sessions
            self.flash_jobs = flash_jobs
        self.flush()

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            return {**self.info, "updated": time.time(), "sessions": list(self.sessions),
                    "flash_jobs": list(self.flash_jobs), "calls": list(self.entries)}

    def flush(self, force: bool = False) -> None:
        if self.path is None:
            return
        now = time.monotonic()
        if not force and now - self._last_flush < ACTIVITY_FLUSH_S:
            return
        self._last_flush = now
        try:
            temp = self.path.with_name(f".{self.path.name}.tmp")
            temp.write_text(json.dumps(self.snapshot(), ensure_ascii=False), encoding="utf-8")
            os.replace(temp, self.path)
        except OSError:
            pass

    def close(self) -> None:
        if self.path is not None:
            try:
                self.path.unlink()
            except OSError:
                pass


class AgentError(Exception):
    """An anticipated failure with a stable machine-readable code."""

    def __init__(self, code: str, message: str, hint: str = "", **details: Any) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.hint = hint
        self.details = details

    def payload(self) -> dict[str, Any]:
        error = {"code": self.code, "message": redact(self.message)}
        if self.hint:
            error["hint"] = self.hint
        error.update(redact_value(self.details))
        return {"ok": False, "error": error}


def redact(text: str) -> str:
    for pattern, replacement in REDACTIONS:
        text = pattern.sub(replacement, text)
    return text


def redact_value(value: Any, identity: bool = False) -> Any:
    """Redact secrets in any JSON value; `identity` also hides serial/MAC-like fields."""
    if isinstance(value, str):
        stripped = value.strip()
        if stripped[:1] in "{[":
            try:
                return json.dumps(redact_value(json.loads(stripped), identity), ensure_ascii=False)
            except json.JSONDecodeError:
                pass
        return redact(value)
    if isinstance(value, list):
        return [redact_value(item, identity) for item in value]
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            if re.fullmatch(rf"[\w-]*(?:{SECRET_KEY})[\w-]*", str(key), re.I) and not isinstance(item, (dict, list)):
                result[key] = "[redacted]"
            elif identity and IDENTITY_KEYS.search(str(key)) and not isinstance(item, (dict, list)):
                result[key] = "[redacted]"
            else:
                result[key] = redact_value(item, identity)
        return result
    return value


def parse_level(line: str) -> str:
    match = LOG_LEVEL_RE.search(line)
    return LEVELS.get(match.group(1), "plain") if match else "plain"


def _clip(text: str) -> str:
    return text if len(text) <= LINE_CHARS else text[:LINE_CHARS] + f"…[+{len(text) - LINE_CHARS} chars]"


def _now() -> str:
    return datetime.datetime.now().isoformat(timespec="milliseconds")


@dataclass
class Waiter:
    """Collects the lifecycle of one firmware request."""

    request_id: str | None
    sequence: int
    hello: bool = False
    event: threading.Event = field(default_factory=threading.Event)
    frames: list[dict[str, Any]] = field(default_factory=list)
    operation_id: str | None = None
    last_event_seq: int = -1
    status: str | None = None
    terminal: dict[str, Any] | None = None

    def offer(self, frame_type: int, sequence: int, message: Any) -> bool:
        """Apply a frame; return True when it belonged to this request."""
        if self.hello:
            if frame_type in (FRAME_HELLO, FRAME_ERROR) and sequence == self.sequence:
                self._finish(frame_type, message, "succeeded" if frame_type == FRAME_HELLO else "rejected")
                return True
            return False
        if not isinstance(message, dict):
            return False
        request_id = message.get("request_id")
        if self.terminal is not None:
            # Late RESPONSE/EVENT frames of a finished request are consumed, never applied.
            return request_id == self.request_id
        if frame_type == FRAME_ERROR:
            if request_id == self.request_id or (not request_id and sequence == self.sequence):
                self._finish(frame_type, message, "rejected")
                return True
            return False
        if frame_type not in (FRAME_RESPONSE, FRAME_EVENT) or request_id != self.request_id:
            return False
        operation_id = message.get("operation_id") or None
        if self.operation_id and operation_id and operation_id != self.operation_id:
            return False
        event_seq = message.get("event_seq")
        if frame_type == FRAME_EVENT and isinstance(event_seq, int):
            if event_seq <= self.last_event_seq:
                return True  # Stale or duplicate lifecycle event.
            self.last_event_seq = event_seq
        self.operation_id = self.operation_id or operation_id
        status = str(message.get("status", ""))
        self.frames.append({"frame": FRAME_NAMES.get(frame_type, str(frame_type)), **message})
        if status and LIFECYCLE_RANK.get(status, 2) >= LIFECYCLE_RANK.get(self.status or "", -1):
            self.status = status  # A late `accepted` never overrides `running`.
        if status in TERMINAL_STATUSES:
            self._finish(frame_type, message, status, recorded=True)
        return True

    def _finish(self, frame_type: int, message: Any, status: str, recorded: bool = False) -> None:
        if self.terminal is None:
            if not recorded:
                self.frames.append({"frame": FRAME_NAMES.get(frame_type, str(frame_type)),
                                    **(message if isinstance(message, dict) else {"payload": message})})
            self.status = status
            self.terminal = message if isinstance(message, dict) else {"payload": message}
        self.event.set()


class Session:
    """One MCP-owned data client for a claimed hub channel."""

    def __init__(self, manager: HubProcessManager, port: str, mode: str,
                 transport_factory: Callable[..., Any] = open_uart_transport) -> None:
        self.manager = manager
        self.port = port
        self.mode = mode
        self.generation = f"{manager.get_status().get('pid')}:{manager.channel_socket}"
        self.transport = transport_factory(manager.endpoint, manager.baud, 0.1)
        self.reader = UartReader(self.transport, frames=mode == "control")
        self.lock = threading.Lock()
        self.records: deque[dict[str, Any]] = deque(maxlen=RING_RECORDS)
        self.next_seq = 1
        self.changed = threading.Condition(self.lock)
        self.waiters: list[Waiter] = []
        self.sequence = secrets.randbelow(1 << 30) + (1 << 30)
        self.lost: str | None = None
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._read_loop, name=f"serial-deck-mcp-{port}", daemon=True)
        self.thread.start()
        try:
            manager.subscribe(self._on_hub_status)
        except OSError:
            pass  # Baud changes by other clients then go unnoticed; data still flows.

    def _on_hub_status(self, status: dict[str, Any]) -> None:
        baud = status.get("baud")
        if type(baud) is int and baud != self.manager.baud:
            self.note(f"UART baud changed {self.manager.baud} -> {baud} by another client", "warning")
            self.manager.baud = baud

    # Records -------------------------------------------------------------

    def append(self, kind: str, level: str, text: str = "", frame: dict[str, Any] | None = None) -> int:
        with self.changed:
            seq = self.next_seq
            self.next_seq += 1
            record: dict[str, Any] = {"seq": seq, "time": _now(), "kind": kind, "level": level}
            if frame is not None:
                record["frame"] = frame
            else:
                record["text"] = _clip(text)
            self.records.append(record)
            self.changed.notify_all()
            return seq

    def note(self, text: str, level: str = "note") -> int:
        return self.append("note", level, f"[mcp] {text}")

    @property
    def cursor(self) -> int:
        with self.lock:
            return self.next_seq

    def _read_loop(self) -> None:
        while not self.stop.is_set():
            try:
                records = self.reader.poll()
            except (OSError, ValueError) as exc:
                if not self.stop.is_set():
                    self._mark_lost(f"hub data socket closed: {exc}")
                return
            for kind, value in records:
                if kind == "log":
                    text = ANSI_ESCAPE_RE.sub("", value)
                    self.append("log", parse_level(text), text)
                    continue
                frame_type, _flags, sequence, message = value
                name = FRAME_NAMES.get(frame_type, f"type-{frame_type}")
                self.append("frame", "error" if frame_type == FRAME_ERROR else "frame",
                            frame={"type": name, "sequence": sequence, "message": message})
                with self.lock:
                    waiters = list(self.waiters)
                for waiter in waiters:
                    if waiter.offer(frame_type, sequence, message):
                        break

    def _mark_lost(self, reason: str) -> None:
        with self.changed:
            self.lost = reason
            waiters = list(self.waiters)
            self.changed.notify_all()
        self.note(reason, "error")
        for waiter in waiters:
            waiter.event.set()

    def ensure_alive(self) -> None:
        if self.lost:
            raise AgentError("transport_unavailable", f"{self.port}: {self.lost}",
                             "call serial_connect again to reattach")

    def close(self) -> None:
        self.stop.set()
        self.manager.unsubscribe(self._on_hub_status)
        try:
            self.transport.close()
        except OSError:
            pass
        self.thread.join(timeout=1.0)
        with self.changed:
            self.changed.notify_all()

    # Firmware requests ---------------------------------------------------

    def _next_sequence(self) -> int:
        with self.lock:
            self.sequence = (self.sequence + 1) & 0x7FFFFFFF or (1 << 30)
            return self.sequence

    def request(self, command: str | None, args: dict[str, Any] | None, timeout: float,
                cancelled: Callable[[], bool] | None = None) -> dict[str, Any]:
        """Send HELLO (command None) or a command and collect its lifecycle."""
        self.ensure_alive()
        if self.mode != "control":
            raise AgentError("invalid_state", "firmware commands are disabled in raw console mode",
                             "reconnect with mode='control'")
        sequence = self._next_sequence()
        if command is None:
            waiter = Waiter(None, sequence, hello=True)
            frame = encode_json_frame(FRAME_HELLO, sequence, {
                "type": "hello", "protocol": "serial-deck-control", "version": PROTOCOL_VERSION,
                "client_id": f"serial-deck-mcp-{os.getpid()}"})
        else:
            request = make_request(command, args or {}, deadline_ms=max(1, min(30000, int(timeout * 1000))))
            waiter = Waiter(request["request_id"], sequence)
            frame = encode_json_frame(FRAME_COMMAND, sequence, request)
        with self.lock:
            if len(self.waiters) >= MAX_WAITERS:
                raise AgentError("busy", "too many firmware requests in flight")
            self.waiters.append(waiter)
        try:
            try:
                send_frame(self.transport, frame)
            except FrameDispatchUnknown as exc:
                dispatch_error = str(exc)
                finished = self._wait_event(waiter.event, timeout, cancelled)
            except OSError as exc:
                raise AgentError("transport_unavailable", f"write refused: {exc}",
                                 "the hub rejected the write before sending it") from exc
            else:
                dispatch_error = ""
                finished = self._wait_event(waiter.event, timeout, cancelled)
        finally:
            with self.lock:
                if waiter in self.waiters:
                    self.waiters.remove(waiter)
        result: dict[str, Any] = {
            "request_id": waiter.request_id, "sequence": sequence,
            "operation_id": waiter.operation_id, "status": waiter.status,
            "frames": waiter.frames[-8:],
        }
        if waiter.terminal is not None:
            result["outcome"] = "completed"
            terminal = waiter.terminal
            if terminal.get("error"):
                result["error"] = terminal.get("error")
            if "result" in terminal:
                raw = terminal["result"]
                try:
                    result["result"] = json.loads(raw) if isinstance(raw, str) else raw
                except json.JSONDecodeError:
                    result["result"] = raw
            if command is None:
                result["hello"] = terminal
            return redact_value(result)
        result["outcome"] = "unknown"
        result["reason"] = self.lost or (f"no hub reply to the write: {dispatch_error}" if dispatch_error
                                         else "timeout" if not finished else "no terminal status")
        result["hint"] = ("the device may or may not have executed it; do not re-send, "
                          "check state with serial_query or serial_logs first")
        return redact_value(result)

    @staticmethod
    def _wait_event(event: threading.Event, timeout: float,
                    cancelled: Callable[[], bool] | None) -> bool:
        deadline = time.monotonic() + timeout
        while not event.is_set():
            remaining = deadline - time.monotonic()
            if remaining <= 0 or (cancelled is not None and cancelled()):
                return event.is_set()
            event.wait(min(remaining, 0.25))
        return True

    # Log access ----------------------------------------------------------

    def select(self, cursor: int | None, limit: int, contains: list[str] | None,
               levels: list[str] | None, frames: bool, ignore_case: bool) -> dict[str, Any]:
        limit = max(1, min(RESPONSE_RECORDS, limit))
        needles = [n.lower() if ignore_case else n for n in (contains or []) if n]
        with self.lock:
            records = list(self.records)
            end = self.next_seq
        first = records[0]["seq"] if records else end
        dropped = 0
        if cursor is None:
            candidates = records
        else:
            if cursor < first:
                dropped = first - cursor
            candidates = [r for r in records if r["seq"] >= cursor]

        def keep(record: dict[str, Any]) -> bool:
            if record["kind"] == "frame" and not frames:
                return False
            if levels and record["level"] not in levels:
                return False
            if needles:
                haystack = record.get("text") or json.dumps(record.get("frame"), ensure_ascii=False)
                haystack = haystack.lower() if ignore_case else haystack
                return any(needle in haystack for needle in needles)
            return True

        matched = [r for r in candidates if keep(r)]
        if cursor is None:
            matched = matched[-limit:]  # Without a cursor, return the most recent records.
            next_cursor = end
            truncated = False
        else:
            truncated = len(matched) > limit
            matched = matched[:limit]
            next_cursor = matched[-1]["seq"] + 1 if truncated else end
        out, size = [], 0
        for record in matched:
            record = redact_value(record)
            size += len(json.dumps(record, ensure_ascii=False))
            if out and size > RESPONSE_BYTES:
                truncated = True
                next_cursor = record["seq"]
                break
            out.append(record)
        return {"records": out, "next_cursor": next_cursor, "truncated": truncated,
                "dropped": dropped, "oldest_seq": first}

    def wait_for(self, any_of: list[str], timeout: float, since: int | None,
                 ignore_case: bool, context: int,
                 cancelled: Callable[[], bool] | None = None) -> dict[str, Any]:
        needles = [n for n in any_of if n]
        if not needles:
            raise AgentError("invalid_argument", "any_of needs at least one non-empty string")
        folded = [n.lower() for n in needles] if ignore_case else needles
        deadline = time.monotonic() + max(0.0, min(MAX_WAIT_S, timeout))
        cursor = self.cursor if since is None else since
        with self.changed:
            while True:
                first = self.records[0]["seq"] if self.records else self.next_seq
                for index in range(max(0, cursor - first), len(self.records)):
                    record = self.records[index]
                    if record["kind"] == "frame":
                        continue
                    text = record.get("text", "")
                    haystack = text.lower() if ignore_case else text
                    hit = next((n for n, f in zip(needles, folded) if f in haystack), None)
                    if hit is not None:
                        before = list(self.records)[max(0, index - context):index]
                        return {"matched": True, "pattern": hit, "record": redact_value(record),
                                "context": redact_value(before), "next_cursor": record["seq"] + 1}
                cursor = self.next_seq  # Everything up to here was scanned; only look at new records.
                if self.lost:
                    raise AgentError("transport_unavailable", f"{self.port}: {self.lost}")
                remaining = deadline - time.monotonic()
                if cancelled is not None and cancelled():
                    return {"matched": False, "reason": "cancelled", "next_cursor": self.next_seq}
                if remaining <= 0:
                    tail = redact_value(list(self.records)[-max(1, context):])
                    return {"matched": False, "reason": "timeout", "tail": tail,
                            "next_cursor": self.next_seq}
                self.changed.wait(min(remaining, 0.5))


@dataclass
class FlashJob:
    token: str
    session_port: str
    snapshot: snapshots.FlashSnapshot
    flash_id: int | None = None
    started: float = 0.0
    events: list[dict[str, Any]] = field(default_factory=list)
    last_revision: int | None = None
    gaps: int = 0
    finished: dict[str, Any] | None = None
    completion_cursor: int | None = None
    verified_transitions: int = 0
    last_line: str = ""
    manager: HubProcessManager | None = None
    verdict: dict[str, Any] | None = None
    poll_revision: int | None = None
    lock: threading.Lock = field(default_factory=threading.Lock)
    finalize_lock: threading.Lock = field(default_factory=threading.Lock)

    def owns(self, flash: dict[str, Any]) -> bool:
        """A hub flash is ours only when it reads this job's snapshot directory."""
        return bool(flash.get("build_dir")) and \
            os.path.realpath(str(flash["build_dir"])) == os.path.realpath(self.snapshot.directory)


class DeckAgent:
    """Process-wide state behind the MCP tools."""

    def __init__(self, policy: str = "observe", socket_path: str = DEFAULT_SOCKET,
                 manager_factory: Callable[..., HubProcessManager] = HubProcessManager,
                 transport_factory: Callable[..., Any] = open_uart_transport,
                 snapshot_root: Path | None = None) -> None:
        if policy not in POLICIES:
            raise ValueError(f"policy must be one of {', '.join(POLICIES)}")
        self.policy = policy
        self.socket_path = socket_path
        self.manager_factory = manager_factory
        self.transport_factory = transport_factory
        self.snapshot_root = snapshot_root
        self.lock = threading.RLock()
        self.sessions: dict[str, Session] = {}
        self.pending: dict[str, tuple[snapshots.FlashSnapshot, dict[str, Any]]] = {}
        self.jobs: dict[str, FlashJob] = {}
        self.activity: ActivityLog | None = None

    def enable_activity(self, directory: Path | None = None, client: str = "") -> ActivityLog:
        """Publish tool calls and sessions so dashboards can show running agents."""
        self.activity = ActivityLog(self.policy, self.socket_path, directory, client)
        return self.activity

    def publish_activity(self) -> None:
        if self.activity is None:
            return
        with self.lock:
            sessions = [{"port": s.port, "mode": s.mode, "baud": s.manager.baud, "lost": s.lost,
                         "records": s.cursor - 1} for s in self.sessions.values()]
            jobs = [self._job_summary(job) for job in self.jobs.values()]
        self.activity.update_state(sessions, jobs)

    # Policy / sessions -----------------------------------------------------

    def allows(self, level: str) -> bool:
        return POLICIES.index(self.policy) >= POLICIES.index(level)

    def require(self, level: str) -> None:
        if not self.allows(level):
            raise AgentError("policy_denied", f"this server runs with policy '{self.policy}'",
                             f"the user must restart the MCP server with --allow {level}")

    def _root(self) -> HubProcessManager:
        manager = self.manager_factory(socket_path=self.socket_path)
        manager.ensure_started()
        status = manager.get_status()
        if status.get("protocol") != MULTIPORT_PROTOCOL:
            raise AgentError("legacy_hub", "a legacy single-port hub owns the control socket",
                             "disconnect its clients and stop it normally; this server never "
                             "starts or stops hubs to work around it")
        return manager

    def session(self, port: str | None) -> Session:
        with self.lock:
            if port is None:
                if len(self.sessions) == 1:
                    return next(iter(self.sessions.values()))
                raise AgentError("ambiguous_port" if self.sessions else "not_connected",
                                 "specify port" if self.sessions else "no port is connected",
                                 "call serial_connect first" if not self.sessions else
                                 f"connected: {', '.join(s.port for s in self.sessions.values())}")
            session = self.sessions.get(port_identity(port))
        if session is None:
            raise AgentError("not_connected", f"{port} is not connected", "call serial_connect first")
        return session

    def status(self) -> dict[str, Any]:
        with self.lock:
            sessions = [{"port": s.port, "mode": s.mode, "baud": s.manager.baud,
                         "generation": s.generation, "cursor": s.cursor, "lost": s.lost}
                        for s in self.sessions.values()]
            jobs = [self._job_summary(job) for job in self.jobs.values()]
        hub: dict[str, Any] | None
        try:
            manager = self.manager_factory(socket_path=self.socket_path)
            hub = manager.get_status() if manager.socket_ready() else None
        except (OSError, RuntimeError, ValueError) as exc:
            hub = {"error": str(exc)}
        if hub and "channels" in hub:
            hub = {"protocol": hub.get("protocol"), "pid": hub.get("pid"), "state": hub.get("state"),
                   "features": hub.get("features", []),
                   "channels": [{"port": c.get("port"), "baud": c.get("baud"), "state": c.get("state"),
                                 "client_count": c.get("client_count"),
                                 "flash": redact_value({k: c.get("flash", {}).get(k) for k in
                                                        ("active", "id", "progress", "step", "exit_code")})}
                                for c in hub.get("channels", [])]}
        if hub and "error" in hub:
            hub = {"error": redact(str(hub["error"]))}
        return {"policy": self.policy, "hub_socket": self.socket_path, "hub": hub,
                "tx_atomic": bool(hub and "write_frame" in (hub.get("features") or [])),
                "sessions": sessions, "flash_jobs": jobs}

    def list_ports(self) -> dict[str, Any]:
        claimed: dict[str, dict[str, Any]] = {}
        try:
            manager = self.manager_factory(socket_path=self.socket_path)
            if manager.socket_ready():
                for channel in manager.get_status().get("channels", []):
                    if channel.get("port"):
                        claimed[port_identity(channel["port"])] = channel
        except (OSError, RuntimeError, ValueError):
            pass
        ports = []
        for item in discover_serial_port_details():
            device = item["device"]
            info = {**item, **usb_identity(device)}
            channel = claimed.get(port_identity(device))
            info["hub_channel"] = ({"baud": channel.get("baud"), "clients": channel.get("client_count")}
                                   if channel else None)
            text = item.get("description", "").lower()
            info["hint"] = ("possibly an ESP32 USB console (confirm with serial_hello)" if "jtag" in text or "usb serial" in text
                            else "")
            ports.append(info)
        return {"ports": ports}

    def connect(self, port: str, baud: int | None, mode: str,
                change_live_baud: bool = False) -> dict[str, Any]:
        if mode not in ("control", "raw"):
            raise AgentError("invalid_argument", "mode must be 'control' or 'raw'")
        if not port or not (is_device_port(port) or is_network_port(port)):
            raise AgentError("invalid_argument", "port must be a device path, COM port or tcp:// / udp:// endpoint")
        if change_live_baud:
            if not baud:
                raise AgentError("invalid_argument", "change_live_baud needs an explicit baud")
            # Retiming is visible to every dashboard and session on the port.
            self.require("interact")
        # "error" still retimes a channel nobody is attached to; a conflict
        # with live clients falls back to joining at their baud.
        on_conflict = "retime" if change_live_baud else "error"
        key = port_identity(port)
        with self.lock:
            existing = self.sessions.get(key)
            if existing is not None and not existing.lost and existing.mode == mode:
                if change_live_baud and baud != existing.manager.baud:
                    try:
                        existing.manager.claim_port(port, int(baud), on_conflict)
                    except (OSError, RuntimeError, ValueError) as exc:
                        raise AgentError("transport_unavailable", f"cannot retime {port}: {exc}") from exc
                    existing.note(f"UART baud set to {existing.manager.baud} for every client")
                return {"port": existing.port, "baud": existing.manager.baud, "mode": mode,
                        "already_connected": True, "opened_uart": False,
                        "generation": existing.generation, "cursor": existing.cursor}
            if existing is not None:
                existing.close()
                del self.sessions[key]
            if len(self.sessions) >= MAX_SESSIONS:
                raise AgentError("busy", f"at most {MAX_SESSIONS} ports can be connected")
            root = self._root()
            live = {port_identity(c["port"]): c for c in root.get_status().get("channels", []) if c.get("port")}
            channel = live.get(key)
            manager = self.manager_factory(socket_path=root.socket_path)
            manager.multiport = True
            requested = baud if baud else (channel.get("baud") if channel else 2000000)
            try:
                try:
                    manager.claim_port(port, int(requested), on_conflict)
                except BaudConflictError:
                    manager.claim_port(port, int(requested))
                session = Session(manager, port, mode, self.transport_factory)
            except AgentError:
                raise
            except (OSError, RuntimeError, ValueError) as exc:
                raise AgentError("transport_unavailable", f"cannot connect {port}: {exc}") from exc
            self.sessions[key] = session
        opened = channel is None
        session.note(f"attached to {port} @ {manager.baud} baud ({mode})")
        result: dict[str, Any] = {
            "port": port, "baud": manager.baud, "mode": mode, "already_connected": False,
            "opened_uart": opened, "generation": session.generation, "cursor": session.cursor,
            "history": "records are kept only from this attach onwards",
        }
        if baud and baud != manager.baud:
            result["baud_note"] = (f"hub kept the live baud {manager.baud}; requested {baud} was not applied. "
                                   "Ask the user before retrying with change_live_baud=true: it changes "
                                   "the baud for every client on this port")
        if mode == "control":
            hello = session.request(None, None, 2.0)
            result["hello"] = hello.get("hello") if hello["outcome"] == "completed" else None
            if result["hello"] is None:
                result["hello_note"] = "no HELLO reply within 2 s (firmware without control plane, or busy)"
        return result

    def disconnect(self, port: str | None) -> dict[str, Any]:
        session = self.session(port)
        with self.lock:
            self.sessions.pop(port_identity(session.port), None)
        session.close()
        return {"port": session.port, "disconnected": True}

    def close(self) -> None:
        with self.lock:
            sessions = list(self.sessions.values())
            self.sessions.clear()
            jobs = list(self.jobs.values())
            pending = [snapshot for snapshot, _ in self.pending.values()]
            self.pending.clear()
        for session in sessions:
            session.close()
        for job in jobs:
            if job.manager is not None:
                job.manager.unsubscribe()
        for snapshot in pending:
            if snapshot.state().get("state") == "prepared":
                snapshot.remove()
        self.collect_snapshots()
        if self.activity is not None:
            self.activity.close()

    # Firmware ------------------------------------------------------------

    def hello(self, port: str | None, timeout: float,
              cancelled: Callable[[], bool] | None = None) -> dict[str, Any]:
        return self.session(port).request(None, None, timeout, cancelled)

    def query(self, kind: str, port: str | None, timeout: float, redact_identity: bool,
              cancelled: Callable[[], bool] | None = None) -> dict[str, Any]:
        if kind not in QUERY_KINDS:
            raise AgentError("invalid_argument", f"kind must be one of {', '.join(QUERY_KINDS)}")
        result = self.session(port).request("query", {"kind": kind}, timeout, cancelled)
        if kind == "identity" and redact_identity:
            if isinstance(result.get("result"), (str, int, float)):
                # Firmware may return identity as one opaque string (a device id).
                value = str(result["result"])
                result["result"] = f"[redacted {len(value)} chars]"
            for frame in result.get("frames", []):
                if isinstance(frame, dict) and "result" in frame:
                    frame["result"] = "[redacted]"
            return redact_value(result, identity=True)
        return result

    def button(self, button: str, action: str, port: str | None, timeout: float) -> dict[str, Any]:
        self.require("interact")
        if button not in BUTTONS or action not in BUTTON_ACTIONS:
            raise AgentError("invalid_argument", f"button in {BUTTONS}, action in {BUTTON_ACTIONS}")
        session = self.session(port)
        session.note(f"button {button} {action}")
        return session.request("input.button", {"button": button, "action": action}, timeout)

    def show_info(self, port: str | None, timeout: float) -> dict[str, Any]:
        self.require("interact")
        session = self.session(port)
        session.note("ui.show_info")
        return session.request("ui.show_info", {}, timeout)

    def reset(self, port: str | None, wait_for: list[str] | None, timeout: float,
              cancelled: Callable[[], bool] | None = None) -> dict[str, Any]:
        self.require("hardware")
        session = self.session(port)
        session.ensure_alive()
        if is_network_port(session.port):
            raise AgentError("invalid_state", "reset needs a physical UART, not a network endpoint")
        cursor = session.cursor
        session.note("reset (RTS/EN pulse)")
        try:
            session.manager.request_control("reset")
        except (OSError, RuntimeError) as exc:
            raise AgentError("hardware_unavailable", f"reset failed: {exc}") from exc
        result: dict[str, Any] = {"reset": True, "cursor": cursor}
        if wait_for:
            result["boot"] = session.wait_for(wait_for, timeout, cursor, False, 10, cancelled)
        return result

    def bootloader(self, port: str | None) -> dict[str, Any]:
        self.require("hardware")
        session = self.session(port)
        session.ensure_alive()
        if is_network_port(session.port):
            raise AgentError("invalid_state", "bootloader needs a physical UART, not a network endpoint")
        session.note("enter ROM bootloader (DTR/RTS)")
        try:
            session.manager.request_control("bootloader")
        except (OSError, RuntimeError) as exc:
            raise AgentError("hardware_unavailable", f"bootloader entry failed: {exc}") from exc
        return {"bootloader": True, "note": "the app stops until the next reset or flash"}

    # Flash ---------------------------------------------------------------

    def _hub_status(self, socket_path: str) -> dict[str, Any] | None:
        manager = self.manager_factory(socket_path=socket_path or self.socket_path)
        return manager.get_status() if manager.socket_ready() else None

    def collect_snapshots(self) -> list[str]:
        with self.lock:
            keep = set(self.pending) | {job.token for job in self.jobs.values() if job.finished is None}
        return snapshots.collect_snapshots(self._hub_status, self.snapshot_root, keep)

    def _binding(self, session: Session, flash_baud: int, snapshot: snapshots.FlashSnapshot) -> dict[str, Any]:
        return {"port": port_identity(session.port), "usb": usb_identity(session.port),
                "generation": session.generation, "flash_baud": flash_baud,
                "hashes": [image.sha256 for image in snapshot.images]}

    def flash_preview(self, build_dir: str, port: str | None, flash_baud: int) -> dict[str, Any]:
        session = self.session(port)
        session.ensure_alive()
        if is_network_port(session.port):
            raise AgentError("invalid_state", "flash needs a physical UART")
        if not 115200 <= flash_baud <= 5000000:
            raise AgentError("invalid_argument", "flash_baud must be between 115200 and 5000000")
        self.collect_snapshots()
        try:
            snapshot = snapshots.prepare_snapshot(build_dir, self.snapshot_root)
        except snapshots.FlashPolicyError as exc:
            raise AgentError("flash_refused", str(exc)) from exc
        except OSError as exc:
            raise AgentError("invalid_argument", f"cannot read build: {exc}") from exc
        try:
            preview = session.manager.preview_flash(str(snapshot.directory), flash_baud)
            command = [str(part) for part in preview.get("command", [])]
            if not snapshots.command_paths_inside(command, snapshot.directory):
                raise AgentError("flash_refused", "hub preview does not point at the snapshot")
        except (OSError, RuntimeError, ValueError) as exc:
            snapshot.remove()
            raise AgentError("flash_refused", f"hub preview failed: {exc}") from exc
        except AgentError:
            snapshot.remove()
            raise
        binding = self._binding(session, flash_baud, snapshot)
        with self.lock:
            self.pending[snapshot.token] = (snapshot, binding)
        return {
            "token": snapshot.token, "expires_in_s": int(snapshot.expires - time.time()),
            "port": session.port, "device": binding["usb"], "flash_baud": flash_baud,
            "build_dir": snapshot.build_dir, "project": snapshot.project,
            "images": [image.summary() for image in snapshot.images],
            "command": [redact(part) for part in command],
            "next": "show this to the user; after explicit approval call serial_flash_start(token)",
        }

    def flash_start(self, token: str) -> dict[str, Any]:
        self.require("hardware")
        with self.lock:
            entry = self.pending.pop(token, None)
        if entry is None:
            raise AgentError("token_invalid", "unknown, used or expired flash token",
                             "call serial_flash_preview again")
        snapshot, binding = entry
        try:
            if time.time() > snapshot.expires:
                raise AgentError("token_invalid", "flash token expired", "call serial_flash_preview again")
            session = self.session(binding["port"])
            session.ensure_alive()
            current = self._binding(session, binding["flash_baud"], snapshot)
            if current != binding:
                changed = sorted(k for k in binding if binding[k] != current.get(k))
                raise AgentError("token_invalid", f"device or channel changed since preview: {changed}",
                                 "call serial_flash_preview again")
            snapshot.verify()
            status = session.manager.get_status()
            flash = status.get("flash") or {}
            if flash.get("active"):
                raise AgentError("busy", "a flash is already running on this channel")
        except snapshots.FlashPolicyError as exc:
            snapshot.remove()
            raise AgentError("token_invalid", str(exc)) from exc
        except AgentError:
            snapshot.remove()
            raise
        job = FlashJob(token, port_identity(session.port), snapshot, started=time.time())
        job.manager = self.manager_factory(socket_path=session.manager.socket_path)
        job.manager.multiport = True
        job.manager.channel_socket = session.manager.channel_socket
        job.manager.subscribe(lambda event: self._on_flash_status(job, event))
        # The hub starts its worker before it replies: mark the snapshot as
        # possibly in use first so a lost reply never lets it be deleted.
        # Holding finalize_lock until the reply is handled keeps a concurrent
        # serial_flash_status from finalizing (and deleting) mid-bookkeeping.
        job.finalize_lock.acquire()
        snapshot.set_state("sending", hub_pid=status.get("pid"), hub_socket=session.manager.socket_path,
                           channel_socket=session.manager.channel_socket,
                           flash_id_before=int(flash.get("id", 0)))
        with self.lock:
            self.jobs[token] = job
        session.note(f"flash start {snapshot.build_dir} ({len(snapshot.images)} images)")
        try:
            try:
                accepted = session.manager.start_flash(str(snapshot.directory), binding["flash_baud"])
            except (OSError, RuntimeError, ValueError) as exc:
                return {"token": token, "accepted": None, "outcome": "unknown", "reason": redact(str(exc)),
                        "hint": "do not retry; call serial_flash_status to learn whether it started"}
            with job.lock:
                job.flash_id = job.flash_id or int(accepted.get("flash_id", 0)) or None
            snapshot.set_state("in_use", flash_id=job.flash_id or 0)
        finally:
            job.finalize_lock.release()
        return {"token": token, "accepted": True, "flash_id": job.flash_id, "port": session.port,
                "next": "call serial_flash_status(token, wait_s=...) until it finishes"}

    def _on_flash_status(self, job: FlashJob, event: dict[str, Any], pushed: bool = True) -> None:
        if event.get("event") != "status":
            return
        channel = event.get("channel_socket")
        if channel is not None and job.manager is not None and channel != job.manager.channel_socket:
            return
        flash = event.get("flash")
        if not isinstance(flash, dict) or not job.owns(flash):
            return  # Another client's flash on this channel, or an idle status.
        with job.lock:
            revision = event.get("revision")
            if pushed and isinstance(revision, int):
                # Only the subscription stream is checked for continuity.
                if job.last_revision is not None and revision > job.last_revision + 1:
                    job.gaps += 1
                job.last_revision = max(revision, job.last_revision or 0)
            flash_id = int(flash.get("id", 0))
            if job.flash_id is None:
                job.flash_id = flash_id  # Recovered from status when the reply was lost.
            elif flash_id != job.flash_id:
                return
            line = str(flash.get("line", ""))
            if pushed and line and line != job.last_line:
                # Per-image proof comes only from the ordered push stream, so a
                # poll followed by the same pushed line is never counted twice.
                job.last_line = line
                if FLASH_VERIFIED_RE.search(line):
                    job.verified_transitions += 1
            job.events.append({"progress": flash.get("progress"), "step": redact(str(flash.get("step", "")))})
            del job.events[:-50]
            if not flash.get("active") and flash.get("exit_code") is not None and job.finished is None:
                if not pushed:
                    # Set with `finished` under the same lock: evidence is
                    # complete only once the push stream reaches this revision.
                    job.poll_revision = revision if isinstance(revision, int) else -1
                job.finished = {"exit_code": flash.get("exit_code"), "error": flash.get("error", ""),
                                "step": flash.get("step"), "state": event.get("state"),
                                "port": event.get("port")}
                session = self.sessions.get(job.session_port)
                job.completion_cursor = session.cursor if session else None

    def _job_summary(self, job: FlashJob) -> dict[str, Any]:
        with job.lock:
            last = job.events[-1] if job.events else {}
            return {"token": job.token, "flash_id": job.flash_id, "port": job.session_port,
                    "progress": last.get("progress", 0), "step": last.get("step", "Queued"),
                    "finished": job.finished is not None}

    def _poll_job(self, job: FlashJob) -> None:
        """Fill in state from a fresh status when the push stream missed it."""
        if job.finished is not None or job.manager is None:
            return
        try:
            status = job.manager.get_status()
        except (OSError, RuntimeError, ValueError):
            return
        flash = status.get("flash")
        with job.lock:
            unowned = isinstance(flash, dict) and not job.owns(flash) and not flash.get("active")
            if unowned and job.flash_id is None and not job.events and time.time() - job.started > \
                    snapshots.UNACCEPTED_GRACE:
                # The hub never ran this snapshot: its last flash is someone else's.
                job.finished = {"exit_code": None, "error": "the hub never started this flash",
                                "step": "not started", "state": status.get("state"), "port": status.get("port")}
                return
        self._on_flash_status(job, status, pushed=False)

    def flash_status(self, token: str, wait_s: float,
                     progress: Callable[[float, str], None] | None = None,
                     cancelled: Callable[[], bool] | None = None) -> dict[str, Any]:
        with self.lock:
            job = self.jobs.get(token)
        if job is None:
            raise AgentError("token_invalid", "no flash job for this token")
        deadline = time.monotonic() + max(0.0, min(MAX_FLASH_WAIT_S, wait_s))
        reported = -1.0
        while True:
            self._poll_job(job)
            summary = self._job_summary(job)
            value = float(summary["progress"] or 0)
            if progress is not None and value > reported:
                reported = value
                progress(value, str(summary["step"]))
            if job.finished is not None:
                self._await_push(job, 1.0)
                break
            if time.monotonic() >= deadline or (cancelled and cancelled()):
                break
            time.sleep(0.25)
        if job.finished is None:
            return {**summary, "verdict": "running", "hint": "call again with wait_s to keep waiting"}
        return {**summary, **self._finalize(job)}

    @staticmethod
    def _push_caught_up(job: FlashJob) -> bool:
        if job.poll_revision is None:
            return True
        return job.last_revision is not None and job.poll_revision >= 0 and \
            job.last_revision >= job.poll_revision

    def _await_push(self, job: FlashJob, timeout: float) -> None:
        """Give a live subscription a moment to deliver what polling already saw."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with job.lock:
                if self._push_caught_up(job):
                    return
            time.sleep(0.05)

    def _finalize(self, job: FlashJob) -> dict[str, Any]:
        """Compute the verdict exactly once, then release the snapshot."""
        with job.finalize_lock:
            if job.verdict is None:
                job.verdict = self._verdict(job)
                if job.manager is not None:
                    job.manager.unsubscribe()
                # The hub reported this flash finished, so it no longer reads the snapshot.
                job.snapshot.set_state("done")
                job.snapshot.remove()
            return job.verdict

    def _verdict(self, job: FlashJob) -> dict[str, Any]:
        with job.lock:
            finished = dict(job.finished or {})
            transitions = job.verified_transitions
            evidence_complete = job.gaps == 0 and self._push_caught_up(job)
            completion_cursor = job.completion_cursor
        exit_ok = finished.get("exit_code") == 0 and not finished.get("error")
        images = len(job.snapshot.images)
        if not exit_ok:
            flash_verified: bool | None = False
        elif evidence_complete and transitions == images:
            flash_verified = True
        else:
            flash_verified = None  # esptool succeeded but the per-image proof is incomplete.
        session = self.sessions.get(job.session_port)
        uart_reopened = bool(session and not session.lost and finished.get("state") in ("ready", "flashing")
                             and finished.get("port"))
        firmware_ready: bool | None = None
        boot_evidence = None
        if session is not None and completion_cursor is not None and not session.lost and exit_ok:
            if session.mode == "control":
                hello = session.request(None, None, 3.0)
                firmware_ready = hello["outcome"] == "completed" and hello.get("status") == "succeeded"
            if not firmware_ready:
                found = session.select(completion_cursor, 20, None, None, False, False)["records"]
                boot_evidence = [r.get("text") for r in found][-5:] or None
                firmware_ready = False if session.mode == "control" else (bool(found) or None)
        if flash_verified and uart_reopened and firmware_ready:
            verdict = "verified"
        elif flash_verified is False:
            verdict = "blocked"
        elif flash_verified is None:
            verdict = "unknown"
        else:
            verdict = "partial"
        return {"verdict": verdict, "flash_verified": flash_verified,
                "verified_images": f"{transitions}/{images}",
                "evidence_complete": evidence_complete, "uart_reopened": uart_reopened,
                "firmware_ready": firmware_ready, "boot_evidence": boot_evidence,
                "exit_code": finished.get("exit_code"), "error": redact(str(finished.get("error") or "")),
                "step": redact(str(finished.get("step") or ""))}


def usb_identity(device: str) -> dict[str, str]:
    """USB vid:pid:serial for a tty from sysfs, without opening it."""
    if not device.startswith("/dev/"):
        return {}
    try:
        parent = (Path("/sys/class/tty") / Path(os.path.realpath(device)).name / "device").resolve()
    except OSError:
        return {}
    for ancestor in (parent, *list(parent.parents)[:4]):
        try:
            vid = (ancestor / "idVendor").read_text().strip()
            pid = (ancestor / "idProduct").read_text().strip()
        except OSError:
            continue
        try:
            serial = (ancestor / "serial").read_text().strip()
        except OSError:
            serial = ""
        return {"usb_vid_pid": f"{vid}:{pid}", "usb_serial": serial}
    return {}
