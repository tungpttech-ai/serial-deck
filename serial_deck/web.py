#!/usr/bin/env python3
"""Serial Deck Web Dashboard: Modern web-based UART control, telemetry, and log streaming."""

from __future__ import annotations

import argparse
import base64
import dataclasses
import datetime
import errno
import ipaddress
import json
import mimetypes
import os
import queue
import re
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.parse
import uuid
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable

try:
    from . import mcp_status, runtime
    from .hub_client import (
        DEFAULT_SOCKET, BaudConflictError, HubProcessManager, HubRegistry, find_existing_hub)
    from .uart_client import (
        FRAME_COMMAND,
        FRAME_HELLO,
        FRAME_NAMES,
        FRAME_RESPONSE,
        FRAME_EVENT,
        FRAME_ERROR,
        discover_serial_ports,
        discover_serial_port_details,
        is_network_port,
        open_uart_transport,
        UartReader,
        encode_json_frame,
        make_request,
        send_frame,
        send_hello,
    )
except ImportError:
    import mcp_status
    import runtime
    from hub_client import (
        DEFAULT_SOCKET, BaudConflictError, HubProcessManager, HubRegistry, find_existing_hub)
    from uart_client import (
        FRAME_COMMAND,
        FRAME_HELLO,
        FRAME_NAMES,
        FRAME_RESPONSE,
        FRAME_EVENT,
        FRAME_ERROR,
        discover_serial_ports,
        discover_serial_port_details,
        is_network_port,
        open_uart_transport,
        UartReader,
        encode_json_frame,
        make_request,
        send_frame,
        send_hello,
    )


LOG_LEVEL_RE = re.compile(r"(?:^|\s)([EWIDV])\s+\(")
ADDRESS_RE = re.compile(r"0x[0-9a-fA-F]{4,}")
ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
SYMBOLIZE_LOG_RE = re.compile(r"backtrace|panic|assert|guru meditation|abort\s*\(", re.IGNORECASE)
FLASH_PERCENT_RE = re.compile(r"(?:\(|\s)(\d{1,3}(?:\.\d+)?)\s*%\)?")
FLASH_STEP_RE = re.compile(r"^(Connecting|Erasing|Writing|Verifying|Leaving|Hash of data verified)", re.IGNORECASE)
MAX_POST_BODY = 256 * 1024
LOOPBACK_NAMES = {"localhost", "127.0.0.1", "::1"}

def split_host_header(value: str) -> tuple[str, int | None]:
    """`host[:port]` or `[v6]:port` -> (lowercase host, port or None)."""
    value = value.strip().lower()
    if value.startswith("["):
        host, _, rest = value[1:].partition("]")
        port = rest[1:] if rest.startswith(":") else ""
    elif value.count(":") == 1:
        host, _, port = value.partition(":")
    else:
        host, port = value, ""
    if port and not port.isdigit():
        return host, -1
    return host, int(port) if port else None

def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True

def host_allowed(header: str, bound_host: str, bound_port: int) -> bool:
    """Accept only Host values that name this server, never a DNS-rebinding name.

    A loopback bind accepts loopback names; a specific-IP bind accepts that IP
    and loopback; a wildcard bind accepts `localhost` and any IP literal.
    """
    host, port = split_host_header(header)
    if not host or port != bound_port:
        return False
    bound = bound_host.strip("[]").lower()
    if host in LOOPBACK_NAMES:
        return True
    if bound in ("", "0.0.0.0", "::"):
        return _is_ip_literal(host)
    return host == bound


def parse_log_level(line: str) -> str:
    match = LOG_LEVEL_RE.search(line)
    if not match:
        return "plain"
    return {
        "E": "error",
        "W": "warning",
        "I": "info",
        "D": "debug",
        "V": "verbose",
    }.get(match.group(1), "plain")


def parse_flash_progress(line: str) -> tuple[float | None, str | None]:
    line = ANSI_ESCAPE_RE.sub("", line).strip()
    percent = None
    step = None
    percent_match = FLASH_PERCENT_RE.search(line)
    if percent_match:
        try:
            percent = float(percent_match.group(1))
        except ValueError:
            pass
    step_match = FLASH_STEP_RE.search(line.strip())
    if step_match:
        step = step_match.group(1)
    elif "write-flash" in line:
        step = "Initializing"
    elif "Leaving" in line or "Hard resetting" in line:
        step = "Completed"
    return percent, step


CONSOLE_MODES = ("control", "linux")
RAW_HISTORY_BYTES = 64 * 1024

TX_LINE_ENDINGS = {"none": b"", "lf": b"\n", "cr": b"\r", "crlf": b"\r\n"}


def parse_tx_payload(text: str, mode: str = "ascii", line_ending: str = "none") -> bytes:
    """Convert the TX box input into raw UART bytes."""
    if line_ending not in TX_LINE_ENDINGS:
        raise ValueError(f"unknown line ending: {line_ending}")
    if mode == "hex":
        digits = re.sub(r"0x|[\s,:;-]", "", text, flags=re.IGNORECASE)
        if len(digits) % 2 or re.search(r"[^0-9a-fA-F]", digits):
            raise ValueError("HEX payload must be pairs of hex digits, e.g. 50 03 or 0x50,0x03")
        data = bytes.fromhex(digits)
    elif mode == "ascii":
        data = text.encode("utf-8")
    else:
        raise ValueError(f"unknown TX mode: {mode}")
    return data + TX_LINE_ENDINGS[line_ending]


def format_tx_echo(data: bytes, mode: str) -> str:
    if mode == "hex":
        return "TX> " + data.hex(" ").upper()
    return "TX> " + data.decode("utf-8", errors="backslashreplace").encode(
        "unicode_escape").decode("ascii")


def should_symbolize_log(line: str) -> bool:
    return bool(SYMBOLIZE_LOG_RE.search(line))


def auto_find_elf(build_dir_path: str) -> str:
    path = Path(build_dir_path).expanduser().resolve()
    if not path.is_dir():
        return ""
    candidates = sorted(path.glob("*.elf"), key=lambda p: p.stat().st_mtime, reverse=True)
    if candidates:
        return str(candidates[0])
    return ""


class ElfSymbolizer:
    """Resolve application addresses with the ESP toolchain addr2line."""

    def __init__(self, elf_path: str, tool_path: str | None = None) -> None:
        self.elf_path = str(Path(elf_path).expanduser().resolve())
        if not Path(self.elf_path).is_file():
            raise ValueError(f"ELF file does not exist: {self.elf_path}")
        self.tool_path = tool_path or self._find_addr2line()
        if self.tool_path is None:
            raise RuntimeError("ESP addr2line not found; set IDF tools PATH")

    def _find_addr2line(self) -> str | None:
        # ELF e_machine: 94 = Xtensa (esp32, -s2, -s3), 243 = RISC-V (c3, c6, h2, p4, ...).
        try:
            with open(self.elf_path, "rb") as handle:
                header = handle.read(20)
            machine = int.from_bytes(header[18:20], "little") if header[:4] == b"\x7fELF" else 0
        except OSError:
            machine = 0
        xtensa = ["xtensa-esp-elf-addr2line", "xtensa-esp32-elf-addr2line"]
        riscv = ["riscv32-esp-elf-addr2line"]
        # The ELF's own architecture first, searched everywhere, before any fallback.
        groups = [xtensa, riscv] if machine == 94 else [riscv, xtensa] if machine == 243 else [riscv + xtensa]
        suffix = ".exe" if os.name == "nt" else ""
        tools_root = Path(os.environ.get("IDF_TOOLS_PATH", Path.home() / ".espressif"))
        for names in groups:
            for name in names:
                found = shutil.which(name)
                if found:
                    return found
            for name in names:
                matches = sorted(tools_root.glob(f"*/**/bin/{name}{suffix}"), reverse=True)
                if matches:
                    return str(matches[0])
        return None

    def decode(self, line: str) -> list[str]:
        addresses = list(dict.fromkeys(ADDRESS_RE.findall(line)))
        if not addresses:
            return []
        try:
            result = runtime.run_host(  # a host tool: undo the bundle's loader state
                [self.tool_path, "-pfiaC", "-e", self.elf_path, *addresses],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=1.0, check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return []
        if result.returncode != 0:
            return []
        decoded = []
        for address, trace in zip(addresses, result.stdout.splitlines()):
            if trace and "?? ??:0" not in trace:
                decoded.append(f"{address}: {trace}")
        return decoded


class DeckWebBridge:
    """Core state and communication bridge between UART hardware and web clients."""

    def __init__(self, default_port: str = "", default_baud: int = 2000000,
                 elf: str = "", hub_manager: HubProcessManager | None = None,
                 hub_registry: HubRegistry | None = None) -> None:
        self.lock = threading.Lock()
        self.transport: Any = None
        self.reader: UartReader | None = None
        self.reader_thread: threading.Thread | None = None
        self.stop_reader = threading.Event()
        self.port = default_port
        self.baud = default_baud
        self.connected = False
        # "control": COBS control frames + ESP log lines (hello, buttons, query).
        # "linux": generic console for Linux boards/other apps; no control
        # frames, raw bytes are streamed to the interactive terminal view.
        # Linux/raw is the default: nothing is sent to a device unasked.
        self.console_mode = "linux"
        self.raw_history = bytearray()
        self.dtr_state: bool | None = None
        self.rts_state: bool | None = None
        self.sequence = 1
        self.symbolizer: ElfSymbolizer | None = None
        self.elf_path = elf
        if elf:
            try:
                self.symbolizer = ElfSymbolizer(elf)
            except Exception:
                self.symbolizer = None

        self.fsm_state = "UNKNOWN"
        self.device_info = "Not connected"
        self.telemetry: dict[str, Any] = {}
        self.history_logs: list[dict[str, Any]] = []
        self.max_history = 2000
        self.sse_clients: set[queue.Queue[dict[str, Any]]] = set()
        self.sse_lock = threading.Lock()
        self.flashing = False
        self.flash_progress = 0
        self.flash_step = "Idle"
        self.flash_id = 0
        self.flash_exit_code: int | None = None
        self.hub_state = "idle"
        self._last_hub_flash_line: tuple[int, str] | None = None
        self.hub_manager = hub_manager
        self.hub_registry = hub_registry
        # True when this bridge acquired hub_manager itself from hub_registry
        # (one physical port owned by this connection) rather than being
        # constructed with a fixed, externally-owned manager.
        self._owns_manager = False
        self._registry_port = ""
        if self.hub_manager is not None:
            self.hub_manager.subscribe(self._handle_hub_status)

    def register_client(self) -> queue.Queue[dict[str, Any]]:
        q: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=1000)
        with self.sse_lock:
            self.sse_clients.add(q)
        return q

    def unregister_client(self, q: queue.Queue[dict[str, Any]]) -> None:
        with self.sse_lock:
            self.sse_clients.discard(q)

    def broadcast(self, event: dict[str, Any]) -> None:
        if "time" not in event:
            event["time"] = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]

        if event.get("type") == "log":
            with self.lock:
                self.history_logs.append(event)
                if len(self.history_logs) > self.max_history:
                    self.history_logs.pop(0)

        with self.sse_lock:
            dead = []
            for client in self.sse_clients:
                try:
                    client.put_nowait(event)
                except queue.Full:
                    dead.append(client)
            for client in dead:
                self.sse_clients.discard(client)

    def get_status(self) -> dict[str, Any]:
        with self.lock:
            return {
                "connected": self.connected,
                "port": self.port,
                "baud": self.baud,
                "dtr": self.dtr_state,
                "rts": self.rts_state,
                "fsm": self.fsm_state,
                "device": self.device_info,
                "telemetry": self.telemetry,
                "elf": self.symbolizer.elf_path if self.symbolizer else self.elf_path,
                "flashing": self.flashing,
                "flash_progress": self.flash_progress,
                "flash_step": self.flash_step,
                "hub_state": self.hub_state,
                "console_mode": self.console_mode,
                "transport_label": ("Control" if self.console_mode == "control" else "Linux") + " / "
                                   + (self.port.split("://", 1)[0].upper()
                                      if is_network_port(self.port) else "UART"),
            }

    def list_ports(self) -> list[str]:
        """Return physical UART choices discovered by the hub owner."""
        if self.hub_manager is None:
            return []
        return self.hub_manager.scan_ports()

    def _release_owned_manager(self) -> None:
        """Release and drop a hub_manager this bridge acquired itself.

        Ref-counted through hub_registry; the shared daemon retains its
        independent lifetime and reaps channels after their clients leave.
        """
        manager = self.hub_manager
        self.hub_manager = None
        self._owns_manager = False
        if manager is None:
            return
        try:
            manager.unsubscribe(self._handle_hub_status)
        finally:
            if self.hub_registry is not None:
                self.hub_registry.release(self._registry_port, manager)
                self._registry_port = ""

    def connect(self, port: str, baud: int, mode: str | None = None,
                on_baud_conflict: str = "join") -> dict[str, Any]:
        if not port or port.startswith("hub://"):
            raise ValueError("Select a physical UART or enter a tcp:// / udp:// endpoint")
        if mode is not None and mode not in CONSOLE_MODES:
            raise ValueError(f"unknown console mode: {mode}")
        if self.hub_registry is not None:
            if self.connected or self._owns_manager:
                self.disconnect()
            manager = self.hub_registry.acquire(port, baud, on_baud_conflict)
            if self.hub_manager is not None:
                self.hub_manager.unsubscribe(self._handle_hub_status)
            self.hub_manager = manager
            self._owns_manager = True
            self._registry_port = port
            self.port = port
            baud = manager.baud
            try:
                manager.subscribe(self._handle_hub_status)
            except Exception:
                self._release_owned_manager()
                raise
        elif self.hub_manager is not None:
            self.hub_manager.claim_port(port, baud, on_baud_conflict)
            baud = self.hub_manager.baud
        else:
            raise RuntimeError("UART hub is not configured")
        try:
            with self.lock:
                if self.connected:
                    self._disconnect_locked()
                self.transport = open_uart_transport(self.hub_manager.endpoint, baud, 0.1)
        except Exception as exc:
            self.transport = None
            self.connected = False
            if self._owns_manager:
                self._release_owned_manager()
            raise RuntimeError(f"Connection failed: {exc}") from exc
        with self.lock:
            self.port = port
            self.baud = baud
            if mode is not None:
                self.console_mode = mode
            self.raw_history.clear()
            self.connected = True

            try:
                if is_network_port(port):
                    raise OSError("no modem lines over the network")
                self.dtr_state, self.rts_state = self.transport.get_modem_lines()
            except Exception:
                self.dtr_state, self.rts_state = None, None

            self.stop_reader.clear()
            self.reader = UartReader(self.transport, frames=self.console_mode == "control")
            self.reader_thread = threading.Thread(target=self._reader_loop, daemon=True)
            self.reader_thread.start()

        self._send_hello()
        self.broadcast({
            "type": "status",
            **self.get_status(),
        })
        return self.get_status()

    def disconnect(self) -> dict[str, Any]:
        with self.lock:
            self._disconnect_locked()
        try:
            if self._owns_manager:
                self._release_owned_manager()
            elif self.hub_manager is not None:
                self.hub_manager.release_port()
        except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
            self.broadcast({"type": "log", "level": "warning", "text": f"[hub] release failed: {exc}"})
        self.broadcast({
            "type": "status",
            **self.get_status(),
        })
        return self.get_status()

    def _disconnect_locked(self) -> None:
        self.stop_reader.set()
        reader_thread = self.reader_thread
        self.reader_thread = None
        if reader_thread is not None and reader_thread is not threading.current_thread():
            # Wait for the reader's in-flight poll() to return before closing
            # the transport, otherwise a concurrent recv()/read() on the same
            # fd can raise "[Errno 9] Bad file descriptor".
            reader_thread.join(timeout=1.0)
        if self.transport is not None:
            try:
                self.transport.close()
            except Exception:
                pass
        self.transport = None
        self.reader = None
        self.connected = False
        self.dtr_state = None
        self.rts_state = None

    def _reader_loop(self) -> None:
        reader = self.reader
        while not self.stop_reader.is_set() and reader is not None:
            try:
                chunk = reader.transport.read()
                if chunk and self.console_mode == "linux":
                    self._broadcast_raw(chunk)
                records = reader.feed(chunk)
                for record in records:
                    self._handle_record(record)
            except Exception as exc:
                self.broadcast({
                    "type": "log",
                    "level": "error",
                    "text": f"[serial error] {exc}",
                })
                self.disconnect()
                return

    def _broadcast_raw(self, chunk: bytes) -> None:
        with self.lock:
            self.raw_history.extend(chunk)
            del self.raw_history[:-RAW_HISTORY_BYTES]
        self.broadcast({"type": "raw", "data": base64.b64encode(chunk).decode("ascii")})

    def raw_history_b64(self) -> str:
        with self.lock:
            return base64.b64encode(bytes(self.raw_history)).decode("ascii")

    def set_console_mode(self, mode: str) -> dict[str, Any]:
        if mode not in CONSOLE_MODES:
            raise ValueError(f"unknown console mode: {mode}")
        with self.lock:
            changed = self.console_mode != mode
            self.console_mode = mode
            if self.reader is not None:
                self.reader.frames = mode == "control"
        if changed and mode == "control":
            self._send_hello()
        status = self.get_status()
        self.broadcast({"type": "status", **status})
        return status

    def _handle_record(self, record: tuple[str, Any]) -> None:
        kind, value = record
        if kind == "log":
            value = ANSI_ESCAPE_RE.sub("", value)
            level = parse_log_level(value)
            self.broadcast({
                "type": "log",
                "level": level,
                "text": value,
            })
            if self.symbolizer is not None and should_symbolize_log(value):
                for decoded in self.symbolizer.decode(value):
                    self.broadcast({
                        "type": "log",
                        "level": "elf",
                        "text": f"  [ELF] {decoded}",
                    })
        else:
            frame_type, _flags, sequence, message = value
            name = FRAME_NAMES.get(frame_type, f"type-{frame_type}")
            self.broadcast({
                "type": "frame",
                "frame_type": name,
                "sequence": sequence,
                "message": message,
            })
            self._update_telemetry(frame_type, message)

    def _update_telemetry(self, frame_type: int, message: Any) -> None:
        if not isinstance(message, dict):
            return
        with self.lock:
            if frame_type == FRAME_HELLO:
                cmds = ", ".join(message.get("commands", []))
                self.device_info = f"{message.get('target', 'device')} @ {message.get('baud', self.baud)} baud [{cmds}]"
            if "status" in message:
                self.fsm_state = str(message["status"]).upper()
            if "result" in message:
                res = message["result"]
                if isinstance(res, dict):
                    self.telemetry.update(res)
                    if "state" in res:
                        self.fsm_state = str(res["state"]).upper()
                    if "fsm" in res:
                        self.fsm_state = str(res["fsm"]).upper()
                else:
                    self.fsm_state = str(res)
        self.broadcast({
            "type": "status",
            **self.get_status(),
        })

    def _send_hello(self) -> None:
        with self.lock:
            if not self.connected or self.transport is None or self.console_mode != "control":
                return
            try:
                send_hello(self.transport, self.sequence, "serial-deck-web")
                self.sequence += 1
            except Exception as exc:
                self.broadcast({"type": "log", "level": "error", "text": f"[send_hello error] {exc}"})

    def send_command(self, payload: dict[str, Any]) -> None:
        with self.lock:
            if not self.connected or self.transport is None:
                raise RuntimeError("Not connected to UART")
            if self.console_mode != "control":
                raise RuntimeError("Control commands are off in Linux console mode")
            frame = encode_json_frame(FRAME_COMMAND, self.sequence, payload)
            send_frame(self.transport, frame)
            self.sequence += 1

    def send_raw(self, text: str, mode: str = "ascii", line_ending: str = "none") -> int:
        data = parse_tx_payload(text, mode, line_ending)
        if not data:
            raise ValueError("Nothing to send")
        with self.lock:
            if not self.connected or self.transport is None:
                raise RuntimeError("Not connected to UART")
            self.transport.write(data)
        self.broadcast({"type": "log", "level": "tx", "text": format_tx_echo(data, mode)})
        return len(data)

    def send_term_input(self, data: bytes) -> None:
        """Forward interactive terminal keystrokes verbatim (no console echo)."""
        if not data:
            return
        with self.lock:
            if not self.connected or self.transport is None:
                raise RuntimeError("Not connected to UART")
            self.transport.write(data)

    def send_break(self) -> None:
        if self.hub_manager is None or not self.connected:
            raise RuntimeError("Not connected to UART")
        self.hub_manager.request_control("break")
        self.broadcast({"type": "log", "level": "tx", "text": f"TX> <BREAK> on {self.port}"})

    def send_button(self, button: str, action: str = "press") -> None:
        self.send_command(make_request("input.button", {"button": button, "action": action}))

    def send_query(self, kind: str) -> None:
        self.send_command(make_request("query", {"kind": kind}, deadline_ms=1000))

    def show_info(self) -> None:
        self.send_command(make_request("ui.show_info", {}))

    def control_lines(self, action: str, line: str | None = None) -> dict[str, Any]:
        if self.hub_manager is None:
            raise RuntimeError("UART hub is not configured")
        if action in ("reset", "bootloader"):
            response = self.hub_manager.request_control(action)
        elif action == "toggle_dtr":
            current = self.hub_manager.request_control("get_lines")
            response = self.hub_manager.request_control(
                "lines", dtr=not bool(current.get("dtr")))
        elif action == "toggle_rts":
            current = self.hub_manager.request_control("get_lines")
            response = self.hub_manager.request_control(
                "lines", rts=not bool(current.get("rts")))
        else:
            raise ValueError(f"unknown line action: {action}")
        self.dtr_state = bool(response.get("dtr"))
        self.rts_state = bool(response.get("rts"))
        self.broadcast({
            "type": "log",
            "level": "elf",
            "text": f"[hub] {action} on {self.port}",
        })

        status = self.get_status()
        self.broadcast({"type": "status", **status})
        return status

    def load_elf(self, elf_path: str) -> dict[str, Any]:
        self.symbolizer = ElfSymbolizer(elf_path)
        self.elf_path = elf_path
        self.broadcast({"type": "log", "level": "elf", "text": f"[ELF] Loaded symbols from {self.symbolizer.elf_path}"})
        return {"ok": True, "elf": self.symbolizer.elf_path}

    def start_flash(self, build_dir: str, flash_baud: int) -> None:
        if self.hub_manager is None:
            raise RuntimeError("UART hub is not configured")
        if not self.port:
            raise ValueError("Connect a physical UART through the hub before flashing")
        self.hub_manager.preview_flash(build_dir, flash_baud)
        self.hub_manager.start_flash(build_dir, flash_baud)

    def _handle_hub_status(self, status: dict[str, object]) -> None:
        flash = status.get("flash")
        if not isinstance(flash, dict):
            return
        lost_while_connected = False
        retimed: tuple[int, int] | None = None
        with self.lock:
            self.hub_state = str(status.get("state", "idle"))
            port = status.get("port")
            if isinstance(port, str):
                self.port = port
            if isinstance(status.get("baud"), int):
                if self.connected and status["baud"] != self.baud:
                    retimed = (self.baud, status["baud"])
                self.baud = status["baud"]
            if not isinstance(port, str) and self.connected and not flash.get("active"):
                # The hub only reports no port while a data client (us) is
                # still attached when it force-dropped a physically lost
                # UART (UartHub._handle_serial_lost) — its own `release`
                # action refuses to run while a client is connected. Reflect
                # the loss immediately instead of waiting for our own data
                # socket to notice the closed connection on its next poll.
                lost_while_connected = True
            self.flashing = bool(flash.get("active"))
            self.flash_id = int(flash.get("id", 0))
            self.flash_progress = float(flash.get("progress", 0))
            self.flash_step = str(flash.get("step", "Idle"))
            exit_code = flash.get("exit_code")
            new_exit_code = int(exit_code) if exit_code is not None else None
            done_changed = new_exit_code is not None and new_exit_code != self.flash_exit_code
            self.flash_exit_code = new_exit_code
            line = str(flash.get("line", ""))
            line_key = (self.flash_id, line)
            new_flash_line = bool(line) and line_key != self._last_hub_flash_line
            if new_flash_line:
                self._last_hub_flash_line = line_key
        if lost_while_connected:
            self.broadcast({
                "type": "log",
                "level": "error",
                "text": "[hub] physical UART was lost",
            })
            self.disconnect()
            return
        if retimed is not None:
            self.broadcast({
                "type": "log",
                "level": "warning",
                "text": f"[hub] UART baud changed {retimed[0]} -> {retimed[1]}",
            })
        self.broadcast({
            "type": "flash",
            "text": line,
            "percent": self.flash_progress,
            "step": self.flash_step,
            "flash_id": self.flash_id,
        })
        self.broadcast({"type": "status", **self.get_status()})
        if new_flash_line:
            self.broadcast({
                "type": "log",
                "level": "elf",
                "text": f"[hub flash] {line}",
            })
        if not self.flashing and done_changed:
            code = self.flash_exit_code if self.flash_exit_code is not None else 1
            self.broadcast({
                "type": "flash_done",
                "success": code == 0,
                "code": code,
                "text": self.flash_step,
                "flash_id": self.flash_id,
            })

    def close(self) -> None:
        self.disconnect()
        if self.hub_manager is not None:
            self.hub_manager.unsubscribe()


class ConnectionManager:
    """Own one `DeckWebBridge` per open dashboard tab.

    Every tab keeps streaming/logging independently of which one is
    currently focused in the browser; different physical ports run fully
    independent channels via `hub_registry`, while all tabs share one daemon.
    """

    DEFAULT_ID = "default"

    def __init__(self, default_bridge: DeckWebBridge, hub_registry: HubRegistry,
                 baud: int, elf: str) -> None:
        self.hub_registry = hub_registry
        self.baud = baud
        self.elf = elf
        self.lock = threading.Lock()
        self._bridges: dict[str, DeckWebBridge] = {self.DEFAULT_ID: default_bridge}
        self._order: list[str] = [self.DEFAULT_ID]
        self.lifecycle_hubs: list[HubProcessManager] = []

    def get(self, conn_id: str) -> DeckWebBridge:
        with self.lock:
            bridge = self._bridges.get(conn_id)
        if bridge is None:
            raise KeyError(f"unknown connection id: {conn_id}")
        return bridge

    def create(self) -> tuple[str, DeckWebBridge]:
        conn_id = uuid.uuid4().hex[:12]
        bridge = DeckWebBridge(default_baud=self.baud, elf=self.elf, hub_registry=self.hub_registry)
        with self.lock:
            self._bridges[conn_id] = bridge
            self._order.append(conn_id)
        return conn_id, bridge

    def close(self, conn_id: str) -> None:
        if conn_id == self.DEFAULT_ID:
            raise ValueError("the default connection cannot be closed")
        with self.lock:
            bridge = self._bridges.pop(conn_id, None)
            if conn_id in self._order:
                self._order.remove(conn_id)
        if bridge is not None:
            bridge.close()

    def list_status(self) -> list[dict[str, Any]]:
        with self.lock:
            items = [(conn_id, self._bridges[conn_id]) for conn_id in self._order
                     if conn_id in self._bridges]
        return [{"id": conn_id, "default": conn_id == self.DEFAULT_ID, **bridge.get_status()}
                for conn_id, bridge in items]

    def close_all(self) -> None:
        with self.lock:
            bridges = list(self._bridges.values())
            self._bridges.clear()
            self._order.clear()
        for bridge in bridges:
            bridge.close()

    def hub_flash_states(self, timeout: float = 1.0) -> list[tuple[str, Any, str]]:
        """`(label, manager, state)` for each distinct hub of every connection.

        `state` is "active" or "idle" from a fresh `status` request, so a
        flash started by another client of a shared hub counts too. When a
        hub does not answer, the state is "unknown" if this process started
        that hub and it is still running, since stopping it could interrupt a
        flash. It is "idle" if that process has already exited, or if this
        process only attached to the hub: we never stop a hub we attached to.
        A cached `flashing` flag is never trusted to mean idle.
        """
        with self.lock:
            bridges = [self._bridges[conn_id] for conn_id in self._order
                       if conn_id in self._bridges]
        states: list[tuple[str, Any, str]] = []
        checked: set[int] = set()
        for bridge in bridges:
            manager = bridge.hub_manager
            if manager is None or id(manager) in checked:
                continue
            checked.add(id(manager))
            states.append((bridge.port or manager.socket_path, manager,
                           hub_flash_state(manager, timeout)))
        for manager in self.lifecycle_hubs:
            if id(manager) not in checked:
                states.append((manager.socket_path, manager, hub_flash_state(manager, timeout)))
                checked.add(id(manager))
        return states

    def flash_check(self, timeout: float = 1.0) -> FlashCheck:
        check = FlashCheck()
        for label, _manager, state in self.hub_flash_states(timeout):
            if state == "active":
                check.active.append(label)
            elif state == "unknown":
                check.unknown.append(label)
        return check


def _owns_live_process(manager: Any) -> bool:
    process = getattr(manager, "process", None)
    return (bool(getattr(manager, "owns_process", False))
            and process is not None and process.poll() is None)


def hub_flash_state(manager: Any, timeout: float = 1.0) -> str:
    """"active"/"idle" from a fresh `status` whose `flash.active` is a bool.

    No answer or a malformed answer is "unknown" when this process started the
    hub and it is still running (stopping it could interrupt a flash), and
    "idle" otherwise: a dead process cannot flash, and a hub we only attached
    to is never stopped by us.
    """
    try:
        flash = manager.request_control("status", timeout=timeout).get("flash")
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError):
        flash = None
    if isinstance(flash, dict) and isinstance(flash.get("active"), bool):
        return "active" if flash["active"] else "idle"
    return "unknown" if _owns_live_process(manager) else "idle"


def keep_unsafe_hub_running(manager: Any, label: str, state: str | None = None) -> bool:
    """Before stopping `manager`: if it is an owned hub that is flashing or
    whose flash state is unknown, clear `owns_process` so `stop()` leaves it
    running, and say so. Returns True when the hub was kept."""
    if not getattr(manager, "owns_process", False):
        return False
    if state is None:
        state = hub_flash_state(manager)
    if state == "idle":
        return False
    pid = getattr(getattr(manager, "process", None), "pid", "?")
    reason = "is flashing" if state == "active" else "did not report its flash state"
    print(f"Leaving UART hub for {label} running (pid {pid}, {manager.socket_path}): "
          f"it {reason}. Stop it after checking its status.",
          file=sys.stderr, flush=True)
    manager.owns_process = False
    return True


@dataclasses.dataclass
class FlashCheck:
    """Hubs that make closing unsafe: flashing now, or state unknown."""

    active: list[str] = dataclasses.field(default_factory=list)
    unknown: list[str] = dataclasses.field(default_factory=list)

    @property
    def blocked(self) -> bool:
        return bool(self.active or self.unknown)


class BrowserLifecycle:
    """When a browser-mode app (no native window) may stop serving.

    It stops on Quit from the dashboard, or once every dashboard tab has been
    gone for `idle_s` (after at least one connected, or `first_tab_s` after
    start when the browser never came). Both obey the same flash guard as
    closing the app window: never while a flash runs or a hub's state is unknown.
    """

    def __init__(self, blocker, idle_s: float = 60.0, first_tab_s: float = 120.0) -> None:
        self._blocker = blocker  # () -> str | None, like AppController.close_blocker
        self.idle_s = idle_s
        self.first_tab_s = first_tab_s
        self._lock = threading.Lock()
        self._streams = 0
        self._seen = False
        self._last_change = time.monotonic()
        self.quit_requested = threading.Event()

    def stream_opened(self) -> None:
        with self._lock:
            self._streams += 1
            self._seen = True
            self._last_change = time.monotonic()

    def stream_closed(self) -> None:
        with self._lock:
            self._streams = max(0, self._streams - 1)
            self._last_change = time.monotonic()

    def request_quit(self) -> str | None:
        blocker = self._blocker()
        if blocker is None:
            self.quit_requested.set()
        return blocker

    def idle_expired(self) -> bool:
        with self._lock:
            if self._streams:
                return False
            limit = self.idle_s if self._seen else self.first_tab_s
            return time.monotonic() - self._last_change >= limit


ASSET_ROOT = Path(__file__).resolve().with_name("web_assets")
ASSET_TYPES = {
    ".js": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".woff2": "font/woff2",
    ".woff": "font/woff",
    ".ttf": "font/ttf",
}


def resolve_asset(url_path: str, root: Path = ASSET_ROOT) -> Path | None:
    """Map `/assets/<relative path>` to a vendored file, or None.

    Only plain relative names below `root` with an allowlisted extension are
    served: no `..`, hidden names, backslashes, or symlinks leading outside.
    """
    if not url_path.startswith("/assets/"):
        return None
    relative = urllib.parse.unquote(url_path[len("/assets/"):])
    if not relative or "\\" in relative or "\x00" in relative:
        return None
    parts = relative.split("/")
    if any(not part or part.startswith(".") for part in parts):
        return None
    root = root.resolve()
    candidate = root.joinpath(*parts).resolve()
    if not candidate.is_relative_to(root) or candidate.suffix.lower() not in ASSET_TYPES:
        return None
    return candidate if candidate.is_file() else None


class DeckHttpHandler(BaseHTTPRequestHandler):
    connections: ConnectionManager
    # Random per-process value the pywebview app uses to confirm it reached
    # its own server rather than some other listener on that port.
    instance_token = ""

    def _conn_id(self, query: dict[str, list[str]]) -> str:
        return query.get("id", [ConnectionManager.DEFAULT_ID])[0] or ConnectionManager.DEFAULT_ID

    def _reject(self, status: HTTPStatus, error: str) -> None:
        self._send_json({"ok": False, "error": error}, status=status)

    def _host_ok(self) -> bool:
        """Refuse requests addressed to another name (DNS rebinding)."""
        bound_host, bound_port = self.server.server_address[:2]
        if host_allowed(self.headers.get("Host", ""), str(bound_host), int(bound_port)):
            return True
        self._reject(HTTPStatus.FORBIDDEN, "request Host does not name this dashboard")
        return False

    def _post_ok(self) -> bool:
        """Browsers send cross-site text/plain/form POSTs without preflight; a
        JSON content type plus a same-origin Origin blocks those (CSRF)."""
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            self._reject(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "POST requires Content-Type: application/json")
            return False
        origin = self.headers.get("Origin")
        if origin is not None and origin.lower() != f"http://{self.headers.get('Host', '')}".lower():
            self._reject(HTTPStatus.FORBIDDEN, "cross-origin request refused")
            return False
        return True

    def do_GET(self) -> None:
        if not self._host_ok():
            return
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        if path == "/" or path == "/index.html":
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(HTML_PAGE.encode("utf-8"))
            return

        if path.startswith("/assets/"):
            self._send_asset(path)
            return

        if path == "/api/instance":
            self._send_json({"app": "serial-deck-web", "instance": self.instance_token,
                             "browser_mode": getattr(self, "lifecycle", None) is not None})
            return

        if path == "/api/connections":
            self._send_json({"connections": self.connections.list_status()})
            return

        if path == "/api/mcp":
            self._send_json(mcp_status.overview())
            return

        if path == "/api/ports":
            details = discover_serial_port_details()
            self._send_json({"ports": [item["device"] for item in details], "details": details})
            return

        if path == "/api/autodetect_elf":
            build_dir = query.get("build_dir", ["build"])[0]
            elf = auto_find_elf(build_dir)
            self._send_json({"elf": elf})
            return

        try:
            bridge = self.connections.get(self._conn_id(query))
        except KeyError as exc:
            self.send_error(HTTPStatus.NOT_FOUND, str(exc))
            return

        if path == "/api/status":
            self._send_json(bridge.get_status())
            return

        if path == "/api/export_logs":
            self.send_response(HTTPStatus.OK)
            # octet-stream (not text/plain) so WebKit in the app window saves
            # the file instead of displaying it; the content is UTF-8 text.
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Disposition", 'attachment; filename="serial_console.log"')
            self.end_headers()
            with bridge.lock:
                for entry in bridge.history_logs:
                    t = entry.get("time", "")
                    lvl = entry.get("level", "plain").upper()
                    txt = entry.get("text", "")
                    self.wfile.write(f"[{t}] [{lvl}] {txt}\n".encode("utf-8"))
            return

        if path == "/api/stream":
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.end_headers()

            q = bridge.register_client()
            lifecycle = getattr(self, "lifecycle", None)
            if lifecycle is not None:
                lifecycle.stream_opened()
            try:
                # Send initial status & history replay
                init_msg = json.dumps({"type": "init", "status": bridge.get_status(),
                                       "logs": bridge.history_logs[-200:],
                                       "raw": bridge.raw_history_b64()})
                self.wfile.write(f"data: {init_msg}\n\n".encode("utf-8"))
                self.wfile.flush()

                while True:
                    try:
                        event = q.get(timeout=20.0)
                        data = json.dumps(event)
                        self.wfile.write(f"data: {data}\n\n".encode("utf-8"))
                        self.wfile.flush()
                    except queue.Empty:
                        # Heartbeat
                        self.wfile.write(b": heartbeat\n\n")
                        self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass
            finally:
                bridge.unregister_client(q)
                if lifecycle is not None:
                    lifecycle.stream_closed()
            return

        self.send_error(HTTPStatus.NOT_FOUND, "Not found")

    def do_POST(self) -> None:
        if not self._host_ok() or not self._post_ok():
            return
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        try:
            body = self._read_json_body()
        except ValueError as exc:
            status = (HTTPStatus.REQUEST_ENTITY_TOO_LARGE if "too large" in str(exc)
                      else HTTPStatus.BAD_REQUEST)
            self._reject(status, str(exc))
            return

        try:
            if path == "/api/quit":
                lifecycle = getattr(self, "lifecycle", None)
                if lifecycle is None:
                    self.send_error(HTTPStatus.NOT_FOUND, "Not found")
                    return
                blocker = lifecycle.request_quit()
                if blocker:
                    self._send_json({"ok": False, "error": blocker}, status=HTTPStatus.CONFLICT)
                else:
                    self._send_json({"ok": True})
                return

            if path == "/api/connections":
                conn_id, bridge = self.connections.create()
                self._send_json({"ok": True, "id": conn_id, "status": bridge.get_status()})
                return

            if path == "/api/connections/close":
                conn_id = str(body.get("id", ""))
                self.connections.close(conn_id)
                self._send_json({"ok": True})
                return

            bridge = self.connections.get(str(body.get("id", "")) or ConnectionManager.DEFAULT_ID)

            if path == "/api/connect":
                port = body.get("port", "").strip()
                baud = int(body.get("baud", 2000000))
                mode = body.get("mode")
                try:
                    status = bridge.connect(port, baud, str(mode) if mode else None,
                                            str(body.get("on_baud_conflict", "join")))
                except BaudConflictError as exc:
                    self._send_json({"ok": False, "error": str(exc), "baud_conflict": {
                        "port": exc.port, "live_baud": exc.live_baud,
                        "requested_baud": exc.requested_baud, "client_count": exc.client_count,
                    }}, status=HTTPStatus.CONFLICT)
                    return
                self._send_json({"ok": True, "status": status})
                return

            if path == "/api/disconnect":
                status = bridge.disconnect()
                self._send_json({"ok": True, "status": status})
                return

            if path == "/api/button":
                btn = body.get("button", "ENTER")
                action = body.get("action", "press")
                bridge.send_button(btn, action)
                self._send_json({"ok": True})
                return

            if path == "/api/tx":
                sent = bridge.send_raw(str(body.get("data", "")),
                                       str(body.get("mode", "ascii")),
                                       str(body.get("line_ending", "none")))
                self._send_json({"ok": True, "bytes": sent})
                return

            if path == "/api/console_mode":
                status = bridge.set_console_mode(str(body.get("mode", "")))
                self._send_json({"ok": True, "status": status})
                return

            if path == "/api/term_input":
                bridge.send_term_input(base64.b64decode(str(body.get("data", "")), validate=True))
                self._send_json({"ok": True})
                return

            if path == "/api/break":
                bridge.send_break()
                self._send_json({"ok": True})
                return

            if path == "/api/query":
                kind = body.get("kind", "snapshot")
                bridge.send_query(kind)
                self._send_json({"ok": True})
                return

            if path == "/api/show_info":
                bridge.show_info()
                self._send_json({"ok": True})
                return

            if path == "/api/lines":
                action = body.get("action", "")
                status = bridge.control_lines(action)
                self._send_json({"ok": True, "status": status})
                return

            if path == "/api/symbols":
                elf_path = body.get("elf_path", "")
                res = bridge.load_elf(elf_path)
                self._send_json(res)
                return

            if path == "/api/flash":
                build_dir = body.get("build_dir", "build")
                flash_baud = int(body.get("flash_baud", 3000000))
                bridge.start_flash(build_dir, flash_baud)
                self._send_json({"ok": True})
                return

            self.send_error(HTTPStatus.NOT_FOUND, f"Endpoint {path} not found")
        except Exception as exc:
            self._send_json({"ok": False, "error": str(exc)}, status=HTTPStatus.BAD_REQUEST)

    def _read_json_body(self) -> dict[str, Any]:
        try:
            length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            raise ValueError("invalid Content-Length") from None
        if length <= 0:
            return {}
        if length > MAX_POST_BODY:
            self.close_connection = True
            raise ValueError("request body too large")
        raw = self.wfile.flush() or self.rfile.read(length)
        try:
            body = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ValueError("request body is not valid JSON") from None
        if not isinstance(body, dict):
            raise ValueError("request body must be a JSON object")
        return body

    def _send_json(self, data: Any, status: HTTPStatus = HTTPStatus.OK) -> None:
        payload = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _send_asset(self, path: str) -> None:
        asset = resolve_asset(path)
        if asset is None:
            self.send_error(HTTPStatus.NOT_FOUND, "Not found")
            return
        payload = asset.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", ASSET_TYPES[asset.suffix.lower()])
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "max-age=86400")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args: Any) -> None:
        # Suppress noisy default http logging
        pass


HTML_PAGE = """<!DOCTYPE html>
<html lang="en" class="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Serial Deck</title>
  <script src="/assets/vendor/tailwindcss/tailwindcss-3.4.17.js"></script>
  <script>
    tailwind.config = {
      darkMode: 'class',
      theme: {
        extend: {
          colors: {
            brand: {
              bg: '#111318',
              surface: '#1e2024',
              surfaceAlt: '#1a1c20',
              border: '#3b494c',
              accent: '#00e5ff',
              accentHover: '#00daf3',
              flash: '#fd9000',
              flashHover: '#ffb778',
              danger: '#ff6b61',
              success: '#22ef7e',
              warning: '#ffb778',
              cyan: '#00daf3',
              blue: '#8fd8ff',
              purple: '#b1ffbf',
              tx: '#ff8fd8',
              muted: '#bac9cc',
              text: '#e2e2e8'
            }
          }
        }
      }
    }
  </script>
  <!-- Vendored locally (web_assets/vendor/README.md) so the UI works offline. -->
  <link rel="stylesheet" href="/assets/vendor/fontawesome/6.4.0/css/all.min.css">
  <link rel="stylesheet" href="/assets/vendor/xterm/5.5.0/xterm.min.css">
  <script src="/assets/vendor/xterm/5.5.0/xterm.min.js"></script>
  <script src="/assets/vendor/xterm-addon-fit/0.10.0/addon-fit.min.js"></script>
  <link rel="stylesheet" href="/assets/vendor/fonts/fonts.css">
  <style>
    body {
      background:
        radial-gradient(circle at 78% -20%, rgba(0,229,255,.08), transparent 33rem),
        linear-gradient(rgba(255,255,255,.015) 1px, transparent 1px),
        linear-gradient(90deg, rgba(255,255,255,.015) 1px, transparent 1px),
        #111318;
      background-size: auto, 32px 32px, 32px 32px, auto;
      color: #e2e2e8;
      font-family: 'Inter', ui-sans-serif, system-ui, sans-serif;
    }
    .mono { font-family: 'JetBrains Mono', 'Cascadia Mono', 'Fira Code', ui-monospace, monospace; }
    ::-webkit-scrollbar { width: 8px; height: 8px; }
    ::-webkit-scrollbar-track { background: #111318; }
    ::-webkit-scrollbar-thumb { background: #3b494c; border-radius: 0; }
    ::-webkit-scrollbar-thumb:hover { background: #849396; }
    #terminalHost .xterm-viewport { background-color: #0c0e12 !important; scrollbar-color: #3b494c transparent; }
    .glass-card { background: #1e2024; border: 1px solid #3b494c; border-radius: 4px; box-shadow: inset 0 1px 0 rgba(255,255,255,.025); }
    .rounded-lg, .rounded-xl { border-radius: 4px; }
    .shadow, .shadow-md, .shadow-lg, .shadow-md { box-shadow: none !important; }
    .dpad-btn {
      background: #1a1c20;
      border: 1px solid #3b494c;
      transition: all 0.12s ease-in-out;
      user-select: none;
    }
    .dpad-btn:active, .dpad-btn.active-key {
      background: #00e5ff;
      color: #00363d;
      transform: scale(0.96);
      box-shadow: 0 0 12px rgba(0, 229, 255, 0.35);
    }
    .power-btn:active, .power-btn.active-key {
      background: #ff6b61 !important;
      color: #fff !important;
      box-shadow: 0 0 12px rgba(255, 107, 97, 0.4) !important;
    }
    .control-rail {
      position: fixed;
      inset: 0 auto 0 0;
      z-index: 40;
      width: 56px;
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 8px;
      padding: 12px 8px;
      background: #0c0e12;
      border-right: 1px solid #3b494c;
    }
    .rail-mark {
      display: grid;
      place-items: center;
      width: 32px;
      height: 32px;
      margin-bottom: 12px;
      color: #00e5ff;
      font-size: 17px;
    }
    .rail-btn {
      width: 36px;
      height: 36px;
      border: 1px solid transparent;
      border-radius: 4px;
      background: transparent;
      color: #849396;
      cursor: pointer;
      transition: color .15s ease, background .15s ease, border-color .15s ease;
    }
    .rail-btn:hover, .rail-btn.active {
      color: #00363d;
      background: #00e5ff;
      border-color: #00e5ff;
    }
    .rail-btn { position: relative; }
    .rail-sep { width: 24px; height: 1px; background: #3b494c; margin: 4px 0; }
    .rail-badge {
      position: absolute; top: -4px; right: -6px; min-width: 16px; height: 16px; padding: 0 4px;
      border-radius: 8px; background: #22ef7e; color: #00210d; font-size: 10px; font-weight: 800;
      line-height: 16px; text-align: center;
    }
    header, body > section, main { margin-left: 56px; }
    /* Collapsing the dock removes it from layout (and hit-testing) instead of
       leaving zero-width cards that still overlap the console. */
    #sidebarPanel.collapsed { display: none; }
    body[data-page="mcp"] #telemetryPanel { display: none; }
    body:not([data-page="mcp"]) #mcpPage { display: none; }
    #mcpPage { min-height: 0; }
    .mcp-card { background: #1e2024; border: 1px solid #3b494c; border-radius: 4px; }
    .mcp-code { position: relative; }
    .mcp-code pre {
      margin: 0; padding: 8px 40px 8px 10px; background: #0c0e12; border: 1px solid #3b494c; border-radius: 4px;
      white-space: pre-wrap; word-break: break-all; font-size: 11px; color: #e2e2e8; user-select: text;
    }
    .mcp-code button {
      position: absolute; top: 4px; right: 4px; padding: 2px 6px; font-size: 11px; border-radius: 3px;
      background: #1a1c20; border: 1px solid #3b494c; color: #bac9cc;
    }
    .mcp-code button:hover { color: #00e5ff; border-color: #00e5ff; }
    .select-text, .select-text * { user-select: text; -webkit-user-select: text; }
    button:focus-visible, input:focus-visible, select:focus-visible {
      outline: 2px solid #00e5ff;
      outline-offset: 2px;
    }
    :root { color-scheme: dark; }
    /* WebKitGTK (app window) draws native selects with the light GTK theme,
       ignoring the Tailwind colors. Drop the native look and draw the arrow
       ourselves; background colors still come from each select's classes. */
    select {
      -webkit-appearance: none;
      appearance: none;
      color-scheme: dark;
      color: #e2e2e8;
      background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='10' height='6' viewBox='0 0 10 6'%3E%3Cpath d='M1 1l4 4 4-4' fill='none' stroke='%23bac9cc' stroke-width='1.5'/%3E%3C/svg%3E");
      background-repeat: no-repeat;
      background-position: right .45rem center;
      background-size: 10px 6px;
      padding-right: 1.4rem !important;
    }
    select:disabled { color: #849396; opacity: .7; cursor: not-allowed; }
    select option, select optgroup { background-color: #1e2024; color: #e2e2e8; }
    select option:disabled { color: #849396; }
    select option:checked { background-color: #3b494c; }
    #appHeader { gap: 12px; flex-wrap: wrap; }
    #appHeader > div:first-child { min-width: 0; }
    #appHeader h1 { overflow-wrap: anywhere; }
    #connectionControls { flex: 1 1 640px; min-width: 0; flex-wrap: wrap; gap: 8px; justify-content: flex-end; }
    #connectionControls > * { margin-left: 0; }
    #connectionForm { flex: 1 1 520px; min-width: 0; display: grid; gap: 8px; grid-template-columns: minmax(140px, 1fr) auto auto auto; }
    #connectionForm > * { margin-left: 0; }
    #portPicker { min-width: 0; flex-wrap: wrap; }
    #portSelect { flex: 1 1 0; min-width: 0; width: 0; text-overflow: ellipsis; }
    #portPicker > button, #portPicker > i { flex-shrink: 0; }
    #netPortInput { flex: 1 0 100%; width: 100%; min-width: 0; margin: 6px 0 0; }
    #connectionStatus { min-width: 0; max-width: 100%; }
    #connLabel { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    #connTabsBar, #connTabs { min-width: 0; }
    #healthBar, #healthBar > div { flex-wrap: wrap; gap: 8px 16px; min-width: 0; }
    #healthBar > div > * { margin-left: 0; }
    #deviceBadge { overflow-wrap: anywhere; min-width: 0; }
    #telemetryPanel, #consolePanel, #viewLogs, #viewEvents, #viewInspector, #viewTerminal { min-height: 0; }
    #sidebarPanel { transition: width .15s ease, opacity .15s ease; min-width: 0; }
    #consoleToolbar { flex-wrap: wrap; gap: 8px; }
    #consoleTabs, #consoleFilters, #levelFilters { flex-wrap: wrap; gap: 4px; min-width: 0; }
    #consoleTabs > *, #consoleFilters > *, #levelFilters > * { margin-left: 0; }
    #consoleTabs button { white-space: nowrap; padding-left: 8px; padding-right: 8px; }
    #consoleFilters { flex: 1 1 100%; }
    #consoleFilters > div:first-child { flex: 1 1 150px; min-width: 0; }
    #logSearchInput { width: 100%; }
    #terminalToolbar, #terminalToolbar > div { flex-wrap: wrap; gap: 6px; }
    #terminalToolbar > div > * { margin-left: 0; }
    /* xterm sizes its screen in fixed pixels from cols x cell width. Without
       min-width:0 every flex ancestor grows to that width, so after the
       window shrinks the console overflows off-screen, fit() measures the
       overflowed size and clicks map to the wrong cells. Let them shrink. */
    #terminalHost { overflow: hidden; position: relative; min-width: 0; width: 100%; }
    #terminalHost .xterm { position: absolute; inset: 4px; }
    #viewTerminal, #terminalToolbar, #consoleToolbar, #txBar { min-width: 0; max-width: 100%; }
    #consolePanel { min-width: 0; max-width: 100%; }
    #txBar { flex-wrap: wrap; gap: 6px; }
    #txBar > * { margin-left: 0; }
    #txInput { flex: 1 1 180px; }
    #splitConnSelect { max-width: 100%; min-width: 0; }
    @media (min-width: 901px) {
      #sidebarPanel { max-width: 38%; }
    }
    @media (max-width: 1100px) {
      #connectionStatus { flex-basis: auto; }
      #connectionControls { flex-basis: 100%; }
    }
    @media (max-width: 900px), (max-height: 620px) {
      body { height: auto !important; min-height: 100vh; overflow: auto !important; }
      #telemetryPanel { overflow: visible; }
      /* Fixed height for page scrolling, but keep shrinking horizontally. */
      #consolePanel { flex: 1 1 0%; height: max(520px, 80vh); }
    }
    @media (max-width: 900px) {
      .control-rail {
        inset: auto 0 0 0; width: auto; height: 48px; flex-direction: row; justify-content: center;
        padding: 6px; border-right: none; border-top: 1px solid #3b494c;
      }
      .rail-mark, .rail-sep { display: none; }
      header, body > section, main, #mcpPage { margin-left: 0; }
      /* The rail becomes a bottom bar: reserve its height so it never sits on
         top of the last controls (it is position:fixed, outside the flow). */
      body { padding-bottom: 48px; box-sizing: border-box; }
      #telemetryPanel, #mcpPage { margin-bottom: 0; }
      #appHeader { align-items: stretch; }
      #appHeader > div:first-child { width: 100%; }
      #connectionControls { width: 100%; justify-content: flex-start; }
      #connectionForm { flex-basis: 100%; }
      #telemetryPanel { flex-direction: column; gap: 16px; }
      #sidebarPanel { width: 100% !important; max-width: none; opacity: 1 !important; pointer-events: auto !important; overflow: visible !important; padding-right: 0 !important; }
      #sidebarResizeHandle { display: none; }
      #viewLogs { flex-direction: column; }
      #logsPaneSplit { border-left: none; border-top: 1px solid #3b494c; }
    }
    @media (max-width: 560px) {
      #appHeader { padding: 12px; }
      #appHeader > div:first-child > div:last-child { min-width: 0; }
      #appHeader > div:first-child > div:last-child > div { flex-wrap: wrap; gap: 4px; }
      #connectionForm { grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); }
      #portPicker, #connectBtn { grid-column: 1 / -1; }
      #connectBtn { justify-content: center; }
      #healthBar { padding: 8px 12px; }
      #telemetryPanel { padding: 12px; }
      #consoleTabs button { font-size: 11px; }
      #txInput { flex-basis: calc(100% - 32px); }
      #consolePanel { height: max(580px, 80vh); }
    }
  </style>
</head>
<body class="h-screen flex flex-col overflow-hidden select-none">

  <nav class="control-rail" aria-label="Control Deck sections">
    <div class="rail-mark" aria-hidden="true"><i class="fa-solid fa-microchip"></i></div>
    <button class="rail-btn active" type="button" data-rail="console" title="Console only (hide the control dock)" onclick="railSelect('console')"><i class="fa-solid fa-terminal"></i></button>
    <button class="rail-btn" type="button" data-rail="control" title="Device control and quick queries (control protocol)" onclick="railSelect('control')"><i class="fa-solid fa-gamepad"></i></button>
    <button class="rail-btn" type="button" data-rail="flash" title="Flash utility" onclick="railSelect('flash')"><i class="fa-solid fa-bolt"></i></button>
    <div class="rail-sep" aria-hidden="true"></div>
    <button class="rail-btn" type="button" data-rail="mcp" title="MCP: AI agent setup and live activity" onclick="railSelect('mcp')"><i class="fa-solid fa-plug-circle-bolt"></i><span id="mcpRailBadge" class="rail-badge hidden">0</span></button>
  </nav>

  <!-- TOP HEADER -->
  <header id="appHeader" class="bg-brand-surface border-b border-brand-border px-5 py-3 flex items-center justify-between shrink-0 shadow-md">
    <div class="flex items-center space-x-3">
      <div class="w-9 h-9 rounded-lg bg-brand-accent flex items-center justify-center text-[#00363d] font-black text-xl shadow-lg shadow-brand-accent/20">
        <i class="fa-solid fa-microchip"></i>
      </div>
      <div>
        <div class="flex items-center space-x-2">
          <h1 class="text-lg font-bold tracking-wide text-brand-text">SERIAL DECK</h1>
          <span id="transportBadge" class="text-xs bg-brand-surfaceAlt text-brand-accent px-2 py-0.5 rounded border border-brand-border mono font-semibold">UART</span>
        </div>
        <p class="text-xs text-brand-muted">Shared serial console, device control and ESP32 flashing</p>
      </div>
    </div>

    <!-- Connection & Modem Controls -->
    <div id="connectionControls" class="flex items-center space-x-3">
      <div id="connectionForm" class="flex items-center bg-brand-surfaceAlt border border-brand-border rounded-lg p-1 space-x-2">
        <div id="portPicker" class="flex items-center px-2 space-x-1.5">
          <i class="fa-solid fa-microchip text-xs text-brand-muted"></i>
          <select id="portSelect" aria-label="Serial device" onchange="onPortSelectChange()" class="bg-transparent text-sm text-brand-text mono focus:outline-none cursor-pointer pr-2">
            <option value="">Scanning ports...</option>
          </select>
          <input id="netPortInput" type="text" list="netPortHistory" autocomplete="off" spellcheck="false" placeholder="tcp://192.168.1.50:23" title="tcp://host:port (ser2net, ESP-Link, telnet console) or udp://host:port — udp://:5000 listens and replies to the last sender" class="hidden w-52 bg-brand-surface text-xs text-brand-text mono border border-brand-border rounded px-2 py-1 focus:outline-none focus:border-brand-accent">
          <datalist id="netPortHistory"></datalist>
          <button onclick="scanPorts()" title="Rescan Serial Ports" class="text-xs text-brand-muted hover:text-brand-accent px-1.5 py-0.5 rounded hover:bg-brand-border transition">
            <i class="fa-solid fa-rotate"></i>
          </button>
        </div>

        <select id="baudSelect" class="bg-brand-surface text-xs text-brand-text mono border border-brand-border rounded px-2 py-1 focus:outline-none">
          <option value="9600">9600</option>
          <option value="19200">19200</option>
          <option value="38400">38400</option>
          <option value="57600">57600</option>
          <option value="115200">115200</option>
          <option value="230400">230400</option>
          <option value="460800">460800</option>
          <option value="500000">500000</option>
          <option value="576000">576000</option>
          <option value="921600">921600</option>
          <option value="1000000">1000000</option>
          <option value="1500000">1500000</option>
          <option value="2000000" selected>2000000</option>
          <option value="3000000">3000000</option>
        </select>

        <select id="modeSelect" onchange="changeConsoleMode(this.value)" title="Control: control-protocol frames + ESP logs. Linux: interactive raw terminal for Linux boards / other apps (no control frames)." class="bg-brand-surface text-xs text-brand-text mono border border-brand-border rounded px-2 py-1 focus:outline-none">
          <option value="linux" selected>Linux / Raw</option>
          <option value="control">Control</option>
        </select>

        <button id="quitBtn" onclick="quitApp()" title="Stop Serial Deck (the hub keeps running for other tools)" class="hidden px-3 py-1 rounded text-xs font-bold border border-brand-border text-brand-muted hover:text-brand-danger hover:border-brand-danger transition">Quit</button>

        <button id="connectBtn" onclick="toggleConnect()" class="px-4 py-1 rounded text-xs font-bold transition flex items-center space-x-1.5 bg-brand-accent hover:bg-brand-accentHover text-brand-bg shadow">
          <i class="fa-solid fa-plug text-xs"></i>
          <span id="connectBtnText">Connect</span>
        </button>
      </div>

      <!-- Live Connection Pill -->
      <div id="connectionStatus" class="flex items-center bg-brand-surfaceAlt border border-brand-border rounded-lg px-3 py-1.5 space-x-2 text-xs font-medium">
        <span id="connDot" class="w-2.5 h-2.5 rounded-full bg-brand-danger animate-pulse"></span>
        <span id="connLabel" class="mono text-brand-muted">Disconnected</span>
      </div>
    </div>
  </header>

  <!-- CONNECTION TABS: several physical UARTs can be watched at once -->
  <section id="connTabsBar" class="bg-brand-surfaceAlt/40 border-b border-brand-border px-5 py-1.5 flex items-center space-x-2 shrink-0 text-xs">
    <span class="text-brand-muted uppercase font-bold tracking-wider text-[10px] shrink-0">Connections:</span>
    <div id="connTabs" class="flex items-center space-x-1.5 overflow-x-auto"></div>
    <button onclick="addConnection()" title="Open another UART connection" class="shrink-0 px-2 py-1 bg-brand-surface hover:bg-brand-border border border-brand-border rounded-lg text-brand-muted hover:text-brand-accent transition">
      <i class="fa-solid fa-plus"></i>
    </button>
  </section>

  <!-- TELEMETRY / HEALTH BAR -->
  <section id="healthBar" class="bg-brand-surfaceAlt/60 border-b border-brand-border px-5 py-2 flex items-center justify-between shrink-0 text-xs mono">
    <div class="flex items-center space-x-6">
      <div class="flex items-center space-x-2">
        <span class="text-brand-muted uppercase font-bold tracking-wider">FSM:</span>
        <span id="fsmBadge" class="px-2 py-0.5 rounded bg-brand-surface border border-brand-border text-brand-accent font-bold">UNKNOWN</span>
      </div>
      <div class="flex items-center space-x-2">
        <span class="text-brand-muted uppercase font-bold tracking-wider">Target:</span>
        <span id="deviceBadge" class="text-brand-text">Not Connected</span>
      </div>
      <div class="flex items-center space-x-2">
        <span class="text-brand-muted uppercase font-bold tracking-wider">Lines:</span>
        <span id="dtrStatus" class="px-1.5 py-0.5 rounded bg-brand-surface text-brand-muted border border-brand-border">DTR: --</span>
        <span id="rtsStatus" class="px-1.5 py-0.5 rounded bg-brand-surface text-brand-muted border border-brand-border">RTS: --</span>
      </div>
    </div>

    <!-- Hardware Quick Actions -->
    <div class="flex items-center space-x-2">
      <button onclick="controlLine('reset')" class="px-2.5 py-1 bg-brand-surface hover:bg-brand-danger/20 hover:text-brand-danger border border-brand-border rounded text-brand-text transition flex items-center space-x-1">
        <i class="fa-solid fa-arrows-rotate text-xs"></i>
        <span>Reset</span>
      </button>
      <button onclick="controlLine('bootloader')" class="px-2.5 py-1 bg-brand-surface hover:bg-brand-danger/20 hover:text-brand-danger border border-brand-border rounded text-brand-text transition flex items-center space-x-1">
        <i class="fa-solid fa-download text-xs"></i>
        <span>Bootloader</span>
      </button>
      <button onclick="controlLine('toggle_dtr')" class="px-2 py-1 bg-brand-surface hover:bg-brand-border border border-brand-border rounded text-brand-muted transition">DTR</button>
      <button onclick="controlLine('toggle_rts')" class="px-2 py-1 bg-brand-surface hover:bg-brand-border border border-brand-border rounded text-brand-muted transition">RTS</button>
    </div>
  </section>

  <!-- MAIN DUAL-PANE BODY -->
  <main id="telemetryPanel" class="flex-1 flex overflow-hidden p-4">

    <!-- LEFT SIDEBAR: CONTROLS & FLASH -->
    <aside id="sidebarPanel" class="collapsed flex flex-col space-y-4 shrink-0 overflow-y-auto pr-1" style="width: 384px;">

      <!-- D-PAD & ROBOT NAVIGATION -->
      <div id="controlPanel" class="glass-card p-4 flex flex-col">
        <div class="flex items-center justify-between pb-3 mb-3 border-b border-brand-border">
          <div class="flex items-center space-x-2">
            <i class="fa-solid fa-gamepad text-brand-accent"></i>
            <h2 class="text-xs font-bold tracking-wider text-brand-text uppercase">Device Control</h2>
          </div>
          <!-- Action Mode -->
          <select id="actionMode" class="bg-brand-surfaceAlt text-xs text-brand-text border border-brand-border rounded px-2 py-0.5 focus:outline-none">
            <option value="press">Action: Press</option>
            <option value="long_press">Action: Long Press</option>
            <option value="release">Action: Release</option>
          </select>
        </div>

        <!-- Visual Control Row: ONOFF, LEFT, ENTER, RIGHT, HOME -->
        <div class="flex items-center justify-center gap-2 my-2">
          <button id="btn-ONOFF" onclick="sendButton('ONOFF')" class="dpad-btn power-btn h-12 w-12 shrink-0 rounded-xl flex flex-col items-center justify-center font-bold text-xs shadow text-brand-danger bg-brand-danger/10 border-brand-danger/30">
            <i class="fa-solid fa-power-off mb-0.5"></i>
            <span class="text-[10px]">ONOFF</span>
          </button>
          <button id="btn-LEFT" onclick="sendButton('LEFT')" class="dpad-btn h-12 w-12 shrink-0 rounded-xl flex flex-col items-center justify-center font-bold text-xs shadow">
            <i class="fa-solid fa-arrow-left mb-0.5"></i>
            <span class="text-[10px]">LEFT</span>
          </button>
          <button id="btn-ENTER" onclick="sendButton('ENTER')" class="dpad-btn h-12 w-12 shrink-0 rounded-xl flex flex-col items-center justify-center font-bold text-xs shadow bg-brand-accent/20 border-brand-accent/50 text-brand-accent">
            <i class="fa-solid fa-circle-check mb-0.5"></i>
            <span class="text-[10px]">ENTER</span>
          </button>
          <button id="btn-RIGHT" onclick="sendButton('RIGHT')" class="dpad-btn h-12 w-12 shrink-0 rounded-xl flex flex-col items-center justify-center font-bold text-xs shadow">
            <i class="fa-solid fa-arrow-right mb-0.5"></i>
            <span class="text-[10px]">RIGHT</span>
          </button>
          <button id="btn-HOME" onclick="sendButton('HOME')" class="dpad-btn h-12 w-12 shrink-0 rounded-xl flex flex-col items-center justify-center font-bold text-xs shadow">
            <i class="fa-solid fa-house mb-0.5"></i>
            <span class="text-[10px]">HOME</span>
          </button>
        </div>

        <!-- Keyboard Hint -->
        <div class="mt-3 pt-2 border-t border-brand-border/60 flex items-center justify-between text-[11px] text-brand-muted">
          <span><i class="fa-regular fa-keyboard mr-1"></i> Hotkeys:</span>
          <span class="mono bg-brand-surfaceAlt px-1.5 py-0.5 rounded border border-brand-border">W/A/S/D / Arrows / Space</span>
        </div>
      </div>

      <!-- DEVICE QUERIES & SNAPSHOT -->
      <div id="queryPanel" class="glass-card p-4 flex flex-col">
        <div class="flex items-center space-x-2 pb-2 mb-3 border-b border-brand-border">
          <i class="fa-solid fa-magnifying-glass-chart text-brand-cyan"></i>
          <h2 class="text-xs font-bold tracking-wider text-brand-text uppercase">Quick Queries</h2>
        </div>
        <div class="grid grid-cols-2 gap-2">
          <button onclick="sendQuery('snapshot')" class="px-3 py-2 bg-brand-surfaceAlt hover:bg-brand-border border border-brand-border rounded-lg text-xs font-semibold transition text-left flex items-center space-x-2">
            <i class="fa-solid fa-camera text-brand-accent"></i>
            <span>Snapshot</span>
          </button>
          <button onclick="sendQuery('fsm')" class="px-3 py-2 bg-brand-surfaceAlt hover:bg-brand-border border border-brand-border rounded-lg text-xs font-semibold transition text-left flex items-center space-x-2">
            <i class="fa-solid fa-diagram-project text-brand-purple"></i>
            <span>Read FSM</span>
          </button>
          <button onclick="sendQuery('identity')" class="px-3 py-2 bg-brand-surfaceAlt hover:bg-brand-border border border-brand-border rounded-lg text-xs font-semibold transition text-left flex items-center space-x-2">
            <i class="fa-solid fa-id-card text-brand-blue"></i>
            <span>Identity</span>
          </button>
          <button onclick="sendShowInfo()" class="px-3 py-2 bg-brand-surfaceAlt hover:bg-brand-border border border-brand-border rounded-lg text-xs font-semibold transition text-left flex items-center space-x-2">
            <i class="fa-solid fa-tv text-brand-success"></i>
            <span>Show Info</span>
          </button>
        </div>
      </div>

      <!-- FIRMWARE FLASH & SYMBOLS -->
      <div id="flashPanel" class="glass-card p-4 flex flex-col">
        <div class="flex items-center justify-between pb-2 mb-3 border-b border-brand-border">
          <div class="flex items-center space-x-2">
            <i class="fa-solid fa-bolt text-brand-flash"></i>
            <h2 class="text-xs font-bold tracking-wider text-brand-text uppercase">Target Image</h2>
          </div>
          <select id="flashBaudSelect" class="bg-brand-surfaceAlt text-xs text-brand-text mono border border-brand-border rounded px-2 py-0.5">
            <option value="460800">460800</option>
            <option value="921600">921600</option>
            <option value="1500000">1500000</option>
            <option value="2000000">2000000</option>
            <option value="3000000" selected>3000000</option>
            <option value="6000000">6000000</option>
          </select>
        </div>

        <div class="space-y-2 text-xs">
          <div>
            <label class="text-[11px] text-brand-muted uppercase font-bold block mb-1">Build Directory</label>
            <div class="flex space-x-1.5">
              <input id="buildDirInput" type="text" value="build" class="flex-1 bg-brand-surfaceAlt border border-brand-border rounded px-2 py-1.5 mono focus:outline-none focus:border-brand-accent">
              <button onclick="autoDetectElf()" title="Auto detect ELF in build dir" class="px-2 py-1 bg-brand-surfaceAlt hover:bg-brand-border border border-brand-border rounded text-brand-muted hover:text-brand-text">
                <i class="fa-solid fa-wand-magic-sparkles"></i>
              </button>
            </div>
          </div>

          <div>
            <label class="text-[11px] text-brand-muted uppercase font-bold block mb-1">ELF Symbols (Addr2Line)</label>
            <div class="flex space-x-1.5">
              <input id="elfPathInput" type="text" placeholder="build/firmware.elf" class="flex-1 bg-brand-surfaceAlt border border-brand-border rounded px-2 py-1.5 mono focus:outline-none focus:border-brand-accent">
              <button onclick="loadElfSymbols()" class="px-2.5 py-1 bg-brand-surfaceAlt hover:bg-brand-accent hover:text-brand-bg border border-brand-border rounded font-bold transition">Load</button>
            </div>
          </div>

          <!-- Flash Progress Bar -->
          <div id="flashProgressContainer" class="pt-2 hidden">
            <div class="flex justify-between text-[11px] mb-1 font-semibold">
              <span id="flashStepLabel" class="text-brand-flash">Flashing...</span>
              <span id="flashPercentLabel" class="mono text-brand-text">0%</span>
            </div>
            <div class="w-full h-2 bg-brand-surfaceAlt rounded-full overflow-hidden border border-brand-border">
              <div id="flashProgressBar" class="h-full bg-gradient-to-r from-brand-flash to-brand-flashHover transition-all duration-150 w-0"></div>
            </div>
          </div>

          <button id="flashBtn" onclick="startFlash()" class="w-full mt-2 py-2 bg-brand-flash hover:bg-brand-flashHover text-[#301800] font-bold rounded-lg shadow-md transition flex items-center justify-center space-x-2">
            <i class="fa-solid fa-bolt"></i>
            <span>INITIATE FLASH SEQUENCE</span>
          </button>
        </div>
      </div>

    </aside>

    <!-- SIDEBAR RESIZE / COLLAPSE HANDLE -->
    <div id="sidebarResizeHandle" class="w-5 shrink-0 mx-1 flex items-center justify-center cursor-col-resize">
      <button id="sidebarToggleBtn" onclick="toggleSidebar()" title="Hide/show sidebar" class="w-5 h-10 rounded bg-brand-surface hover:bg-brand-border border border-brand-border text-brand-muted hover:text-brand-accent flex items-center justify-center transition">
        <i id="sidebarToggleIcon" class="fa-solid fa-chevron-right text-[10px]"></i>
      </button>
    </div>

    <!-- RIGHT MAIN: CONSOLE LOG & EVENTS STREAM -->
    <section id="consolePanel" class="flex-1 flex flex-col glass-card overflow-hidden min-w-0">

      <!-- Tab Header & Filter Toolbar -->
      <div id="consoleToolbar" class="bg-brand-surfaceAlt/80 border-b border-brand-border p-2.5 flex items-center justify-between shrink-0">
        <!-- Tabs -->
        <div id="consoleTabs" class="flex items-center space-x-1">
          <button id="tabLogsBtn" onclick="switchTab('logs')" class="px-3 py-1.5 rounded-lg text-xs font-bold bg-brand-surface text-brand-text border border-brand-border transition flex items-center space-x-1.5">
            <i class="fa-solid fa-terminal text-brand-accent"></i>
            <span>Console Stream</span>
            <span id="logCountBadge" class="text-[10px] bg-brand-surfaceAlt px-1.5 py-0.2 rounded-full text-brand-muted">0</span>
          </button>
          <button id="tabEventsBtn" onclick="switchTab('events')" class="px-3 py-1.5 rounded-lg text-xs font-bold text-brand-muted hover:text-brand-text hover:bg-brand-surface transition flex items-center space-x-1.5">
            <i class="fa-solid fa-network-wired text-brand-cyan"></i>
            <span>Control Events</span>
            <span id="eventCountBadge" class="text-[10px] bg-brand-surfaceAlt px-1.5 py-0.2 rounded-full text-brand-muted">0</span>
          </button>
          <button id="tabTerminalBtn" onclick="switchTab('terminal')" class="px-3 py-1.5 rounded-lg text-xs font-bold text-brand-muted hover:text-brand-text hover:bg-brand-surface transition flex items-center space-x-1.5">
            <i class="fa-solid fa-keyboard text-brand-tx"></i>
            <span>Terminal</span>
          </button>
          <button id="tabInspectorBtn" onclick="switchTab('inspector')" class="px-3 py-1.5 rounded-lg text-xs font-bold text-brand-muted hover:text-brand-text hover:bg-brand-surface transition flex items-center space-x-1.5">
            <i class="fa-solid fa-cube text-brand-purple"></i>
            <span>Telemetry Inspector</span>
          </button>
        </div>

        <!-- Filter & Search Controls -->
        <div id="consoleFilters" class="flex items-center space-x-2 text-xs">
          <!-- Search Box -->
          <div class="relative">
            <i class="fa-solid fa-filter absolute left-2.5 top-2 text-brand-muted text-[10px]"></i>
            <input id="logSearchInput" oninput="applyLogFilter()" type="text" placeholder="Filter regex / text..." class="pl-7 pr-3 py-1 bg-brand-surface border border-brand-border rounded-lg text-xs mono text-brand-text focus:outline-none focus:border-brand-accent w-44">
          </div>

          <!-- Log Level Filters -->
          <div id="levelFilters" class="flex items-center bg-brand-surface border border-brand-border rounded-lg p-0.5 space-x-0.5 text-[11px] font-bold mono">
            <button onclick="toggleLevelFilter('E')" id="lvl-E" class="px-2 py-0.5 rounded bg-brand-danger/20 text-brand-danger border border-brand-danger/40">E</button>
            <button onclick="toggleLevelFilter('W')" id="lvl-W" class="px-2 py-0.5 rounded bg-brand-warning/20 text-brand-warning border border-brand-warning/40">W</button>
            <button onclick="toggleLevelFilter('I')" id="lvl-I" class="px-2 py-0.5 rounded bg-brand-success/20 text-brand-success border border-brand-success/40">I</button>
            <button onclick="toggleLevelFilter('D')" id="lvl-D" class="px-2 py-0.5 rounded bg-brand-blue/20 text-brand-blue border border-brand-blue/40">D</button>
            <button onclick="toggleLevelFilter('V')" id="lvl-V" class="px-2 py-0.5 rounded text-brand-muted hover:text-brand-text">V</button>
            <button onclick="toggleLevelFilter('elf')" id="lvl-elf" class="px-2 py-0.5 rounded bg-brand-cyan/20 text-brand-cyan border border-brand-cyan/40">ELF</button>
            <button onclick="toggleLevelFilter('tx')" id="lvl-tx" class="px-2 py-0.5 rounded bg-brand-tx/20 text-brand-tx border border-brand-tx/40">TX</button>
            <button onclick="toggleLevelFilter('plain')" id="lvl-plain" class="px-2 py-0.5 rounded bg-brand-surfaceAlt text-brand-text border border-brand-border">RAW</button>
          </div>

          <!-- Actions -->
          <button id="pauseScrollBtn" onclick="toggleAutoScroll()" title="Toggle Auto-Scroll" class="px-2.5 py-1 bg-brand-surface hover:bg-brand-border border border-brand-border rounded-lg text-brand-text transition flex items-center space-x-1">
            <i class="fa-solid fa-arrows-up-down text-xs text-brand-accent"></i>
            <span id="scrollStateLabel">Follow</span>
          </button>
          <button id="splitViewBtn" onclick="toggleSplitView()" title="Split console: watch a second connection side by side" class="px-2.5 py-1 bg-brand-surface hover:bg-brand-border border border-brand-border rounded-lg text-brand-muted hover:text-brand-text transition">
            <i class="fa-solid fa-table-columns"></i>
          </button>
          <button onclick="exportLogs()" title="Export logs as file" class="px-2.5 py-1 bg-brand-surface hover:bg-brand-border border border-brand-border rounded-lg text-brand-muted hover:text-brand-text transition">
            <i class="fa-solid fa-file-arrow-down"></i>
          </button>
          <button onclick="clearCurrentLogs()" title="Clear view" class="px-2.5 py-1 bg-brand-surface hover:bg-brand-danger/20 hover:text-brand-danger border border-brand-border rounded-lg text-brand-muted transition">
            <i class="fa-solid fa-trash-can"></i>
          </button>
        </div>
      </div>

      <!-- VIEW 1: CONSOLE LOG STREAM (optionally split to watch a 2nd connection) -->
      <div id="viewLogs" class="flex-1 flex overflow-hidden">
        <div id="logsPanePrimary" class="flex-1 overflow-y-auto p-3 mono text-xs leading-relaxed space-y-0.5 select-text bg-[#0c0e12]"></div>
        <div id="logsPaneSplit" class="hidden flex-1 flex-col overflow-hidden border-l border-brand-border">
          <div class="flex items-center justify-between px-2 py-1.5 bg-brand-surfaceAlt/60 border-b border-brand-border text-[11px] shrink-0">
            <select id="splitConnSelect" onchange="onSplitConnChange(this.value)" class="bg-transparent text-brand-text mono text-[11px] focus:outline-none cursor-pointer"></select>
            <div class="flex items-center space-x-2">
              <button onclick="clearSplitLogs()" title="Clear this pane" class="text-brand-muted hover:text-brand-danger"><i class="fa-solid fa-trash-can text-[10px]"></i></button>
              <button onclick="toggleSplitView()" title="Close split view" class="text-brand-muted hover:text-brand-danger"><i class="fa-solid fa-xmark"></i></button>
            </div>
          </div>
          <div id="logsPaneSplitContent" class="flex-1 overflow-y-auto p-3 mono text-xs leading-relaxed space-y-0.5 select-text bg-[#0c0e12]"></div>
        </div>
      </div>

      <!-- VIEW 2: CONTROL EVENTS -->
      <div id="viewEvents" class="flex-1 overflow-y-auto p-3 mono text-xs leading-relaxed space-y-1.5 select-text bg-[#0c0e12] hidden"></div>

      <!-- VIEW 4: INTERACTIVE TERMINAL (Linux / Raw mode) -->
      <div id="viewTerminal" class="flex-1 flex flex-col overflow-hidden bg-[#0c0e12] hidden">
        <div id="terminalToolbar" class="shrink-0 flex items-center justify-between px-2 py-1.5 bg-brand-surfaceAlt/60 border-b border-brand-border text-[11px]">
          <span id="termHint" class="text-brand-muted">Click the terminal and type; keys go straight to the UART. Select to copy · Ctrl+Shift+V paste.</span>
          <div class="flex items-center space-x-1.5 mono">
            <button onclick="termSendKey('\x03')" title="Send Ctrl+C (interrupt)" class="px-2 py-0.5 bg-brand-surface hover:bg-brand-border border border-brand-border rounded text-brand-text">^C</button>
            <button onclick="termSendKey('\x04')" title="Send Ctrl+D (EOF / logout)" class="px-2 py-0.5 bg-brand-surface hover:bg-brand-border border border-brand-border rounded text-brand-text">^D</button>
            <button onclick="termSendKey('\x1a')" title="Send Ctrl+Z (suspend)" class="px-2 py-0.5 bg-brand-surface hover:bg-brand-border border border-brand-border rounded text-brand-text">^Z</button>
            <button onclick="termSendBreak()" title="Send a serial BREAK (magic SysRq, U-Boot break-in)" class="px-2 py-0.5 bg-brand-surface hover:bg-brand-danger/20 hover:text-brand-danger border border-brand-border rounded text-brand-text">BREAK</button>
            <button onclick="termSyncSize()" title="Run stty on the target so full-screen apps (vi, top, htop) use this window size" class="px-2 py-0.5 bg-brand-surface hover:bg-brand-border border border-brand-border rounded text-brand-text"><i class="fa-solid fa-up-right-and-down-left-from-center text-[10px]"></i> <span id="termSizeLabel">stty</span></button>
            <button onclick="termClear()" title="Clear terminal" class="px-2 py-0.5 bg-brand-surface hover:bg-brand-danger/20 hover:text-brand-danger border border-brand-border rounded text-brand-muted"><i class="fa-solid fa-trash-can text-[10px]"></i></button>
          </div>
        </div>
        <div id="terminalHost" class="flex-1 min-h-0 p-1"></div>
      </div>

      <!-- VIEW 3: TELEMETRY INSPECTOR -->
      <div id="viewInspector" class="flex-1 overflow-y-auto p-4 select-text bg-[#0c0e12] hidden">
        <h3 class="text-sm font-bold text-brand-accent mb-3 uppercase tracking-wider flex items-center space-x-2">
          <i class="fa-solid fa-database"></i>
          <span>Parsed Telemetry & JSON Snapshot</span>
        </h3>
        <pre id="inspectorContent" class="mono text-xs bg-brand-surface border border-brand-border p-4 rounded-xl text-brand-cyan overflow-x-auto">{}</pre>
      </div>

      <!-- TX BAR: raw bytes to the active connection's UART -->
      <form id="txBar" onsubmit="sendTx(event)" class="shrink-0 flex items-center space-x-2 p-2 bg-brand-surfaceAlt/80 border-t border-brand-border text-xs">
        <span class="font-bold mono text-brand-tx select-none">TX</span>
        <input id="txInput" onkeydown="txHistoryKey(event)" type="text" autocomplete="off" spellcheck="false" placeholder="Type data to send, Enter to transmit (↑/↓ history)" class="flex-1 min-w-0 px-2 py-1 bg-brand-surface border border-brand-border rounded-lg mono text-brand-text focus:outline-none focus:border-brand-tx">
        <select id="txMode" title="Payload format" class="bg-brand-surface text-brand-text mono border border-brand-border rounded px-1.5 py-1 focus:outline-none">
          <option value="ascii" selected>ASCII</option>
          <option value="hex">HEX</option>
        </select>
        <select id="txLineEnding" title="Line ending appended" class="bg-brand-surface text-brand-text mono border border-brand-border rounded px-1.5 py-1 focus:outline-none">
          <option value="none">None</option>
          <option value="lf" selected>LF</option>
          <option value="cr">CR</option>
          <option value="crlf">CRLF</option>
        </select>
        <button type="submit" class="px-3 py-1 rounded-lg font-bold bg-brand-tx/20 text-brand-tx border border-brand-tx/40 hover:bg-brand-tx/30 transition flex items-center space-x-1.5">
          <i class="fa-solid fa-paper-plane text-[10px]"></i>
          <span>Send</span>
        </button>
      </form>

    </section>

  </main>

  <!-- MCP PAGE: agent setup, registrations and live tool activity -->
  <section id="mcpPage" class="flex-1 overflow-y-auto p-4 select-text">
    <div class="max-w-6xl mx-auto space-y-4">
      <div class="flex items-center justify-between flex-wrap gap-2">
        <div class="flex items-center space-x-2">
          <i class="fa-solid fa-plug-circle-bolt text-brand-accent"></i>
          <h2 class="text-sm font-bold tracking-wider uppercase">MCP — AI agent access</h2>
          <span id="mcpSdkBadge" class="text-[10px] mono px-2 py-0.5 rounded border border-brand-border text-brand-muted">checking…</span>
        </div>
        <div class="flex items-center gap-2 text-xs">
          <label class="flex items-center gap-1 text-brand-muted"><input id="mcpAutoRefresh" type="checkbox" checked> auto refresh</label>
          <button onclick="refreshMcp()" class="px-2 py-1 bg-brand-surfaceAlt hover:bg-brand-border border border-brand-border rounded"><i class="fa-solid fa-rotate"></i> Refresh</button>
        </div>
      </div>

      <div class="grid gap-4 lg:grid-cols-2">
        <div class="mcp-card p-4 space-y-3">
          <h3 class="text-xs font-bold uppercase text-brand-muted">What it is</h3>
          <p class="text-xs leading-relaxed">
            <span class="mono">mcp_server.py</span> lets Claude Code, Codex, Claude Desktop or Cursor read logs,
            query the firmware, press buttons and flash the board. It is a client of the same shared hub as this
            dashboard: it never opens a UART itself, so you can watch here while an agent works.
          </p>
          <h3 class="text-xs font-bold uppercase text-brand-muted pt-1">Policy (chosen by you, not the agent)</h3>
          <div id="mcpPolicyTable" class="text-xs space-y-1"></div>
          <p class="text-[11px] text-brand-muted">Your MCP client still asks before each call. Use <span class="mono">interact</span>
            day to day; register a <span class="mono">hardware</span> server only when you want the agent to reset or flash.</p>
        </div>

        <div class="mcp-card p-4 space-y-3">
          <div class="flex items-center justify-between">
            <h3 class="text-xs font-bold uppercase text-brand-muted">Install / register</h3>
            <select id="mcpPolicySelect" onchange="renderMcpInstall()" class="bg-brand-surfaceAlt text-xs border border-brand-border rounded px-2 py-0.5">
              <option value="observe">--allow observe</option>
              <option value="interact" selected>--allow interact</option>
              <option value="hardware">--allow hardware</option>
            </select>
          </div>
          <div id="mcpInstall" class="space-y-2 text-xs"></div>
          <div id="mcpRegistrations" class="text-xs space-y-1 pt-1"></div>
        </div>
      </div>

      <div class="mcp-card p-4 space-y-3">
        <div class="flex items-center justify-between">
          <h3 class="text-xs font-bold uppercase text-brand-muted">Running MCP servers</h3>
          <span id="mcpUpdated" class="text-[10px] mono text-brand-muted"></span>
        </div>
        <div id="mcpServers" class="space-y-3 text-xs"></div>
      </div>

      <div class="mcp-card p-4 space-y-2 text-xs">
        <h3 class="text-xs font-bold uppercase text-brand-muted">Typical agent flows</h3>
        <div class="grid gap-2 md:grid-cols-2 mono text-[11px]">
          <div><span class="text-brand-accent">observe</span>  serial_list_ports → serial_connect → serial_query("fsm") → serial_logs / serial_wait_for</div>
          <div><span class="text-brand-accent">crash</span>    serial_wait_for(["Guru Meditation","Backtrace"]) → serial_symbolize(text, elf)</div>
          <div><span class="text-brand-danger">reset</span>    serial_reset(wait_for=["main_task: Calling app_main"])</div>
          <div><span class="text-brand-flash">flash</span>    serial_flash_preview(build) → you approve → serial_flash_start(token) → serial_flash_status</div>
        </div>
        <p class="text-[11px] text-brand-muted">An <span class="mono">outcome: "unknown"</span> result is never retried
          automatically. Full guide: <span class="mono">docs/MCP.md</span>.</p>
      </div>
    </div>
  </section>

  <!-- JAVASCRIPT APP LOGIC -->
  <script>
    let activeTab = 'logs';
    let autoScroll = true;
    let enabledLevels = new Set(['E', 'W', 'I', 'D', 'elf', 'tx', 'plain']);

    // Each open dashboard tab keeps its own logs/events/status/EventSource so
    // several physical UARTs can stream concurrently in the background;
    // `connId` picks which one is currently rendered in the DOM.
    let connId = 'default';
    const conns = {};
    let connOrder = [];

    function ensureConn(id) {
      if (!conns[id]) {
        conns[id] = { logsBuffer: [], eventsBuffer: [], rawChunks: [], rawBytes: 0, status: {}, eventSource: null,
          termPending: [], termSending: false };
        if (!connOrder.includes(id)) connOrder.push(id);
      }
      return conns[id];
    }

    // Split console view: a second connection rendered side by side with
    // the primary one, sharing the same search/level filter.
    let splitEnabled = false;
    let splitConnId = null;

    // Sidebar hide/show + drag-to-resize.
    let sidebarWidth = 384;
    // The control dock starts hidden; the console gets the full width.
    let sidebarCollapsed = (() => {
      try { return localStorage.getItem('serialdeck.sidebarCollapsed') !== '0'; } catch (err) { return true; }
    })();
    let currentPage = 'deck';

    function focusPanel(id) {
      const panel = document.getElementById(id);
      if (panel) panel.scrollIntoView({ behavior: 'smooth', block: 'nearest', inline: 'nearest' });
    }

    function showPage(page) {
      currentPage = page;
      document.body.dataset.page = page;
      if (page === 'mcp') { refreshMcp().then(scheduleMcp); } else { requestAnimationFrame(termFit); }
      updateRail();
    }

    // Left rail: Console = deck without dock; Control / Flash = deck with the
    // dock open on that card; MCP = agent setup + activity page.
    function railSelect(target) {
      if (target === 'mcp') { showPage('mcp'); return; }
      showPage('deck');
      if (target === 'console') { setSidebarCollapsed(true); return; }
      setSidebarCollapsed(false);
      focusPanel(target === 'flash' ? 'flashPanel' : 'controlPanel');
    }

    function updateRail() {
      const active = currentPage === 'mcp' ? 'mcp' : (sidebarCollapsed ? 'console' : 'control');
      document.querySelectorAll('.rail-btn').forEach(btn => {
        const rail = btn.dataset.rail;
        btn.classList.toggle('active', rail === active);
      });
    }

    // Hotkey listener
    window.addEventListener('keydown', (e) => {
      if (['INPUT', 'TEXTAREA', 'SELECT'].includes(document.activeElement.tagName)) return;
      if (currentMode() === 'linux') return;
      const keyMap = {
        'ArrowUp': 'HOME', 'KeyW': 'HOME', 'w': 'HOME', 'W': 'HOME',
        'ArrowLeft': 'LEFT', 'KeyA': 'LEFT', 'a': 'LEFT', 'A': 'LEFT',
        'ArrowRight': 'RIGHT', 'KeyD': 'RIGHT', 'd': 'RIGHT', 'D': 'RIGHT',
        'Enter': 'ENTER', 'Space': 'ENTER', ' ': 'ENTER',
        'KeyP': 'ONOFF', 'p': 'ONOFF', 'P': 'ONOFF', 'Escape': 'HOME'
      };
      if (keyMap[e.code] || keyMap[e.key]) {
        const btn = keyMap[e.code] || keyMap[e.key];
        e.preventDefault();
        highlightKey(btn);
        sendButton(btn);
      }
    });

    function highlightKey(btnName) {
      const el = document.getElementById('btn-' + btnName);
      if (el) {
        el.classList.add('active-key');
        setTimeout(() => el.classList.remove('active-key'), 160);
      }
    }

    function switchTab(tab) {
      activeTab = tab;
      document.getElementById('viewLogs').classList.toggle('hidden', tab !== 'logs');
      document.getElementById('viewEvents').classList.toggle('hidden', tab !== 'events');
      document.getElementById('viewInspector').classList.toggle('hidden', tab !== 'inspector');
      document.getElementById('viewTerminal').classList.toggle('hidden', tab !== 'terminal');

      const btnLogs = document.getElementById('tabLogsBtn');
      const btnEvents = document.getElementById('tabEventsBtn');
      const btnInsp = document.getElementById('tabInspectorBtn');
      const btnTerm = document.getElementById('tabTerminalBtn');

      [btnLogs, btnEvents, btnInsp, btnTerm].forEach(b => {
        b.className = "px-3 py-1.5 rounded-lg text-xs font-bold text-brand-muted hover:text-brand-text hover:bg-brand-surface transition flex items-center space-x-1.5";
      });

      const activeEl = { logs: btnLogs, events: btnEvents, inspector: btnInsp, terminal: btnTerm }[tab];
      activeEl.className = "px-3 py-1.5 rounded-lg text-xs font-bold bg-brand-surface text-brand-text border border-brand-border transition flex items-center space-x-1.5";
      if (tab === 'terminal') { ensureTerminal(); termFit(); term && term.focus(); }
    }

    function toggleAutoScroll() {
      autoScroll = !autoScroll;
      const lbl = document.getElementById('scrollStateLabel');
      const btn = document.getElementById('pauseScrollBtn');
      if (autoScroll) {
        lbl.innerText = 'Follow';
        btn.classList.remove('bg-amber-500/20', 'text-amber-400', 'border-amber-500/40');
      } else {
        lbl.innerText = 'Paused';
        btn.classList.add('bg-amber-500/20', 'text-amber-400', 'border-amber-500/40');
      }
    }

    function toggleLevelFilter(lvl) {
      const el = document.getElementById('lvl-' + lvl);
      if (enabledLevels.has(lvl)) {
        enabledLevels.delete(lvl);
        el.className = "px-2 py-0.5 rounded text-brand-muted hover:text-brand-text";
      } else {
        enabledLevels.add(lvl);
        const colorMap = {
          'E': 'bg-brand-danger/20 text-brand-danger border border-brand-danger/40',
          'W': 'bg-brand-warning/20 text-brand-warning border border-brand-warning/40',
          'I': 'bg-brand-success/20 text-brand-success border border-brand-success/40',
          'D': 'bg-brand-blue/20 text-brand-blue border border-brand-blue/40',
          'V': 'bg-brand-purple/20 text-brand-purple border border-brand-purple/40',
          'elf': 'bg-brand-cyan/20 text-brand-cyan border border-brand-cyan/40',
          'tx': 'bg-brand-tx/20 text-brand-tx border border-brand-tx/40',
          'plain': 'bg-brand-surfaceAlt text-brand-text border border-brand-border',
        };
        el.className = `px-2 py-0.5 rounded ${colorMap[lvl] || ''}`;
      }
      applyLogFilter();
    }

    function renderLogsInto(id, containerId) {
      const search = document.getElementById('logSearchInput').value.toLowerCase();
      const container = document.getElementById(containerId);
      container.innerHTML = '';
      ensureConn(id).logsBuffer.forEach(entry => {
        if (!shouldDisplayLog(entry, search)) return;
        renderLogEntry(entry, false, containerId);
      });
      if (autoScroll) container.scrollTop = container.scrollHeight;
    }

    function applyLogFilter() {
      renderLogsInto(connId, 'logsPanePrimary');
      if (splitEnabled && splitConnId) renderLogsInto(splitConnId, 'logsPaneSplitContent');
    }

    function shouldDisplayLog(entry, search) {
      const lvl = entry.level || 'plain';
      const lvlKey = lvl === 'error' ? 'E' : (lvl === 'warning' ? 'W' : (lvl === 'info' ? 'I' : (lvl === 'debug' ? 'D' : (lvl === 'verbose' ? 'V' : lvl))));
      if (!enabledLevels.has(lvlKey)) return false;
      if (search && !entry.text.toLowerCase().includes(search)) return false;
      return true;
    }

    function renderLogEntry(entry, doScroll = true, containerId = 'logsPanePrimary') {
      const container = document.getElementById(containerId);
      const div = document.createElement('div');
      div.className = "py-0.5 px-1 hover:bg-brand-surfaceAlt/40 rounded flex items-start space-x-2";

      const timeSpan = `<span class="text-brand-muted select-none text-[10px] w-20 shrink-0">${entry.time || ''}</span>`;
      let textClass = 'text-brand-text';
      if (entry.level === 'error') textClass = 'text-brand-danger font-semibold';
      else if (entry.level === 'warning') textClass = 'text-brand-warning';
      else if (entry.level === 'info') textClass = 'text-brand-success';
      else if (entry.level === 'debug') textClass = 'text-brand-blue';
      else if (entry.level === 'verbose') textClass = 'text-brand-purple';
      else if (entry.level === 'elf') textClass = 'text-brand-cyan';
      else if (entry.level === 'tx') textClass = 'text-brand-tx';

      div.innerHTML = `${timeSpan}<span class="${textClass} flex-1 break-all">${escapeHtml(entry.text)}</span>`;
      container.appendChild(div);

      if (doScroll && autoScroll) {
        container.scrollTop = container.scrollHeight;
      }
    }

    function renderEventEntry(entry) {
      const container = document.getElementById('viewEvents');
      const div = document.createElement('div');
      div.className = "p-2 bg-brand-surface border border-brand-border rounded-lg text-xs";
      const isResp = entry.frame_type === 'FRAME_RESPONSE';
      const badgeClass = isResp ? 'bg-brand-success/20 text-brand-success border-brand-success/40' : 'bg-brand-cyan/20 text-brand-cyan border-brand-cyan/40';

      div.innerHTML = `
        <div class="flex items-center justify-between pb-1 mb-1 border-b border-brand-border/50">
          <span class="px-2 py-0.5 rounded text-[10px] font-bold border ${badgeClass}">${entry.frame_type} [seq=${entry.sequence}]</span>
          <span class="text-brand-muted text-[10px]">${entry.time || ''}</span>
        </div>
        <pre class="text-brand-text text-[11px] overflow-x-auto">${escapeHtml(JSON.stringify(entry.message, null, 2))}</pre>
      `;
      container.appendChild(div);
      if (autoScroll) container.scrollTop = container.scrollHeight;
    }

    function escapeHtml(str) {
      if (!str) return '';
      return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
    }

    function clearCurrentLogs() {
      const conn = ensureConn(connId);
      if (activeTab === 'logs') {
        conn.logsBuffer.length = 0;
        document.getElementById('logsPanePrimary').innerHTML = '';
        document.getElementById('logCountBadge').innerText = '0';
      } else if (activeTab === 'events') {
        conn.eventsBuffer.length = 0;
        document.getElementById('viewEvents').innerHTML = '';
        document.getElementById('eventCountBadge').innerText = '0';
      }
    }

    function clearSplitLogs() {
      if (!splitConnId) return;
      ensureConn(splitConnId).logsBuffer.length = 0;
      document.getElementById('logsPaneSplitContent').innerHTML = '';
    }

    function exportLogs() {
      // A same-page download link rather than window.open(): the app window
      // (pywebview) sends new windows to the system browser, but handles
      // downloads with a save dialog. Browsers download it either way.
      const link = document.createElement('a');
      link.href = '/api/export_logs?id=' + encodeURIComponent(connId);
      link.download = 'serial_console.log';
      document.body.appendChild(link);
      link.click();
      link.remove();
    }

    // API Interactions
    // ---- Network endpoints (tcp:// / udp://) share the port picker ----
    const NET_OPTION = '__net__';
    const NET_HISTORY_KEY = 'serialdeck.netPorts';
    let portScanId = 0;
    let portDetails = new Map();

    function isNetworkPort(port) {
      return /^(tcp|udp):[/][/]/i.test(port || '');
    }

    function loadNetHistory() {
      try { return JSON.parse(localStorage.getItem(NET_HISTORY_KEY) || '[]'); } catch (err) { return []; }
    }

    function rememberNetPort(port) {
      const list = [port, ...loadNetHistory().filter(p => p !== port)].slice(0, 10);
      try { localStorage.setItem(NET_HISTORY_KEY, JSON.stringify(list)); } catch (err) {}
      renderNetHistory();
    }

    function renderNetHistory() {
      const dl = document.getElementById('netPortHistory');
      dl.innerHTML = '';
      loadNetHistory().forEach(p => {
        const opt = document.createElement('option');
        opt.value = p;
        dl.appendChild(opt);
      });
    }

    function onPortSelectChange() {
      const net = document.getElementById('portSelect').value === NET_OPTION;
      const input = document.getElementById('netPortInput');
      const picker = document.getElementById('portSelect');
      picker.title = picker.selectedOptions[0]?.textContent || '';
      input.classList.toggle('hidden', !net);
      if (net) {
        if (!input.value) input.value = loadNetHistory()[0] || '';
        input.focus();
      }
    }

    function selectedPort() {
      const sel = document.getElementById('portSelect').value;
      return sel === NET_OPTION ? document.getElementById('netPortInput').value.trim() : sel;
    }

    function showPortInPicker(port) {
      const portSel = document.getElementById('portSelect');
      if (isNetworkPort(port)) {
        portSel.value = NET_OPTION;
        document.getElementById('netPortInput').value = port;
      } else {
        if (!Array.from(portSel.options).some(o => o.value === port)) {
          const opt = document.createElement('option');
          opt.value = port;
          opt.innerText = portDetails.get(port)?.label || port;
          portSel.insertBefore(opt, portSel.lastElementChild);
        }
        portSel.value = port;
      }
      onPortSelectChange();
    }

    async function scanPorts() {
      const scanId = ++portScanId;
      const sel = document.getElementById('portSelect');
      try {
        const res = await fetch('/api/ports');
        if (!res.ok) throw new Error(`Port scan failed (HTTP ${res.status})`);
        const data = await res.json();
        if (!Array.isArray(data.ports)) throw new Error('Invalid port list');
        if (scanId !== portScanId) return;
        // Read the current choice after the await so a tab/selection change is
        // not overwritten by a slower scan response.
        const previous = sel.value;
        portDetails = new Map((data.details || []).map(item => [item.device, item]));
        sel.replaceChildren();
        for (const device of data.ports) {
          const opt = document.createElement('option');
          opt.value = device;
          opt.textContent = portDetails.get(device)?.label || device;
          sel.appendChild(opt);
        }
        if (!data.ports.length) sel.add(new Option('No accessible serial devices', ''));
        sel.add(new Option('Network (TCP/UDP)…', NET_OPTION));
        const current = ensureConn(connId).status;
        if (current.connected && current.port) showPortInPicker(current.port);
        else if (Array.from(sel.options).some(o => o.value === previous)) sel.value = previous;
        else if (previous && previous !== NET_OPTION) {
          const missing = new Option('Device removed — rescan or select a device', '');
          missing.disabled = true;
          sel.insertBefore(missing, sel.firstChild);
          sel.value = '';
        }
        onPortSelectChange();
      } catch (err) {
        if (scanId !== portScanId) return;
        sel.title = 'Port scan failed; use Rescan to retry.';
        if (!Array.from(sel.options).some(o => o.value === NET_OPTION)) {
          sel.replaceChildren(new Option('Scan failed — retry', ''), new Option('Network (TCP/UDP)…', NET_OPTION));
        }
        console.error('Scan ports error', err);
      }
    }

    async function toggleConnect() {
      const port = selectedPort();
      const baud = parseInt(document.getElementById('baudSelect').value);
      const conn = ensureConn(connId);
      if (conn.status.connected) {
        await fetch('/api/disconnect', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ id: connId })
        });
      } else {
        if (!port) { alert('Select a serial port or enter a tcp:// / udp:// endpoint first.'); return; }
        const connect = async (on_baud_conflict) => {
          const res = await fetch('/api/connect', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ id: connId, port, baud, mode: document.getElementById('modeSelect').value,
                                   on_baud_conflict })
          });
          return res.json();
        };
        let data = await connect('error');
        const conflict = data.baud_conflict;
        if (conflict) {
          // Other clients share this UART at another baud: the user decides.
          const others = `${conflict.client_count} other client(s)`;
          if (confirm(`${conflict.port} is open by ${others} at ${conflict.live_baud} baud.\n\n` +
                      `Change the UART to ${conflict.requested_baud} baud for everyone?\n` +
                      `It must match the firmware, or every client will see garbage.`)) {
            data = await connect('retime');
          } else if (confirm(`Connect at the live ${conflict.live_baud} baud instead?`)) {
            data = await connect('join');
          } else {
            return;
          }
        }
        if (!data.ok) alert(data.error || 'Connection failed');
        else if (isNetworkPort(port)) rememberNetPort(port);
      }
    }

    async function sendButton(button) {
      const action = document.getElementById('actionMode').value;
      try {
        await fetch('/api/button', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ id: connId, button, action })
        });
      } catch (err) {
        console.error(err);
      }
    }

    // ---- Console mode + interactive terminal (Linux boards / other apps) ----
    const RAW_KEEP_BYTES = 256 * 1024;
    let term = null;
    let termFitAddon = null;

    function currentMode() {
      return document.getElementById('modeSelect').value;
    }

    function applyModeUi(mode) {
      const sel = document.getElementById('modeSelect');
      const prev = sel.dataset.applied;
      sel.value = mode;
      sel.dataset.applied = mode;
      const linux = mode === 'linux';
      ['controlPanel', 'queryPanel'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.classList.toggle('opacity-40', linux);
        if (el) el.classList.toggle('pointer-events-none', linux);
      });
      document.getElementById('termHint').innerText = linux
        ? 'Click the terminal and type; keys go straight to the UART. Select to copy · Ctrl+Shift+V paste.'
        : 'Control mode: control frames are active. Switch to "Linux / Raw" to use this terminal.';
      if (linux && prev !== 'linux') switchTab('terminal');
    }

    async function changeConsoleMode(mode) {
      const conn = ensureConn(connId);
      conn.status.console_mode = mode;
      applyModeUi(mode);
      const res = await fetch('/api/console_mode', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id: connId, mode })
      });
      const out = await res.json();
      if (!out.ok) alert('Mode change failed: ' + out.error);
    }

    function b64ToBytes(b64) {
      const bin = atob(b64);
      const out = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
      return out;
    }

    function bytesToB64(bytes) {
      let bin = '';
      for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
      return btoa(bin);
    }

    function pushRaw(conn, bytes) {
      conn.rawChunks.push(bytes);
      conn.rawBytes += bytes.length;
      while (conn.rawBytes > RAW_KEEP_BYTES && conn.rawChunks.length > 1) {
        conn.rawBytes -= conn.rawChunks.shift().length;
      }
    }

    function ensureTerminal() {
      if (term || !window.Terminal) return term;
      term = new Terminal({
        cursorBlink: true,
        convertEol: false,
        scrollback: 10000,
        fontFamily: "'JetBrains Mono', monospace",
        fontSize: 13,
        theme: { background: '#0c0e12', foreground: '#e2e2e8', cursor: '#00e5ff', selectionBackground: '#3b494c' },
      });
      termFitAddon = new FitAddon.FitAddon();
      term.loadAddon(termFitAddon);
      term.open(document.getElementById('terminalHost'));
      // Ctrl+C must still reach the target as ^C, so copy/paste use the usual
      // terminal shortcuts instead: Ctrl+Shift+C / Ctrl+Shift+V (Ctrl+Insert,
      // Shift+Insert), and selecting text copies it as well.
      term.attachCustomKeyEventHandler(ev => {
        if (ev.type !== 'keydown') return true;
        const key = ev.key.toLowerCase();
        if ((ev.ctrlKey && ev.shiftKey && key === 'c') || (ev.ctrlKey && key === 'insert')) {
          if (term.hasSelection()) copyText(term.getSelection());
          ev.preventDefault();
          return false;
        }
        if ((ev.ctrlKey && ev.shiftKey && key === 'v') || (ev.shiftKey && key === 'insert')) {
          if (navigator.clipboard && navigator.clipboard.readText) {
            navigator.clipboard.readText().then(text => text && term.paste(text)).catch(() => {});
            ev.preventDefault();
            return false;
          }
          return true;  // let the browser deliver a native paste event
        }
        return true;
      });
      term.onSelectionChange(() => {
        const text = term.getSelection();
        if (text) copyText(text);
      });
      term.onData(data => termQueue(data));
      term.onBinary(data => termQueue(data, true));
      term.onResize(({ cols, rows }) => {
        document.getElementById('termSizeLabel').innerText = `${cols}x${rows}`;
      });
      window.addEventListener('resize', termFit);
      new ResizeObserver(() => requestAnimationFrame(termFit)).observe(document.getElementById('terminalHost'));
      termReplay(ensureConn(connId));
      return term;
    }

    function termFit() {
      if (term && termFitAddon && activeTab === 'terminal') {
        try { termFitAddon.fit(); } catch (err) { console.error(err); }
      }
    }

    function termReplay(conn) {
      if (!term) return;
      term.reset();
      conn.rawChunks.forEach(chunk => term.write(chunk));
    }

    // Keystrokes are batched and sent strictly in order so fast typing or
    // pastes reach the UART unshuffled.
    function termQueue(data, binary = false) {
      if (currentMode() !== 'linux') return;
      const bytes = binary
        ? Uint8Array.from(data, c => c.charCodeAt(0) & 0xff)
        : new TextEncoder().encode(data);
      const conn = ensureConn(connId);
      if (!conn.status.connected) return;
      conn.termPending.push(...bytes);
      termFlush(connId);
    }

    async function termFlush(id) {
      const conn = conns[id];
      if (!conn || conn.termSending || !conn.termPending.length) return;
      conn.termSending = true;
      const merged = conn.termPending;
      conn.termPending = [];
      try {
        const res = await fetch('/api/term_input', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ id, data: bytesToB64(Uint8Array.from(merged)) })
        });
        const out = await res.json();
        if (!out.ok && term && id === connId) term.write(`\r\n\x1b[31m[terminal] ${out.error}\x1b[0m\r\n`);
      } catch (err) {
        console.error(err);
      } finally {
        conn.termSending = false;
        if (conns[id] === conn && conn.termPending.length) termFlush(id);
      }
    }

    function termSendKey(key) {
      termQueue(key);
      if (term) term.focus();
    }

    async function termSendBreak() {
      const res = await fetch('/api/break', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id: connId })
      });
      const out = await res.json();
      if (!out.ok) alert('BREAK failed: ' + out.error);
      if (term) term.focus();
    }

    function termSyncSize() {
      if (!term) return;
      termQueue(`stty rows ${term.rows} cols ${term.cols}\r`);
      term.focus();
    }

    function termClear() {
      const conn = ensureConn(connId);
      conn.rawChunks = []; conn.rawBytes = 0;
      if (term) { term.reset(); term.focus(); }
    }

    const txHistory = [];
    let txHistoryPos = 0;

    async function sendTx(e) {
      e.preventDefault();
      const input = document.getElementById('txInput');
      const data = input.value;
      const line_ending = document.getElementById('txLineEnding').value;
      if (!data && line_ending === 'none') return;
      try {
        const res = await fetch('/api/tx', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            id: connId, data, line_ending,
            mode: document.getElementById('txMode').value,
          })
        });
        const out = await res.json();
        if (!out.ok) { alert('TX failed: ' + out.error); return; }
        if (data && txHistory[txHistory.length - 1] !== data) txHistory.push(data);
        txHistoryPos = txHistory.length;
        input.value = '';
      } catch (err) {
        console.error(err);
      }
    }

    function txHistoryKey(e) {
      if (e.key !== 'ArrowUp' && e.key !== 'ArrowDown') return;
      if (!txHistory.length) return;
      e.preventDefault();
      txHistoryPos += e.key === 'ArrowUp' ? -1 : 1;
      txHistoryPos = Math.max(0, Math.min(txHistory.length, txHistoryPos));
      e.target.value = txHistory[txHistoryPos] || '';
    }

    async function sendQuery(kind) {
      await fetch('/api/query', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id: connId, kind })
      });
    }

    async function sendShowInfo() {
      await fetch('/api/show_info', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id: connId })
      });
    }

    async function controlLine(action) {
      await fetch('/api/lines', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id: connId, action })
      });
    }

    async function autoDetectElf() {
      const bDir = document.getElementById('buildDirInput').value;
      const res = await fetch(`/api/autodetect_elf?build_dir=${encodeURIComponent(bDir)}`);
      const data = await res.json();
      if (data.elf) {
        document.getElementById('elfPathInput').value = data.elf;
        loadElfSymbols();
      } else {
        alert('No .elf found in ' + bDir);
      }
    }

    async function loadElfSymbols() {
      const elf_path = document.getElementById('elfPathInput').value;
      if (!elf_path) return;
      const res = await fetch('/api/symbols', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id: connId, elf_path })
      });
      const data = await res.json();
      if (!data.ok) alert(data.error || 'Failed to load ELF');
    }

    async function startFlash() {
      const build_dir = document.getElementById('buildDirInput').value;
      const flash_baud = parseInt(document.getElementById('flashBaudSelect').value);
      if (!confirm(`Flash target with build in "${build_dir}" at ${flash_baud} baud?`)) return;

      document.getElementById('flashProgressContainer').classList.remove('hidden');
      document.getElementById('flashBtn').disabled = true;
      document.getElementById('flashBtn').classList.add('opacity-50');

      const res = await fetch('/api/flash', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id: connId, build_dir, flash_baud })
      });
      const data = await res.json();
      if (!data.ok) {
        alert(data.error || 'Failed to start flash');
        document.getElementById('flashBtn').disabled = false;
        document.getElementById('flashBtn').classList.remove('opacity-50');
      }
    }

    // One EventSource per open connection; every tab keeps streaming in the
    // background regardless of which one is currently rendered.
    function openStream(id) {
      const conn = ensureConn(id);
      if (conn.eventSource) return;
      const es = new EventSource('/api/stream?id=' + encodeURIComponent(id));
      es.onmessage = (e) => {
        try {
          handleStreamEvent(id, JSON.parse(e.data));
        } catch (err) {
          console.error(err);
        }
      };
      es.onerror = () => {
        handleStreamEvent(id, { type: 'status', connected: false });
      };
      conn.eventSource = es;
    }

    function handleStreamEvent(id, event) {
      const conn = ensureConn(id);
      const isActive = id === connId;
      if (event.type === 'init') {
        conn.status = event.status || {};
        if (event.logs) conn.logsBuffer = event.logs;
        conn.rawChunks = []; conn.rawBytes = 0;
        if (event.raw) pushRaw(conn, b64ToBytes(event.raw));
        if (isActive) termReplay(conn);
        renderConnTabs();
        if (isActive) { updateStatus(conn.status); applyLogFilter(); }
      } else if (event.type === 'status') {
        conn.status = Object.assign({}, conn.status, event);
        if (!conn.status.connected) conn.termPending = [];
        renderConnTabs();
        if (isActive) updateStatus(conn.status);
      } else if (event.type === 'log') {
        conn.logsBuffer.push(event);
        const search = document.getElementById('logSearchInput').value.toLowerCase();
        if (isActive) {
          document.getElementById('logCountBadge').innerText = conn.logsBuffer.length;
          if (shouldDisplayLog(event, search)) renderLogEntry(event, true, 'logsPanePrimary');
        }
        if (splitEnabled && id === splitConnId && shouldDisplayLog(event, search)) {
          renderLogEntry(event, true, 'logsPaneSplitContent');
        }
      } else if (event.type === 'raw') {
        const bytes = b64ToBytes(event.data);
        pushRaw(conn, bytes);
        if (isActive && term) term.write(bytes);
      } else if (event.type === 'frame') {
        conn.eventsBuffer.push(event);
        if (isActive) {
          document.getElementById('eventCountBadge').innerText = conn.eventsBuffer.length;
          renderEventEntry(event);
        }
      } else if (event.type === 'flash') {
        if (!isActive) return;
        document.getElementById('flashProgressContainer').classList.remove('hidden');
        document.getElementById('flashStepLabel').innerText = event.step || 'Flashing...';
        const pct = event.percent || 0;
        document.getElementById('flashPercentLabel').innerText = pct + '%';
        document.getElementById('flashProgressBar').style.width = pct + '%';
      } else if (event.type === 'flash_done') {
        if (!isActive) return;
        document.getElementById('flashBtn').disabled = false;
        document.getElementById('flashBtn').classList.remove('opacity-50');
        document.getElementById('flashStepLabel').innerText = event.text;
      }
    }

    function connLabel(id, status) {
      if (status && status.connected && status.port) return status.port;
      return id === 'default' ? 'Default' : 'New tab';
    }

    function renderConnTabs() {
      const bar = document.getElementById('connTabs');
      bar.innerHTML = '';
      connOrder.forEach(id => {
        const conn = ensureConn(id);
        const chip = document.createElement('button');
        chip.type = 'button';
        chip.title = id;
        chip.className = 'flex items-center space-x-1.5 px-2.5 py-1 rounded-lg text-[11px] font-semibold border transition mono ' +
          (id === connId
            ? 'bg-brand-surface text-brand-text border-brand-accent/60'
            : 'bg-transparent text-brand-muted border-brand-border hover:text-brand-text hover:bg-brand-surface');
        const dotColor = conn.status.connected ? 'bg-brand-success' : 'bg-brand-border';
        chip.innerHTML = `<span class="w-1.5 h-1.5 rounded-full ${dotColor}"></span><span>${escapeHtml(connLabel(id, conn.status))}</span>`;
        if (id !== 'default') {
          const closeBtn = document.createElement('span');
          closeBtn.className = 'ml-1 text-brand-muted hover:text-brand-danger';
          closeBtn.innerHTML = '<i class="fa-solid fa-xmark"></i>';
          closeBtn.onclick = (e) => { e.stopPropagation(); closeConnection(id); };
          chip.appendChild(closeBtn);
        }
        chip.onclick = () => switchConnection(id);
        bar.appendChild(chip);
      });
      if (splitEnabled) populateSplitConnSelect();
    }

    function switchConnection(id) {
      connId = id;
      const conn = ensureConn(id);
      openStream(id);

      if (splitEnabled && splitConnId === id) {
        const candidate = connOrder.find(x => x !== id);
        if (candidate) {
          splitConnId = candidate;
        } else {
          splitEnabled = false;
          document.getElementById('logsPaneSplit').classList.add('hidden');
          document.getElementById('splitViewBtn').classList.remove('text-brand-accent');
        }
      }
      renderConnTabs();
      syncUrlToConn(id);

      document.getElementById('viewEvents').innerHTML = '';
      document.getElementById('logCountBadge').innerText = conn.logsBuffer.length;
      document.getElementById('eventCountBadge').innerText = conn.eventsBuffer.length;
      applyLogFilter();
      conn.eventsBuffer.forEach(renderEventEntry);
      if (splitEnabled && splitConnId) { openStream(splitConnId); renderLogsInto(splitConnId, 'logsPaneSplitContent'); }

      updateStatus(conn.status);
      if (conn.status.port) showPortInPicker(conn.status.port);
      if (conn.status.baud) {
        document.getElementById('baudSelect').value = conn.status.baud;
      }
      termReplay(conn);
    }

    async function addConnection() {
      try {
        const res = await fetch('/api/connections', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: '{}'
        });
        const data = await res.json();
        if (!data.ok) { alert(data.error || 'Failed to open a new connection'); return; }
        ensureConn(data.id).status = data.status || {};
        switchConnection(data.id);
      } catch (err) {
        alert('Failed to open a new connection');
      }
    }

    async function closeConnection(id) {
      if (id === 'default') return;
      try {
        await fetch('/api/connections/close', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ id })
        });
      } catch (err) {
        console.error(err);
      }
      const conn = conns[id];
      if (conn && conn.eventSource) conn.eventSource.close();
      delete conns[id];
      connOrder = connOrder.filter(x => x !== id);
      if (splitConnId === id) {
        splitConnId = null;
        splitEnabled = false;
        document.getElementById('logsPaneSplit').classList.add('hidden');
        document.getElementById('splitViewBtn').classList.remove('text-brand-accent');
      }
      if (connId === id) {
        switchConnection('default');
      } else {
        renderConnTabs();
      }
    }

    // Split console view: pick a second open connection to render alongside
    // the primary one, so 2 physical UARTs can be watched at once without
    // switching tabs back and forth.
    function toggleSplitView() {
      splitEnabled = !splitEnabled;
      document.getElementById('logsPaneSplit').classList.toggle('hidden', !splitEnabled);
      document.getElementById('splitViewBtn').classList.toggle('text-brand-accent', splitEnabled);
      if (!splitEnabled) return;
      populateSplitConnSelect();
      if (!splitConnId || splitConnId === connId) {
        splitConnId = connOrder.find(x => x !== connId) || null;
      }
      if (!splitConnId) {
        alert('Open another connection first (the + button) to split against it.');
        splitEnabled = false;
        document.getElementById('logsPaneSplit').classList.add('hidden');
        document.getElementById('splitViewBtn').classList.remove('text-brand-accent');
        return;
      }
      document.getElementById('splitConnSelect').value = splitConnId;
      openStream(splitConnId);
      renderLogsInto(splitConnId, 'logsPaneSplitContent');
    }

    function populateSplitConnSelect() {
      const sel = document.getElementById('splitConnSelect');
      const previous = sel.value;
      sel.innerHTML = '';
      connOrder.filter(x => x !== connId).forEach(id => {
        const opt = document.createElement('option');
        opt.value = id;
        opt.innerText = connLabel(id, ensureConn(id).status);
        sel.appendChild(opt);
      });
      const target = splitConnId || previous;
      if (target && Array.from(sel.options).some(o => o.value === target)) sel.value = target;
    }

    function onSplitConnChange(id) {
      splitConnId = id;
      openStream(id);
      renderLogsInto(id, 'logsPaneSplitContent');
    }

    // Sidebar hide/show + drag-to-resize.
    function applySidebarWidth() {
      const aside = document.getElementById('sidebarPanel');
      const icon = document.getElementById('sidebarToggleIcon');
      aside.classList.toggle('collapsed', sidebarCollapsed);
      if (sidebarCollapsed) {
        icon.className = 'fa-solid fa-chevron-right text-[10px]';
      } else {
        const available = document.getElementById('telemetryPanel').clientWidth;
        aside.style.width = Math.min(sidebarWidth, Math.max(260, available * .34)) + 'px';
        icon.className = 'fa-solid fa-chevron-left text-[10px]';
      }
      updateRail();
      requestAnimationFrame(termFit);
    }

    function setSidebarCollapsed(collapsed) {
      sidebarCollapsed = collapsed;
      try { localStorage.setItem('serialdeck.sidebarCollapsed', collapsed ? '1' : '0'); } catch (err) {}
      applySidebarWidth();
    }

    function toggleSidebar() {
      setSidebarCollapsed(!sidebarCollapsed);
    }

    (function setupSidebarResize() {
      const handle = document.getElementById('sidebarResizeHandle');
      let dragging = false;
      handle.addEventListener('mousedown', (e) => {
        if (e.target.closest('#sidebarToggleBtn')) return;
        dragging = true;
        if (sidebarCollapsed) { setSidebarCollapsed(false); }
        e.preventDefault();
      });
      window.addEventListener('mousemove', (e) => {
        if (!dragging) return;
        const mainRect = document.getElementById('telemetryPanel').getBoundingClientRect();
        sidebarWidth = Math.min(560, Math.max(260, e.clientX - mainRect.left - 16));
        applySidebarWidth();
      });
      window.addEventListener('mouseup', () => { dragging = false; });
    })();

    // Keep the address bar in sync so a copied URL (or a new browser
    // window/tab opened with it) lands on the same connection — the basis
    // for a native side-by-side split using the OS/browser's own window
    // snapping instead of the in-page split view above.
    function syncUrlToConn(id) {
      const url = new URL(window.location.href);
      if (id === 'default') {
        url.searchParams.delete('conn');
      } else {
        url.searchParams.set('conn', id);
      }
      history.replaceState(null, '', url.toString());
    }

    async function bootstrapConnections() {
      try {
        const res = await fetch('/api/connections');
        const data = await res.json();
        (data.connections || []).forEach(c => { ensureConn(c.id).status = c; });
      } catch (err) {
        console.error('list connections failed', err);
      }
      ensureConn('default');
      connOrder.forEach(openStream);
      const requested = new URLSearchParams(location.search).get('conn');
      const initial = (requested && conns[requested]) ? requested : 'default';
      switchConnection(initial);
    }

    function updateStatus(st) {
      if (!st) return;
      const connected = !!st.connected;
      const dot = document.getElementById('connDot');
      const lbl = document.getElementById('connLabel');
      const btn = document.getElementById('connectBtn');
      const btnText = document.getElementById('connectBtnText');

      if (connected) {
        if (st.port) showPortInPicker(st.port);
        if (st.baud) {
          const baudSelect = document.getElementById('baudSelect');
          if (!Array.from(baudSelect.options).some(o => o.value === String(st.baud))) {
            baudSelect.add(new Option(String(st.baud), String(st.baud)));
          }
          baudSelect.value = String(st.baud);
        }
        dot.className = "w-2.5 h-2.5 rounded-full bg-brand-success shadow-lg shadow-brand-success/50";
        lbl.innerText = isNetworkPort(st.port) ? st.port : `${st.port} @ ${st.baud}`;
        lbl.className = "mono text-brand-success font-bold";
        btnText.innerText = "Disconnect";
        btn.className = "px-4 py-1 rounded text-xs font-bold transition flex items-center space-x-1.5 bg-brand-danger hover:bg-brand-danger/80 text-white shadow";
      } else {
        dot.className = "w-2.5 h-2.5 rounded-full bg-brand-danger";
        lbl.innerText = "Disconnected";
        lbl.className = "mono text-brand-muted";
        btnText.innerText = "Connect";
        btn.className = "px-4 py-1 rounded text-xs font-bold transition flex items-center space-x-1.5 bg-brand-accent hover:bg-brand-accentHover text-brand-bg shadow";
      }

      if (st.console_mode) applyModeUi(st.console_mode);
      if (st.fsm) {
        document.getElementById('fsmBadge').innerText = st.fsm;
      }
      if (st.transport_label) {
        document.getElementById('transportBadge').innerText = st.transport_label;
      }
      if (st.device) {
        document.getElementById('deviceBadge').innerText = st.device;
      }
      if (st.dtr !== undefined) {
        document.getElementById('dtrStatus').innerText = `DTR: ${st.dtr === null ? '--' : (st.dtr ? 'HIGH' : 'LOW')}`;
      }
      if (st.rts !== undefined) {
        document.getElementById('rtsStatus').innerText = `RTS: ${st.rts === null ? '--' : (st.rts ? 'HIGH' : 'LOW')}`;
      }
      if (st.telemetry) {
        document.getElementById('inspectorContent').innerText = JSON.stringify(st.telemetry, null, 2);
      }
      if (st.elf && !document.getElementById('elfPathInput').value) {
        document.getElementById('elfPathInput').value = st.elf;
      }
    }

    // ---------------- MCP page ----------------
    let mcpData = null;
    let mcpTimer = null;

    function copyText(text, btn) {
      const done = () => {
        if (!btn) return;
        const old = btn.innerHTML;
        btn.innerHTML = '<i class="fa-solid fa-check"></i>';
        setTimeout(() => { btn.innerHTML = old; }, 1200);
      };
      const fallback = () => {
        const area = document.createElement('textarea');
        area.value = text;
        area.style.position = 'fixed';
        area.style.opacity = '0';
        document.body.appendChild(area);
        area.select();
        try { document.execCommand('copy'); } catch (err) {}
        area.remove();
        done();
      };
      if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).then(done, fallback);
      } else {
        fallback();
      }
    }

    function codeBlock(text) {
      const id = 'code-' + Math.random().toString(36).slice(2);
      return `<div class="mcp-code"><pre id="${id}" class="mono">${escapeHtml(text)}</pre>` +
             `<button type="button" title="Copy" onclick="copyText(document.getElementById('${id}').innerText, this)"><i class="fa-regular fa-copy"></i></button></div>`;
    }

    function renderMcpInstall() {
      if (!mcpData) return;
      const policy = document.getElementById('mcpPolicySelect').value;
      const cmd = mcpData.install[policy];
      document.getElementById('mcpInstall').innerHTML =
        (mcpData.sdk_installed ? '' : `<div class="text-brand-warning">1. Install the MCP SDK into the venv</div>${codeBlock(cmd.pip)}`) +
        `<div class="text-brand-muted">Claude Code (user scope)</div>${codeBlock(cmd.claude)}` +
        `<div class="text-brand-muted">Codex</div>${codeBlock(cmd.codex)}` +
        `<div class="text-brand-muted">Claude Desktop / Cursor (JSON)</div>${codeBlock(cmd.json)}` +
        `<div class="text-[11px] text-brand-muted">Re-run the add command to change the policy; tools load in the next client session.</div>`;
    }

    function renderMcpRegistrations() {
      const regs = mcpData.registrations;
      const row = (name, reg, cli) => {
        if (!reg) return `<div class="flex items-center gap-2"><span class="w-2 h-2 rounded-full bg-brand-muted/40"></span>` +
          `<span class="font-semibold">${name}</span><span class="text-brand-muted">${cli ? 'not registered' : 'CLI not found'}</span></div>`;
        const off = reg.enabled === false;
        return `<div class="flex items-center gap-2 flex-wrap"><span class="w-2 h-2 rounded-full ${off ? 'bg-brand-warning' : 'bg-brand-success'}"></span>` +
          `<span class="font-semibold">${name}</span><span class="mono text-brand-muted">${escapeHtml(reg.scope)}</span>` +
          `<span class="mono px-1.5 rounded border border-brand-border">--allow ${escapeHtml(reg.policy)}</span>${off ? '<span class="text-brand-warning">disabled</span>' : ''}</div>`;
      };
      document.getElementById('mcpRegistrations').innerHTML =
        '<div class="text-brand-muted uppercase text-[10px] font-bold">Registered</div>' +
        row('Claude Code', regs.claude, regs.claude_cli) + row('Codex', regs.codex, regs.codex_cli);
    }

    function renderMcpPolicies() {
      const desc = { observe: 'read-only: status, ports, logs, queries, flash preview',
                     interact: '+ buttons, show info (changes firmware UI state)',
                     hardware: '+ reset, ROM bootloader, flash' };
      document.getElementById('mcpPolicyTable').innerHTML = ['observe', 'interact', 'hardware'].map(level =>
        `<div class="flex gap-2"><span class="mono w-20 shrink-0 ${level === 'hardware' ? 'text-brand-danger' : 'text-brand-accent'}">${level}</span>` +
        `<span>${desc[level]}<br><span class="mono text-[10px] text-brand-muted">${mcpData.tools[level].join(', ')}</span></span></div>`).join('');
    }

    function fmtAgo(seconds) {
      if (seconds < 60) return `${Math.round(seconds)}s`;
      if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
      return `${(seconds / 3600).toFixed(1)}h`;
    }

    function renderMcpServers() {
      const servers = mcpData.servers || [];
      const badge = document.getElementById('mcpRailBadge');
      badge.textContent = servers.length;
      badge.classList.toggle('hidden', !servers.length);
      const box = document.getElementById('mcpServers');
      if (!servers.length) {
        box.innerHTML = '<div class="text-brand-muted">No MCP server is running. Start a Claude Code / Codex session that has the <span class="mono">serial-deck</span> server registered; it appears here within a second.</div>';
        return;
      }
      const now = Date.now() / 1000;
      box.innerHTML = servers.map(srv => {
        const sessions = (srv.sessions || []).map(sess =>
          `<span class="mono px-1.5 py-0.5 rounded border ${sess.lost ? 'border-brand-danger text-brand-danger' : 'border-brand-border'}">${escapeHtml(sess.port)} · ${sess.mode} · ${sess.baud}</span>`).join(' ') ||
          '<span class="text-brand-muted">no port attached</span>';
        const jobs = (srv.flash_jobs || []).map(job =>
          `<span class="mono text-brand-flash">flash ${Math.round(job.progress || 0)}% ${escapeHtml(job.step || '')}</span>`).join(' ');
        const calls = (srv.calls || []).slice(-25).reverse().map(call => {
          const color = call.state === 'running' ? 'text-brand-accent' : (call.state === 'ok' ? 'text-brand-success' : 'text-brand-danger');
          const args = Object.keys(call.args || {}).length ? JSON.stringify(call.args) : '';
          const when = new Date(call.started * 1000).toLocaleTimeString();
          const dur = call.state === 'running' ? `${fmtAgo(now - call.started)}…` : `${call.duration_ms}ms`;
          return `<tr class="border-t border-brand-border/40 align-top">` +
            `<td class="py-1 pr-2 mono text-brand-muted whitespace-nowrap">${when}</td>` +
            `<td class="py-1 pr-2 mono font-semibold whitespace-nowrap">${escapeHtml(call.tool)}</td>` +
            `<td class="py-1 pr-2 mono text-brand-muted break-all">${escapeHtml(args)}</td>` +
            `<td class="py-1 pr-2 mono whitespace-nowrap ${color}">${call.state}</td>` +
            `<td class="py-1 pr-2 mono whitespace-nowrap text-brand-muted">${dur}</td>` +
            `<td class="py-1 mono break-all">${escapeHtml(call.summary || '')}</td></tr>`;
        }).join('');
        return `<div class="border border-brand-border rounded p-3 space-y-2">` +
          `<div class="flex items-center gap-2 flex-wrap"><span class="w-2 h-2 rounded-full bg-brand-success"></span>` +
          `<span class="font-semibold">pid ${srv.pid}</span><span class="text-brand-muted">${escapeHtml(srv.parent || 'client')}</span>` +
          `<span class="mono px-1.5 rounded border border-brand-border">--allow ${escapeHtml(srv.policy)}</span>` +
          `<span class="text-brand-muted">up ${fmtAgo(srv.uptime_s || 0)}</span>${jobs}</div>` +
          `<div class="flex items-center gap-1 flex-wrap">${sessions}</div>` +
          (calls ? `<div class="overflow-x-auto"><table class="w-full text-[11px]"><thead><tr class="text-left text-brand-muted text-[10px] uppercase">` +
            `<th class="pr-2">time</th><th class="pr-2">tool</th><th class="pr-2">args</th><th class="pr-2">state</th><th class="pr-2">took</th><th>result</th></tr></thead><tbody>${calls}</tbody></table></div>`
            : '<div class="text-brand-muted">no tool calls yet</div>') +
          `</div>`;
      }).join('');
    }

    async function refreshMcp() {
      try {
        const res = await fetch('/api/mcp');
        mcpData = await res.json();
      } catch (err) {
        return;
      }
      const sdk = document.getElementById('mcpSdkBadge');
      sdk.textContent = mcpData.sdk_installed ? 'SDK installed' : 'SDK missing';
      sdk.className = 'text-[10px] mono px-2 py-0.5 rounded border ' +
        (mcpData.sdk_installed ? 'border-brand-success/50 text-brand-success' : 'border-brand-warning/50 text-brand-warning');
      if (!document.getElementById('mcpInstall').innerHTML) renderMcpInstall();
      renderMcpPolicies();
      renderMcpRegistrations();
      renderMcpServers();
      document.getElementById('mcpUpdated').textContent = 'updated ' + new Date().toLocaleTimeString();
    }

    function scheduleMcp() {
      clearTimeout(mcpTimer);
      // Fast while the page is open, slow in the background (rail badge only).
      const delay = currentPage === 'mcp' && document.getElementById('mcpAutoRefresh').checked ? 1500 : 10000;
      mcpTimer = setTimeout(async () => { await refreshMcp(); scheduleMcp(); }, delay);
    }

    document.body.dataset.page = 'deck';
    window.addEventListener('resize', applySidebarWidth);
    applySidebarWidth();
    refreshMcp().then(scheduleMcp);

    // Startup
    renderNetHistory();
    scanPorts();

    // Browser mode (no app window): offer Quit, which the app refuses mid-flash.
    fetch('/api/instance').then(r => r.json()).then(info => {
      if (info.browser_mode) document.getElementById('quitBtn').classList.remove('hidden');
    }).catch(() => {});

    async function quitApp() {
      const res = await fetch('/api/quit', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
      const data = await res.json().catch(() => ({}));
      if (!data.ok) { alert(data.error || 'Cannot quit right now.'); return; }
      document.body.innerHTML = '<div style="padding:40px;font-family:sans-serif;color:#cfd8dc;background:#111318;height:100vh">Serial Deck stopped. You can close this tab.</div>';
    }
    bootstrapConnections();
  </script>
</body>
</html>
"""


DEFAULT_WEB_PORT = 8081
SHUTDOWN_SIGNALS = ("SIGINT", "SIGTERM", "SIGHUP")


def install_shutdown_signals() -> None:
    """Turn SIGINT/SIGTERM/SIGHUP into KeyboardInterrupt so `kill`, a closed
    terminal or systemd run the normal cleanup (which stops owned hubs).

    SIGINT is re-armed too: a shell starts background jobs with it ignored,
    which would otherwise make `kill -INT` a no-op. Repeats are ignored so a
    second signal cannot cut the cleanup short.
    """
    signals = [getattr(signal, name) for name in SHUTDOWN_SIGNALS if hasattr(signal, name)]

    def _request_shutdown(signum: int, _frame: object) -> None:
        for sig in signals:
            signal.signal(sig, signal.SIG_IGN)
        raise KeyboardInterrupt(f"signal {signum}")

    for sig in signals:
        signal.signal(sig, _request_shutdown)


def bind_web_server(host: str, port: int | None, attempts: int = 20,
                    handler: type[DeckHttpHandler] = DeckHttpHandler) -> ThreadingHTTPServer:
    """Bind the dashboard; without an explicit port, skip past busy defaults."""
    if port is not None:
        return ThreadingHTTPServer((host, port), handler)
    for candidate in range(DEFAULT_WEB_PORT, DEFAULT_WEB_PORT + attempts):
        try:
            return ThreadingHTTPServer((host, candidate), handler)
        except OSError as exc:
            if exc.errno != errno.EADDRINUSE:
                raise
    raise OSError(errno.EADDRINUSE, f"ports {DEFAULT_WEB_PORT}-{DEFAULT_WEB_PORT + attempts - 1} are all in use")


class HubStartupError(RuntimeError):
    """The web server bound, but the hub could not be started or attached."""


class WebBackend:
    """HTTP server, default hub, and connection manager for one dashboard.

    Shared by the browser entrypoint (`main`) and the pywebview app. `close()`
    detaches channel clients. The multi-port daemon survives UI shutdown;
    legacy single-port hubs retain their previous ownership rules.
    """

    def __init__(self, host: str = "127.0.0.1", port_web: int | None = None,
                 uart_port: str = "", baud: int = 2000000,
                 socket_path: str = DEFAULT_SOCKET, attach_only: bool = False,
                 elf: str = "",
                 hub_manager_factory: Callable[..., HubProcessManager] = HubProcessManager,
                 hub_registry: HubRegistry | None = None) -> None:
        # Each backend gets its own handler class so two backends in one
        # process never serve each other's connections or instance token.
        self.handler = type("DeckBackendHttpHandler", (DeckHttpHandler,), {})
        self.instance_token = uuid.uuid4().hex
        self.handler.instance_token = self.instance_token
        # Bind the web port before spawning the hub so a busy port does not
        # leave an orphaned hub process behind.
        self.server = bind_web_server(host, port_web, handler=self.handler)
        self._serve_thread: threading.Thread | None = None
        self._closed = False
        self.hub_manager = hub_manager_factory(uart_port, baud, socket_path)
        try:
            if attach_only:
                if not self.hub_manager.socket_ready():
                    raise RuntimeError(f"UART hub is not listening at {socket_path}")
            else:
                self.hub_manager.ensure_started()
        except (OSError, RuntimeError, TimeoutError, ValueError) as exc:
            self.server.server_close()
            raise HubStartupError(str(exc)) from exc

        try:
            bridge = DeckWebBridge(default_port=uart_port, default_baud=baud, elf=elf,
                                   hub_manager=self.hub_manager)
        except Exception as exc:
            # The bridge subscribes to hub status; a hub that accepted the
            # readiness probe but then refused the subscription lands here.
            try:
                keep_unsafe_hub_running(self.hub_manager, uart_port or socket_path)
                self.hub_manager.stop()
            finally:
                self.server.server_close()
            raise HubStartupError(f"cannot subscribe to UART hub: {exc}") from exc

        # Route every tab, including Default, by the selected physical port.
        # The rendezvous socket may already belong to a different device.
        self.hub_registry = hub_registry if hub_registry is not None else HubRegistry(
            baud=baud, default_manager=self.hub_manager, reuse_live_baud=True)
        bridge.hub_registry = self.hub_registry
        self.connections = ConnectionManager(bridge, self.hub_registry, baud, elf)
        self.connections.lifecycle_hubs.append(self.hub_manager)
        self.handler.connections = self.connections

    @property
    def port(self) -> int:
        return int(self.server.server_address[1])

    @property
    def url(self) -> str:
        host = self.server.server_address[0]
        return f"http://{host}:{self.port}/"

    def serve_forever(self) -> None:
        self.server.serve_forever(poll_interval=0.2)

    def start_in_thread(self) -> threading.Thread:
        self._serve_thread = threading.Thread(
            target=self.serve_forever, name="serial-deck-web-http", daemon=True)
        self._serve_thread.start()
        return self._serve_thread

    def flash_check(self) -> FlashCheck:
        return self.connections.flash_check()

    def _detach_unsafe_hubs(self) -> None:
        for label, manager, state in self.connections.hub_flash_states():
            keep_unsafe_hub_running(manager, label, state)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._serve_thread is not None:
            self.server.shutdown()
            self._serve_thread.join(timeout=2.0)
        try:
            self._detach_unsafe_hubs()
            self.connections.close_all()
        finally:
            try:
                self.hub_manager.stop()
            finally:
                self.server.server_close()


def main(argv: list[str] | None = None) -> int:
    try:
        from .ipc import configure_console_streams
    except ImportError:
        from ipc import configure_console_streams
    configure_console_streams()
    parser = argparse.ArgumentParser(description="Serial Deck Modern Web Dashboard")
    parser.add_argument("--host", default="127.0.0.1", help="host to bind web server (default: 127.0.0.1)")
    parser.add_argument("--port-web", type=int, default=None,
                        help=f"port to bind web server (default: {DEFAULT_WEB_PORT}, "
                             "or the next free port if it is taken)")
    parser.add_argument("--port", default="", help="initial physical UART selection for the hub")
    parser.add_argument("--baud", type=int, default=2000000, help="initial UART baudrate")
    parser.add_argument("--socket", default=DEFAULT_SOCKET, help="hub endpoint path")
    parser.add_argument("--attach-only", action="store_true", help="require an existing hub")
    parser.add_argument("--elf", default="", help="application ELF file for address symbolization")
    parser.add_argument("--open-browser", action="store_true", help="automatically open browser on startup")
    args = parser.parse_args(argv)

    try:
        backend = WebBackend(args.host, args.port_web, args.port, args.baud,
                             args.socket, args.attach_only, args.elf)
    except HubStartupError as exc:
        print(f"Hub startup failed: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"Cannot bind web server on {args.host}:{args.port_web or DEFAULT_WEB_PORT}: {exc}\n"
              f"Pick another port with --port-web <port>.", file=sys.stderr)
        return 2

    url = f"http://{args.host}:{backend.port}/"
    print(f"============================================================")
    print("Serial Deck web dashboard")
    print(f"🚀 Running at: {url}")
    print(f"============================================================", flush=True)

    if args.open_browser:
        threading.Thread(target=lambda: (time.sleep(0.5), runtime.open_browser(url)), daemon=True).start()

    install_shutdown_signals()
    try:
        backend.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping Serial Deck Web server...")
    finally:
        backend.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
