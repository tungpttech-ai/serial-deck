#!/usr/bin/env python3
"""Reference control-plane contract and UART v1 codec.

The target adapter can reuse the C codec, while host tools use this module for
golden vectors and bounded request validation. No serial dependency is needed
for contract tests.
"""

from __future__ import annotations

import base64
import json
import os
import select
import stat
import socket
import struct
import sys
import time
import uuid
import zlib
import argparse
import re
import urllib.parse
from pathlib import Path
from typing import Any

PROTOCOL_VERSION = 1
MAX_DECODED_PAYLOAD = 1536
MAX_ENCODED_FRAME = 2048
PENDING_LIMIT = MAX_ENCODED_FRAME * 4
HEADER_SIZE = 9
CRC_SIZE = 4

FRAME_HELLO = 1
FRAME_COMMAND = 2
FRAME_RESPONSE = 3
FRAME_EVENT = 4
FRAME_ERROR = 5

COMMANDS = {
    "query": False,
    "input.button": True,
    "ui.show_info": True,
}

STATUSES = {
    "accepted",
    "running",
    "succeeded",
    "failed",
    "cancelled",
    "expired",
    "rejected",
}

ERROR_CODES = {
    "",
    "invalid_schema",
    "unknown_command",
    "unauthorized",
    "forbidden",
    "invalid_state",
    "busy",
    "deadline_exceeded",
    "duplicate_request",
    "transport_unavailable",
    "hardware_unavailable",
    "operation_not_found",
    "internal_error",
    "already_running",
}


def crc32_ieee(data: bytes) -> int:
    return zlib.crc32(data) & 0xFFFFFFFF


def cobs_encode(data: bytes) -> bytes:
    out = bytearray((0,))
    code_index = 0
    code = 1
    for value in data:
        if value == 0:
            out[code_index] = code
            code_index = len(out)
            out.append(0)
            code = 1
        else:
            out.append(value)
            code += 1
            if code == 0xFF:
                out[code_index] = code
                code_index = len(out)
                out.append(0)
                code = 1
    out[code_index] = code
    return bytes(out)


def cobs_decode(data: bytes) -> bytes:
    if not data:
        raise ValueError("empty COBS frame")
    out = bytearray()
    index = 0
    while index < len(data):
        code = data[index]
        index += 1
        if code == 0 or index + code - 1 > len(data):
            raise ValueError("malformed COBS frame")
        out.extend(data[index : index + code - 1])
        index += code - 1
        if code != 0xFF and index < len(data):
            out.append(0)
    return bytes(out)


def encode_frame(frame_type: int, flags: int, sequence: int, payload: bytes) -> bytes:
    if len(payload) > MAX_DECODED_PAYLOAD:
        raise ValueError("payload too large")
    header = struct.pack("<BBB I H", PROTOCOL_VERSION, frame_type, flags, sequence, len(payload))
    raw = header + payload
    raw += struct.pack("<I", crc32_ieee(raw))
    encoded = cobs_encode(raw) + b"\0"
    if len(encoded) > MAX_ENCODED_FRAME:
        raise ValueError("encoded frame too large")
    return encoded


def decode_frame(frame: bytes) -> tuple[int, int, int, bytes]:
    if frame.endswith(b"\0"):
        frame = frame[:-1]
    raw = cobs_decode(frame)
    if len(raw) < HEADER_SIZE + CRC_SIZE:
        raise ValueError("frame too short")
    version, frame_type, flags, sequence, payload_len = struct.unpack_from("<BBB I H", raw)
    if version != PROTOCOL_VERSION:
        raise ValueError("unsupported protocol version")
    expected_len = HEADER_SIZE + payload_len + CRC_SIZE
    if payload_len > MAX_DECODED_PAYLOAD or len(raw) != expected_len:
        raise ValueError("invalid payload length")
    payload = raw[HEADER_SIZE : HEADER_SIZE + payload_len]
    expected_crc = struct.unpack_from("<I", raw, HEADER_SIZE + payload_len)[0]
    if crc32_ieee(raw[: HEADER_SIZE + payload_len]) != expected_crc:
        raise ValueError("CRC mismatch")
    return frame_type, flags, sequence, payload


def canonical_args(args: dict[str, Any]) -> bytes:
    return json.dumps(args, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def validate_request(request: dict[str, Any]) -> None:
    required = {"version", "request_id", "command", "args", "deadline_ms"}
    unknown = set(request) - required - {"auth_tag", "confirm", "idempotency_key"}
    if unknown or not required.issubset(request):
        raise ValueError("invalid_schema")
    if request["version"] != PROTOCOL_VERSION:
        raise ValueError("invalid_schema")
    if not isinstance(request["request_id"], str) or not 1 <= len(request["request_id"]) <= 32:
        raise ValueError("invalid_schema")
    command = request["command"]
    if command not in COMMANDS:
        raise ValueError("unknown_command")
    if not isinstance(request["args"], dict) or len(canonical_args(request["args"])) > 1024:
        raise ValueError("invalid_schema")
    deadline = request["deadline_ms"]
    if not isinstance(deadline, int) or isinstance(deadline, bool) or not 1 <= deadline <= 30000:
        raise ValueError("invalid_schema")
    idem = request.get("idempotency_key", "")
    if COMMANDS[command] and (not isinstance(idem, str) or not 1 <= len(idem) <= 64):
        raise ValueError("invalid_schema")
    if command == "input.button":
        if set(request["args"]) != {"button", "action"}:
            raise ValueError("invalid_schema")
        if request["args"]["button"] not in {"HOME", "LEFT", "RIGHT", "ENTER", "ONOFF"}:
            raise ValueError("invalid_schema")
        if request["args"]["action"] not in {"press", "release", "long_press"}:
            raise ValueError("invalid_schema")
    elif command == "query":
        if set(request["args"]) != {"kind"}:
            raise ValueError("invalid_schema")
        if request["args"]["kind"] not in {"capabilities", "identity", "fsm", "snapshot"}:
            raise ValueError("invalid_schema")
    elif command == "ui.show_info" and request["args"]:
        raise ValueError("invalid_schema")


def encode_json_frame(frame_type: int, sequence: int, message: dict[str, Any]) -> bytes:
    payload = json.dumps(message, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return encode_frame(frame_type, 0, sequence, payload)


FRAME_NAMES = {
    FRAME_HELLO: "hello",
    FRAME_COMMAND: "command",
    FRAME_RESPONSE: "response",
    FRAME_EVENT: "event",
    FRAME_ERROR: "error",
}


def make_request(command: str, args: dict[str, Any], deadline_ms: int = 3000) -> dict[str, Any]:
    """Build and validate one logical request envelope."""
    request: dict[str, Any] = {
        "version": PROTOCOL_VERSION,
        "request_id": uuid.uuid4().hex[:16],
        "command": command,
        "args": args,
        "deadline_ms": deadline_ms,
    }
    if COMMANDS.get(command, False):
        request["idempotency_key"] = request["request_id"]
    validate_request(request)
    return request


class SerialTransport:
    """Serial wrapper with pyserial and a POSIX standard-library fallback."""

    def __init__(self, port: str, baud: int, timeout: float) -> None:
        self._serial = None
        self._fd: int | None = None
        self._dtr_state: bool | None = None
        self._rts_state: bool | None = None
        try:
            import serial  # type: ignore
        except ImportError:
            if os.name != "posix":
                raise RuntimeError(
                    "pyserial is not installed for this Python interpreter "
                    f"({sys.executable}); install pyserial before running the desktop UI."
                )
            self._timeout = timeout
            self._fd = self._open_posix(port, baud)
            # POSIX exposes modem-line writes on some USB-UART drivers without
            # supporting TIOCMGET readback. Keep a deterministic baseline so a
            # later toggle can still be represented and reported.
            self._dtr_state = False
            self._rts_state = False
        else:
            # A bounded write: a wedged USB driver must not hold the hub's locks forever.
            self._serial = serial.Serial(port=port, baudrate=baud, timeout=timeout,
                                         write_timeout=max(2.0, timeout))
            self._dtr_state = bool(self._serial.dtr)
            self._rts_state = bool(self._serial.rts)

    @staticmethod
    def _open_posix(port: str, baud: int) -> int:
        import termios

        baud_constant = getattr(termios, f"B{baud}", None)
        if baud_constant is None:
            raise ValueError(f"unsupported POSIX baud rate: {baud}")
        fd = os.open(port, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
        try:
            attrs = termios.tcgetattr(fd)
            attrs[0] = 0
            attrs[1] = 0
            attrs[2] = termios.CS8 | termios.CLOCAL | termios.CREAD
            attrs[3] = 0
            attrs[4] = baud_constant
            attrs[5] = baud_constant
            attrs[6][termios.VMIN] = 0
            attrs[6][termios.VTIME] = 0
            termios.tcsetattr(fd, termios.TCSANOW, attrs)
        except Exception:
            os.close(fd)
            raise
        return fd

    def set_baud(self, baud: int) -> None:
        """Retime the open port in place: no close/reopen, so no DTR/RTS pulse."""
        if self._serial is not None:
            self._serial.baudrate = baud
            return
        if self._fd is None:
            raise OSError("serial transport is closed")
        import termios

        baud_constant = getattr(termios, f"B{baud}", None)
        if baud_constant is None:
            raise ValueError(f"unsupported POSIX baud rate: {baud}")
        attrs = termios.tcgetattr(self._fd)
        attrs[4] = baud_constant
        attrs[5] = baud_constant
        termios.tcsetattr(self._fd, termios.TCSADRAIN, attrs)

    def write(self, frame: bytes) -> None:
        if self._serial is not None:
            # Bounded by write_timeout; no flush(): it can wait forever on a wedged
            # driver while the hub holds its serial lock.
            self._serial.write(frame)
            return
        if self._fd is None:
            raise OSError("serial transport is closed")
        offset = 0
        while offset < len(frame):
            _, writable, _ = select.select([], [self._fd], [], self._timeout)
            if not writable:
                raise TimeoutError("serial write timed out")
            offset += os.write(self._fd, frame[offset:])
        import termios
        termios.tcdrain(self._fd)

    def set_modem_lines(self, dtr: bool | None = None, rts: bool | None = None) -> None:
        """Set active modem-control outputs used by common ESP auto-reset circuits."""
        if self._serial is not None:
            if dtr is not None:
                self._serial.dtr = dtr
                self._dtr_state = dtr
            if rts is not None:
                self._serial.rts = rts
                self._rts_state = rts
            return
        if self._fd is None:
            raise OSError("serial transport is closed")
        import fcntl
        import termios

        for value, bit in ((dtr, termios.TIOCM_DTR), (rts, termios.TIOCM_RTS)):
            if value is None:
                continue
            operation = termios.TIOCMBIS if value else termios.TIOCMBIC
            fcntl.ioctl(self._fd, operation, struct.pack("I", bit))
            if bit == termios.TIOCM_DTR:
                self._dtr_state = value
            else:
                self._rts_state = value

    def get_modem_lines(self) -> tuple[bool, bool]:
        if self._serial is not None:
            return bool(self._serial.dtr), bool(self._serial.rts)
        if self._fd is None:
            raise OSError("serial transport is closed")
        import fcntl
        import termios

        try:
            status = struct.unpack("I", fcntl.ioctl(
                self._fd, termios.TIOCMGET, struct.pack("I", 0)))[0]
            self._dtr_state = bool(status & termios.TIOCM_DTR)
            self._rts_state = bool(status & termios.TIOCM_RTS)
        except OSError:
            if self._dtr_state is None or self._rts_state is None:
                raise
        return bool(self._dtr_state), bool(self._rts_state)

    def hard_reset(self) -> None:
        """Pulse RTS as EN reset using Espressif's active-low convention."""
        self.set_modem_lines(dtr=False, rts=True)
        time.sleep(0.1)
        self.set_modem_lines(dtr=False, rts=False)

    def enter_bootloader(self) -> None:
        """Use DTR=GPIO0 and RTS=EN to enter ROM download mode."""
        self.set_modem_lines(dtr=False, rts=True)
        time.sleep(0.1)
        self.set_modem_lines(dtr=True, rts=False)
        time.sleep(0.1)
        self.set_modem_lines(dtr=False, rts=False)

    def send_break(self) -> None:
        """Hold TX low for ~0.25 s (Linux magic SysRq, U-Boot break-in)."""
        if self._serial is not None:
            self._serial.send_break(duration=0.25)
            return
        if self._fd is None:
            raise OSError("serial transport is closed")
        import termios
        termios.tcsendbreak(self._fd, 0)

    def read(self, size: int = 4096) -> bytes:
        if self._serial is not None:
            # read(size) would block for the whole timeout unless `size`
            # bytes arrive; wait for the first byte, then drain what is queued.
            data = bytes(self._serial.read(1))
            waiting = self._serial.in_waiting if data else 0
            if waiting:
                data += bytes(self._serial.read(min(size - 1, waiting)))
            return data
        if self._fd is None:
            return b""
        readable, _, _ = select.select([self._fd], [], [], self._timeout)
        if not readable:
            return b""
        try:
            data = os.read(self._fd, size)
        except BlockingIOError:
            return b""
        if not data:
            # Readable yet empty is the tty's EOF: the other end hung up
            # (USB-serial disconnect, closed pty master). Report it as lost
            # instead of spinning on endless empty reads.
            raise OSError("serial device hung up")
        return data

    def close(self) -> None:
        if self._serial is not None:
            self._serial.close()
            self._serial = None
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None


NETWORK_SCHEMES = ("tcp", "udp")


def is_network_port(port: str) -> bool:
    """True for `tcp://host:port` / `udp://host:port` UART-over-IP endpoints."""
    return port.split("://", 1)[0].lower() in NETWORK_SCHEMES and "://" in port


HUB_SCHEME = "hub://"
_COM_PORT_RE = re.compile(r"^(?:\\\\\.\\)?(COM[0-9]+)$", re.IGNORECASE)


def is_device_port(port: str) -> bool:
    """A local serial device: a POSIX path, or `COM3` / `\\\\.\\COM12` on Windows."""
    return isinstance(port, str) and (port.startswith("/") or _COM_PORT_RE.match(port) is not None)


def port_identity(port: str) -> str:
    """Resolve device aliases without opening the UART."""
    match = _COM_PORT_RE.match(port)
    if match:
        return match.group(1).upper()
    # Only POSIX resolves /dev aliases; Windows would turn "/dev/x" into "D:\\dev\\x".
    return os.path.realpath(port) if port.startswith("/") and os.name != "nt" else port


def parse_network_port(port: str) -> tuple[str, str, int, int]:
    """Split a network endpoint into (scheme, host, port, local_port).

    `udp://host:port?local=N` binds UDP to local port N (default: ephemeral,
    or the same port in listen mode). `udp://:5000` / `udp://0.0.0.0:5000`
    listens and replies to whoever sent the latest datagram.
    """
    parsed = urllib.parse.urlsplit(port)
    scheme = parsed.scheme.lower()
    if scheme not in NETWORK_SCHEMES:
        raise ValueError(f"unsupported network scheme: {port}")
    try:
        remote_port = parsed.port
    except ValueError as exc:
        raise ValueError(f"invalid port in {port}") from exc
    if remote_port is None:
        raise ValueError(f"{scheme}:// endpoint needs a port, e.g. {scheme}://192.168.1.50:23")
    host = parsed.hostname or ""
    if scheme == "tcp" and not host:
        raise ValueError("tcp:// endpoint needs a host, e.g. tcp://192.168.1.50:23")
    query = urllib.parse.parse_qs(parsed.query)
    local = query.get("local", ["0"])[0]
    if not local.isdigit() or int(local) > 65535:
        raise ValueError(f"invalid local UDP port: {local}")
    return scheme, host, remote_port, int(local)


class NetworkTransport:
    """UART-over-IP transport (ser2net, ESP-Link, WiFi-UART modules, telnet consoles).

    Presents the same read/write surface as `SerialTransport`; modem lines,
    BREAK, reset and flashing need a physical UART and raise instead.
    """

    def __init__(self, port: str, timeout: float, connect_timeout: float = 5.0) -> None:
        scheme, host, remote_port, local_port = parse_network_port(port)
        self.scheme = scheme
        self._timeout = timeout
        self._peer: tuple[str, int] | None = None
        self._listen = False
        if scheme == "tcp":
            self._socket = socket.create_connection((host, remote_port), timeout=connect_timeout)
            self._socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        else:
            self._listen = host in ("", "0.0.0.0", "::")
            family = socket.AF_INET6 if ":" in host else socket.AF_INET
            self._socket = socket.socket(family, socket.SOCK_DGRAM)
            self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            bind_port = local_port or (remote_port if self._listen else 0)
            self._socket.bind(("::" if family == socket.AF_INET6 else "0.0.0.0", bind_port))
            if not self._listen:
                self._peer = socket.getaddrinfo(host, remote_port, family, socket.SOCK_DGRAM)[0][4][:2]
        self._socket.settimeout(timeout)

    def write(self, frame: bytes) -> None:
        if self.scheme == "tcp":
            self._socket.sendall(frame)
            return
        if self._peer is None:
            raise OSError("UDP listen mode: no datagram received yet, peer unknown")
        # Keep datagrams under a typical Ethernet MTU payload.
        for offset in range(0, len(frame), 1400):
            self._socket.sendto(frame[offset:offset + 1400], self._peer)

    def read(self, size: int = 4096) -> bytes:
        try:
            if self.scheme == "tcp":
                data = self._socket.recv(size)
                if not data:
                    raise OSError("TCP peer closed the connection")
                return data
            data, peer = self._socket.recvfrom(65535)
        except socket.timeout:
            return b""
        except ConnectionRefusedError:
            # ICMP port-unreachable from a UDP peer that is not up yet.
            return b""
        if self._listen:
            # Listen mode replies to whoever sent the latest datagram.
            self._peer = peer[:2]
        return data

    def _unsupported(self, what: str) -> OSError:
        return OSError(f"{what} needs a physical UART, not {self.scheme}://")

    def set_modem_lines(self, dtr: bool | None = None, rts: bool | None = None) -> None:
        raise self._unsupported("DTR/RTS control")

    def get_modem_lines(self) -> tuple[bool, bool]:
        raise self._unsupported("DTR/RTS readback")

    def hard_reset(self) -> None:
        raise self._unsupported("Reset")

    def enter_bootloader(self) -> None:
        raise self._unsupported("Bootloader entry")

    def send_break(self) -> None:
        raise self._unsupported("BREAK")

    def close(self) -> None:
        self._socket.close()


def open_device_transport(port: str, baud: int, timeout: float) -> SerialTransport | NetworkTransport:
    """Open the device side of a connection: a serial path or a tcp/udp endpoint."""
    if is_network_port(port):
        return NetworkTransport(port, timeout)
    return SerialTransport(port, baud, timeout)


class HubRefused(OSError):
    """The hub answered a control request with an error before acting on it."""

class FrameDispatchUnknown(OSError):
    """A frame write request got no hub verdict; it may have been written."""

class UartSocketTransport:
    """Raw UART stream client for the local fan-out hub."""

    def __init__(self, socket_path: str, timeout: float) -> None:
        try:
            from . import ipc
        except ImportError:
            import ipc
        self._ipc = ipc
        self._socket_path = socket_path
        self._timeout = timeout
        self._socket = ipc.connect(socket_path, timeout)
        self._frame_control = True
        self._dtr_state: bool | None = None
        self._rts_state: bool | None = None

    def write(self, frame: bytes) -> None:
        self._socket.sendall(frame)

    def set_modem_lines(self, dtr: bool | None = None, rts: bool | None = None) -> None:
        response = self._control({"action": "lines", "dtr": dtr, "rts": rts})
        self._dtr_state = response.get("dtr", self._dtr_state)
        self._rts_state = response.get("rts", self._rts_state)

    def get_modem_lines(self) -> tuple[bool, bool]:
        response = self._control({"action": "get_lines"})
        self._dtr_state = response.get("dtr", self._dtr_state)
        self._rts_state = response.get("rts", self._rts_state)
        if self._dtr_state is None or self._rts_state is None:
            raise OSError("hub did not return DTR/RTS state")
        return bool(self._dtr_state), bool(self._rts_state)

    def hard_reset(self) -> None:
        response = self._control({"action": "reset"})
        self._dtr_state = response.get("dtr", self._dtr_state)
        self._rts_state = response.get("rts", self._rts_state)

    def enter_bootloader(self) -> None:
        response = self._control({"action": "bootloader"})
        self._dtr_state = response.get("dtr", self._dtr_state)
        self._rts_state = response.get("rts", self._rts_state)

    def write_frame(self, frame: bytes) -> None:
        """Write one control frame atomically through the hub when supported.

        Hubs without `write_frame` (legacy Python/Rust) reject the unknown
        action before touching the UART, so falling back cannot send twice.
        Other failures raise `OSError`; a `FrameDispatchUnknown` subclass
        means the hub may already have written the frame.
        """
        if self._frame_control:
            try:
                self._control({"action": "write_frame",
                               "data": base64.b64encode(frame).decode("ascii")})
                return
            except FrameDispatchUnknown:
                raise
            except HubRefused as exc:
                if "unknown control action" not in str(exc):
                    raise
                self._frame_control = False
            except (OSError, ValueError) as exc:
                # The request reached the hub but no verdict came back.
                raise FrameDispatchUnknown(str(exc)) from exc
        self.write(frame)

    def _control(self, request: dict[str, Any]) -> dict[str, Any]:
        # Control actions may wait behind one bounded UART read in the hub.
        timeout = max(self._timeout, 1.0)
        control = self._ipc.connect(f"{self._socket_path}.ctl", timeout)
        try:
            control.sendall(json.dumps(request, separators=(",", ":")).encode("utf-8") + b"\n")
            response = json.loads(self._ipc.read_line(control, 65536, timeout).decode("utf-8"))
        finally:
            control.close()
        if not response.get("ok"):
            error = str(response.get("error", "hub control failed"))
            if response.get("dispatch") == "unknown":
                raise FrameDispatchUnknown(error)
            raise HubRefused(error)
        return response

    def read(self, size: int = 4096) -> bytes:
        try:
            data = self._socket.recv(size)
        except socket.timeout:
            return b""
        if not data:
            raise OSError("UART hub data socket closed")
        return data

    def close(self) -> None:
        self._socket.close()


def open_uart_transport(port: str, baud: int,
                        timeout: float) -> SerialTransport | NetworkTransport | UartSocketTransport:
    """Open a physical UART, a tcp/udp endpoint, or a local hub endpoint (`hub://<path>`)."""
    if port.startswith(HUB_SCHEME):
        return UartSocketTransport(port[len(HUB_SCHEME):], timeout)
    return open_device_transport(port, baud, timeout)


def discover_serial_ports() -> list[str]:
    """Return local serial devices, preferring pyserial's descriptive scan."""
    try:
        from serial.tools import list_ports  # type: ignore
    except ImportError:
        return sorted(str(path) for pattern in ("/dev/ttyACM*", "/dev/ttyUSB*")
                      for path in Path("/").glob(pattern[1:]))
    return [port.device for port in list_ports.comports()]


def _sysfs_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError):
        return ""


def serial_port_details(device: str, description: str = "", manufacturer: str = "",
                        interface: str = "", *, sysfs_root: Path = Path("/sys/class/tty")) -> dict[str, str] | None:
    """Inspect metadata only: opening a UART to probe it can reset its board."""
    if os.name == "posix":
        try:
            if not stat.S_ISCHR(Path(device).stat().st_mode):
                return None
        except OSError:
            return None
        if not os.access(device, os.R_OK | os.W_OK):
            return None
    tty = sysfs_root / Path(device).name
    if sys.platform.startswith("linux"):
        # PORT_UNKNOWN (0) identifies the unconfigured serial8250 slots that
        # otherwise appear as dozens of selectable ttyS devices.
        uart_type = _sysfs_text(tty / "type")
        if uart_type == "0":
            return None
        parent = (tty / "device").resolve()
        if not uart_type and "serial8250" in str(parent):
            return None
        interface = interface or _sysfs_text(parent / "interface")
        number = _sysfs_text(parent / "bInterfaceNumber")
        if not interface and number:
            interface = f"Interface {number}"
        for ancestor in (parent, *list(parent.parents)[:4]):
            product = _sysfs_text(ancestor / "product")
            if product:
                if not description or description == "n/a":
                    description = product
                manufacturer = manufacturer or _sysfs_text(ancestor / "manufacturer")
                break
    description = description if description and description != "n/a" else "Serial port"
    parts = [description]
    for item in (manufacturer, interface):
        if item and item.lower() not in " ".join(parts).lower():
            parts.append(item)
    name = " - ".join(parts)
    return {"device": device, "description": name, "label": f"{device} - {name}"}


def discover_serial_port_details() -> list[dict[str, str]]:
    """Accessible, configured serial candidates with names; never claim a port.

    Enumeration cannot guarantee that another program has not reserved a port.
    In particular, hub-owned ports remain candidates for shared connections.
    """
    try:
        from serial.tools import list_ports  # type: ignore
    except ImportError:
        candidates = [(device, "", "", "") for device in discover_serial_ports()]
    else:
        candidates = [(port.device, port.description, port.manufacturer, port.interface)
                      for port in list_ports.comports()]
    result = {}
    for device, description, manufacturer, interface in candidates:
        details = serial_port_details(device, description, manufacturer, interface)
        if details is not None:
            result[device] = details
    return [result[device] for device in sorted(result)]


class UartReader:
    """Classify complete COBS frames and ordinary console log lines."""

    def __init__(self, transport: SerialTransport, frames: bool = True) -> None:
        self.transport = transport
        # frames=False is for generic/Linux consoles that never speak the
        # control protocol: every newline ends a log line, even one holding
        # ANSI colour codes or other control bytes.
        self.frames = frames
        self._pending = bytearray()

    @staticmethod
    def _is_text(value: bytes) -> bool:
        try:
            text = value.decode("utf-8")
        except UnicodeDecodeError:
            return False
        return all(char in "\t\r\n" or ord(char) >= 32 for char in text)

    def poll(self) -> list[tuple[str, Any]]:
        return self.feed(self.transport.read())

    def feed(self, chunk: bytes) -> list[tuple[str, Any]]:
        """Classify bytes already read from the transport."""
        records: list[tuple[str, Any]] = []
        if chunk:
            self._pending.extend(chunk)

        if not self.frames:
            *lines, rest = self._pending.split(b"\n")
            self._pending = bytearray(rest[-MAX_ENCODED_FRAME * 4:])
            for line in lines:
                line = line.rstrip(b"\r")
                if line:
                    records.append(("log", line.decode("utf-8", errors="replace")))
            return records

        while True:
            try:
                delimiter = self._pending.index(0)
            except ValueError:
                break
            segment = bytes(self._pending[:delimiter])
            del self._pending[: delimiter + 1]
            if not segment:
                continue
            self._parse_segment(segment, records)

        # Console logs are newline-delimited and do not contain the frame delimiter.
        while True:
            try:
                newline = self._pending.index(10)
            except ValueError:
                break
            line = bytes(self._pending[:newline])
            if not self._is_text(line):
                break
            line = line.rstrip(b"\r")
            del self._pending[: newline + 1]
            if line:
                records.append(("log", line.decode("utf-8", errors="replace")))
        # No frame is longer than MAX_ENCODED_FRAME, so a longer undelimited
        # run is noise (wrong baud, binary data); keep memory bounded.
        if len(self._pending) > PENDING_LIMIT:
            dropped = bytes(self._pending[:-MAX_ENCODED_FRAME])
            del self._pending[:-MAX_ENCODED_FRAME]
            text = dropped[-MAX_ENCODED_FRAME:].decode("utf-8", errors="replace")
            records.append(("log", f"[truncated {len(dropped)} undelimited bytes] {text}"))
        return records

    @classmethod
    def _append_console(cls, value: bytes, records: list[tuple[str, Any]]) -> None:
        """Keep a damaged console line from blocking later binary frames."""
        for line in value.split(b"\n"):
            line = line.rstrip(b"\r")
            if line:
                records.append(("log", line.decode("utf-8", errors="replace")))

    @classmethod
    def _parse_segment(cls, segment: bytes, records: list[tuple[str, Any]]) -> None:
        """Parse a NUL-delimited UART segment containing logs and/or one frame.

        Console writes and control-frame writes can overlap on UART0. A valid
        frame still has a CRC and is recoverable when a log prefix was damaged
        by an interleaved byte, so scan for a valid frame suffix before treating
        the complete segment as console text.
        """
        # An encoded frame is at most MAX_ENCODED_FRAME bytes, so only its
        # tail window can hold one; try the offset right after the last log
        # newline first since that is where an undamaged frame starts.
        window = max(0, len(segment) - MAX_ENCODED_FRAME)
        after_newline = segment.rfind(b"\n", window) + 1
        starts = range(window, len(segment))
        if after_newline > window:
            starts = [after_newline, *(i for i in starts if i != after_newline)]
        for start in starts:
            try:
                frame_type, flags, sequence, payload = decode_frame(segment[start:])
            except ValueError:
                continue
            if start:
                cls._append_console(segment[:start], records)
            try:
                message: Any = json.loads(payload.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                message = payload.hex()
            records.append(("frame", (frame_type, flags, sequence, message)))
            return
        cls._append_console(segment, records)


def print_record(record: tuple[str, Any]) -> None:
    kind, value = record
    if kind == "log":
        print(value, flush=True)
        return
    frame_type, _flags, sequence, message = value
    name = FRAME_NAMES.get(frame_type, f"type-{frame_type}")
    print(f"[{name} seq={sequence}] {json.dumps(message, ensure_ascii=False)}", flush=True)


def send_frame(transport: Any, frame: bytes) -> None:
    """Send an encoded control frame, atomically when the transport can."""
    write_frame = getattr(transport, "write_frame", None)
    (write_frame or transport.write)(frame)

def send_hello(transport: SerialTransport, sequence: int, client_id: str) -> None:
    message = {
        "type": "hello",
        "protocol": "serial-deck-control",
        "version": PROTOCOL_VERSION,
        "client_id": client_id,
    }
    send_frame(transport, encode_json_frame(FRAME_HELLO, sequence, message))


def wait_for_response(reader: UartReader, request_sequence: int, timeout: float,
                      accepted_types: tuple[int, ...] = (FRAME_RESPONSE, FRAME_ERROR)) -> int:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for record in reader.poll():
            print_record(record)
            if record[0] != "frame":
                continue
            frame_type, _flags, sequence, _message = record[1]
            if sequence == request_sequence and frame_type in accepted_types:
                return 0 if frame_type != FRAME_ERROR else 1
    print(f"timeout waiting for response sequence {request_sequence}", file=sys.stderr)
    return 2


def monitor(transport: SerialTransport, reader: UartReader, sequence: int, client_id: str,
            hello: bool = False) -> int:
    if hello:
        send_hello(transport, sequence, client_id)
    try:
        while True:
            for record in reader.poll():
                print_record(record)
    except KeyboardInterrupt:
        return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="UART control and log monitor")
    parser.add_argument("--port", required=True, help="device selected through the shared hub, or a hub:// channel")
    parser.add_argument("--hub-socket", default=None, help="shared hub endpoint path (default: per-user hub)")
    parser.add_argument("--baud", type=int, default=2000000)
    parser.add_argument("--timeout", type=float, default=0.1, help="serial read timeout in seconds")
    parser.add_argument("--response-timeout", type=float, default=5.0)
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    monitor_parser = subparsers.add_parser("monitor", help="stream console output (and control frames with --control)")
    monitor_parser.add_argument("--control", action="store_true",
                                help="send HELLO and decode control-protocol frames")
    subparsers.add_parser("hello", help="request firmware UART capabilities")
    subparsers.add_parser("reset", help="pulse RTS/EN to reset the board")
    subparsers.add_parser("bootloader", help="toggle DTR/RTS into ROM download mode")

    query = subparsers.add_parser("query", help="read a device snapshot")
    query.add_argument("kind", choices=("capabilities", "identity", "fsm", "snapshot"))

    button = subparsers.add_parser("button", help="send a logical button action")
    button.add_argument("button", choices=("HOME", "LEFT", "RIGHT", "ENTER", "ONOFF"))
    button.add_argument("action", choices=("press", "release", "long_press"))
    subparsers.add_parser("show-info", help="show the info screen")
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        from .ipc import configure_console_streams
    except ImportError:
        from ipc import configure_console_streams
    configure_console_streams()
    args = build_parser().parse_args(argv)
    manager = None
    if args.port.startswith(HUB_SCHEME):
        endpoint = args.port
    else:
        try:
            from .hub_client import HubProcessManager
        except ImportError:
            from hub_client import HubProcessManager
        manager = (HubProcessManager(socket_path=args.hub_socket) if args.hub_socket
                   else HubProcessManager())
        manager.ensure_started()
        manager.claim_port(args.port, args.baud)
        endpoint = manager.endpoint
    transport = open_uart_transport(endpoint, args.baud, args.timeout)
    reader = UartReader(transport, frames=args.subcommand != "monitor" or args.control)
    sequence = 1
    client_id = f"serial-deck-cli-{uuid.uuid4().hex[:8]}"
    try:
        if args.subcommand == "monitor":
            return monitor(transport, reader, sequence, client_id, args.control)
        if args.subcommand == "reset":
            transport.hard_reset()
            return 0
        if args.subcommand == "bootloader":
            transport.enter_bootloader()
            return 0
        if args.subcommand == "hello":
            send_hello(transport, sequence, client_id)
            return wait_for_response(reader, sequence, args.response_timeout, (FRAME_HELLO, FRAME_ERROR))

        if args.subcommand == "query":
            request = make_request("query", {"kind": args.kind})
        elif args.subcommand == "button":
            request = make_request("input.button", {"button": args.button, "action": args.action})
        else:
            request = make_request("ui.show_info", {})
        send_frame(transport, encode_json_frame(FRAME_COMMAND, sequence, request))
        return wait_for_response(reader, sequence, args.response_timeout)
    finally:
        transport.close()
        if manager is not None:
            manager.stop()


if __name__ == "__main__":
    raise SystemExit(main())
