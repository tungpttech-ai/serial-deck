#!/usr/bin/env python3
"""Per-port UART engine and entrypoint for the shared multi-port daemon."""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import signal
import socket
import sys
import threading
import time
from pathlib import Path

try:
    from . import ipc
    from .flash import build_flash_command, flash_build_in_process
    from .uart_client import (
        MAX_ENCODED_FRAME, NetworkTransport, SerialTransport, discover_serial_ports,
        is_device_port, is_network_port, open_device_transport, port_identity)
except ImportError:
    import ipc
    from flash import build_flash_command, flash_build_in_process
    from uart_client import (
        MAX_ENCODED_FRAME, NetworkTransport, SerialTransport, discover_serial_ports,
        is_device_port, is_network_port, open_device_transport, port_identity)


ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
FLASH_PERCENT_RE = re.compile(r"(?:\(|\s)(\d{1,3}(?:\.\d+)?)\s*%\)?")
FLASH_STEP_RE = re.compile(
    r"^(Connecting|Erasing|Writing|Verifying|Leaving|Hash of data verified|Hard resetting)",
    re.IGNORECASE,
)
# Additive capabilities advertised in status; old clients ignore the key.
HUB_FEATURES = ("write_frame",)


class UartHub:
    def __init__(self, port: str | None, baud: int, socket_path: str) -> None:
        self.port = port or ""
        self.baud = baud
        self.serial: SerialTransport | NetworkTransport | None = (
            open_device_transport(self.port, baud, 0.1) if self.port else None
        )
        self.socket_path = Path(socket_path).expanduser()
        self.control_path = Path(f"{self.socket_path}.ctl")
        self.server: ipc.Listener | None = None
        self.control_server: ipc.Listener | None = None
        self.clients: set[socket.socket] = set()
        self.clients_lock = threading.Lock()
        self.status_clients: set[socket.socket] = set()
        self.status_clients_lock = threading.Lock()
        self.serial_lock = threading.Lock()
        self.serial_read_lock = threading.Lock()
        self.status_lock = threading.Lock()
        self.revision = 0
        self.flashing = False
        self.flash_id = 0
        self.flash_progress = 0
        self.flash_step = "Idle"
        self.flash_line = ""
        self.flash_build_dir = ""
        self.flash_baud = 0
        self.flash_exit_code: int | None = None
        self.flash_error = ""
        self.stop = threading.Event()

    def start(self) -> None:
        ipc.private_dir(self.socket_path.parent)
        self.server = ipc.listen(self.socket_path, 8)
        try:
            self.control_server = ipc.listen(self.control_path, 4)
        except Exception:
            self.server.close()
            raise
        threading.Thread(target=self._accept_loop, daemon=True).start()
        threading.Thread(target=self._control_loop, daemon=True).start()
        owner = self.serial_port or "idle"
        print(f"UART hub: {self.socket_path} <- {owner}", flush=True)

    @property
    def serial_port(self) -> str:
        return self.port

    def _status_payload(self) -> dict[str, object]:
        with self.clients_lock:
            client_count = len(self.clients)
        with self.status_lock:
            flash = {
                "active": self.flashing,
                "id": self.flash_id,
                "build_dir": self.flash_build_dir,
                "baud": self.flash_baud,
                "progress": self.flash_progress,
                "step": self.flash_step,
                "line": self.flash_line,
                "exit_code": self.flash_exit_code,
                "error": self.flash_error,
            }
            revision = self.revision
            flashing = self.flashing
        ready = self.serial is not None
        return {
            "ok": True,
            "event": "status",
            "revision": revision,
            "state": "flashing" if flashing else ("ready" if ready else "idle"),
            "port": self.port or None,
            "baud": self.baud,
            "client_count": client_count,
            "flash": flash,
            "features": list(HUB_FEATURES),
        }

    def _publish_status(self) -> None:
        with self.status_lock:
            self.revision += 1
        payload = json.dumps(self._status_payload(), separators=(",", ":")).encode("utf-8") + b"\n"
        dead: list[socket.socket] = []
        with self.status_clients_lock:
            for client in self.status_clients:
                try:
                    if ipc.send_nowait(client, payload) != len(payload):
                        dead.append(client)
                except (BlockingIOError, OSError):
                    dead.append(client)
            for client in dead:
                self.status_clients.discard(client)
                try:
                    client.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                client.close()

    def _set_flash_output(self, line: str) -> None:
        line = ANSI_ESCAPE_RE.sub("", line).strip()
        percent_match = FLASH_PERCENT_RE.search(line)
        step_match = FLASH_STEP_RE.search(line.strip())
        with self.status_lock:
            if percent_match is not None:
                self.flash_progress = max(0.0, min(100.0, float(percent_match.group(1))))
            if step_match is not None:
                self.flash_step = step_match.group(1)
            elif "write-flash" in line:
                self.flash_step = "Initializing"
            self.flash_line = line
        self._publish_status()

    def _close_serial_for_flash(self) -> tuple[str, int]:
        with self.serial_lock:
            if self.serial is None:
                raise RuntimeError("UART hub has no claimed port")
            if is_network_port(self.port):
                raise RuntimeError(f"flash needs a physical UART, not {self.port}")
            serial = self.serial
            self.serial = None
            port = self.port
            baud = self.baud
        with self.serial_read_lock:
            serial.close()
        return port, baud

    def _restore_serial_after_flash(self, port: str, baud: int) -> None:
        deadline = time.monotonic() + 5.0
        last_error: Exception | None = None
        while time.monotonic() < deadline and not self.stop.is_set():
            try:
                serial = SerialTransport(port, baud, 0.1)
            except (OSError, RuntimeError, ValueError) as exc:
                last_error = exc
                time.sleep(0.2)
                continue
            with self.serial_lock:
                self.serial = serial
            return
        raise RuntimeError(f"failed to reopen {port} after flash: {last_error}")

    def _flash_worker(self, build_dir: str, flash_baud: int) -> None:
        port = ""
        monitor_baud = self.baud
        exit_code = 1
        error = ""
        try:
            port, monitor_baud = self._close_serial_for_flash()
            exit_code = flash_build_in_process(
                port, build_dir, flash_baud, output=self._set_flash_output)
        except Exception as exc:
            error = str(exc)
        finally:
            if port:
                try:
                    self._restore_serial_after_flash(port, monitor_baud)
                except Exception as exc:
                    reopen_error = str(exc)
                    error = f"{error}; {reopen_error}" if error else reopen_error
                    exit_code = exit_code or 1
            with self.status_lock:
                self.flashing = False
                self.flash_exit_code = exit_code
                self.flash_error = error
                if error:
                    self.flash_step = f"Flash error: {error}"
                elif exit_code == 0:
                    self.flash_progress = 100
                    self.flash_step = "Flash completed successfully"
                else:
                    self.flash_step = f"Flash failed (exit {exit_code})"
            self._publish_status()

    def _accept_loop(self) -> None:
        assert self.server is not None
        self.server.settimeout(0.5)
        while not self.stop.is_set():
            try:
                client, _ = self.server.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with self.serial_lock:
                available = self.serial is not None
            if not available:
                client.close()
                continue
            ipc.make_nonblocking(client)
            with self.clients_lock:
                self.clients.add(client)
            self._publish_status()
            threading.Thread(target=self._client_loop, args=(client,), daemon=True).start()

    def _client_loop(self, client: socket.socket) -> None:
        try:
            while not self.stop.is_set():
                data = ipc.recv_ready(client, 4096, self.stop)
                if not data:
                    break
                with self.serial_lock:
                    serial = self.serial
                if serial is None:
                    with self.status_lock:
                        flashing = self.flashing
                    if flashing:
                        continue
                    raise OSError("UART hub has no claimed port")
                try:
                    with self.serial_read_lock:
                        serial.write(data)
                except OSError:
                    with self.serial_lock:
                        if self.serial is serial:
                            self.serial = None
                        raise OSError("UART hub has no claimed port")
        except OSError:
            pass
        finally:
            with self.clients_lock:
                self.clients.discard(client)
            client.close()
            self._publish_status()

    def _control_loop(self) -> None:
        assert self.control_server is not None
        self.control_server.settimeout(0.5)
        while not self.stop.is_set():
            try:
                client, _ = self.control_server.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(target=self._handle_control, args=(client,), daemon=True).start()

    def _handle_control(self, client: socket.socket, request: dict | None = None) -> None:
        response: dict[str, object]
        try:
            if request is None:
                request = json.loads(ipc.read_line(client, 65536, timeout=2.0).decode("utf-8"))
            action = request.get("action")
            if action == "subscribe":
                client.settimeout(2.0)
                client.sendall(
                    json.dumps(self._status_payload(), separators=(",", ":")).encode("utf-8")
                    + b"\n"
                )
                ipc.make_nonblocking(client)
                with self.status_clients_lock:
                    self.status_clients.add(client)
                threading.Thread(target=self._watch_subscription, args=(client,), daemon=True).start()
                return
            if action == "status":
                response = self._status_payload()
            elif action == "scan":
                response = {
                    "ok": True,
                    "ports": discover_serial_ports(),
                    "hub_port": self.serial_port or None,
                }
            elif action == "flash_preview":
                build_dir = request.get("build_dir")
                flash_baud = request.get("flash_baud", 3000000)
                if not isinstance(build_dir, str) or not build_dir:
                    raise ValueError("flash_preview requires a build directory")
                if not isinstance(flash_baud, int) or isinstance(flash_baud, bool) or flash_baud <= 0:
                    raise ValueError("flash_preview requires a positive baud rate")
                with self.serial_lock:
                    if self.serial is None:
                        raise RuntimeError("UART hub has no claimed port")
                    port = self.port
                if is_network_port(port):
                    raise RuntimeError(f"flash needs a physical UART, not {port}")
                response = {
                    "ok": True,
                    "port": port,
                    "command": build_flash_command(port, build_dir, flash_baud),
                }
            elif action == "flash":
                build_dir = request.get("build_dir")
                flash_baud = request.get("flash_baud", 3000000)
                if not isinstance(build_dir, str) or not build_dir:
                    raise ValueError("flash requires a build directory")
                if not isinstance(flash_baud, int) or isinstance(flash_baud, bool) or flash_baud <= 0:
                    raise ValueError("flash requires a positive baud rate")
                with self.status_lock:
                    if self.flashing:
                        raise RuntimeError("flash already in progress")
                with self.serial_lock:
                    if self.serial is None:
                        raise RuntimeError("UART hub has no claimed port")
                    port = self.port
                if is_network_port(port):
                    raise RuntimeError(f"flash needs a physical UART, not {port}")
                command = build_flash_command(port, build_dir, flash_baud)
                with self.status_lock:
                    self.flashing = True
                    self.flash_id += 1
                    self.flash_progress = 0
                    self.flash_step = "Starting flash"
                    self.flash_line = " ".join(command)
                    self.flash_build_dir = str(Path(build_dir).expanduser().resolve())
                    self.flash_baud = flash_baud
                    self.flash_exit_code = None
                    self.flash_error = ""
                    flash_id = self.flash_id
                self._publish_status()
                threading.Thread(
                    target=self._flash_worker,
                    args=(build_dir, flash_baud),
                    daemon=True,
                ).start()
                response = {
                    "ok": True,
                    "accepted": True,
                    "flash_id": flash_id,
                    "port": port,
                }
            else:
                with self.serial_lock:
                    if action == "claim":
                        if self.flashing:
                            raise RuntimeError("cannot claim while flash is in progress")
                        port = request.get("port")
                        baud = request.get("baud", self.baud)
                        if not isinstance(port, str) or not (
                                is_device_port(port) or is_network_port(port)):
                            raise ValueError("claim requires a UART path or tcp:// / udp:// endpoint")
                        if not isinstance(baud, int) or isinstance(baud, bool) or baud <= 0:
                            raise ValueError("claim requires a positive baud rate")
                        if self.serial is not None:
                            if self.port == port and self.baud == baud:
                                response = {
                                    "ok": True,
                                    "claimed": False,
                                    "port": self.port,
                                    "baud": self.baud,
                                }
                            else:
                                raise RuntimeError(
                                    f"UART already claimed: {self.port} at {self.baud}"
                                )
                        else:
                            if not is_network_port(port) and port_identity(port) not in {
                                    port_identity(p) for p in discover_serial_ports()}:
                                raise RuntimeError(f"UART port is not available: {port}")
                            try:
                                self.serial = open_device_transport(port, baud, 0.1)
                            except OSError as exc:
                                raise RuntimeError(f"cannot open {port}: {exc}") from exc
                            self.port = port
                            self.baud = baud
                            response = {
                                "ok": True,
                                "claimed": True,
                                "port": self.port,
                                "baud": self.baud,
                            }
                        self._publish_status()
                    elif action == "release":
                        with self.status_lock:
                            flashing = self.flashing
                        if flashing:
                            response = {"ok": True, "released": False, "flash_in_progress": True}
                            self._publish_status()
                            client.sendall(json.dumps(response).encode("utf-8") + b"\n")
                            client.close()
                            return
                        if self.serial is None:
                            response = {"ok": True, "released": False}
                        else:
                            with self.clients_lock:
                                if self.clients:
                                    raise RuntimeError("cannot release while clients are connected")
                            with self.serial_read_lock:
                                self.serial.close()
                            self.serial = None
                            self.port = ""
                            response = {"ok": True, "released": True}
                        self._publish_status()
                    elif action == "reset":
                        if self.serial is None:
                            raise RuntimeError("UART hub has no claimed port")
                        self.serial.hard_reset()
                        dtr, rts = self.serial.get_modem_lines()
                        response = {"ok": True, "dtr": dtr, "rts": rts}
                    elif action == "bootloader":
                        if self.serial is None:
                            raise RuntimeError("UART hub has no claimed port")
                        self.serial.enter_bootloader()
                        dtr, rts = self.serial.get_modem_lines()
                        response = {"ok": True, "dtr": dtr, "rts": rts}
                    elif action == "lines":
                        if self.serial is None:
                            raise RuntimeError("UART hub has no claimed port")
                        self.serial.set_modem_lines(request.get("dtr"), request.get("rts"))
                        dtr, rts = self.serial.get_modem_lines()
                        response = {"ok": True, "dtr": dtr, "rts": rts}
                    elif action == "write_frame":
                        # One whole control frame per write. Data-socket bytes
                        # arrive in arbitrary recv() chunks, so frames from two
                        # clients could otherwise interleave on the UART.
                        with self.status_lock:
                            flashing = self.flashing
                        if flashing:
                            raise RuntimeError("cannot write while flash is in progress")
                        if self.serial is None:
                            raise RuntimeError("UART hub has no claimed port")
                        try:
                            frame = base64.b64decode(str(request.get("data", "")), validate=True)
                        except ValueError as exc:
                            raise ValueError("write_frame requires base64 data") from exc
                        if (not frame or len(frame) > MAX_ENCODED_FRAME
                                or frame.find(0) != len(frame) - 1):
                            raise ValueError("write_frame requires one NUL-terminated frame")
                        try:
                            with self.serial_read_lock:
                                self.serial.write(frame)
                        except (OSError, ValueError) as exc:
                            # Part of the frame may already be on the wire.
                            response = {"ok": False, "error": f"UART write failed: {exc}",
                                        "dispatch": "unknown"}
                        else:
                            response = {"ok": True, "bytes": len(frame)}
                    elif action == "break":
                        if self.serial is None:
                            raise RuntimeError("UART hub has no claimed port")
                        with self.serial_read_lock:
                            self.serial.send_break()
                        response = {"ok": True}
                    elif action == "get_lines":
                        if self.serial is None:
                            raise RuntimeError("UART hub has no claimed port")
                        dtr, rts = self.serial.get_modem_lines()
                        response = {"ok": True, "dtr": dtr, "rts": rts}
                        client.sendall(json.dumps(response).encode("utf-8") + b"\n")
                        client.close()
                        return
                    else:
                        raise ValueError(f"unknown control action: {action}")
        except Exception as exc:
            response = {"ok": False, "error": str(exc)}
        try:
            client.sendall(json.dumps(response).encode("utf-8") + b"\n")
        finally:
            client.close()

    def _watch_subscription(self, client: socket.socket) -> None:
        try:
            while not self.stop.is_set() and ipc.recv_ready(client, 1, self.stop):
                pass
        except OSError:
            pass
        finally:
            with self.status_clients_lock:
                self.status_clients.discard(client)
            client.close()

    def broadcast(self, data: bytes) -> None:
        dead: list[socket.socket] = []
        with self.clients_lock:
            for client in self.clients:
                try:
                    if ipc.send_nowait(client, data) != len(data):
                        dead.append(client)
                except (BlockingIOError, OSError):
                    dead.append(client)
            for client in dead:
                self.clients.discard(client)
                try:
                    client.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                client.close()

    def _handle_serial_lost(self, serial: SerialTransport | NetworkTransport, exc: OSError) -> None:
        """React to a physical UART read failure (e.g. USB unplugged).

        Drops the dead serial object so the port can be reclaimed, and
        proactively closes every fan-out client so their reader threads see
        an immediate EOF instead of silently stalling with no more data.
        """
        with self.serial_lock:
            if self.serial is not serial:
                return
            self.serial = None
            lost_port = self.port
            self.port = ""
        print(f"UART hub: lost {lost_port}: {exc}", flush=True)
        try:
            with self.serial_read_lock:
                serial.close()
        except OSError:
            pass
        with self.clients_lock:
            dead_clients = list(self.clients)
            self.clients.clear()
        for client in dead_clients:
            # shutdown() first: close() alone does not wake the client's
            # _client_loop thread blocked in recv(), so no FIN would be sent.
            try:
                client.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            client.close()
        self._publish_status()

    def run(self) -> None:
        self.start()
        self.read_forever()

    def read_forever(self) -> None:
        try:
            while not self.stop.is_set():
                with self.serial_lock:
                    serial = self.serial
                if serial is None:
                    if self.stop.wait(0.1):
                        break
                    continue
                try:
                    with self.serial_read_lock:
                        data = serial.read()
                except OSError as exc:
                    self._handle_serial_lost(serial, exc)
                    continue
                if data:
                    self.broadcast(data)
                else:
                    # An idle read just released the lock; let a waiting writer,
                    # retime or flash take it before the next bounded read.
                    time.sleep(0.001)
        except KeyboardInterrupt:
            pass
        finally:
            self.close()

    def close(self) -> None:
        self.stop.set()
        if self.server is not None:
            self.server.close()
        if self.control_server is not None:
            self.control_server.close()
        with self.clients_lock:
            for client in self.clients:
                try:
                    client.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                client.close()
            self.clients.clear()
        with self.status_clients_lock:
            for client in self.status_clients:
                try:
                    client.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                client.close()
            self.status_clients.clear()
        with self.serial_lock:
            serial = self.serial
            self.serial = None
        if serial is not None:
            with self.serial_read_lock:
                serial.close()


# `hub --status` / `hub --shutdown` exit codes, for installers and scripts.
EXIT_OK, EXIT_NOT_RUNNING, EXIT_REFUSED, EXIT_TIMEOUT = 0, 3, 4, 5


def main(argv: list[str] | None = None) -> int:
    ipc.configure_console_streams()
    parser = argparse.ArgumentParser(description="UART fan-out hub")
    parser.add_argument("--port", help="optional initial UART path or tcp:// / udp:// endpoint claim")
    parser.add_argument("--baud", type=int, default=2000000)
    parser.add_argument("--socket", default=ipc.default_hub_path())
    parser.add_argument("--single-port", action="store_true", help="legacy protocol for conformance testing")
    parser.add_argument("--port-idle-timeout", type=float, default=5.0,
                        help="close UART channels with no data clients after this many seconds")
    maintenance = parser.add_mutually_exclusive_group()
    maintenance.add_argument("--status", action="store_true", help="show the running daemon and its channels")
    maintenance.add_argument("--shutdown", action="store_true", help="stop daemon only when no data clients or flash remain")
    args = parser.parse_args(argv)

    if args.status or args.shutdown:
        try:
            from .hub_client import HubProcessManager
        except ImportError:
            from hub_client import HubProcessManager
        manager = HubProcessManager(socket_path=args.socket)
        if not manager.socket_ready():
            print(f"no hub is running at {args.socket}", file=sys.stderr)
            return EXIT_NOT_RUNNING
        if not args.shutdown:
            print(json.dumps(manager.get_status(), indent=2))
            return EXIT_OK
        try:
            pid = manager.shutdown()
        except TimeoutError as exc:
            print(f"hub did not stop: {exc}", file=sys.stderr)
            return EXIT_TIMEOUT
        except (OSError, RuntimeError) as exc:
            if not manager.socket_ready():
                return EXIT_OK  # it went away while we asked
            print(f"hub refused to stop: {exc}", file=sys.stderr)
            return EXIT_REFUSED
        print(f"hub stopped (pid {pid})" if pid else "hub stopped")
        return EXIT_OK

    # Clean shutdown (sockets unlinked, UART closed) on kill / terminal hang-up,
    # and on SIGINT even when it was inherited as ignored from a background job.
    def _request_shutdown(signum: int, _frame: object) -> None:
        raise KeyboardInterrupt(f"signal {signum}")

    for name in ("SIGINT", "SIGTERM", "SIGHUP"):
        if hasattr(signal, name):
            signal.signal(getattr(signal, name), _request_shutdown)
    if args.single_port:
        UartHub(args.port, args.baud, args.socket).run()
    else:
        try:
            from .service import MultiPortHub
        except ImportError:
            from service import MultiPortHub
        MultiPortHub(args.socket, args.baud, args.port_idle_timeout).run(args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
