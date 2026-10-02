"""One daemon, multiple UART channels. Channels are threads, never processes."""

from __future__ import annotations

import hashlib
import json
import os
import socket
import threading
import time
import uuid
from contextlib import ExitStack
from pathlib import Path

try:
    from . import ipc
    from .hub import UartHub
    from .uart_client import is_device_port, is_network_port, port_identity
except ImportError:
    import ipc
    from hub import UartHub
    from uart_client import is_device_port, is_network_port, port_identity


PROTOCOL = "serial-deck-multiport-v1"
# What a claim does when the port is live at another baud: keep the live
# baud (legacy default), refuse so the UI can ask, or retime every client.
BAUD_CONFLICT_POLICIES = ("join", "error", "retime")


class BaudConflict(RuntimeError):
    def __init__(self, details: dict) -> None:
        super().__init__(f"{details['port']} is open by {details['client_count']} client(s) "
                         f"at {details['live_baud']} baud")
        self.details = details


def device_key(port: str) -> str:
    return port_identity(port)


def read_request(client: socket.socket) -> dict:
    try:
        line = ipc.read_line(client, 65536, timeout=2.0)
    except ConnectionError:
        raise ValueError("incomplete control request") from None
    request = json.loads(line)
    if not isinstance(request, dict):
        raise ValueError("control request must be an object")
    return request


def reply(client: socket.socket, response: dict) -> None:
    try:
        client.sendall(json.dumps(response).encode() + b"\n")
    except OSError:
        pass
    finally:
        client.close()


class PortChannel(UartHub):
    def __init__(self, service: MultiPortHub, socket_path: str, baud: int) -> None:
        super().__init__(None, baud, socket_path)
        self.service = service
        self.gate = threading.RLock()
        self.last_used = time.monotonic()
        self.closed = False
        self.reader_thread: threading.Thread | None = None
        self._flash_owns_lock = False

    def start(self) -> None:
        super().start()
        self.reader_thread = threading.Thread(target=self.read_forever, daemon=True)
        self.reader_thread.start()

    def _status_payload(self) -> dict:
        return {**super()._status_payload(), "protocol": PROTOCOL,
                "service_socket": str(self.service.socket_path), "pid": os.getpid(),
                "channel_socket": str(self.socket_path)}

    def _handle_control(self, client: socket.socket, request: dict | None = None) -> None:
        try:
            request = request if request is not None else read_request(client)
            with self.gate:
                if self.closed or self.service.stop.is_set():
                    raise RuntimeError("UART channel expired; reconnect through the hub")
                action = request.get("action")
                if action == "claim":
                    raise RuntimeError("select ports through the shared hub control socket")
                if action == "flash":
                    # esptool redirects process-wide stdout/stderr. Serialize
                    # flashes while other channels continue reading/writing.
                    if not self.service.flash_lock.acquire(blocking=False):
                        raise RuntimeError("another port is flashing; retry after it finishes")
                    self._flash_owns_lock = True
                    try:
                        super()._handle_control(client, request)
                    finally:
                        if not self.flashing and self._flash_owns_lock:
                            self._flash_owns_lock = False
                            self.service.flash_lock.release()
                    return
                super()._handle_control(client, request)
        except Exception as exc:
            reply(client, {"ok": False, "error": str(exc)})

    def _flash_worker(self, build_dir: str, flash_baud: int) -> None:
        try:
            super()._flash_worker(build_dir, flash_baud)
        finally:
            self.last_used = time.monotonic()
            # The worker is the only releaser after an accepted flash.
            with self.gate:
                if self._flash_owns_lock:
                    self._flash_owns_lock = False
                    self.service.flash_lock.release()

    def attach(self, client: socket.socket) -> None:
        with self.gate:
            if (self.closed or self.service.stop.is_set() or self.service.closing
                    or (self.serial is None and not self.flashing)):
                client.close()
                return
            ipc.make_nonblocking(client)
            with self.clients_lock:
                self.clients.add(client)
            self.last_used = time.monotonic()
            self._publish_status()
            threading.Thread(target=self._client_loop, args=(client,), daemon=True).start()

    def _accept_loop(self) -> None:
        self.server.settimeout(0.5)
        while not self.stop.is_set():
            try:
                client, _ = self.server.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            self.attach(client)

    def claim(self, port: str, baud: int, on_conflict: str = "join") -> dict:
        with self.gate:
            if self.closed:
                raise RuntimeError("UART channel expired")
            if self.port and (self.serial is not None or self.flashing):
                self.last_used = time.monotonic()
                live = {"ok": True, "claimed": False, "port": self.port, "baud": self.baud}
                # A network bridge sets its own UART speed; the label is moot.
                if baud == self.baud or is_network_port(self.port):
                    return live
                # "join" keeps the live baud even with no data client: another
                # claimer may not have attached its data socket yet.
                if on_conflict == "join":
                    return live
                if self.flashing:
                    raise RuntimeError("cannot change baud while flash is in progress")
                with self.clients_lock:
                    client_count = len(self.clients)
                # A channel lingering until the idle reap has nobody to ask.
                if client_count and on_conflict == "error":
                    raise BaudConflict({"port": self.port, "live_baud": self.baud,
                                        "requested_baud": baud, "client_count": client_count})
                return {**live, "baud": self.retime(baud)}
            client, server = socket.socketpair()
            try:
                UartHub._handle_control(self, server, {"action": "claim", "port": port, "baud": baud})
                result = json.loads(ipc.read_line(client, 65536, timeout=5.0))
            finally:
                client.close()
            if not result.get("ok"):
                raise RuntimeError(result.get("error", "claim failed"))
            self.last_used = time.monotonic()
            return result

    def retime(self, baud: int) -> int:
        """Change the live UART baud in place; attached clients keep streaming."""
        with self.gate:
            with self.serial_lock:
                serial = self.serial
            if serial is None:
                raise RuntimeError("UART hub has no claimed port")
            try:
                with self.serial_read_lock:
                    serial.set_baud(baud)
            except (OSError, ValueError) as exc:
                raise RuntimeError(f"cannot set {self.port} to {baud} baud: {exc}") from exc
            print(f"UART hub: {self.port} baud {self.baud} -> {baud}", flush=True)
            self.baud = baud
        self._publish_status()
        return baud

    def close(self) -> None:
        with self.gate:
            if self.closed:
                return
            self.closed = True
            super().close()


class MultiPortHub(UartHub):
    def __init__(self, socket_path: str, baud: int = 2000000, idle_timeout: float = 5.0) -> None:
        if idle_timeout <= 0:
            raise ValueError("port idle timeout must be positive")
        super().__init__(None, baud, socket_path)
        self.channels: dict[str, PortChannel] = {}
        self.channels_lock = threading.RLock()
        self.flash_lock = threading.Lock()
        self.idle_timeout = idle_timeout
        digest = hashlib.sha256(str(self.socket_path.absolute()).encode()).hexdigest()[:12]
        self.channel_dir = ipc.channel_root() / digest
        self.lock: ipc.FileLock | None = None
        self.closing = False  # set once a shutdown is accepted; refuses new work

    def start(self) -> None:
        ipc.private_dir(self.socket_path.parent)
        lock = ipc.FileLock(str(self.socket_path) + ".lock")
        if not lock.acquire(blocking=False):
            raise RuntimeError(f"hub already running at {self.socket_path}")
        self.lock = lock
        try:
            # Do not remove the endpoints of a daemon that holds no lock.
            try:
                ipc.connect(self.control_path, timeout=0.2).close()
            except OSError:
                pass
            else:
                raise RuntimeError(f"hub already listening at {self.socket_path}")
            ipc.private_dir(self.channel_dir)
            # Only this daemon can hold the lock; these are leftovers from a crash.
            for path in self.channel_dir.glob("*.sock*"):
                ipc.remove(path)
            super().start()
            ipc.register(self.socket_path)
        except Exception:
            self.lock = None
            lock.release()
            raise

    def _status_payload(self) -> dict:
        with self.channels_lock:
            channels = [c._status_payload() for c in self.channels.values()]
        active = [s for s in channels if s["port"]]
        status = super()._status_payload()
        if len(active) == 1:
            status.update({key: active[0][key] for key in ("port", "baud", "state", "flash")})
        status.update(protocol=PROTOCOL, pid=os.getpid(), service_socket=str(self.socket_path),
                      channels=channels, client_count=sum(s["client_count"] for s in channels))
        status.pop("channel_socket", None)
        flashing = next((s for s in channels if s["flash"]["active"]), None)
        if flashing:
            status["flash"] = flashing["flash"]
            status["state"] = "flashing"
        elif active:
            status["state"] = "ready"
        return status

    def claim(self, port: str, baud: int, on_conflict: str = "join") -> dict:
        if (not isinstance(port, str) or not (is_device_port(port) or is_network_port(port))
                or type(baud) is not int or baud <= 0):
            raise ValueError("claim requires a device path/endpoint and positive baud")
        if on_conflict not in BAUD_CONFLICT_POLICIES:
            raise ValueError(f"on_baud_conflict must be one of {', '.join(BAUD_CONFLICT_POLICIES)}")
        key = device_key(port)
        with self.channels_lock:
            if self.stop.is_set() or self.closing:
                raise RuntimeError("hub is shutting down")
            channel = self.channels.get(key)
            created = channel is None
            if created:
                path = str(self.channel_dir / f"{uuid.uuid4().hex[:8]}.sock")
                channel = PortChannel(self, path, baud)
            try:
                result = channel.claim(key, baud, on_conflict)
                if created:
                    channel.start()
                    self.channels[key] = channel
            except Exception:
                if created:
                    channel.close()
                raise
            return {**result, "protocol": PROTOCOL, "pid": os.getpid(),
                    "service_socket": str(self.socket_path), "channel_socket": str(channel.socket_path)}

    def _handle_control(self, client: socket.socket, request: dict | None = None) -> None:
        try:
            request = request if request is not None else read_request(client)
            action = request.get("action")
            if action == "claim":
                try:
                    result = self.claim(request.get("port"), request.get("baud", self.baud),
                                        request.get("on_baud_conflict", "join"))
                except BaudConflict as exc:
                    reply(client, {"ok": False, "error": str(exc), "baud_conflict": exc.details})
                    return
                reply(client, result)
                self._publish_status()
                return
            if action == "shutdown":
                # One atomic check under every channel gate that also closes the
                # door: once it returns, claims and attaches are refused, so the
                # daemon is committed to exiting. The acknowledgment (with the pid
                # the caller waits for) is sent *before* the run loop may tear the
                # sockets down; only then is the stop released.
                self.request_shutdown(commit=False)
                reply(client, {"ok": True, "stopping": True, "pid": os.getpid()})
                self.stop.set()
                return
            if action in ("status", "scan", "subscribe") and "port" not in request:
                super()._handle_control(client, request)
                return
            with self.channels_lock:
                port = request.get("port")
                if port is None and len(self.channels) == 1:
                    channel = next(iter(self.channels.values()))
                elif isinstance(port, str):
                    channel = self.channels.get(device_key(port))
                else:
                    channel = None
                if channel is None:
                    raise RuntimeError("select a port; the hub has zero or multiple UART channels")
                channel._handle_control(client, request)
        except Exception as exc:
            reply(client, {"ok": False, "error": str(exc)})

    def request_shutdown(self, require_idle: bool = True, commit: bool = True) -> None:
        """Refuse while clients or a flash are active; otherwise stop accepting work.

        `commit=False` closes the door (`closing`: claims and attaches refused)
        without releasing the run loop yet, so a caller can answer first.
        """
        with self.channels_lock, ExitStack() as stack:
            for channel in self.channels.values():
                stack.enter_context(channel.gate)
            if any(c.flashing or (require_idle and c.clients) for c in self.channels.values()):
                raise RuntimeError("cannot shut down while clients or flash are active")
            self.closing = True
            if commit:
                self.stop.set()

    def _accept_loop(self) -> None:
        # Legacy raw clients may attach to the root only with one live port.
        self.server.settimeout(0.5)
        while not self.stop.is_set():
            try:
                client, _ = self.server.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with self.channels_lock:
                active = [c for c in self.channels.values() if c.serial is not None or c.flashing]
                if len(active) != 1:
                    client.close()
                    continue
                channel = active[0]
                channel.attach(client)

    def reap_idle(self) -> None:
        with self.channels_lock:
            now = time.monotonic()
            for key, channel in list(self.channels.items()):
                with channel.gate:
                    with channel.clients_lock:
                        busy = bool(channel.clients) or channel.flashing
                    if busy:
                        channel.last_used = now
                    elif now - channel.last_used >= self.idle_timeout:
                        channel.close()
                        del self.channels[key]

    def run(self, initial_port: str | None = None) -> None:
        self.start()
        try:
            if initial_port:
                self.claim(initial_port, self.baud)
            while not self.stop.is_set():
                try:
                    self.stop.wait(0.25)
                    self.reap_idle()
                    self._publish_status()
                except KeyboardInterrupt:
                    try:
                        self.request_shutdown(require_idle=False)
                    except RuntimeError:
                        continue
        finally:
            self.close()

    def close(self) -> None:
        with self.channels_lock:
            self.stop.set()
            for channel in self.channels.values():
                channel.close()
            self.channels.clear()
        super().close()
        try:
            self.channel_dir.rmdir()
        except OSError:
            pass
        if self.lock is not None:
            ipc.unregister(self.socket_path)
            self.lock.release()
            self.lock = None
