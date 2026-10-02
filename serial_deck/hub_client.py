#!/usr/bin/env python3
"""Shared lifecycle and control client for the local UART hub."""

from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import sys
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Callable

try:
    from . import ipc
    from .uart_client import HUB_SCHEME, is_device_port, port_identity
except ImportError:
    import ipc
    from uart_client import HUB_SCHEME, is_device_port, port_identity

MULTIPORT_PROTOCOL = "serial-deck-multiport-v1"
DEFAULT_SOCKET = ipc.default_hub_path()


class BaudConflictError(RuntimeError):
    """Claim refused: other clients hold the port at a different live baud."""

    def __init__(self, message: str, details: dict[str, object]) -> None:
        super().__init__(message)
        self.port = str(details.get("port", ""))
        self.live_baud = int(details.get("live_baud", 0))
        self.requested_baud = int(details.get("requested_baud", 0))
        self.client_count = int(details.get("client_count", 0))


@contextmanager
def hub_routing_lock():
    """Serialize discovery/start/claim across dashboard processes."""
    with ipc.FileLock(ipc.runtime_dir() / "routing.lock"):
        yield

def hub_socket_paths() -> list[str]:
    """Root hubs of this user: the default path plus any registered custom path."""
    return ipc.registered()


def valid_hub_status(status: object) -> bool:
    """A status reply shaped like a serial-deck hub's (current or legacy)."""
    if not isinstance(status, dict):
        return False
    claimed, baud, flash = status.get("port"), status.get("baud"), status.get("flash")
    return (status.get("event") == "status" and status.get("state") in ("ready", "idle", "flashing")
            and type(baud) is int and baud > 0
            and isinstance(flash, dict) and type(flash.get("active")) is bool
            and (claimed is None or isinstance(claimed, str))
            and status.get("protocol") in (None, MULTIPORT_PROTOCOL))


def find_existing_hub(port: str | None = None, *,
                      exclude: tuple[str, ...] = (),
                      allow_idle: bool = False) -> HubProcessManager | None:
    """Read status only; never spawn, claim, or reconfigure a discovered hub."""
    idle = None
    legacy = None
    for path in hub_socket_paths():
        if path in exclude:
            continue
        manager = HubProcessManager(socket_path=path)
        try:
            status = manager.request_control("status", timeout=0.2)
        except (OSError, RuntimeError, ValueError):
            continue
        claimed, baud, flash = status.get("port"), status.get("baud"), status.get("flash")
        if status.get("channel_socket"):
            continue  # Channel sockets belong to the root daemon, not another hub.
        if not valid_hub_status(status):
            continue
        manager.uart_port = manager.hub_port = claimed or ""
        manager.baud = baud
        protocol = status.get("protocol")
        if protocol == MULTIPORT_PROTOCOL:
            manager.multiport = True
            return manager
        if protocol is not None:
            continue  # Another program or version: never reuse or reclassify it.
        if port is not None:
            if claimed and port_identity(claimed) == port_identity(port):
                return manager
            if not claimed and not flash["active"]:
                idle = manager
        elif claimed:
            legacy = manager
        else:
            idle = manager
    return (legacy or idle) if port is None else (idle if allow_idle else None)


class HubProcessManager:
    """Start or attach to the hub and keep clients off the physical UART."""

    def __init__(self, uart_port: str = "", baud: int = 2000000,
                 socket_path: str = DEFAULT_SOCKET,
                 hub_script: str | None = None) -> None:
        if uart_port.startswith(HUB_SCHEME):
            raise ValueError("hub manager requires a physical UART selection")
        self.uart_port = uart_port
        self.baud = baud
        self.socket_path = str(Path(socket_path).expanduser())
        # New daemons always use the multi-port Python implementation.
        self._explicit_hub_script = hub_script is not None
        self.hub_script = (
            Path(hub_script) if hub_script else Path(__file__).with_name("hub.py")
        )
        self.process: subprocess.Popen[str] | None = None
        self.owns_process = False
        self.owns_port = False
        self.multiport = False
        self.channel_socket = ""
        self.hub_port = ""
        self._subscriber: socket.socket | None = None
        self._subscriber_thread: threading.Thread | None = None
        self._subscriber_stop = threading.Event()
        self._callbacks: list[Callable[[dict[str, object]], None]] = []
        self._callbacks_lock = threading.Lock()

    @property
    def endpoint(self) -> str:
        return f"{HUB_SCHEME}{self.channel_socket or self.socket_path}"

    @property
    def control_endpoint(self) -> str:
        return f"{self.channel_socket or self.socket_path}.ctl"

    def socket_ready(self) -> bool:
        try:
            ipc.connect(f"{self.socket_path}.ctl", timeout=0.2).close()
        except OSError:
            return False
        return True

    def request_control(self, action: str, timeout: float = 3.0,
                        **payload: object) -> dict[str, object]:
        endpoint = (f"{self.socket_path}.ctl" if action in ("claim", "scan", "shutdown")
                    else self.control_endpoint)
        client = ipc.connect(endpoint, timeout)
        try:
            request = {"action": action, **payload}
            client.sendall(json.dumps(request, separators=(",", ":")).encode("utf-8") + b"\n")
            try:
                line = ipc.read_line(client, 4 * 1024 * 1024, timeout)
            except ConnectionError:
                raise RuntimeError("UART hub closed without a response") from None
            except ValueError:
                raise RuntimeError("UART hub response too large") from None
            response = json.loads(line)
        finally:
            client.close()
        if not isinstance(response, dict):
            raise RuntimeError("invalid response from UART hub")
        if not response.get("ok"):
            conflict = response.get("baud_conflict")
            if isinstance(conflict, dict):
                raise BaudConflictError(str(response.get("error", "baud conflict")), conflict)
            raise RuntimeError(str(response.get("error", "UART hub request failed")))
        if response.get("protocol") == MULTIPORT_PROTOCOL:
            self.multiport = True
        return response

    def scan_ports(self) -> list[str]:
        response = self.request_control("scan")
        ports = response.get("ports", [])
        if not isinstance(ports, list) or not all(isinstance(port, str) for port in ports):
            raise RuntimeError("UART hub returned an invalid port list")
        hub_port = response.get("hub_port")
        if hub_port is not None and not isinstance(hub_port, str):
            raise RuntimeError("UART hub returned an invalid active port")
        if not self.channel_socket:
            self.hub_port = hub_port or ""
        return ports

    def claim_port(self, port: str, baud: int, on_baud_conflict: str = "join") -> None:
        """`on_baud_conflict` decides a claim at another live baud: "join" keeps
        the live baud, "error" raises BaudConflictError, "retime" changes it for
        every attached client."""
        payload: dict[str, object] = {"port": port, "baud": baud}
        if on_baud_conflict != "join":
            payload["on_baud_conflict"] = on_baud_conflict
        response = self.request_control("claim", **payload)
        claimed = response.get("claimed", False)
        if not isinstance(claimed, bool):
            raise RuntimeError("UART hub returned an invalid claim state")
        self.uart_port = str(response.get("port", port))
        self.hub_port = self.uart_port
        self.baud = int(response.get("baud", baud))
        self.owns_port = claimed
        channel_socket = response.get("channel_socket")
        if isinstance(channel_socket, str) and channel_socket != self.channel_socket:
            callbacks = list(self._callbacks)
            self.unsubscribe()
            self.multiport = True
            self.channel_socket = channel_socket
            for callback in callbacks:
                self.subscribe(callback)

    def release_port(self) -> None:
        if self.multiport:
            # The daemon reaps unused channels. A client never releases another
            # client's UART, including the gap between claim and stream attach.
            return
        if not self.owns_port:
            return
        response = self.request_control("release")
        if response.get("released"):
            self.uart_port = ""
            self.hub_port = ""
            self.owns_port = False

    def get_status(self) -> dict[str, object]:
        return self.request_control("status")

    def preview_flash(self, build_dir: str, flash_baud: int) -> dict[str, object]:
        return self.request_control(
            "flash_preview", build_dir=build_dir, flash_baud=flash_baud)

    def start_flash(self, build_dir: str, flash_baud: int) -> dict[str, object]:
        return self.request_control("flash", build_dir=build_dir, flash_baud=flash_baud)

    def subscribe(self, callback: Callable[[dict[str, object]], None]) -> None:
        """Register a status callback.

        Several logical connections can share one manager when they claim
        the same physical port (see `HubRegistry`); every registered
        callback receives every status event over one shared subscription.
        """
        with self._callbacks_lock:
            self._callbacks.append(callback)
            if self._subscriber is not None:
                return
            client = ipc.connect(self.control_endpoint, 1.0)
            client.sendall(b'{"action":"subscribe"}\n')
            client.settimeout(0.5)
            self._subscriber = client
            self._subscriber_stop.clear()

            def _reader() -> None:
                buffer = bytearray()
                while not self._subscriber_stop.is_set():
                    try:
                        chunk = client.recv(4096)
                    except socket.timeout:
                        continue
                    except OSError:
                        break
                    if not chunk:
                        break
                    buffer.extend(chunk)
                    while b"\n" in buffer:
                        raw, _, remainder = buffer.partition(b"\n")
                        buffer = bytearray(remainder)
                        try:
                            event = json.loads(raw.decode("utf-8"))
                        except (UnicodeDecodeError, json.JSONDecodeError):
                            continue
                        if not isinstance(event, dict):
                            continue
                        with self._callbacks_lock:
                            callbacks = list(self._callbacks)
                        for cb in callbacks:
                            cb(event)

            self._subscriber_thread = threading.Thread(target=_reader, daemon=True)
            self._subscriber_thread.start()

    def unsubscribe(self, callback: Callable[[dict[str, object]], None] | None = None) -> None:
        """Drop one callback, or tear the shared subscription down entirely
        when called with no argument (the pre-multi-connection behavior)."""
        with self._callbacks_lock:
            if callback is not None:
                if callback in self._callbacks:
                    self._callbacks.remove(callback)
                if self._callbacks:
                    return
            self._callbacks.clear()
            self._subscriber_stop.set()
            subscriber = self._subscriber
            self._subscriber = None
        if subscriber is not None:
            try:
                subscriber.close()
            except OSError:
                pass
        thread = self._subscriber_thread
        self._subscriber_thread = None
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=1.0)

    def ensure_started(self, timeout: float = 3.0) -> bool:
        with hub_routing_lock():
            return self._ensure_started(timeout)

    def _check_protocol(self) -> None:
        """Refuse to drive an endpoint that is not a serial-deck hub (or a legacy one)."""
        status = self.request_control("status", timeout=2.0)
        if not valid_hub_status(status):
            protocol = status.get("protocol") if isinstance(status, dict) else None
            raise RuntimeError(f"{self.socket_path} is not a serial-deck hub"
                               + (f" (protocol {protocol!r})" if protocol else "")
                               + "; stop it or pass a different --socket")
        self.multiport = status.get("protocol") == MULTIPORT_PROTOCOL

    def _ensure_started(self, timeout: float) -> bool:
        if self.socket_ready():
            self._check_protocol()
            self.owns_process = False
            return False
        existing = find_existing_hub()
        if existing is not None:
            self.socket_path = existing.socket_path
            self.multiport = existing.multiport
            self.owns_process = False
            return False
        if not self.hub_script.is_file():
            raise RuntimeError(f"hub script not found: {self.hub_script}")
        command = [sys.executable, str(self.hub_script), "--baud", str(self.baud),
                   "--socket", self.socket_path]
        # Detach the daemon from this process's console and Ctrl+C group.
        detach: dict[str, object] = (
            {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW}
            if os.name == "nt" else {"start_new_session": True})
        self.process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.STDOUT,
            text=True,
            **detach,
        )
        self.owns_process = True
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.socket_ready():
                self.multiport = True
                return True
            if self.process.poll() is not None:
                self.process = None
                self.owns_process = False
                raise RuntimeError("UART hub exited during startup; run hub.py to diagnose")
            time.sleep(0.05)
        # Leave the slow child alone: it may still come up and serve clients.
        self.unsubscribe()
        raise TimeoutError(f"UART hub did not create {self.control_endpoint} in {timeout:g} s; "
                           f"it may still be starting (pid {self.process.pid})")

    def stop(self) -> None:
        self.unsubscribe()
        if self.multiport:
            return  # The shared daemon has an independent lifetime.
        process = self.process
        if not self.owns_process or process is None:
            return
        # A hub is never killed: only its own acknowledged shutdown stops it.
        # The daemon refuses atomically while a client or flash is active, and
        # no reply is no proof of idleness (a client may attach at any moment).
        if process.poll() is None:
            try:
                status = self.get_status()
                flash = status.get("flash")
                if isinstance(flash, dict) and flash.get("active"):
                    return
                if isinstance(status.get("client_count"), int) and status["client_count"] > 0:
                    return
                self.request_control("shutdown")
                process.wait(timeout=5.0)
            except (OSError, RuntimeError, ValueError, json.JSONDecodeError, subprocess.TimeoutExpired):
                return  # Refused, unanswered or still exiting: leave it running.
        self.process = None
        self.owns_process = False
        self.owns_port = False

    def shutdown(self) -> None:
        """Explicit maintenance operation; the daemon refuses active clients/flash."""
        self.request_control("shutdown")
        if self.process is not None:
            self.process.wait(timeout=5)


class HubRegistry:
    """Reference-count channel clients in one shared multi-port daemon."""

    def __init__(self, baud: int = 2000000, hub_script: str | None = None,
                 default_manager: HubProcessManager | None = None,
                 reuse_live_baud: bool = False) -> None:
        self.baud = baud
        self.hub_script = hub_script
        self._lock = threading.Lock()
        self._entries: dict[str, tuple[HubProcessManager, int]] = {}
        self.default_manager = default_manager
        self.reuse_live_baud = reuse_live_baud

    def pin(self, port: str, manager: HubProcessManager) -> None:
        """Register an already-running, externally-owned manager for `port`.

        Lets `acquire()` reuse a manager the caller started outside the
        registry (for example a fixed default connection) instead of
        spawning a second, conflicting hub process for the same physical
        port. The pinned reservation counts as one permanent reference: the
        caller remains responsible for calling `manager.stop()` itself.
        """
        port = port_identity(port)
        with self._lock:
            _, refcount = self._entries.get(port, (None, 0))
            self._entries[port] = (manager, refcount + 1)

    def acquire(self, port: str, baud: int, on_baud_conflict: str = "join") -> HubProcessManager:
        key = port_identity(port)
        with self._lock:
            manager, refcount = self._entries.get(key, (None, 0))
            if manager is None:
                root = self.default_manager
                if root is None:
                    root = HubProcessManager(baud=self.baud, hub_script=self.hub_script)
                    root.ensure_started()
                    self.default_manager = root
                status = root.get_status()
                protocol = status.get("protocol")
                if protocol == MULTIPORT_PROTOCOL:
                    # Independent channel clients, all talking to one daemon PID.
                    manager = HubProcessManager(baud=baud, socket_path=root.socket_path)
                    manager.multiport = True
                elif protocol is not None:
                    raise RuntimeError(
                        f"{root.socket_path} is served by an unsupported hub ({protocol!r}). "
                        "Stop it, or pass a different --socket. No additional hub was started.")
                else:
                    claimed = status.get("port")
                    if claimed and port_identity(claimed) != key:
                        raise RuntimeError(
                            "Legacy single-port hub is running. Disconnect its clients and "
                            "stop that hub, then reopen the app to use one multi-port daemon. "
                            "No additional hub was started.")
                    manager = root
                    if claimed and type(status.get("baud")) is int:
                        baud = status["baud"]
                        port = claimed
            elif self.reuse_live_baud and on_baud_conflict == "join":
                baud = manager.baud
            try:
                if on_baud_conflict == "join":
                    manager.claim_port(port, baud)
                else:
                    manager.claim_port(port, baud, on_baud_conflict)
            except Exception:
                if refcount == 0 and manager is not self.default_manager:
                    manager.unsubscribe()
                raise
            self._entries[key] = (manager, refcount + 1)
            return manager

    def release(self, port: str, manager: HubProcessManager) -> None:
        port = port_identity(port)
        with self._lock:
            entry = self._entries.get(port)
            if entry is None or entry[0] is not manager:
                return
            refcount = entry[1] - 1
            if refcount > 0:
                self._entries[port] = (manager, refcount)
                return
            del self._entries[port]
        # The backend owns this hub's lifetime, even when no tab uses it.
        if manager is self.default_manager:
            return
        try:
            manager.release_port()
        finally:
            manager.stop()

    def claimed_ports(self) -> list[str]:
        with self._lock:
            return sorted(self._entries.keys())
