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
    from . import ipc, script_supervisor, scripting, ssh_socket
    from . import profiles as profiles_module
    from .hub import UartHub
    from .uart_client import is_device_port, is_non_serial_port, port_identity, usb_identity
except ImportError:
    import ipc
    import script_supervisor
    import scripting
    import ssh_socket
    import profiles as profiles_module
    from hub import UartHub
    from uart_client import is_device_port, is_non_serial_port, port_identity, usb_identity


PROTOCOL = "serial-deck-multiport-v1"
# SSH device actions, served by the root socket only. Pairing carries a
# password or passphrase: those requests are never logged and the secret is
# dropped after the one ssh process that needs it.
SSH_ACTIONS = ("ssh_devices", "ssh_fingerprint", "ssh_pair", "ssh_forget", "ssh_retry", "ssh_unlock",
               "ssh_restart", "ssh_screen", "ssh_profiles")
# User scripts run as supervised processes owned by this daemon (script_supervisor).
SCRIPT_ACTIONS = ("script_list", "script_run", "script_stop", "script_status", "script_logs",
                  "script_autorun", "runner_attached")
# A script run started by the hub itself may be stopped once nobody else uses its
# port; give its runner this long to attach before judging.
AUTORUN_GRACE_S = 10.0
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
        set_listener = getattr(self.serial, "set_listener", None)
        if callable(set_listener):
            # Tunnel state changes (reconnecting, auth_failed, ...) reach subscribers.
            set_listener(self._publish_status)
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
                # A shutdown was accepted (its reply may still be in flight): read-only
                # status keeps working, but nothing may start, least of all a flash.
                if self.service.closing and request.get("action") not in ("status", "get_lines"):
                    raise RuntimeError("hub is shutting down")
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
                if baud == self.baud or is_non_serial_port(self.port):
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
                error = RuntimeError(result.get("error", "claim failed"))
                if result.get("code"):
                    error.code = result["code"]  # type: ignore[attr-defined]
                raise error
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
        self.ssh_store = ssh_socket.DeviceStore()
        self.scripts = script_supervisor.ScriptSupervisor(str(self.socket_path))

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

    def claim(self, port: str, baud: int, on_conflict: str = "join",
              secret: bytearray | None = None) -> dict:
        if (not isinstance(port, str) or not (is_device_port(port) or is_non_serial_port(port))
                or type(baud) is not int or baud <= 0):
            raise ValueError("claim requires a device path/endpoint and positive baud")
        if on_conflict not in BAUD_CONFLICT_POLICIES:
            raise ValueError(f"on_baud_conflict must be one of {', '.join(BAUD_CONFLICT_POLICIES)}")
        key = device_key(port)
        preopened = None
        if port.startswith(ssh_socket.SCHEME):
            with self.channels_lock:
                exists = key in self.channels
            if not exists:
                # The SSH tunnel takes seconds: never hold channels_lock (status,
                # other claims, the idle reaper) while it comes up.
                try:
                    preopened = ssh_socket.SshSocketTransport(port, 0.1, self.ssh_store, secret)
                except ssh_socket.SshSocketError as exc:
                    error = RuntimeError(f"cannot open {port}: {exc}")
                    error.code = exc.state  # type: ignore[attr-defined]
                    raise error from exc
        with self.channels_lock:
            if self.stop.is_set() or self.closing:
                if preopened is not None:
                    preopened.close()
                raise RuntimeError("hub is shutting down")
            channel = self.channels.get(key)
            created = channel is None
            if created:
                path = str(self.channel_dir / f"{uuid.uuid4().hex[:8]}.sock")
                channel = PortChannel(self, path, baud)
                channel.preopened = preopened
            elif preopened is not None:
                preopened.close()  # lost a race with another claimer: share theirs
            try:
                result = channel.claim(key, baud, on_conflict)
                if created:
                    channel.start()
                    self.channels[key] = channel
            except Exception:
                if created:
                    channel.close()
                raise
            response = {**result, "protocol": PROTOCOL, "pid": os.getpid(),
                        "service_socket": str(self.socket_path), "channel_socket": str(channel.socket_path)}
        if result.get("claimed"):
            # The port just opened (first claim, or reopened after a loss). Outside
            # channels_lock: a runner claims the same port and must not wait on us.
            self._start_autoruns(key, int(result.get("baud", baud)))
        return response

    def _start_autoruns(self, key: str, baud: int) -> None:
        try:
            identity = usb_identity(key) if not is_non_serial_port(key) else {}
            self.scripts.on_channel_opened(key, baud, identity)
        except Exception:
            pass  # a script problem must never fail a claim

    def _handle_control(self, client: socket.socket, request: dict | None = None) -> None:
        try:
            request = request if request is not None else read_request(client)
            action = request.get("action")
            if action == "claim":
                value = request.pop("passphrase", None)
                secret = bytearray(value.encode("utf-8")) if isinstance(value, str) and value else None
                value = None
                try:
                    result = self.claim(request.get("port"), request.get("baud", self.baud),
                                        request.get("on_baud_conflict", "join"), secret)
                except BaudConflict as exc:
                    reply(client, {"ok": False, "error": str(exc), "baud_conflict": exc.details})
                    return
                except RuntimeError as exc:
                    reply(client, {"ok": False, "error": str(exc),
                                   **({"code": exc.code} if getattr(exc, "code", None) else {})})
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
                self.scripts.stop_all()
                reply(client, {"ok": True, "stopping": True, "pid": os.getpid()})
                self.stop.set()
                return
            if action in SSH_ACTIONS:
                reply(client, self._ssh_action(action, request))
                return
            if action in SCRIPT_ACTIONS:
                reply(client, self._script_action(action, request))
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

    def _script_action(self, action: str, request: dict) -> dict:
        try:
            if action == "script_list":
                return {"ok": True, "scripts": scripting.list_scripts(),
                        "autorun": self.scripts.autorun_rules(), "folder": str(scripting.scripts_dir())}
            if action == "script_status":
                return {"ok": True, "runs": self.scripts.status()}
            if action == "script_run":
                port = request.get("port")
                if not isinstance(port, str) or not (is_device_port(port) or is_non_serial_port(port)):
                    raise ValueError("script_run needs a UART path or a device endpoint")
                baud = request.get("baud", 115200)
                run = self.scripts.start(str(request.get("name", "")), port, baud)
                return {"ok": True, "run": run.summary()}
            if action == "runner_attached":
                self.scripts.mark_attached(str(request.get("id", "")))
                return {"ok": True}
            if action == "script_stop":
                return {"ok": True, "run": self.scripts.stop(str(request.get("id", ""))).summary()}
            if action == "script_logs":
                run = self.scripts.get(str(request.get("id", "")))
                after = request.get("after", 0)
                limit = request.get("limit", 200)
                lines, cursor, dropped = run.read_logs(after if type(after) is int else 0,
                                                       min(limit, 500) if type(limit) is int else 200)
                return {"ok": True, "run": run.summary(), "lines": lines, "cursor": cursor, "dropped": dropped}
            # script_autorun
            rules = self.scripts.set_autorun(str(request.get("name", "")), bool(request.get("enabled")),
                                             request.get("match") if isinstance(request.get("match"), dict) else None,
                                             request.get("baud") if type(request.get("baud")) is int else None)
            return {"ok": True, "autorun": rules}
        except KeyError as exc:
            return {"ok": False, "error": str(exc.args[0]) if exc.args else "not found"}
        except (ValueError, RuntimeError, OSError) as exc:
            return {"ok": False, "error": str(exc)}

    def _ssh_channel(self, name: str) -> PortChannel | None:
        with self.channels_lock:
            return self.channels.get(ssh_socket.device_url(name))

    def _ssh_action(self, action: str, request: dict) -> dict:
        store = self.ssh_store
        try:
            if action == "ssh_devices":
                with self.channels_lock:
                    live = {}
                    for channel in self.channels.values():
                        link_state = getattr(channel.serial, "link_state", None)
                        if callable(link_state):
                            state = link_state()
                            live[state["device"]] = state
                return {"ok": True, "supported": ssh_socket.supported(),
                        "devices": ssh_socket.list_devices(store, live)}
            if action == "ssh_profiles":
                profiles, problems = profiles_module.load_all()
                return {"ok": True, "profiles": list(profiles.values()), "problems": problems}
            if action == "ssh_fingerprint":
                port = request.get("ssh_port", 22)
                return {"ok": True, **ssh_socket.fingerprint(store, str(request.get("host", "")),
                                                             port if type(port) is int else 22)}
            if action == "ssh_pair":
                fields = {**request, "port": request.get("ssh_port", 22)}
                for key in ("password", "passphrase"):
                    # Only a wipeable copy goes on; drop the str from both dicts.
                    value = request.pop(key, None)
                    fields.pop(key, None)
                    if isinstance(value, str) and value:
                        fields[key] = bytearray(value.encode("utf-8"))
                    value = None
                try:
                    return {"ok": True, **ssh_socket.pair(store, fields)}
                finally:
                    for key in ("password", "passphrase", "key_passphrase"):
                        ssh_socket.wipe(fields.pop(key, None))
            name = str(request.get("name", ""))
            if action == "ssh_forget":
                channel = self._ssh_channel(name)
                if channel is not None:
                    with channel.clients_lock:
                        if channel.clients:
                            raise RuntimeError("disconnect the device before forgetting it")
                value = request.pop("passphrase", None)
                secret = bytearray(value.encode("utf-8")) if isinstance(value, str) and value else None
                value = None
                return {"ok": True, **ssh_socket.forget(store, name, bool(request.get("local_only")), secret)}
            if action == "ssh_restart":
                value = request.pop("passphrase", None)
                secret = bytearray(value.encode("utf-8")) if isinstance(value, str) and value else None
                value = None
                return {"ok": True, **ssh_socket.restart(store, name, str(request.get("arg", "")), secret)}
            channel = self._ssh_channel(name)
            transport = channel.serial if channel is not None else None
            if transport is None:
                raise RuntimeError(f"{name} is not connected")
            if action == "ssh_retry":
                transport.retry_now()
                return {"ok": True, "link": transport.link_state()}
            if action == "ssh_screen":
                screen_path = transport.device.get("screen_path", "")
                control = transport.control_socket
                if not screen_path:
                    raise RuntimeError(f"{name} has no screen_path")
                if not control:
                    raise RuntimeError(f"{name} is not connected")
                after = request.get("after_revision")
                return {"ok": True, **ssh_socket.screen_frame(
                    control, screen_path, after if type(after) is int else None,
                    transport.device.get("screen_revision_header", "x-revision"),
                    transport.device.get("screen_size_header", "x-size"))}
            # ssh_unlock
            value = request.pop("passphrase", None)
            secret = bytearray(value.encode("utf-8")) if isinstance(value, str) else bytearray()
            value = None
            return {"ok": True, "link": transport.unlock(secret)}
        except ssh_socket.SshSocketError as exc:
            return {"ok": False, "error": str(exc), "code": exc.state}

    def real_clients(self, channel: PortChannel) -> int:
        """Data clients on a channel that are not scripts this hub started itself.

        A runner is a data client like a dashboard, so counting it would keep every
        autorun port open (and refuse `hub --shutdown`) forever. Scripts a user
        started by hand count as clients: they hold the port until they finish.
        Only runners that reported `runner_attached` are subtracted: before that
        their socket is not in `clients` yet, and a dashboard must not be mistaken
        for the runner.
        """
        with channel.clients_lock:
            total = len(channel.clients)
        return max(0, total - self.scripts.attached_autoruns_on(channel.port))

    def stop_idle_autoruns(self) -> None:
        """Stop autorun scripts on ports nobody else is using (called by the run loop)."""
        stale = []
        with self.channels_lock:
            for channel in self.channels.values():
                if not channel.port or channel.flashing:
                    continue
                autoruns = [r for r in self.scripts.running_on(channel.port) if r.autorun]
                if (autoruns and self.real_clients(channel) == 0
                        and all(time.time() - r.started > AUTORUN_GRACE_S for r in autoruns)):
                    stale.append(channel.port)
        for port in stale:  # stopping waits on the process: never under channels_lock
            self.scripts.stop_autoruns_on(port)

    def request_shutdown(self, require_idle: bool = True, commit: bool = True) -> None:
        """Refuse while clients or a flash are active; otherwise stop accepting work.

        `commit=False` closes the door (`closing`: claims and attaches refused)
        without releasing the run loop yet, so a caller can answer first.
        """
        with self.channels_lock, ExitStack() as stack:
            for channel in self.channels.values():
                stack.enter_context(channel.gate)
            if any(c.flashing or (require_idle and self.real_clients(c)) for c in self.channels.values()):
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
                    self.stop_idle_autoruns()
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
        self.scripts.stop_all()
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
