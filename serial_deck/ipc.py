"""Local hub transport: Unix sockets on POSIX, authenticated loopback TCP on Windows.

Every hub endpoint is named by a filesystem path (`hub.sock`, its `.ctl`
sibling, per-channel sockets). With the "unix" backend that path is the
AF_UNIX socket itself. With the "tcp" backend (default on Windows, where
Python has no AF_UNIX; force it anywhere with SERIAL_DECK_IPC=tcp) the path
is a private JSON file naming a 127.0.0.1 port and a random token. A client
must send that token first; the listener checks it in a separate thread
under an absolute deadline, so a silent or hostile peer can neither stall
`accept()` nor see a single stream byte.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import queue
import secrets
import select
import socket
import stat
import sys
import threading
import time
from pathlib import Path

BACKEND = os.environ.get("SERIAL_DECK_IPC", "").strip().lower() or ("tcp" if os.name == "nt" else "unix")
if BACKEND not in ("unix", "tcp"):
    raise RuntimeError(f"SERIAL_DECK_IPC must be 'unix' or 'tcp', not {BACKEND!r}")
if BACKEND == "unix" and not hasattr(socket, "AF_UNIX"):
    raise RuntimeError("this Python has no Unix sockets; use SERIAL_DECK_IPC=tcp")

HANDSHAKE_TIMEOUT = 2.0
MAX_PENDING_HANDSHAKES = 32
TOKEN_BYTES = 32
# Darwin's sockaddr_un.sun_path holds 104 bytes, Linux 108, both NUL-terminated.
MAX_UNIX_PATH = 103
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


# ------------------------------------------------------------------ paths

def _uid_tag() -> str:
    if hasattr(os, "getuid"):
        return str(os.getuid())
    return hashlib.sha256(os.path.expanduser("~").encode()).hexdigest()[:8]


def runtime_dir() -> Path:
    """One private per-user directory, whatever environment a process got.

    MCP clients start servers with a minimal environment (often without
    XDG_RUNTIME_DIR), so the location must not depend on it. On macOS the
    short `/tmp` root keeps channel socket paths under the sun_path limit.
    """
    override = os.environ.get("SERIAL_DECK_RUNTIME_DIR", "").strip()
    if override:
        return private_dir(Path(override).expanduser())
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return private_dir(Path(base) / "serial-deck")
    run_user = Path(f"/run/user/{os.getuid()}")
    if run_user.is_dir() and os.access(run_user, os.W_OK):
        return private_dir(run_user / "serial-deck")
    return private_dir(Path(f"/tmp/serial-deck-{_uid_tag()}"))


def default_hub_path() -> str:
    return str(runtime_dir() / "hub.sock")


def channel_root() -> Path:
    """Where a daemon puts per-port channel sockets.

    Kept short and independent of `--socket` so `<root>/<12 hex>/<8 hex>.sock.ctl`
    always fits macOS's 104-byte sun_path, even when the runtime dir is long.
    """
    base = runtime_dir()
    if BACKEND == "unix" and len(os.fsencode(str(base))) > 60:
        base = private_dir(Path(f"/tmp/serial-deck-{_uid_tag()}"))
    return private_dir(base / "ch")


_PRIVATE_DONE: set[str] = set()


def _windows_restrict(path: Path) -> None:
    """Replace `path`'s whole DACL with one ACE: full control for this user.

    The DACL is set as *protected*, so nothing is inherited and no other
    principal's existing grant survives, even under a shared root (a custom
    SERIAL_DECK_RUNTIME_DIR, a public folder). Files created inside inherit it.
    """
    import ctypes
    from ctypes import wintypes
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
    advapi32.GetSecurityDescriptorDacl.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(wintypes.BOOL), ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.BOOL)]
    advapi32.SetNamedSecurityInfoW.argtypes = [
        wintypes.LPWSTR, ctypes.c_int, wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p,
        ctypes.c_void_p, ctypes.c_void_p]
    advapi32.SetNamedSecurityInfoW.restype = wintypes.DWORD
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    # "P" = protected DACL; OICI = inherited by files and subfolders; FA = full access;
    # the SID string is this process's user. Nothing else is granted.
    sid = _windows_user_sid()
    flags = "OICI" if path.is_dir() else ""
    sddl = f"D:P(A;{flags};FA;;;{sid})"
    descriptor = ctypes.c_void_p()
    if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, 1, ctypes.byref(descriptor), None):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        present, defaulted = wintypes.BOOL(), wintypes.BOOL()
        dacl = ctypes.c_void_p()
        if not advapi32.GetSecurityDescriptorDacl(descriptor, ctypes.byref(present),
                                                  ctypes.byref(dacl), ctypes.byref(defaulted)):
            raise ctypes.WinError(ctypes.get_last_error())
        SE_FILE_OBJECT = 1
        DACL = 0x00000004
        PROTECTED_DACL = 0x80000000
        error = advapi32.SetNamedSecurityInfoW(str(path), SE_FILE_OBJECT, DACL | PROTECTED_DACL,
                                               None, None, dacl, None)
        if error:
            raise OSError(error, f"cannot restrict access to {path}")
    finally:
        kernel32.LocalFree(descriptor)


def _windows_user_sid() -> str:
    """This process's user SID as a string (S-1-5-21-...)."""
    import ctypes
    from ctypes import wintypes
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    advapi32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi32.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p,
                                             wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    advapi32.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), 0x0008, ctypes.byref(token)):  # TOKEN_QUERY
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        size = wintypes.DWORD()
        advapi32.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))  # TokenUser
        buffer = ctypes.create_string_buffer(size.value)
        if not advapi32.GetTokenInformation(token, 1, buffer, size, ctypes.byref(size)):
            raise ctypes.WinError(ctypes.get_last_error())
        sid_pointer = ctypes.c_void_p.from_buffer(buffer).value  # TOKEN_USER.User.Sid
        text = wintypes.LPWSTR()
        if not advapi32.ConvertSidToStringSidW(sid_pointer, ctypes.byref(text)):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            return text.value
        finally:
            kernel32.LocalFree(ctypes.cast(text, ctypes.c_void_p))
    finally:
        kernel32.CloseHandle(token)


def private_dir(path: Path) -> Path:
    """Create `path` for this user only and refuse one another user could steer.

    POSIX: mode 0700, owned by us, not a symlink. Windows: not a reparse
    point, and an explicit ACL granting only this user (inherited by the
    endpoint and token files created inside it).
    """
    try:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
    except FileExistsError:
        pass
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & _REPARSE_POINT:
        raise RuntimeError(f"refusing link/reparse point as private directory: {path}")
    if not stat.S_ISDIR(info.st_mode):
        raise RuntimeError(f"not a directory: {path}")
    if os.name != "nt":
        if info.st_uid != os.getuid():
            raise RuntimeError(f"{path} belongs to another user")
        if info.st_mode & 0o077:
            os.chmod(path, 0o700)
    elif str(path) not in _PRIVATE_DONE:
        _windows_restrict(path)
        _PRIVATE_DONE.add(str(path))
    return path


def _write_private(path: Path, data: bytes) -> None:
    # The file inherits the directory's owner-only ACL (Windows) or gets 0600.
    private_dir(path.parent)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(4)}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    # Windows refuses to replace a file another process has open for a moment.
    for attempt in range(20):
        try:
            os.replace(tmp, path)
            return
        except PermissionError:
            if os.name != "nt" or attempt == 19:
                remove(tmp)
                raise
            time.sleep(0.05)


def _read_endpoint(path: str) -> dict | None:
    """The TCP endpoint record at `path`, only when this user wrote it."""
    try:
        fd = os.open(path, os.O_RDONLY | _NOFOLLOW)
    except OSError:
        return None
    try:
        info = os.fstat(fd)
        if os.name != "nt" and (info.st_uid != os.getuid() or info.st_mode & 0o077):
            return None
        raw = os.read(fd, 4096)
    finally:
        os.close(fd)
    try:
        record = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if (not isinstance(record, dict) or type(record.get("port")) is not int
            or not isinstance(record.get("token"), str)):
        return None
    return record


def endpoint_exists(path: str) -> bool:
    if BACKEND == "unix":
        try:
            return stat.S_ISSOCK(os.stat(path).st_mode)
        except OSError:
            return False
    return _read_endpoint(path) is not None


def remove(path: str | Path) -> None:
    """Best-effort delete; never raises, so cleanup paths always finish."""
    for attempt in range(20):
        try:
            os.unlink(path)
            return
        except FileNotFoundError:
            return
        except PermissionError:
            # Windows: another process is reading the endpoint record right now.
            if os.name != "nt" or attempt == 19:
                return
            time.sleep(0.05)
        except OSError:
            return


# --------------------------------------------------------------- sockets

class Listener:
    """Accepts authenticated connections; mimics a listening socket.

    `accept()` honours `settimeout()` and raises `socket.timeout`, and
    `OSError` once closed, like the socket the hub loops were written for.
    """

    def __init__(self, path: str, backlog: int) -> None:
        self.path = path
        self._timeout: float | None = None
        self._closed = False
        if BACKEND == "unix":
            encoded = os.fsencode(path)
            if len(encoded) > MAX_UNIX_PATH:
                raise OSError(f"socket path is {len(encoded)} bytes, over the {MAX_UNIX_PATH}-byte "
                              f"limit: {path}; use a shorter --socket or SERIAL_DECK_IPC=tcp")
            remove(path)
            self._socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                self._socket.bind(path)
                os.chmod(path, 0o600)
                self._socket.listen(backlog)
            except Exception:
                self._socket.close()
                raise
            return
        self._token = secrets.token_hex(TOKEN_BYTES)
        self._ready: queue.Queue[socket.socket] = queue.Queue()
        self._publish_lock = threading.Lock()
        self._handshaking: set[socket.socket] = set()
        self._pending = threading.BoundedSemaphore(MAX_PENDING_HANDSHAKES)
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if os.name == "nt":
            # Without it another process could bind the same port on Windows.
            self._socket.setsockopt(socket.SOL_SOCKET, getattr(socket, "SO_EXCLUSIVEADDRUSE", -5), 1)
        try:
            self._socket.bind(("127.0.0.1", 0))
            self._socket.listen(backlog)
            port = self._socket.getsockname()[1]
            _write_private(Path(path), json.dumps(
                {"port": port, "token": self._token, "pid": os.getpid()}).encode("utf-8"))
        except Exception:
            self._socket.close()
            raise
        self._socket.settimeout(0.5)
        threading.Thread(target=self._accept_raw, name=f"ipc-accept-{Path(path).name}",
                         daemon=True).start()

    def settimeout(self, timeout: float | None) -> None:
        self._timeout = timeout
        if BACKEND == "unix":
            self._socket.settimeout(timeout)

    def accept(self) -> tuple[socket.socket, object]:
        if BACKEND == "unix":
            return self._socket.accept()
        deadline = None if self._timeout is None else time.monotonic() + self._timeout
        while True:
            if self._closed:
                raise OSError("listener closed")
            wait = 0.25 if deadline is None else min(0.25, max(0.0, deadline - time.monotonic()))
            try:
                return self._ready.get(timeout=wait), None
            except queue.Empty:
                if deadline is not None and time.monotonic() >= deadline:
                    raise socket.timeout("accept timed out") from None

    def _accept_raw(self) -> None:
        while not self._closed:
            try:
                client, _ = self._socket.accept()
            except socket.timeout:
                continue
            except OSError:
                if self._closed:
                    return
                time.sleep(0.05)  # e.g. WSAECONNRESET from a peer that gave up
                continue
            if not self._pending.acquire(blocking=False):
                client.close()  # Too many unauthenticated peers at once.
                continue
            with self._publish_lock:
                if self._closed:
                    self._pending.release()
                    client.close()
                    return
                self._handshaking.add(client)
            threading.Thread(target=self._authenticate, args=(client,), daemon=True).start()

    def _authenticate(self, client: socket.socket) -> None:
        try:
            deadline = time.monotonic() + HANDSHAKE_TIMEOUT
            line = bytearray()
            # One byte at a time: nothing past the newline may be consumed.
            while not line.endswith(b"\n"):
                remaining = deadline - time.monotonic()
                if remaining <= 0 or len(line) > TOKEN_BYTES * 2 + 1:
                    raise OSError("handshake failed")
                client.settimeout(remaining)
                byte = client.recv(1)
                if not byte:
                    raise OSError("handshake failed")
                line.extend(byte)
            if not hmac.compare_digest(bytes(line[:-1]), self._token.encode("ascii")):
                raise OSError("handshake failed")
            client.settimeout(None)
            with self._publish_lock:  # never queue a client once close() drained the queue
                self._handshaking.discard(client)  # ownership moves to the queue atomically
                if self._closed:
                    raise OSError("listener closed")
                self._ready.put(client)
        except OSError:
            with self._publish_lock:
                self._handshaking.discard(client)
            client.close()
        finally:
            self._pending.release()

    def close(self) -> None:
        if BACKEND == "tcp":
            with self._publish_lock:
                self._closed = True
                pending = list(self._handshaking)
            for client in pending:  # wake handshakes now instead of at their deadline
                try:
                    client.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                client.close()
        self._closed = True
        try:
            self._socket.close()
        finally:
            if BACKEND == "tcp":
                while True:
                    try:
                        self._ready.get_nowait().close()
                    except queue.Empty:
                        break
                record = _read_endpoint(self.path)
                if record is not None and record.get("token") == self._token:
                    remove(self.path)  # Never delete a newer listener's record.
            else:
                remove(self.path)


def listen(path: str | Path, backlog: int = 8) -> Listener:
    return Listener(str(path), backlog)


def connect(path: str | Path, timeout: float | None = None) -> socket.socket:
    path = str(path)
    if BACKEND == "unix":
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.settimeout(timeout)
        try:
            client.connect(path)
        except Exception:
            client.close()
            raise
        return client
    record = _read_endpoint(path)
    if record is None:
        raise FileNotFoundError(f"no hub endpoint at {path}")
    client = socket.create_connection(("127.0.0.1", record["port"]), timeout=timeout)
    try:
        client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        client.sendall(record["token"].encode("ascii") + b"\n")
    except Exception:
        client.close()
        raise
    return client


def read_line(sock: socket.socket, limit: int = 65536, timeout: float | None = None) -> bytes:
    """Read one newline-terminated message, however the stream fragments it."""
    deadline = None if timeout is None else time.monotonic() + timeout
    data = bytearray()
    while b"\n" not in data:
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise socket.timeout("timed out waiting for a reply")
            sock.settimeout(remaining)
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("peer closed before a complete line")
        data.extend(chunk)
        if len(data) > limit:
            raise ValueError("message too large")
    return bytes(data.split(b"\n", 1)[0])


def make_nonblocking(sock: socket.socket) -> None:
    """Fan-out sockets: sends never block, reads go through `recv_ready`."""
    sock.setblocking(False)


def send_nowait(sock: socket.socket, data: bytes) -> int:
    """Send without blocking on a `make_nonblocking` socket (partial counts as slow)."""
    flags = getattr(socket, "MSG_NOSIGNAL", 0)
    return sock.send(data, flags) if flags else sock.send(data)


def recv_ready(sock: socket.socket, size: int, stop: threading.Event,
               poll: float = 0.5) -> bytes:
    """Blocking-style read on a non-blocking socket; b"" on EOF or stop."""
    while not stop.is_set():
        try:
            readable, _, _ = select.select([sock], [], [], poll)
        except (OSError, ValueError):
            return b""
        if not readable:
            continue
        try:
            return sock.recv(size)
        except (BlockingIOError, InterruptedError):
            continue
    return b""


# ----------------------------------------------------------------- locks

class FileLock:
    """Advisory whole-file lock released by the OS when the process dies."""

    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        self._fd: int | None = None

    def acquire(self, blocking: bool = True) -> bool:
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR | _NOFOLLOW, 0o600)
        try:
            while True:
                if _try_lock(fd):
                    self._fd = fd
                    return True
                if not blocking:
                    os.close(fd)
                    return False
                time.sleep(0.05)
        except BaseException:
            os.close(fd)
            raise

    def release(self) -> None:
        fd, self._fd = self._fd, None
        if fd is None:
            return
        try:
            _unlock(fd)
        finally:
            os.close(fd)

    def __enter__(self) -> "FileLock":
        self.acquire()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.release()


if os.name == "nt":
    import msvcrt

    def _try_lock(fd: int) -> bool:
        os.lseek(fd, 0, os.SEEK_SET)
        try:
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)  # byte 0; may lie past EOF
        except OSError:
            return False
        return True

    def _unlock(fd: int) -> None:
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
else:
    import fcntl

    def _try_lock(fd: int) -> bool:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return False
        return True

    def _unlock(fd: int) -> None:
        fcntl.flock(fd, fcntl.LOCK_UN)


# -------------------------------------------------------------- processes

def pid_alive(pid: object) -> bool:
    if type(pid) is not int or pid <= 0:
        return False
    if os.name == "nt":
        # os.kill(pid, 0) would TerminateProcess() on Windows.
        import ctypes
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        handle = kernel32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        if not handle:
            return ctypes.get_last_error() == 5  # ERROR_ACCESS_DENIED: exists, not ours
        try:
            code = ctypes.c_ulong()
            if not kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
                return False
            return code.value == 259  # STILL_ACTIVE
        finally:
            kernel32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


# ------------------------------------------------------- hub registration

def _registry() -> Path:
    return private_dir(runtime_dir() / "registry")


def register(path: str | Path) -> None:
    """Advertise a root hub so dashboards find it even at a custom path."""
    path = os.path.abspath(str(path))
    entry = _registry() / hashlib.sha256(path.encode("utf-8")).hexdigest()[:16]
    _write_private(entry, path.encode("utf-8"))


def unregister(path: str | Path) -> None:
    path = os.path.abspath(str(path))
    remove(_registry() / hashlib.sha256(path.encode("utf-8")).hexdigest()[:16])


def registered() -> list[str]:
    """Live root hub paths; stale entries from crashed hubs are pruned."""
    paths = []
    try:
        entries = sorted(_registry().iterdir())
    except OSError:
        return paths
    for entry in entries:
        if entry.name.startswith("."):
            continue
        try:
            path = entry.read_text(encoding="utf-8").strip()
        except OSError:
            continue
        if endpoint_exists(path) and endpoint_exists(f"{path}.ctl"):
            paths.append(path)
        elif not os.path.exists(path):
            remove(entry)
    default = default_hub_path()
    if default not in paths and endpoint_exists(default) and endpoint_exists(f"{default}.ctl"):
        paths.append(default)
    return paths


def configure_console_streams() -> None:
    """Never crash on a log line the console code page cannot encode."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(errors="replace")
            except (OSError, ValueError):
                pass
