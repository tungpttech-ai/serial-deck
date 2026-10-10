"""Paired remote Unix sockets reached through hub-owned SSH tunnels.

A device profile names one remote host and one Unix stream socket on it;
`ssh-socket://<name>` claims it like a UART. The hub runs
`ssh -N -L <local socket>:<remote socket>` with this tool's own key and
known_hosts, and the channel streams that socket (a console, a daemon's
byte stream, a UART bridge...).

Nothing secret is stored: profiles hold host/user/paths, the private key lives
in its own 0600 file, and a password or key passphrase only reaches one ssh
process through an SSH_ASKPASS helper that reads a FIFO. Pairing installs a
per-device key restricted to tunnels and a few fixed verbs (never a shell).

POSIX only: it needs AF_UNIX locally and a FIFO for SSH_ASKPASS.
"""

from __future__ import annotations

import os
import re
import secrets
import shlex
import shutil
import socket
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Callable

try:
    from . import ipc, runtime
except ImportError:
    import ipc
    import runtime

SCHEME = "ssh-socket://"
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}$")
HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.:_-]{0,252}$")
USER_RE = re.compile(r"^[a-z_][a-z0-9_.-]{0,31}$")
REMOTE_PATH_RE = re.compile(r"^/[A-Za-z0-9._/-]{1,100}$")
LINK_STATES = ("connecting", "connected", "reconnecting", "auth_failed", "host_key_changed",
               "passphrase_required", "socket_missing", "unreachable", "closed")
CONNECT_TIMEOUT_S = 5
SSH_TIMEOUT_S = 20.0
BACKOFF_S = (0.5, 1.0, 2.0, 4.0, 8.0, 15.0)
REDACT_KEYS = ("password", "passphrase")
HELPER_NAME = "serial-deck-ssh"
HELPER_VERSION = "serial-deck-ssh 1"
MARKER_PREFIX = "serial-deck-device="
KEY_NEEDS_PASSPHRASE = ("passphrase_required",)


class SshSocketError(OSError):
    """An SSH device operation failed; `state` is one of LINK_STATES or a pairing code."""

    def __init__(self, state: str, message: str) -> None:
        super().__init__(message)
        self.state = state


def supported() -> bool:
    return os.name == "posix" and hasattr(socket, "AF_UNIX")


def require_supported() -> None:
    if not supported():
        raise SshSocketError("unsupported", "ssh-socket:// devices need Linux or macOS")


def config_dir() -> Path:
    base = os.environ.get("SERIAL_DECK_CONFIG") or os.path.join(
        os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config"), "serial-deck")
    return Path(base)


def tunnel_dir() -> Path:
    """Local tunnel sockets: kept short (macOS sun_path is 104 bytes), 0700."""
    base = ipc.runtime_dir()
    if len(os.fsencode(str(base))) > 60:
        base = ipc.private_dir(Path(f"/tmp/serial-deck-{ipc._uid_tag()}"))
    return ipc.private_dir(base / "ssh")


def _private_dir(path: Path) -> Path:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path, 0o700)
    return path


def _write_private(path: Path, text: str) -> None:
    """Atomic 0600 write next to `path`."""
    _private_dir(path.parent)
    fd, temp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
        os.chmod(temp, 0o600)
        os.replace(temp, path)
    except BaseException:
        try:
            os.unlink(temp)
        except FileNotFoundError:
            pass
        raise


def redact_text(text: str) -> str:
    """ssh output never carries the password, but strip anything after a prompt."""
    return re.sub(r"(?i)(password|passphrase)[^\n]*", r"\1: [redacted]", text)


def device_url(name: str) -> str:
    return f"{SCHEME}{name}"


def device_name(port: str) -> str:
    name = port[len(SCHEME):] if port.startswith(SCHEME) else ""
    if not NAME_RE.match(name):
        raise SshSocketError("invalid_argument", f"invalid SSH device: {port}")
    return name


class DeviceStore:
    """`devices.json` (0600) plus keys/ and a private known_hosts."""

    def __init__(self, root: Path | None = None) -> None:
        self.root = root or config_dir()
        self.lock = threading.RLock()

    @property
    def devices_path(self) -> Path:
        return self.root / "devices.json"

    @property
    def known_hosts(self) -> Path:
        return self.root / "known_hosts"

    def key_path(self, name: str) -> Path:
        return self.root / "keys" / name

    def load(self) -> dict[str, dict[str, Any]]:
        import json
        with self.lock:
            try:
                data = json.loads(self.devices_path.read_text(encoding="utf-8"))
            except FileNotFoundError:
                return {}
            except (OSError, ValueError) as exc:
                raise SshSocketError("invalid_profile", f"cannot read {self.devices_path}: {exc}") from exc
            devices = data.get("devices", {}) if isinstance(data, dict) else {}
            return {name: dict(item) for name, item in devices.items()
                    if NAME_RE.match(name) and isinstance(item, dict)}

    def _dump(self, devices: dict[str, dict[str, Any]]) -> None:
        import json
        _write_private(self.devices_path, json.dumps({"version": 1, "devices": devices}, indent=2) + "\n")

    def get(self, name: str) -> dict[str, Any]:
        devices = self.load()
        device = devices.get(name)
        if device is None:
            for key, item in devices.items():
                if key.lower() == name.lower():
                    return item
            raise SshSocketError("not_paired", f"no paired SSH device named {name}")
        return device

    def find(self, name: str) -> str | None:
        """Case-insensitive device name lookup."""
        for key in self.load():
            if key.lower() == name.lower():
                return key
        return None

    def save(self, device: dict[str, Any]) -> None:
        with self.lock:
            devices = self.load()
            devices[device["name"]] = device
            self._dump(devices)

    def remove(self, name: str) -> None:
        with self.lock:
            devices = self.load()
            devices.pop(name, None)
            self._dump(devices)

    def set_known_host(self, entry_host: str, lines: list[str]) -> None:
        with self.lock:
            kept = [line for line in self._known_lines() if line.split(" ", 1)[0] != entry_host]
            _write_private(self.known_hosts, "".join(f"{line}\n" for line in kept + lines))

    def drop_known_host(self, entry_host: str) -> None:
        self.set_known_host(entry_host, [])

    def _known_lines(self) -> list[str]:
        try:
            return [line for line in self.known_hosts.read_text(encoding="utf-8").splitlines() if line.strip()]
        except FileNotFoundError:
            return []


def known_host_name(host: str, port: int) -> str:
    return host if port == 22 else f"[{host}]:{port}"


def validate_profile(fields: dict[str, Any]) -> dict[str, Any]:
    name = str(fields.get("name", "")).strip()
    host = str(fields.get("host", "")).strip()
    user = str(fields.get("user", "root")).strip() or "root"
    port = fields.get("port", 22)
    remote = str(fields.get("remote_socket", "")).strip()
    if not NAME_RE.match(name):
        raise SshSocketError("invalid_argument", "name: 1-32 letters, digits, '.', '_' or '-'")
    if not HOST_RE.match(host):
        raise SshSocketError("invalid_argument", "host must be a hostname or IP address")
    if not USER_RE.match(user):
        raise SshSocketError("invalid_argument", "user must be a plain Unix user name")
    if type(port) is not int or not 1 <= port <= 65535:
        raise SshSocketError("invalid_argument", "port must be 1..65535")
    if not REMOTE_PATH_RE.match(remote) or ".." in remote:
        raise SshSocketError("invalid_argument", "remote_socket must be an absolute socket path")
    return {"name": name, "host": host, "port": port, "user": user, "remote_socket": remote}


class Askpass:
    """One-shot SSH_ASKPASS: a helper that cats a FIFO this process writes once.

    The secret is never in argv, a regular file or a lasting environment
    variable; the FIFO and helper live in a private 0700 directory removed on
    close.
    """

    def __init__(self, secret: str | bytes | bytearray, reads: int = 1) -> None:
        require_supported()
        self._reads = reads
        # Own mutable copy, wiped after the single read; the caller wipes its own.
        self._secret = bytearray(secret.encode("utf-8") if isinstance(secret, str) else secret)
        self.directory = tempfile.mkdtemp(prefix="askpass-", dir=str(tunnel_dir()))
        self.fifo = os.path.join(self.directory, "fifo")
        self.helper = os.path.join(self.directory, "askpass")
        os.mkfifo(self.fifo, 0o600)
        with open(self.helper, "w", encoding="utf-8") as handle:
            handle.write('#!/bin/sh\nexec head -n 1 "$SERIAL_DECK_ASKPASS_FIFO"\n')
        os.chmod(self.helper, 0o700)
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._stop = threading.Event()
        self._thread.start()

    def env(self) -> dict[str, str]:
        # Host programs (ssh and the /bin/sh askpass) must not load a bundle's libraries.
        env = {key: value for key, value in runtime.host_env().items()
               if key not in ("SSH_ASKPASS", "SSH_ASKPASS_REQUIRE", "DISPLAY")}
        env.update(SSH_ASKPASS=self.helper, SSH_ASKPASS_REQUIRE="force",
                   SERIAL_DECK_ASKPASS_FIFO=self.fifo)
        return env

    def _serve(self) -> None:
        # Serve exactly `reads` prompts (ssh: one; ssh-keygen -p: new + confirm).
        # A blocking open waits for the helper's `cat`; after writing, wait for
        # EOF on our side (the reader closed) before serving the next one, so
        # two answers never land in the same read.
        while not self._stop.is_set() and self._reads > 0:
            try:
                fd = os.open(self.fifo, os.O_WRONLY | os.O_NONBLOCK)
            except OSError:
                self._stop.wait(0.02)
                continue
            try:
                os.set_blocking(fd, True)
                os.write(fd, bytes(self._secret) + b"\n")
            except OSError:
                pass
            finally:
                os.close(fd)
            self._reads -= 1
            if self._reads > 0:
                self._wait_reader_gone()
        self._wipe()

    def _wait_reader_gone(self) -> None:
        """Block until the reader that got the last answer has exited."""
        deadline = time.monotonic() + 5.0
        while not self._stop.is_set() and time.monotonic() < deadline:
            try:
                probe = os.open(self.fifo, os.O_WRONLY | os.O_NONBLOCK)
            except OSError:
                return  # ENXIO: no reader holds the FIFO any more
            os.close(probe)
            self._stop.wait(0.01)

    def _wipe(self) -> None:
        for index in range(len(self._secret)):
            self._secret[index] = 0

    def close(self) -> None:
        self._stop.set()
        self._thread.join(timeout=1.0)
        self._wipe()
        shutil.rmtree(self.directory, ignore_errors=True)


def ssh_base(device: dict[str, Any], store: DeviceStore, *, batch: bool = True,
             key: str | None = None) -> list[str]:
    command = [
        "ssh", "-F", "/dev/null", "-p", str(device["port"]), "-l", device["user"],
        "-o", f"UserKnownHostsFile={store.known_hosts}", "-o", "GlobalKnownHostsFile=/dev/null",
        "-o", "StrictHostKeyChecking=yes", "-o", f"ConnectTimeout={CONNECT_TIMEOUT_S}",
        "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=3",
        "-o", "LogLevel=ERROR",
    ]
    if batch:
        command += ["-o", "BatchMode=yes"]
    key = key if key is not None else device.get("key_path", "")
    if key:
        command += ["-i", os.path.expanduser(key), "-o", "IdentitiesOnly=yes"]
    return command


def classify_ssh_error(text: str, returncode: int) -> str:
    lowered = text.lower()
    if "remote host identification has changed" in lowered or "host key verification failed" in lowered:
        return "host_key_changed"
    if "permission denied" in lowered or "too many authentication failures" in lowered:
        return "auth_failed"
    if returncode == 255:
        return "unreachable"
    return "remote_failed"


def wipe(secret: Any) -> None:
    """Zero a bytearray secret in place (str cannot be wiped; avoid it)."""
    if isinstance(secret, bytearray):
        for index in range(len(secret)):
            secret[index] = 0


def run_ssh(device: dict[str, Any], store: DeviceStore, remote: str, *, stdin: str = "",
            secret: str | bytearray = "", password: bool = False, key: str | None = None,
            timeout: float = SSH_TIMEOUT_S, env: dict[str, str] | None = None) -> str:
    """Run one remote command; raises SshSocketError with a link state."""
    require_supported()
    askpass = Askpass(secret) if secret else None
    try:
        command = ssh_base(device, store, batch=askpass is None, key=key)
        if password:
            command += ["-o", "PreferredAuthentications=password,keyboard-interactive",
                        "-o", "PubkeyAuthentication=no", "-o", "NumberOfPasswordPrompts=1"]
        elif askpass is not None:
            command += ["-o", "PreferredAuthentications=publickey", "-o", "NumberOfPasswordPrompts=1"]
        command += ["--", device["host"], remote]
        try:
            # input="" still gives ssh a pipe, so it never reads the dashboard's stdin.
            result = subprocess.run(command, input=stdin, capture_output=True, text=True,
                                    timeout=timeout, env=askpass.env() if askpass else (env or runtime.host_env()),
                                    start_new_session=True)
        except subprocess.TimeoutExpired as exc:
            raise SshSocketError("unreachable", f"ssh {device['host']} timed out") from exc
        except FileNotFoundError as exc:
            raise SshSocketError("unreachable", "ssh client is not installed") from exc
        if result.returncode != 0:
            detail = redact_text(result.stderr.strip())[-400:]
            raise SshSocketError(classify_ssh_error(result.stderr, result.returncode),
                                 detail or f"ssh exited {result.returncode}")
        return result.stdout
    finally:
        if askpass is not None:
            askpass.close()


def _fingerprint_of(key_type: str, blob: str) -> str | None:
    try:
        result = subprocess.run(["ssh-keygen", "-lf", "-"], input=f"{key_type} {blob}\n",
                                capture_output=True, text=True, timeout=5, env=runtime.host_env())
    except (OSError, subprocess.TimeoutExpired):
        return None
    fields = result.stdout.split()
    return fields[1] if result.returncode == 0 and len(fields) >= 2 else None


def scan_host_keys(host: str, port: int) -> list[dict[str, str]]:
    """TOFU: keys the host offers now, with SHA256 fingerprints (no trust yet)."""
    if not HOST_RE.match(host):
        raise SshSocketError("invalid_argument", "invalid host")
    try:
        scan = subprocess.run(["ssh-keyscan", "-T", str(CONNECT_TIMEOUT_S), "-p", str(port),
                               "-t", "ed25519,ecdsa,rsa", "--", host],
                              capture_output=True, text=True, timeout=CONNECT_TIMEOUT_S * 3,
                              env=runtime.host_env())
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SshSocketError("unreachable", f"cannot reach {host}:{port}: {exc}") from exc
    keys = []
    for line in scan.stdout.splitlines():
        parts = line.split()
        if line.startswith("#") or len(parts) < 3:
            continue
        fingerprint = _fingerprint_of(parts[1], parts[2])
        if fingerprint:
            keys.append({"type": parts[1], "fingerprint": fingerprint,
                         "line": f"{known_host_name(host, port)} {parts[1]} {parts[2]}"})
    if not keys:
        raise SshSocketError("unreachable", f"no SSH host key from {host}:{port}")
    order = {"ssh-ed25519": 0}
    keys.sort(key=lambda item: order.get(item["type"], 1))
    return keys


def pinned_fingerprints(store: DeviceStore, host: str, port: int) -> list[str]:
    entry = known_host_name(host, port)
    prints = []
    for line in store._known_lines():
        parts = line.split()
        if len(parts) >= 3 and parts[0] == entry:
            fingerprint = _fingerprint_of(parts[1], parts[2])
            if fingerprint:
                prints.append(fingerprint)
    return prints


def generate_key(store: DeviceStore, name: str, passphrase: bytearray | None = None) -> tuple[Path, str]:
    """Device key; with `passphrase` it is encrypted and every connect asks for it."""
    key = store.key_path(name)
    _private_dir(key.parent)
    if passphrase:
        for path in (key, Path(f"{key}.pub")):
            try:
                path.unlink()
            except FileNotFoundError:
                pass
    if not key.exists():
        comment = f"serial-deck@{socket.gethostname()}"
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", comment, "-f", str(key)],
                       check=True, capture_output=True, timeout=10, env=runtime.host_env())
        if passphrase:
            # -N would put the passphrase on argv: encrypt in a second step.
            protect_key(key, passphrase)
    os.chmod(key, 0o600)
    public = Path(f"{key}.pub").read_text(encoding="utf-8").strip()
    return key, public


def protect_key(key: Path, passphrase: bytearray) -> None:
    """Encrypt `key` in place without the passphrase ever reaching argv.

    ssh-keygen -p prompts on its controlling terminal (new + confirm), so it
    runs on a private pty that this process answers; nothing is written to
    disk or the environment.
    """
    import pty
    import select
    env = runtime.host_env()  # built before the fork: the child only execs
    pid, fd = pty.fork()
    if pid == 0:  # child: exec immediately, no Python threads involved
        os.execvpe("ssh-keygen", ["ssh-keygen", "-q", "-p", "-P", "", "-f", str(key)], env)
    output = bytearray()
    answered = 0
    status = 0
    try:
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            ready, _, _ = select.select([fd], [], [], 0.2)
            if not ready:
                continue
            try:
                chunk = os.read(fd, 1024)
            except OSError:
                break  # EIO: child closed the pty
            if not chunk:
                break
            output.extend(chunk)
            # Exactly two prompts ("Enter new passphrase ...:", "Enter same
            # passphrase again:"); answer each once, only when it ends the output.
            prompts = output.count(b"passphrase (empty") + output.count(b"passphrase again")
            if prompts > answered and output.rstrip().endswith(b":"):
                os.write(fd, bytes(passphrase) + b"\n")
                answered += 1
    finally:
        os.close(fd)
        _, status = os.waitpid(pid, 0)
        wipe(output)
    if os.waitstatus_to_exitcode(status) != 0 or answered != 2:
        raise SshSocketError("invalid_argument", "cannot set the device key passphrase")


# Forced command of the device key on the remote host: verbs only, never a
# shell. Installed by `INSTALL_SCRIPT` as ~/.local/bin (or /usr/local/sbin for
# root) and run by sshd for every non-tunnel login of that key.
HELPER_SCRIPT = r"""#!/bin/sh
# Forced command for a Serial Deck device key.
#   restrict,port-forwarding,command="<path> <name>" ssh-ed25519 AAAA... [serial-deck-device=<name>]
# The key can open socket tunnels (ssh -N) and run only the verbs below.
set -u
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
NAME="${1:-}"
AUTH="$HOME/.ssh/authorized_keys"
fail() { echo "serial-deck-ssh: $*" >&2; exit 2; }
case "$NAME" in ''|*[!A-Za-z0-9_.-]*) fail "bad device name" ;; esac
verb=$(printf '%s' "${SSH_ORIGINAL_COMMAND:-}" | cut -d' ' -f1)
arg=$(printf '%s' "${SSH_ORIGINAL_COMMAND:-}" | cut -s -d' ' -f2)
case "$verb" in
    version)
        echo "serial-deck-ssh 1"
        ;;
    probe)
        case "$arg" in /*) ;; *) fail "probe needs an absolute path" ;; esac
        case "$arg" in *[!A-Za-z0-9._/-]*|*..*) fail "bad path" ;; esac
        if [ -S "$arg" ]; then echo "$arg"; else echo "missing"; fi
        ;;
    forget)
        # Remove exactly this device's key line(s). Binary-safe (-a), checked
        # line counts, backup, atomic replace: never truncate other keys.
        [ -f "$AUTH" ] || { echo "forget: no authorized_keys"; exit 0; }
        marker="[serial-deck-device=$NAME]"
        before=$(LC_ALL=C grep -a -c '' "$AUTH")
        drop=$(LC_ALL=C grep -a -c -F -- "$marker" "$AUTH")
        [ "$drop" -gt 0 ] || { echo "forget: no key for $NAME"; exit 0; }
        tmp=$(mktemp "$AUTH.sd.XXXXXX") || fail "mktemp failed"
        LC_ALL=C grep -a -v -F -- "$marker" "$AUTH" > "$tmp"
        after=$(LC_ALL=C grep -a -c '' "$tmp")
        if [ "$after" -ne $((before - drop)) ]; then
            rm -f "$tmp"
            fail "line count check failed ($before - $drop != $after); file unchanged"
        fi
        cp -p "$AUTH" "$AUTH.sd-bak"
        chmod 600 "$tmp"
        mv -f "$tmp" "$AUTH"
        echo "forget: removed $drop line(s)"
        ;;
    "")
        fail "this key only opens socket tunnels"
        ;;
    *)
        fail "verb not allowed: $verb"
        ;;
esac
"""

# Installer run once at pairing (password or a full-access key). stdin: line 1
# = the authorized_keys line with `__HELPER__` for the helper path, then the
# helper script. Binary-safe, checks line counts, keeps a backup and replaces
# authorized_keys atomically: other keys are never touched.
INSTALL_SCRIPT = r"""
set -eu
umask 077
IFS= read -r line
if [ "$(id -u)" = 0 ]; then
  helper=/usr/local/sbin/serial-deck-ssh
else
  helper="$HOME/.local/bin/serial-deck-ssh"
fi
mkdir -p "$(dirname "$helper")" "$HOME/.ssh"
cat > "$helper.new"
chmod 755 "$helper.new"; mv -f "$helper.new" "$helper"
line="${line%%__HELPER__*}$helper${line#*__HELPER__}"
auth="$HOME/.ssh/authorized_keys"; touch "$auth"
key=$(printf '%s\n' "$line" | awk '{for (i = 1; i < NF; i++) if ($i == "ssh-ed25519") { print $i " " $(i + 1); exit }}')
marker=$(printf '%s\n' "$line" | awk '{print $NF}')
case "$key" in "ssh-ed25519 "?*) ;; *) echo "bad key line" >&2; exit 3 ;; esac
case "$marker" in "[serial-deck-device="*"]") ;; *) echo "bad marker" >&2; exit 3 ;; esac
before=$(LC_ALL=C grep -a -c '' "$auth" || true)
drop=$( { LC_ALL=C grep -a -F -- "$key" "$auth"; LC_ALL=C grep -a -F -- "$marker" "$auth"; } | sort -u | LC_ALL=C grep -a -c '' || true)
tmp=$(mktemp "$auth.sd.XXXXXX")
LC_ALL=C grep -a -v -F -e "$key" -e "$marker" "$auth" > "$tmp" || true
after=$(LC_ALL=C grep -a -c '' "$tmp" || true)
if [ "$after" -ne $((before - drop)) ]; then rm -f "$tmp"; echo "line count check failed; authorized_keys unchanged" >&2; exit 3; fi
printf '%s\n' "$line" >> "$tmp"
cp -p "$auth" "$auth.sd-bak"
chmod 600 "$tmp"; mv -f "$tmp" "$auth"
echo "installed $helper"
"""


def authorized_line(name: str, public: str) -> str:
    """Restricted key: socket tunnels + the forced-command verbs, no shell."""
    parts = public.split()
    kind, blob = parts[:2]
    comment = parts[2] if len(parts) > 2 else "serial-deck"
    return (f'restrict,port-forwarding,command="__HELPER__ {name}" {kind} {blob} '
            f'{comment} [{MARKER_PREFIX}{name}]')


def install_restricted_key(device: dict[str, Any], store: DeviceStore, public: str, *,
                           secret: str | bytearray = "", password: bool = False,
                           key: str | None = None) -> str:
    stdin = f"{authorized_line(device['name'], public)}\n{HELPER_SCRIPT}"
    return run_ssh(device, store, f"sh -c {shlex.quote(INSTALL_SCRIPT)}", stdin=stdin,
                   secret=secret, password=password, key=key)


def verb(device: dict[str, Any], store: DeviceStore, command: str, **kwargs: Any) -> str:
    """Run one forced-command verb with the device key (never a shell)."""
    return run_ssh(device, store, command, **kwargs)


def probe_socket(device: dict[str, Any], store: DeviceStore, **kwargs: Any) -> str:
    """The remote socket path, or SshSocketError(socket_missing)."""
    output = verb(device, store, f"probe {device['remote_socket']}", **kwargs)
    if device["remote_socket"] not in output.split():
        raise SshSocketError("socket_missing", f"no socket {device['remote_socket']} on the host")
    return device["remote_socket"]


class Tunnel:
    """One `ssh -N -L` process forwarding the remote socket to a local one."""

    def __init__(self, device: dict[str, Any], store: DeviceStore, secret: str | bytearray = "") -> None:
        require_supported()
        self.device = device
        self.store = store
        tag = f"{device['name'][:12]}-{secrets.token_hex(3)}"
        self.local_socket = str(tunnel_dir() / f"{tag}.sock")
        self.process: subprocess.Popen[str] | None = None
        self._askpass = Askpass(secret) if secret else None
        self.stderr = ""

    def start(self, timeout: float = SSH_TIMEOUT_S) -> None:
        command = ssh_base(self.device, self.store, batch=self._askpass is None)
        command += ["-N", "-o", "ExitOnForwardFailure=yes", "-o", "StreamLocalBindUnlink=yes",
                    "-o", "StreamLocalBindMask=0177",
                    "-L", f"{self.local_socket}:{self.device['remote_socket']}",
                    "--", self.device["host"]]
        self.process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                        stderr=subprocess.PIPE, text=True, start_new_session=True,
                                        env=self._askpass.env() if self._askpass else runtime.host_env())
        deadline = time.monotonic() + timeout
        try:
            while time.monotonic() < deadline:
                if self.process.poll() is not None:
                    self.stderr = redact_text(self.process.stderr.read() if self.process.stderr else "")
                    raise SshSocketError(classify_ssh_error(self.stderr, self.process.returncode),
                                         self.stderr.strip()[-400:] or "ssh tunnel exited")
                if os.path.exists(self.local_socket):
                    return
                time.sleep(0.05)
            raise SshSocketError("unreachable", f"ssh tunnel to {self.device['host']} did not come up")
        except BaseException:
            self.close()
            raise
        finally:
            if self._askpass is not None:
                self._askpass.close()
                self._askpass = None

    def alive(self) -> bool:
        return self.process is not None and self.process.poll() is None

    def close(self) -> None:
        process = self.process
        self.process = None
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)
        try:
            os.unlink(self.local_socket)
        except FileNotFoundError:
            pass


class SshSocketTransport:
    """Hub channel device for `ssh-socket://name`: tunnel + remote socket stream.

    read() never raises for a lost link: the transport reconnects in the
    background with backoff and reports `link_state()`; write() refuses while
    not connected so bytes are never half-sent into a dead tunnel.
    """

    scheme = "ssh-socket"

    def __init__(self, port: str, timeout: float, store: DeviceStore | None = None,
                 secret: bytearray | None = None) -> None:
        self.name = device_name(port)
        self.store = store or DeviceStore()
        self.device = self.store.get(self.name)
        self.timeout = timeout
        self._lock = threading.Lock()
        self._listener: Callable[[], None] | None = None
        self._sock: socket.socket | None = None
        self._tunnel: Tunnel | None = None
        self._state = "connecting"
        self._detail = ""
        self._closed = threading.Event()
        self._wake = threading.Event()
        self._attempt = 0
        try:
            self._connect(secret)  # first attempt is synchronous: claim reports why it failed
        finally:
            wipe(secret)
        self._thread = threading.Thread(target=self._supervise, name=f"ssh-socket-{self.name}", daemon=True)
        self._thread.start()

    # Link state ---------------------------------------------------------

    def set_listener(self, listener: Callable[[], None] | None) -> None:
        self._listener = listener

    def link_state(self) -> dict[str, Any]:
        with self._lock:
            return {"kind": "ssh-socket", "device": self.name, "state": self._state,
                    "detail": self._detail, "host": self.device["host"], "user": self.device["user"],
                    "attempt": self._attempt}

    @property
    def available(self) -> bool:
        with self._lock:
            return self._state == "connected" and self._sock is not None

    def _set_state(self, state: str, detail: str = "") -> None:
        with self._lock:
            changed = (state, detail) != (self._state, self._detail)
            self._state, self._detail = state, detail
        if changed and self._listener is not None:
            try:
                self._listener()
            except Exception:
                pass

    def _connect(self, secret: bytearray | None = None) -> None:
        """Build the tunnel if needed, then open one stream to the remote socket.

        A remote service restart only needs a new stream over the live tunnel;
        only a lost SSH connection rebuilds it, which for a passphrase-protected
        key means asking the user again (`passphrase_required`, never stored).
        """
        tunnel = self._tunnel
        try:
            if tunnel is None or not tunnel.alive():
                if tunnel is not None:
                    tunnel.close()
                self._tunnel = None
                self.device = self.store.get(self.name)
                if self.device.get("key_protected") and not secret:
                    raise SshSocketError("passphrase_required",
                                         "the device key is protected: enter its passphrase to connect")
                probe_socket(self.device, self.store, secret=secret or "")
                tunnel = Tunnel(self.device, self.store, secret or "")
                tunnel.start()
                self._tunnel = tunnel
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            try:
                sock.connect(tunnel.local_socket)
            except OSError as exc:
                sock.close()
                raise SshSocketError("socket_missing", f"remote socket not reachable: {exc}") from exc
        except SshSocketError as exc:
            self._set_state(exc.state, str(exc))
            raise
        with self._lock:
            self._sock = sock
            self._attempt = 0
        self._set_state("connected")

    def _drop(self, reason: str) -> None:
        with self._lock:
            sock, self._sock = self._sock, None
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        if not self._closed.is_set():
            self._set_state("reconnecting", reason)
            self._wake.set()

    def _supervise(self) -> None:
        while not self._closed.is_set():
            self._wake.wait(1.0)
            self._wake.clear()
            if self._closed.is_set() or self.available:
                continue
            with self._lock:
                state = self._state
                delay = BACKOFF_S[min(self._attempt, len(BACKOFF_S) - 1)]
                self._attempt += 1
            # Host key changes and protected keys never heal by retrying: wait
            # for a re-pair or for the user to enter the passphrase.
            if state in ("host_key_changed", "passphrase_required"):
                continue
            if self._closed.wait(delay):
                return
            try:
                self._connect()
            except SshSocketError as exc:
                if exc.state not in ("auth_failed", "host_key_changed", "passphrase_required"):
                    self._set_state("reconnecting" if exc.state == "unreachable" else exc.state, str(exc))

    def unlock(self, secret: bytearray) -> dict[str, Any]:
        """Rebuild the tunnel now with the passphrase the user just typed."""
        try:
            if not self.available:
                self._connect(secret)
        finally:
            wipe(secret)
        return self.link_state()

    def retry_now(self) -> None:
        with self._lock:
            self._attempt = 0
            if self._state == "host_key_changed":
                self._state = "reconnecting"
        self._wake.set()

    # Stream -------------------------------------------------------------

    def read(self, size: int = 4096) -> bytes:
        with self._lock:
            sock = self._sock
        if sock is None:
            if self._closed.is_set():
                raise OSError("SSH device link closed")
            time.sleep(self.timeout)
            return b""
        try:
            data = sock.recv(size)
        except socket.timeout:
            return b""
        except OSError as exc:
            self._drop(f"socket error: {exc}")
            return b""
        if not data:
            self._drop("the remote socket closed (service restart or exit)")
            return b""
        return data

    def write(self, frame: bytes) -> None:
        with self._lock:
            sock = self._sock
            state = self._state
        if sock is None:
            raise SshSocketError(state, f"SSH device link is {state}; nothing was sent")
        sock.sendall(frame)

    def _unsupported(self, what: str) -> OSError:
        return OSError(f"{what} needs a physical UART")

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

    def set_baud(self, baud: int) -> None:
        """A socket has no baud; keep the hub's label only."""

    def close(self) -> None:
        self._closed.set()
        self._wake.set()
        with self._lock:
            sock, self._sock = self._sock, None
            self._state = "closed"
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        tunnel, self._tunnel = self._tunnel, None
        if tunnel is not None:
            tunnel.close()


# Hub control actions -------------------------------------------------------

def public_profile(device: dict[str, Any]) -> dict[str, Any]:
    keep = ("name", "host", "port", "user", "remote_socket", "paired_at", "fingerprint",
            "installer", "key_protected")
    return {key: device[key] for key in keep if key in device}


def list_devices(store: DeviceStore, live: dict[str, dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    live = live or {}
    return [{**public_profile(device), "port_url": device_url(name), "link": live.get(name)}
            for name, device in sorted(store.load().items())]


def fingerprint(store: DeviceStore, host: str, port: int) -> dict[str, Any]:
    keys = scan_host_keys(host, port)
    pinned = pinned_fingerprints(store, host, port)
    offered = [key["fingerprint"] for key in keys]
    return {"host": host, "port": port, "keys": [{k: v for k, v in key.items() if k != "line"} for key in keys],
            "fingerprint": keys[0]["fingerprint"], "type": keys[0]["type"],
            "pinned": pinned, "changed": bool(pinned) and not set(pinned) & set(offered)}


def pair(store: DeviceStore, request: dict[str, Any]) -> dict[str, Any]:
    """Pin the confirmed host key, install a restricted per-device key, verify it.

    `auth` picks how the installer logs in once: "password", "key" (an existing
    key_path, optional passphrase) or "agent". Every device then uses its own
    keys/<name>, limited by a forced command on the host to socket tunnels and
    fixed verbs; with `key_passphrase` that key is encrypted and each SSH
    connection asks for it. The installer credential is never stored and
    every secret (bytearray) is wiped after the one ssh process that needs it.
    """
    require_supported()
    profile = validate_profile(request)
    expected = str(request.get("fingerprint", ""))
    auth = str(request.get("auth", "password"))
    raw = request.pop("password", None) if auth == "password" else request.pop("passphrase", None)
    request.pop("password", None)
    request.pop("passphrase", None)
    secret = raw if isinstance(raw, bytearray) else bytearray(str(raw or "").encode("utf-8"))
    raw = None
    steps: list[dict[str, Any]] = []
    if auth not in ("password", "key", "agent"):
        raise SshSocketError("invalid_argument", "auth must be password, key or agent")
    if not expected.startswith("SHA256:"):
        raise SshSocketError("invalid_argument", "confirm the host fingerprint first")
    if auth == "password" and not secret:
        raise SshSocketError("invalid_argument", "password required to install the key")
    installer_key = ""
    if auth == "key":
        installer_key = os.path.expanduser(str(request.get("key_path", "")))
        if not installer_key or not os.path.isfile(installer_key):
            raise SshSocketError("invalid_argument", "key_path must name an existing private key")
    host_entry = known_host_name(profile["host"], profile["port"])

    keys = scan_host_keys(profile["host"], profile["port"])
    if expected not in [key["fingerprint"] for key in keys]:
        raise SshSocketError("host_key_changed", "the host key changed after you confirmed it")
    pinned = pinned_fingerprints(store, profile["host"], profile["port"])
    if pinned and expected not in pinned and not request.get("replace_host_key"):
        raise SshSocketError("host_key_changed",
                             f"{host_entry} is pinned to another key ({pinned[0]}); confirm a re-pair")
    store.set_known_host(host_entry, [key["line"] for key in keys if key["fingerprint"] == expected])
    steps.append({"step": "host_key", "ok": True, "fingerprint": expected})

    key_secret = request.pop("key_passphrase", None)
    key_secret = key_secret if isinstance(key_secret, bytearray) else \
        bytearray(str(key_secret or "").encode("utf-8"))
    # Verification below logs in with the device key: keep the passphrase until then.
    device_secret = bytearray(key_secret)
    try:
        key_path, public = generate_key(store, profile["name"], key_secret or None)
    except BaseException:
        wipe(device_secret)
        raise
    finally:
        wipe(key_secret)
    protected = bool(device_secret)
    profile.update(key_path=str(key_path), key_comment=public.split()[-1],
                   installer=auth, key_protected=protected)
    steps.append({"step": "generate_key", "ok": True, "key": str(key_path)})
    try:
        install_restricted_key(profile, store, public, secret=secret, password=auth == "password",
                               key=installer_key if auth == "key" else "")
    finally:
        wipe(secret)
    steps.append({"step": "install_key", "ok": True,
                  "target": f"{profile['user']}@{profile['host']}:~/.ssh/authorized_keys"})

    # From here on only the restricted device key is used.
    try:
        if verb(profile, store, "version", secret=device_secret).strip() != HELPER_VERSION:
            raise SshSocketError("remote_failed", "the host did not answer with the Serial Deck helper")
        steps.append({"step": "batch_login", "ok": True})
        probe_socket(profile, store, secret=device_secret)
        tunnel = Tunnel(profile, store, device_secret)
        try:
            tunnel.start()
            check = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            check.settimeout(3.0)
            try:
                check.connect(tunnel.local_socket)
            except OSError as exc:
                raise SshSocketError("socket_missing", f"the remote socket refused the connection: {exc}") from exc
            finally:
                check.close()
        finally:
            tunnel.close()
    finally:
        wipe(device_secret)
    steps.append({"step": "connect", "ok": True, "socket": profile["remote_socket"]})
    profile.update(fingerprint=expected, paired_at=time.strftime("%Y-%m-%dT%H:%M:%S%z"))
    store.save(profile)
    return {"device": public_profile(profile), "port_url": device_url(profile["name"]), "steps": steps}


def forget(store: DeviceStore, name: str, local_only: bool = False,
           secret: bytearray | None = None) -> dict[str, Any]:
    """Remove exactly this device's key line on the host (forced-command
    `forget`, binary-safe and line-count checked), then the local key,
    profile and, when unused, the pinned host key."""
    device = store.get(name)
    removed_remote = False
    warning = ""
    if not local_only:
        if device.get("key_protected") and not secret:
            raise SshSocketError("passphrase_required",
                                 "enter the device key passphrase to remove it from the host")
        try:
            output = verb(device, store, "forget", secret=secret or "")
            removed_remote = "removed" in output
        except SshSocketError as exc:
            raise SshSocketError(exc.state, f"cannot remove the key from the host ({exc}); "
                                 "retry, or forget locally only") from exc
        finally:
            wipe(secret)
    else:
        warning = "the device's key line is still in the host's authorized_keys"
    for path in (Path(device["key_path"]), Path(f"{device['key_path']}.pub")):
        try:
            path.unlink()
        except FileNotFoundError:
            pass
    others = [d for n, d in store.load().items() if n != device["name"]
              and (d["host"], d["port"]) == (device["host"], device["port"])]
    if not others:
        store.drop_known_host(known_host_name(device["host"], device["port"]))
    store.remove(device["name"])
    return {"forgotten": device["name"], "removed_remote_key": removed_remote, "warning": warning}
