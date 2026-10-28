"""unix:// devices and paired ssh-socket:// devices, without a network or a real sshd.

A fake remote service streams bytes on a Unix socket. `ssh`, `ssh-keyscan` and
`ssh-keygen -lf` are replaced by scripts on PATH: the fake ssh records its argv
(never a password), reads the askpass FIFO like real ssh, forwards `-L local:remote`
by linking the local path to the fake service and runs the remote command with
/bin/sh, honouring the forced command of a restricted key.
"""

import os
import shutil
import socket
import stat
import tempfile
import textwrap
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from serial_deck import ipc, ssh_socket
from serial_deck import uart_client as cli
from serial_deck.hub_client import HubProcessManager
from serial_deck.uart_client import (
    NetworkTransport, is_non_serial_port, open_device_transport, open_uart_transport, port_kind)

FINGERPRINT = "SHA256:fakeFingerprintForTestsOnly0000000000000000"
OTHER_FINGERPRINT = "SHA256:someOtherKeyAfterReinstall00000000000000000"

posix_only = unittest.skipUnless(ssh_socket.supported(), "needs Unix sockets and FIFOs")


class FakeService:
    """A remote Unix stream service: greets each client, echoes upper-cased input."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server.bind(path)
        os.chmod(path, 0o600)
        self.server.listen(4)
        self.server.settimeout(0.2)
        self.clients: list[socket.socket] = []
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._accept, daemon=True)
        self.thread.start()

    def _accept(self) -> None:
        while not self.stop.is_set():
            try:
                client, _ = self.server.accept()
            except (socket.timeout, OSError):
                continue
            self.clients.append(client)
            threading.Thread(target=self._serve, args=(client,), daemon=True).start()

    def _serve(self, client: socket.socket) -> None:
        try:
            client.sendall(b"service ready\n")
            while not self.stop.is_set():
                data = client.recv(4096)
                if not data:
                    return
                client.sendall(data.upper())
        except OSError:
            return

    def drop_clients(self) -> None:
        for client in self.clients:
            try:
                client.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            client.close()
        self.clients.clear()

    def close(self) -> None:
        self.stop.set()
        self.drop_clients()
        self.server.close()
        self.thread.join(timeout=1)


def read_until(transport, needle: bytes, seconds: float = 4.0) -> bytes:
    deadline = time.monotonic() + seconds
    data = b""
    while time.monotonic() < deadline and needle not in data:
        data += transport.read()
    return data


class NonSerialPortTest(unittest.TestCase):
    def test_non_serial_ports(self):
        for port in ("tcp://h:1", "udp://h:2", "unix:///tmp/x.sock", "ssh-socket://lab"):
            self.assertTrue(is_non_serial_port(port), port)
        for port in ("/dev/ttyACM0", "COM3", "hub:///tmp/x"):
            self.assertFalse(is_non_serial_port(port), port)
        self.assertEqual(port_kind("unix:///tmp/x.sock"), "unix")
        self.assertEqual(port_kind("/dev/ttyUSB0"), "uart")
        with self.assertRaises(ValueError):
            cli.parse_unix_port("unix://relative.sock")

    def test_unix_endpoint_without_af_unix_is_a_clear_oserror(self):
        import types
        with patch.object(cli, "socket", types.SimpleNamespace()):
            with self.assertRaisesRegex(OSError, "Unix sockets"):
                NetworkTransport("unix:///tmp/x.sock", 0.1)


@posix_only
class UnixDeviceTransportTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="sd-unix-")
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.service = FakeService(os.path.join(self.dir, "svc.sock"))
        self.addCleanup(self.service.close)

    def test_unix_transport_streams_and_refuses_uart_actions(self):
        transport = open_device_transport(f"unix://{self.service.path}", 115200, 0.2)
        self.assertIsInstance(transport, NetworkTransport)
        self.addCleanup(transport.close)
        self.assertIn(b"service ready", read_until(transport, b"ready"))
        transport.write(b"hello\n")
        self.assertIn(b"HELLO", read_until(transport, b"HELLO"))
        for call in (transport.hard_reset, transport.enter_bootloader, transport.send_break,
                     transport.get_modem_lines):
            with self.assertRaises(OSError):
                call()

    def test_open_uart_transport_opens_a_unix_device_directly(self):
        transport = open_uart_transport(f"unix://{self.service.path}", 0, 0.2)
        self.addCleanup(transport.close)
        self.assertIsInstance(transport, NetworkTransport)

    def test_peer_close_surfaces_as_an_error(self):
        transport = open_device_transport(f"unix://{self.service.path}", 115200, 0.2)
        self.addCleanup(transport.close)
        read_until(transport, b"ready")
        self.service.drop_clients()
        with self.assertRaises(OSError):
            read_until(transport, b"never")


@posix_only
class HubUnixDeviceTest(unittest.TestCase):
    """A daemon claims a unix:// device; reset and flash are refused."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="sd-hub-")
        self.addCleanup(shutil.rmtree, self.dir, True)
        runtime = patch.dict(os.environ, {"SERIAL_DECK_RUNTIME_DIR": os.path.join(self.dir, "run")})
        runtime.start()
        self.addCleanup(runtime.stop)
        self.service = FakeService(os.path.join(self.dir, "svc.sock"))
        self.addCleanup(self.service.close)

    def test_claim_stream_and_refusals(self):
        from serial_deck.service import MultiPortHub
        hub = MultiPortHub(os.path.join(self.dir, "hub.sock"))
        hub.start()
        self.addCleanup(hub.close)
        manager = HubProcessManager(socket_path=str(hub.socket_path))
        manager.claim_port(f"unix://{self.service.path}", 115200)
        transport = open_uart_transport(manager.endpoint, 115200, 0.5)
        self.addCleanup(transport.close)
        # The hub keeps no history: the greeting sent at claim time is gone.
        transport.write(b"ping\n")
        self.assertIn(b"PING", read_until(transport, b"PING"))
        for action in ("reset", "bootloader"):
            with self.assertRaises(RuntimeError):
                manager.request_control(action)
        with self.assertRaisesRegex(RuntimeError, "physical UART"):
            manager.request_control("flash_preview", build_dir=self.dir, flash_baud=460800)


@unittest.skipUnless(ssh_socket.supported() and ipc.BACKEND == "unix" and hasattr(socket, "SO_PEERCRED"),
                     "needs SO_PEERCRED on unix sockets (macOS and the tcp backend rely on 0600 + a private directory)")
class HubSocketSecurityTest(unittest.TestCase):
    def test_hub_sockets_are_owner_only_and_check_peer_uid(self):
        directory = tempfile.mkdtemp(prefix="sd-sec-")
        self.addCleanup(shutil.rmtree, directory, True)
        listener = ipc.listen(os.path.join(directory, "hub.sock"))
        self.addCleanup(listener.close)
        self.assertEqual(stat.S_IMODE(os.stat(listener.path).st_mode), 0o600)
        client = ipc.connect(listener.path)
        self.addCleanup(client.close)
        self.assertTrue(ipc.same_user(client))
        accepted, _ = listener.accept()
        accepted.close()
        real_uid = os.getuid()
        with patch.object(ipc.os, "getuid", lambda: real_uid + 1):
            self.assertFalse(ipc.same_user(client))

    def test_a_foreign_uid_never_reaches_accept(self):
        directory = tempfile.mkdtemp(prefix="sd-sec-")
        self.addCleanup(shutil.rmtree, directory, True)
        listener = ipc.listen(os.path.join(directory, "hub.sock"))
        self.addCleanup(listener.close)
        listener.settimeout(0.5)
        real_uid = os.getuid()
        other = ipc.connect(listener.path)
        self.addCleanup(other.close)
        with patch.object(ipc.os, "getuid", lambda: real_uid + 1):
            with self.assertRaises(socket.timeout):
                listener.accept()


FAKE_SSH = r'''#!/usr/bin/env python3
# Behaves like sshd for one host HOME: host key, then auth, then the
# authorized_keys line of the key used (forced command for restricted keys).
import json, os, shlex, subprocess, sys, time
state = os.environ["FAKE_SSH_STATE"]
args = sys.argv[1:]
log = {"argv": args, "askpass": bool(os.environ.get("SSH_ASKPASS")), "secret_seen": None, "forced": None}
forwards, remote, i, identity = [], [], 0, ""
options = {}
while i < len(args):
    a = args[i]
    if a == "--":
        remote = args[i + 2:]
        break
    if a == "-i":
        identity = args[i + 1]
        i += 2
        continue
    if a in ("-p", "-l", "-F"):
        i += 2
        continue
    if a == "-o":
        k, _, v = args[i + 1].partition("=")
        options[k] = v
        i += 2
        continue
    if a == "-L":
        forwards.append(args[i + 1])
        i += 2
        continue
    i += 1
cfg = json.load(open(os.path.join(state, "config.json")))
if cfg.get("host_key_changed"):
    print("@@@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @@@\nHost key verification failed.", file=sys.stderr)
    sys.exit(255)
if cfg.get("unreachable"):
    print("ssh: connect to host lab port 22: No route to host", file=sys.stderr)
    sys.exit(255)
home = cfg["home"]
auth = os.path.join(home, ".ssh", "authorized_keys")
forced = None
password_login = options.get("PreferredAuthentications", "").startswith("password")
if password_login:
    secret = subprocess.run([os.environ["SSH_ASKPASS"]], capture_output=True, text=True).stdout.strip()
    log["secret_seen"] = secret == cfg.get("password")
    if secret != cfg.get("password"):
        print("Permission denied (password).", file=sys.stderr)
        sys.exit(255)
else:
    pub = open(identity + ".pub").read().split()[1] if identity and os.path.exists(identity + ".pub") else ""
    try:
        lines = open(auth, "rb").read().decode("utf-8", "replace").splitlines()
    except FileNotFoundError:
        lines = []
    line = next((l for l in lines if pub and pub in l.split()), None)
    if line is None:
        print("user@host: Permission denied (publickey).", file=sys.stderr)
        sys.exit(255)
    if cfg.get("protected_passphrase") and identity.endswith(cfg.get("protected_key", "")):
        if not os.environ.get("SSH_ASKPASS"):
            print("user@host: Permission denied (publickey).", file=sys.stderr)
            sys.exit(255)
        secret = subprocess.run([os.environ["SSH_ASKPASS"]], capture_output=True, text=True).stdout.strip()
        log["secret_seen"] = secret == cfg["protected_passphrase"]
        if secret != cfg["protected_passphrase"]:
            print("user@host: Permission denied (publickey).", file=sys.stderr)
            sys.exit(255)
    if line.startswith("restrict"):
        forced = line.split('command="', 1)[1].split('"', 1)[0]
        log["forced"] = forced
with open(os.path.join(state, "calls.jsonl"), "a") as handle:
    handle.write(json.dumps(log) + "\n")
if forwards:
    for spec in forwards:
        local, remote_path = spec.split(":", 1)
        target = cfg["sockets"].get(remote_path)
        if target is None:
            print(f"channel open failed: {remote_path}", file=sys.stderr)
            sys.exit(255)
        if os.path.exists(local):
            os.unlink(local)
        os.symlink(target, local)
    while True:
        time.sleep(0.2)
env = {**os.environ, "HOME": home}
cmd = " ".join(remote)
stdin = sys.stdin.read() if not sys.stdin.isatty() else ""
if forced is not None:
    # sshd: SSH_ORIGINAL_COMMAND + the forced command; the helper lives in HOME.
    env["SSH_ORIGINAL_COMMAND"] = cmd
    helper, *helper_args = shlex.split(forced)
    argv = ["/bin/sh", helper, *helper_args]
else:
    if cmd.startswith("sh -c "):
        cmd = shlex.split(cmd)[2]
    cmd = cmd.replace("/usr/local/sbin", os.path.join(home, "sbin"))
    argv = ["/bin/sh", "-c", cmd]
result = subprocess.run(argv, input=stdin, capture_output=True, text=True, env=env)
sys.stdout.write(result.stdout)
sys.stderr.write(result.stderr)
sys.exit(result.returncode)
'''

FAKE_KEYSCAN = r'''#!/bin/sh
host="$(eval echo \${$#})"
echo "$host ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE"
'''

FAKE_KEYGEN = r'''#!/bin/sh
if [ "$1" = "-lf" ]; then
  read -r t k
  case "$k" in *OTHER*) echo "256 SHA256:someOtherKeyAfterReinstall00000000000000000 host (ED25519)";;
  *) echo "256 SHA256:fakeFingerprintForTestsOnly0000000000000000 host (ED25519)";; esac
  exit 0
fi
exec REAL_KEYGEN "$@"
'''


@posix_only
class SshSocketPairingTest(unittest.TestCase):
    def setUp(self):
        real_keygen = shutil.which("ssh-keygen")
        if real_keygen is None:
            self.skipTest("ssh-keygen is not installed")
        self.root = Path(tempfile.mkdtemp(prefix="sd-ssh-"))
        self.addCleanup(shutil.rmtree, self.root, True)
        bin_dir = self.root / "bin"
        bin_dir.mkdir()
        for name, body in (("ssh", FAKE_SSH), ("ssh-keyscan", FAKE_KEYSCAN),
                           ("ssh-keygen", FAKE_KEYGEN.replace("REAL_KEYGEN", real_keygen))):
            path = bin_dir / name
            path.write_text(textwrap.dedent(body))
            path.chmod(0o755)
        self.state = self.root / "state"
        self.state.mkdir()
        self.home = self.root / "host-home"
        (self.home / ".ssh").mkdir(parents=True)
        self.service = FakeService(str(self.root / "remote.sock"))
        self.addCleanup(self.service.close)
        # Remote path the user pairs; the fake sshd maps it onto the fake service.
        self.remote = "/run/console.sock"
        self.config = {"password": "s3cret-pass", "home": str(self.home),
                       "sockets": {self.remote: self.service.path}}
        self.write_config()
        run = self.root / "run"
        run.mkdir(mode=0o700)
        env = patch.dict(os.environ, {"PATH": f"{bin_dir}:{os.environ['PATH']}",
                                      "FAKE_SSH_STATE": str(self.state),
                                      "SERIAL_DECK_CONFIG": str(self.root / "config"),
                                      "SERIAL_DECK_RUNTIME_DIR": str(run)})
        env.start()
        self.addCleanup(env.stop)
        # The probe verb tests `[ -S path ]`: report the service's real path.
        remote_exists = patch.object(ssh_socket, "probe_socket", self._probe)
        remote_exists.start()
        self.addCleanup(remote_exists.stop)
        installed = patch.object(ssh_socket, "INSTALL_SCRIPT",
                                 ssh_socket.INSTALL_SCRIPT.replace('helper=/usr/local/sbin/serial-deck-ssh',
                                                                   f'helper={self.home}/sbin/serial-deck-ssh')
                                 .replace('"$HOME/.local/bin/serial-deck-ssh"', f'"{self.home}/.local/bin/serial-deck-ssh"'))
        installed.start()
        self.addCleanup(installed.stop)
        self.store = ssh_socket.DeviceStore()

    def _probe(self, device, store, **kwargs):
        # Same contract as the real probe, but ask the helper about the fake service's path.
        output = ssh_socket.verb(device, store, f"probe {self.service.path}", **kwargs)
        if self.service.path not in output.split():
            raise ssh_socket.SshSocketError("socket_missing", "no socket on the host")
        return device["remote_socket"]

    def write_config(self):
        (self.state / "config.json").write_text(__import__("json").dumps(self.config))

    def calls(self):
        path = self.state / "calls.jsonl"
        if not path.exists():
            return []
        return [__import__("json").loads(line) for line in path.read_text().splitlines()]

    def authorized(self) -> bytes:
        return (self.home / ".ssh" / "authorized_keys").read_bytes()

    def pair(self, **extra):
        request = {"name": "lab", "host": "192.0.2.9", "user": "pi", "auth": "password",
                   "password": bytearray(b"s3cret-pass"), "fingerprint": FINGERPRINT,
                   "remote_socket": self.remote, **extra}
        return ssh_socket.pair(self.store, request)

    def test_fingerprint_is_offered_before_trust(self):
        result = ssh_socket.fingerprint(self.store, "192.0.2.9", 22)
        self.assertEqual(result["fingerprint"], FINGERPRINT)
        self.assertEqual(result["pinned"], [])
        self.assertFalse(self.store.known_hosts.exists())

    def test_pair_installs_restricted_key_and_keeps_no_secret(self):
        result = self.pair()
        self.assertEqual([step["step"] for step in result["steps"]],
                         ["host_key", "generate_key", "install_key", "batch_login", "connect"])
        key = self.store.key_path("lab")
        self.assertEqual(stat.S_IMODE(key.stat().st_mode), 0o600)
        for path in (self.store.devices_path, self.store.known_hosts):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        lines = [l for l in self.authorized().decode().splitlines() if "serial-deck-device=lab" in l]
        self.assertEqual(len(lines), 1)
        self.assertTrue(lines[0].startswith("restrict,port-forwarding,command="), lines[0])
        stored = self.store.devices_path.read_text() + self.store.known_hosts.read_text()
        self.assertNotIn("s3cret-pass", stored)
        for call in self.calls():
            self.assertNotIn("s3cret-pass", __import__("json").dumps(call["argv"]))
            self.assertIn("StrictHostKeyChecking=yes", call["argv"])
        # After the installer, every login is the restricted key (forced command).
        after = [call for call in self.calls() if not call["secret_seen"]]
        self.assertTrue(after and all(call["forced"] for call in after))
        self.pair()  # re-pairing replaces, never duplicates
        self.assertEqual(self.authorized().count(b"serial-deck-device=lab"), 1)
        self.assertFalse(list((self.root / "run").rglob("askpass-*")))

    def test_restricted_key_cannot_run_a_shell(self):
        self.pair()
        device = self.store.get("lab")
        for command in ("id", "rm -rf /", "sh -c true", ""):
            with self.assertRaises(ssh_socket.SshSocketError, msg=command):
                ssh_socket.run_ssh(device, self.store, command)
        self.assertEqual(ssh_socket.verb(device, self.store, "version").strip(), ssh_socket.HELPER_VERSION)

    def test_wrong_password_is_auth_failed(self):
        with self.assertRaises(ssh_socket.SshSocketError) as raised:
            self.pair(password=bytearray(b"wrong"))
        self.assertEqual(raised.exception.state, "auth_failed")
        self.assertNotIn("wrong", str(raised.exception))

    def test_unconfirmed_or_changed_host_key_is_refused(self):
        with self.assertRaises(ssh_socket.SshSocketError):
            self.pair(fingerprint="")
        with self.assertRaises(ssh_socket.SshSocketError) as raised:
            self.pair(fingerprint=OTHER_FINGERPRINT)
        self.assertEqual(raised.exception.state, "host_key_changed")

    def test_invalid_profile_fields_are_refused(self):
        for bad in ({"name": "../x"}, {"host": "bad host"}, {"user": "Root!"}, {"remote_socket": "relative"},
                    {"remote_socket": "/a/../b"}, {"port": 0}):
            with self.assertRaises(ssh_socket.SshSocketError, msg=str(bad)):
                ssh_socket.validate_profile({"name": "lab", "host": "h", "user": "pi",
                                             "remote_socket": "/run/x.sock", **bad})

    def test_secrets_are_wiped_after_pairing(self):
        password = bytearray(b"s3cret-pass")
        request = {"name": "lab", "host": "192.0.2.9", "user": "pi", "auth": "password",
                   "password": password, "fingerprint": FINGERPRINT, "remote_socket": self.remote}
        ssh_socket.pair(self.store, request)
        self.assertEqual(bytes(password), b"\0" * len(password))
        self.assertNotIn("password", request)

    def test_transport_streams_and_reconnects(self):
        self.pair()
        transport = ssh_socket.SshSocketTransport("ssh-socket://lab", 0.2, self.store)
        self.addCleanup(transport.close)
        self.assertEqual(transport.link_state()["state"], "connected")
        tunnel_call = [call for call in self.calls() if "-N" in call["argv"]][-1]
        for option in ("BatchMode=yes", "ExitOnForwardFailure=yes", "StreamLocalBindUnlink=yes"):
            self.assertIn(option, tunnel_call["argv"])
        self.assertTrue(tunnel_call["forced"])
        self.assertIn(b"service ready", read_until(transport, b"ready"))
        transport.write(b"abc\n")
        self.assertIn(b"ABC", read_until(transport, b"ABC"))
        # The remote service restarts: a new stream over the live tunnel.
        self.service.drop_clients()
        deadline = time.monotonic() + 8
        seen = b""
        while time.monotonic() < deadline and b"ready" not in seen:
            seen += transport.read()
        self.assertIn(b"ready", seen)
        self.assertEqual(transport.link_state()["state"], "connected")
        local = [arg for arg in tunnel_call["argv"] if arg.endswith(":" + self.remote)][0]
        transport.close()
        self.assertFalse(Path(local.split(":", 1)[0]).exists())

    def test_write_is_refused_while_the_link_is_down(self):
        self.pair()
        transport = ssh_socket.SshSocketTransport("ssh-socket://lab", 0.2, self.store)
        self.addCleanup(transport.close)
        transport._drop("test")
        self.assertFalse(transport.available)
        with self.assertRaises(ssh_socket.SshSocketError):
            transport.write(b"x")

    def test_claim_reports_host_key_changed_and_auth_failed(self):
        self.pair()
        self.config["host_key_changed"] = True
        self.write_config()
        with self.assertRaises(ssh_socket.SshSocketError) as raised:
            ssh_socket.SshSocketTransport("ssh-socket://lab", 0.2, self.store)
        self.assertEqual(raised.exception.state, "host_key_changed")
        self.config["host_key_changed"] = False
        self.write_config()
        (self.home / ".ssh" / "authorized_keys").write_text("ssh-ed25519 AAAAOTHER user@elsewhere\n")
        with self.assertRaises(ssh_socket.SshSocketError) as raised:
            ssh_socket.SshSocketTransport("ssh-socket://lab", 0.2, self.store)
        self.assertEqual(raised.exception.state, "auth_failed")

    def test_forget_removes_exactly_our_key_line_even_in_a_binary_file(self):
        authorized = self.home / ".ssh" / "authorized_keys"
        others = b"ssh-ed25519 AAAAOTHER user@elsewhere\n\x00\xff not text\nssh-ed25519 AAAAMORE me\n"
        authorized.write_bytes(others)
        self.pair()
        self.assertEqual(self.authorized().count(b"\n"), 4)
        result = ssh_socket.forget(self.store, "lab")
        self.assertTrue(result["removed_remote_key"])
        self.assertEqual(self.authorized(), others)
        self.assertTrue((self.home / ".ssh" / "authorized_keys.sd-bak").exists())
        self.assertFalse(self.store.key_path("lab").exists())
        self.assertEqual(self.store.load(), {})

    def test_protected_device_key_asks_for_passphrase_on_connect(self):
        self.config.update(protected_passphrase="key-pass", protected_key="/keys/lab")
        self.write_config()
        self.pair(key_passphrase=bytearray(b"key-pass"))
        self.assertTrue(self.store.get("lab")["key_protected"])
        with self.assertRaises(ssh_socket.SshSocketError) as raised:
            ssh_socket.SshSocketTransport("ssh-socket://lab", 0.2, self.store)
        self.assertEqual(raised.exception.state, "passphrase_required")
        secret = bytearray(b"key-pass")
        transport = ssh_socket.SshSocketTransport("ssh-socket://lab", 0.2, self.store, secret)
        self.addCleanup(transport.close)
        self.assertEqual(transport.link_state()["state"], "connected")
        self.assertEqual(bytes(secret), b"\0" * 8)
        self.assertNotIn("key-pass", self.store.devices_path.read_text())
        transport.close()
        with self.assertRaises(ssh_socket.SshSocketError) as raised:
            ssh_socket.forget(self.store, "lab")
        self.assertEqual(raised.exception.state, "passphrase_required")
        result = ssh_socket.forget(self.store, "lab", secret=bytearray(b"key-pass"))
        self.assertTrue(result["removed_remote_key"])
        self.assertNotIn(b"serial-deck-device", self.authorized())

    def test_hub_claims_a_paired_device_and_reports_link_state(self):
        from serial_deck.service import MultiPortHub
        self.pair()
        hub = MultiPortHub(str(self.root / "hub.sock"))
        hub.start()
        self.addCleanup(hub.close)
        manager = HubProcessManager(socket_path=str(hub.socket_path))
        manager.claim_port("ssh-socket://lab", 115200)
        listed = manager.request_control("ssh_devices")
        self.assertEqual([d["name"] for d in listed["devices"]], ["lab"])
        self.assertEqual(listed["devices"][0]["link"]["state"], "connected")
        transport = open_uart_transport(manager.endpoint, 115200, 0.5)
        self.addCleanup(transport.close)
        transport.write(b"ping\n")
        self.assertIn(b"PING", read_until(transport, b"PING"))
        # The channel's own status carries the tunnel state for subscribers.
        self.assertEqual(manager.get_status()["link"]["state"], "connected")
        root = HubProcessManager(socket_path=str(hub.socket_path))
        self.assertEqual(root.get_status()["channels"][0]["link"]["state"], "connected")
        for action in ("reset", "bootloader"):
            with self.assertRaises(RuntimeError):
                manager.request_control(action)
        with self.assertRaisesRegex(RuntimeError, "physical UART"):
            manager.request_control("flash_preview", build_dir=str(self.root), flash_baud=460800)
        # A claim failure names its state for the UI's fix button.
        self.config["host_key_changed"] = True
        self.write_config()
        other = HubProcessManager(socket_path=str(hub.socket_path))
        self.store.save({**self.store.get("lab"), "name": "lab2"})
        with self.assertRaises(RuntimeError) as raised:
            other.claim_port("ssh-socket://lab2", 115200)
        self.assertEqual(getattr(raised.exception, "code", ""), "host_key_changed")

    def test_hub_serves_screen_and_restart_extras(self):
        from serial_deck.service import MultiPortHub
        body = b"\xff\xd8frame\xff\xd9"
        ctl = self.root / "ctl.sock"
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(str(ctl))
        server.listen(4)
        self.addCleanup(server.close)

        def http():
            while True:
                try:
                    client, _ = server.accept()
                except OSError:
                    return
                with client:
                    client.recv(4096)
                    client.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: image/jpeg\r\nX-Revision: 3\r\n\r\n" + body)
        threading.Thread(target=http, daemon=True).start()
        self.config["sockets"]["/run/console.ctl"] = str(ctl)
        self.write_config()
        marker = self.home / "restarted"
        self.pair(control_socket="/run/console.ctl", screen_path="/screen", restart_args=["null", "alt"],
                  restart_cmd=f"echo $RESTART_ARG > {marker}")
        self.assertIn("RESTART_CMD=", (self.home / ".config" / "serial-deck" / "ssh.conf").read_text())
        self.assertNotIn("RESTART", self.store.devices_path.read_text())
        hub = MultiPortHub(str(self.root / "hub.sock"))
        hub.start()
        self.addCleanup(hub.close)
        manager = HubProcessManager(socket_path=str(hub.socket_path))
        with self.assertRaisesRegex(RuntimeError, "not connected"):
            manager.request_control("ssh_screen", name="lab")
        manager.claim_port("ssh-socket://lab", 115200)
        frame = manager.request_control("ssh_screen", name="lab")
        self.assertEqual((frame["revision"], frame["changed"]), (3, True))
        self.assertEqual(__import__("base64").b64decode(frame["data"]), body)
        result = manager.request_control("ssh_restart", name="lab", arg="alt")
        self.assertEqual(result["arg"], "alt")
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and not marker.exists():
            time.sleep(0.05)
        self.assertEqual(marker.read_text().strip(), "alt")
        with self.assertRaises(RuntimeError) as raised:
            manager.request_control("ssh_restart", name="lab", arg="other")
        self.assertEqual(getattr(raised.exception, "code", ""), "invalid_argument")


@posix_only
class HelperScriptTest(unittest.TestCase):
    """The forced-command helper itself: probe and verb filtering, no shell."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="sd-helper-"))
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.helper = self.dir / "serial-deck-ssh"
        self.helper.write_text(ssh_socket.HELPER_SCRIPT)
        (self.dir / ".ssh").mkdir()
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket.bind(str(self.dir / "real.sock"))
        self.addCleanup(self.socket.close)

    def run_verb(self, command: str):
        import subprocess
        return subprocess.run(["/bin/sh", str(self.helper), "lab"], capture_output=True, text=True,
                              env={"HOME": str(self.dir), "SSH_ORIGINAL_COMMAND": command, "PATH": os.environ["PATH"]})

    def test_probe_reports_found_and_missing_sockets(self):
        found = self.run_verb(f"probe {self.dir}/real.sock")
        self.assertEqual((found.returncode, found.stdout.strip()), (0, f"{self.dir}/real.sock"))
        missing = self.run_verb(f"probe {self.dir}/nope.sock")
        self.assertEqual((missing.returncode, missing.stdout.strip()), (0, "missing"))

    def test_probe_rejects_unsafe_paths_and_other_verbs(self):
        for command in ("probe relative.sock", "probe /a/../etc/passwd", "probe /a;id", "rm -rf /", "sh", ""):
            result = self.run_verb(command)
            self.assertEqual(result.returncode, 2, command)
            self.assertEqual(result.stdout, "", command)

    def write_conf(self, text: str, mode: int = 0o600) -> Path:
        conf = self.dir / ".config" / "serial-deck" / "ssh.conf"
        conf.parent.mkdir(parents=True, exist_ok=True)
        conf.write_text(text)
        conf.chmod(mode)
        return conf

    def test_restart_runs_the_host_command_with_one_plain_word(self):
        if os.getuid() == 0:
            self.skipTest("root reads /etc/serial-deck")
        marker = self.dir / "restarted"
        self.write_conf(f'RESTART_CMD="echo \\$RESTART_ARG > {marker}"\n')
        result = self.run_verb("restart alt")
        self.assertEqual((result.returncode, result.stdout.strip()), (0, "restart alt"), result.stderr)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and not marker.exists():
            time.sleep(0.05)
        self.assertEqual(marker.read_text().strip(), "alt")
        for command in ("restart", "restart a;id", "restart $(id)", "restart ../x"):
            self.assertEqual(self.run_verb(command).returncode, 2, command)

    def test_restart_refuses_missing_or_writable_config(self):
        if os.getuid() == 0:
            self.skipTest("root reads /etc/serial-deck")
        self.assertIn("no restart command", self.run_verb("restart alt").stderr)
        for mode in (0o622, 0o602, 0o620):
            self.write_conf('RESTART_CMD="true"\n', mode)
            result = self.run_verb("restart alt")
            self.assertEqual(result.returncode, 2, oct(mode))
            self.assertIn("writable", result.stderr)


class ScreenFrameTest(unittest.TestCase):
    """`screen_frame` over a local Unix-socket HTTP server (the forwarded control socket)."""

    def serve(self, response: bytes) -> str:
        directory = tempfile.mkdtemp(prefix="sd-screen-")
        self.addCleanup(shutil.rmtree, directory, True)
        path = os.path.join(directory, "ctl.sock")
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(path)
        server.listen(1)
        self.addCleanup(server.close)
        self.requests: list[bytes] = []

        def run():
            client, _ = server.accept()
            with client:
                self.requests.append(client.recv(4096))
                client.sendall(response)
        threading.Thread(target=run, daemon=True).start()
        return path

    @posix_only
    def test_jpeg_frame_and_revision(self):
        body = b"\xff\xd8jpeg\xff\xd9"
        path = self.serve(b"HTTP/1.1 200 OK\r\nContent-Type: image/jpeg\r\nX-Frame-Rev: 7\r\n"
                          b"X-Frame-Size: 480x800\r\n\r\n" + body)
        frame = ssh_socket.screen_frame(path, "/api/face/frame?format=jpeg", 6, "X-Frame-Rev", "X-Frame-Size")
        self.assertIn(b"GET /api/face/frame?format=jpeg&after=6 ", self.requests[0])
        self.assertEqual((frame["revision"], frame["changed"], frame["size"], frame["bytes"]), (7, True, "480x800", 8))
        self.assertEqual(__import__("base64").b64decode(frame["data"]), body)

    @posix_only
    def test_unchanged_and_error(self):
        path = self.serve(b"HTTP/1.1 304 Not Modified\r\nX-Revision: 7\r\n\r\n")
        self.assertEqual(ssh_socket.screen_frame(path, "/screen", 7), {"revision": 7, "changed": False})
        path = self.serve(b"HTTP/1.1 404 Not Found\r\n\r\n")
        with self.assertRaises(ssh_socket.SshSocketError) as raised:
            ssh_socket.screen_frame(path, "/screen", None)
        self.assertEqual(raised.exception.state, "screen_unavailable")
        for bad in (b"HTTP/1.1 200 OK\r\nContent-Type: image/jpeg\r\nContent-Length: 99\r\n\r\nshort",
                    b"HTTP/1.1 200 OK\r\nContent-Type: image/jpeg\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nabcde\r\n0\r\n\r\n",
                    b"HTTP/1.1 200 OK\r\nContent-Type: image/jpeg\r\n\r\n" + b"x" * (ssh_socket.FRAME_MAX_BYTES + 10000)):
            path = self.serve(bad)
            with self.assertRaises(ssh_socket.SshSocketError, msg=bad[:80]) as raised:
                ssh_socket.screen_frame(path, "/screen", None)
            self.assertEqual(raised.exception.state, "screen_unavailable")

    @posix_only
    def test_default_headers_are_x_revision_and_x_size(self):
        path = self.serve(b"HTTP/1.1 200 OK\r\nContent-Type: image/jpeg\r\nX-Revision: 3\r\nX-Size: 2x2\r\n\r\nabc")
        frame = ssh_socket.screen_frame(path, "/screen", None)
        self.assertEqual((frame["revision"], frame["size"]), (3, "2x2"))
        path = self.serve(b"HTTP/1.1 200 OK\r\nContent-Type: image/jpeg\r\nX-Frame-Rev: 3\r\n\r\nabc")
        self.assertIsNone(ssh_socket.screen_frame(path, "/screen", None)["revision"])  # other names need the profile

    def test_follow_suffix_follows_a_service_that_moved(self):
        device = {"name": "lab", "remote_socket": "/tmp/svc.sock.stream", "control_socket": "/tmp/svc.sock",
                  "follow_socket_suffix": ".stream"}
        with patch.object(ssh_socket, "verb", return_value="/run/svc/svc.sock.stream\n"):
            self.assertEqual(ssh_socket.probe_socket(device, None), "/run/svc/svc.sock.stream")
        self.assertEqual((device["remote_socket"], device["control_socket"]),
                         ("/run/svc/svc.sock.stream", "/run/svc/svc.sock"))
        plain = {"name": "lab", "remote_socket": "/tmp/svc.sock.stream"}  # no suffix configured: never guess
        with patch.object(ssh_socket, "verb", return_value="/run/svc/svc.sock.stream\n"):
            with self.assertRaises(ssh_socket.SshSocketError) as raised:
                ssh_socket.probe_socket(plain, None)
        self.assertEqual(raised.exception.state, "socket_missing")

    def test_restart_hint_comes_from_the_profile(self):
        store = type("Store", (), {"get": lambda self, name: {"name": "lab", "restart_args": ["alt"],
                                                              "restart_conf_hint": "MY_VAR in /etc/my.conf"},
                                   "save": lambda self, device: None})()
        error = ssh_socket.SshSocketError("remote_failed", "serial-deck-ssh: no restart command: set X")
        with patch.object(ssh_socket, "verb", side_effect=error):
            with self.assertRaises(ssh_socket.SshSocketError) as raised:
                ssh_socket.restart(store, "lab", "alt")
        self.assertIn("MY_VAR in /etc/my.conf", str(raised.exception))

    def test_new_profile_fields_are_validated(self):
        base = {"name": "lab", "host": "h", "user": "pi", "remote_socket": "/run/x.sock"}
        good = ssh_socket.validate_profile({**base, "follow_socket_suffix": ".stream",
                                            "screen_revision_header": "X-Frame-Rev", "restart_conf_hint": "edit ssh.conf"})
        self.assertEqual((good["follow_socket_suffix"], good["screen_revision_header"]), (".stream", "X-Frame-Rev"))
        for bad in ({"follow_socket_suffix": "stream"}, {"follow_socket_suffix": "/x"},
                    {"screen_revision_header": "X Rev"}, {"screen_size_header": "X:Size"},
                    {"restart_conf_hint": "a\nb"}, {"restart_conf_hint": "x" * 300}):
            with self.assertRaises(ssh_socket.SshSocketError, msg=str(bad)):
                ssh_socket.validate_profile({**base, **bad})

    def test_profile_extras_are_validated(self):
        base = {"name": "lab", "host": "h", "user": "pi", "remote_socket": "/run/x.sock"}
        profile = ssh_socket.validate_profile({**base, "control_socket": "/run/x.ctl",
                                               "screen_path": "/api/face/frame?format=jpeg",
                                               "restart_args": ["null", "alt"]})
        self.assertEqual(profile["restart_args"], ["null", "alt"])
        for bad in ({"screen_path": "/s"}, {"control_socket": "rel", "screen_path": "/s"},
                    {"control_socket": "/c", "screen_path": "http://x/"}, {"restart_args": ["a b"]},
                    {"restart_args": "alt"}):
            with self.assertRaises(ssh_socket.SshSocketError, msg=str(bad)):
                ssh_socket.validate_profile({**base, **bad})
        self.assertEqual(ssh_socket.restart_conf("systemctl restart d"), "RESTART_CMD='systemctl restart d'")
        with self.assertRaises(ssh_socket.SshSocketError):
            ssh_socket.restart_conf("a\nb")


class WebSshActionsTest(unittest.TestCase):
    def handler(self, token="tok", supplied=""):
        from serial_deck import web
        handler = type("H", (), {"headers": {"X-Deck-Action": supplied}, "action_token": token,
                                 "connections": None})()
        handler._action_token_ok = lambda: web.DeckHttpHandler._action_token_ok(handler)
        return web, handler

    def test_host_changing_actions_need_the_page_token(self):
        web, handler = self.handler(supplied="")
        for name in ("pair", "forget", "unlock", "restart"):
            body = {"name": "lab", "password": "x", "passphrase": "y"}
            result, status = web.DeckHttpHandler._ssh_request(handler, name, body)
            self.assertEqual(status, web.HTTPStatus.FORBIDDEN, name)
            self.assertNotIn("password", body)
            self.assertNotIn("passphrase", body)

    def test_unknown_action_is_404(self):
        web, handler = self.handler(supplied="tok")
        _, status = web.DeckHttpHandler._ssh_request(handler, "shell", {})
        self.assertEqual(status, web.HTTPStatus.NOT_FOUND)

    def test_transport_labels(self):
        from serial_deck import web
        self.assertEqual(web.transport_label("ssh-socket://lab", "linux"), "SSH / SOCKET")
        self.assertEqual(web.transport_label("unix:///tmp/x", "linux"), "Linux / UNIX")
        self.assertEqual(web.transport_label("/dev/ttyUSB0", "control"), "Control / UART")


class AgentSshNamesTest(unittest.TestCase):
    @posix_only
    def test_names_resolve_to_ssh_socket_urls(self):
        from serial_deck.agent import DeckAgent
        agent = DeckAgent(policy="observe", socket_path="/nonexistent/hub.sock")
        store = type("Store", (), {"find": lambda self, name: "Lab" if name.lower() == "lab" else None})()
        with patch.object(agent, "_ssh_store", lambda: store):
            self.assertEqual(agent.resolve_port("lab"), "ssh-socket://Lab")
            self.assertEqual(agent.resolve_port("/dev/ttyACM0"), "/dev/ttyACM0")
            self.assertEqual(agent.resolve_port("tcp://h:1"), "tcp://h:1")
            self.assertEqual(agent.resolve_port("other"), "other")


if __name__ == "__main__":
    unittest.main()
