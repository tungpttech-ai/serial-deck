"""Hub transport primitives on both backends, no hardware."""

import importlib
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from serial_deck import ipc


def tcp_backend():
    """A fresh `ipc` module forced onto the loopback-TCP (Windows) backend."""
    with patch.dict(os.environ, {"SERIAL_DECK_IPC": "tcp"}):
        return importlib.reload(importlib.import_module("serial_deck.ipc"))


class TcpBackendTest(unittest.TestCase):
    def setUp(self):
        self.ipc = tcp_backend()
        self.addCleanup(importlib.reload, ipc)
        self.temp = tempfile.TemporaryDirectory(prefix="sd-ipc-")
        self.addCleanup(self.temp.cleanup)
        self.path = str(Path(self.temp.name) / "hub.sock")
        self.listener = self.ipc.listen(self.path)
        self.addCleanup(self.listener.close)
        self.listener.settimeout(2)

    def raw_connect(self):
        record = json.loads(Path(self.path).read_text(encoding="utf-8"))
        return socket.create_connection(("127.0.0.1", record["port"]), timeout=2), record

    def test_authenticated_client_streams_and_first_bytes_survive(self):
        client = self.ipc.connect(self.path, 2)
        client.sendall(b"DATA-1")  # sent right behind the token
        server, _ = self.listener.accept()
        with client, server:
            self.assertEqual(server.recv(64), b"DATA-1")
            server.sendall(b"BACK")
            self.assertEqual(client.recv(64), b"BACK")

    def test_wrong_token_is_dropped_and_listener_keeps_serving(self):
        bad, _ = self.raw_connect()
        with bad:
            bad.sendall(b"0" * 64 + b"\n" + b"PAYLOAD")
            try:
                self.assertEqual(bad.recv(64), b"")  # closed, nothing accepted
            except ConnectionResetError:
                pass  # unread PAYLOAD turns the close into a reset
        with self.assertRaises(socket.timeout):
            self.listener.settimeout(0.3)
            self.listener.accept()
        self.listener.settimeout(2)
        good = self.ipc.connect(self.path, 2)
        server, _ = self.listener.accept()
        good.close()
        server.close()

    def test_silent_peer_never_blocks_other_clients(self):
        silent, _ = self.raw_connect()  # sends nothing
        self.addCleanup(silent.close)
        started = time.monotonic()
        client = self.ipc.connect(self.path, 2)
        server, _ = self.listener.accept()
        self.assertLess(time.monotonic() - started, 1.0)
        client.close()
        server.close()
        silent.settimeout(self.ipc.HANDSHAKE_TIMEOUT + 2)
        self.assertEqual(silent.recv(1), b"")  # dropped at the handshake deadline

    def test_close_drops_peers_still_in_the_handshake(self):
        silent, _ = self.raw_connect()  # never sends its token
        self.addCleanup(silent.close)
        time.sleep(0.2)  # let the listener pick it up
        started = time.monotonic()
        self.listener.close()
        silent.settimeout(1.5)
        try:
            self.assertEqual(silent.recv(1), b"")
        except ConnectionResetError:
            pass
        self.assertLess(time.monotonic() - started, 1.0)  # not the 2 s handshake deadline

    def test_endpoint_file_is_private_and_removed_on_close(self):
        if os.name != "nt":
            self.assertEqual(os.stat(self.path).st_mode & 0o077, 0)
        self.assertTrue(self.ipc.endpoint_exists(self.path))
        self.listener.close()
        self.assertFalse(os.path.exists(self.path))

    def test_close_keeps_a_newer_listeners_record(self):
        newer = self.ipc.listen(self.path)
        self.addCleanup(newer.close)
        self.listener.close()
        self.assertTrue(self.ipc.endpoint_exists(self.path))

    def test_read_line_reassembles_fragments(self):
        left, right = socket.socketpair()
        with left, right:
            def send():
                for part in (b'{"ok":', b' true', b'}\nNEXT'):
                    left.sendall(part)
                    time.sleep(0.02)
            threading.Thread(target=send).start()
            self.assertEqual(self.ipc.read_line(right, timeout=2), b'{"ok": true}')


class FileLockTest(unittest.TestCase):
    def test_second_process_cannot_take_a_held_lock(self):
        with tempfile.TemporaryDirectory() as temp:
            path = str(Path(temp) / "x.lock")
            lock = ipc.FileLock(path)
            self.assertTrue(lock.acquire(blocking=False))
            try:
                code = ("import sys; from serial_deck import ipc; "
                        f"sys.exit(0 if ipc.FileLock({path!r}).acquire(blocking=False) else 3)")
                root = str(Path(__file__).resolve().parents[1])
                result = subprocess.run([sys.executable, "-c", code], cwd=root, timeout=20)
                self.assertEqual(result.returncode, 3)
            finally:
                lock.release()
            again = ipc.FileLock(path)
            self.assertTrue(again.acquire(blocking=False))
            again.release()


class ProcessTest(unittest.TestCase):
    def test_pid_alive(self):
        self.assertTrue(ipc.pid_alive(os.getpid()))
        child = subprocess.Popen([sys.executable, "-c", "pass"])
        child.wait(timeout=20)
        self.assertFalse(ipc.pid_alive(child.pid))
        self.assertFalse(ipc.pid_alive(0))
        self.assertFalse(ipc.pid_alive("1"))


@unittest.skipUnless(os.name == "nt", "Windows ACLs")
class WindowsAclTest(unittest.TestCase):
    def test_private_dir_dacl_is_exactly_this_user(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "shared-root" / "rt"
            ipc.private_dir(target)
            # icacls output lists one ACE line per grant; only ours may remain.
            out = subprocess.run(["icacls", str(target)], capture_output=True, text=True,
                                 encoding="utf-8", errors="replace").stdout
            grants = [line for line in out.splitlines()[0:-2] if ":(" in line]
            self.assertEqual(len(grants), 1, out)
            self.assertIn(os.environ["USERNAME"].lower(), out.lower())
            self.assertNotIn("Everyone", out)
            self.assertNotIn("BUILTIN\\Users", out)
            (target / "x.json").write_text("{}", encoding="utf-8")
            out = subprocess.run(["icacls", str(target / "x.json")], capture_output=True, text=True,
                                 encoding="utf-8", errors="replace").stdout
            self.assertNotIn("BUILTIN\\Users", out)


@unittest.skipIf(ipc.BACKEND != "unix", "Unix socket backend")
class UnixBackendTest(unittest.TestCase):
    def test_overlong_socket_path_is_refused_with_advice(self):
        with tempfile.TemporaryDirectory() as temp:
            path = str(Path(temp) / ("x" * 120) / "hub.sock")
            with self.assertRaisesRegex(OSError, "SERIAL_DECK_IPC=tcp"):
                ipc.listen(path)


if __name__ == "__main__":
    unittest.main()
