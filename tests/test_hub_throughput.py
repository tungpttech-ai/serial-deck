"""Fan-out throughput guard: the Python hub must keep up with a fast UART.

A 2 Mbaud UART carries at most ~200 KB/s. The hub is fed 1 MB/s through a PTY
for a few seconds and every attached client must receive every byte. Measured
on a 2026 ARM laptop: ~20% CPU for hub + 4 readers at this rate, no drops; this
test exists so a regression shows up before anyone reaches for a rewrite.
"""

import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

try:
    import pty
    import tty
except ImportError:  # Windows: no pseudo-terminals
    pty = tty = None

from serial_deck import hub as uart
from serial_deck.hub_client import HubProcessManager
from serial_deck.service import MultiPortHub
from serial_deck.uart_client import open_uart_transport

RATE = 1_000_000  # bytes/s
SECONDS = 3.0
CLIENTS = 4


@unittest.skipUnless(pty is not None and sys.platform.startswith("linux"),
                     "needs a Linux pseudo-terminal (the hub cannot open a macOS pty)")
class HubThroughputTest(unittest.TestCase):
    def test_every_client_gets_every_byte_at_five_times_uart_speed(self):
        master, slave = pty.openpty()
        tty.setraw(master)
        tty.setraw(slave)
        self.addCleanup(os.close, master)
        self.addCleanup(os.close, slave)
        port = os.ttyname(slave)
        scan = patch.object(uart, "discover_serial_ports", return_value=[port])
        scan.start()
        self.addCleanup(scan.stop)
        temp = tempfile.TemporaryDirectory(prefix="sd-tput-")
        self.addCleanup(temp.cleanup)
        hub = MultiPortHub(str(Path(temp.name) / "hub.sock"), idle_timeout=30)
        hub.start()
        self.addCleanup(hub.close)
        manager = HubProcessManager(socket_path=str(hub.socket_path))
        manager.claim_port(port, 2000000)

        counts = [0] * CLIENTS
        stop = threading.Event()

        def read(index, transport):
            while not stop.is_set():
                try:
                    counts[index] += len(transport.read())
                except OSError:
                    return

        threads = []
        for index in range(CLIENTS):
            transport = open_uart_transport(manager.endpoint, 2000000, 0.05)
            self.addCleanup(transport.close)
            thread = threading.Thread(target=read, args=(index, transport), daemon=True)
            thread.start()
            threads.append(thread)
        time.sleep(0.3)

        chunk = b"I (12345) app: telemetry 0123456789abcdef0123456789abcdef\r\n" * 160
        started = time.monotonic()
        sent = 0
        while time.monotonic() - started < SECONDS:
            os.write(master, chunk)
            sent += len(chunk)
            delay = started + sent / RATE - time.monotonic()
            if delay > 0:
                time.sleep(delay)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and min(counts) < sent:
            time.sleep(0.05)
        stop.set()
        self.assertEqual(counts, [sent] * CLIENTS, f"sent {sent} bytes")


if __name__ == "__main__":
    unittest.main()
