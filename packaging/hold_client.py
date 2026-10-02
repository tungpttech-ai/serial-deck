"""Hold one real hub data client open (for installer refusal tests).

usage: python hold_client.py <serial-deck-cli> <ready-file>
Starts a fake TCP UART bridge, claims it through the bundle's hub with a
console monitor, writes <ready-file> once the hub dialed the bridge, then
waits for stdin to close. It always stops its monitor on exit, so the hub
itself (an independent daemon) keeps running and goes idle.
"""

import socket
import subprocess
import sys
from pathlib import Path

cli, ready = sys.argv[1], Path(sys.argv[2])
server = socket.socket()
server.bind(("127.0.0.1", 0))
server.listen(1)
server.settimeout(60)
port = f"tcp://127.0.0.1:{server.getsockname()[1]}"
monitor = subprocess.Popen([cli, "console", "--port", port, "--baud", "115200", "monitor"],
                           stdin=subprocess.DEVNULL)
try:
    device, _ = server.accept()  # the hub opened the "UART": the channel and its client are live
    ready.write_text(str(monitor.pid), encoding="utf-8")
    print(f"holding a client on {port} (monitor pid {monitor.pid})", flush=True)
    sys.stdin.read()  # until the test closes our stdin
finally:
    monitor.terminate()
    try:
        monitor.wait(timeout=10)
    except subprocess.TimeoutExpired:
        monitor.kill()
