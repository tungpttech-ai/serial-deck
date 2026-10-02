"""Hold one real hub data client open (for installer refusal tests).

usage: python hold_client.py <serial-deck-cli>
Starts a fake TCP UART bridge, claims it through the bundle's hub, attaches a
data client and then sleeps until killed, so `hub --shutdown` must refuse.
"""

import socket
import subprocess
import sys
import time

cli = sys.argv[1]
server = socket.socket()
server.bind(("127.0.0.1", 0))
server.listen(1)
port = f"tcp://127.0.0.1:{server.getsockname()[1]}"
monitor = subprocess.Popen([cli, "console", "--port", port, "--baud", "115200", "monitor"])
device, _ = server.accept()  # the hub dialed the fake bridge: the channel is live
print(f"holding a client on {port} (pid {monitor.pid})", flush=True)
try:
    while monitor.poll() is None:
        time.sleep(0.5)
finally:
    monitor.kill()
