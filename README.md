# Serial Deck

A shared serial console for embedded work. One small hub process owns your
UARTs, and any number of clients watch and drive them at the same time: a Web
dashboard, a native window, a Tk desktop app, a CLI and an MCP server for AI
agents. You can keep a browser tab streaming logs while you flash firmware from
another window and an agent queries the device, all on the same port, without
"port busy" errors.

- **Shared ports.** Every client attaches through the hub, so several tools read
  one UART at once. TCP and UDP UART bridges (ser2net, ESP-Link, Wi-Fi modules)
  work too.
- **Consoles.** A raw console with an interactive terminal (xterm.js) for Linux
  boards and anything else, plus an optional *control* mode for firmware that
  speaks the [control protocol](docs/PROTOCOL.md).
- **ESP32 flashing** from an ESP-IDF build directory, for any chip esptool
  supports. Only the flashing port pauses; other ports keep streaming.
- **Crash decoding** of ESP backtraces with the ESP-IDF `addr2line`.
- **MCP server** so Claude Code, Codex, Cursor and others can read logs, run
  commands and (when you allow it) reset or flash. See [docs/MCP.md](docs/MCP.md).
- **Linux, macOS and Windows.**

## Download

Installers are on the [Releases page](https://github.com/tungpttech-ai/serial-deck/releases/latest).
No Python needed.

| OS | File | Notes |
|---|---|---|
| Windows 10/11 (x64) | `SerialDeck-<version>-Setup.exe` | Per-user install, no admin. A portable `-win-x64.zip` is also provided |
| macOS 15+ (Apple silicon) | `SerialDeck-<version>-macos-arm64.dmg` | Drag *Serial Deck* to Applications |
| macOS 15+ (Intel) | `SerialDeck-<version>-macos-x86_64.dmg` | |
| Linux x86_64 (Ubuntu 22.04) | `serial-deck_<version>_amd64.deb` or `SerialDeck-<version>-x86_64.AppImage` | Native window; use AppImage on other distributions |

The app is the Web dashboard in its own window; on Linux it uses your browser.
Every installer also ships `serial-deck-cli` for the hub, CLI and MCP server
(`serial-deck-cli --help`). `SHA256SUMS.txt` lists every file's checksum.

Builds are currently **not code-signed**:

- **Windows:** SmartScreen may warn on first run. Choose *More info → Run anyway*.
- **macOS:** the first time, right-click *Serial Deck* in Applications and choose *Open*.
- **Linux:** add yourself to the `dialout` (Debian/Ubuntu) or `uucp` (Arch) group
  for serial access, then log out and in. Without FUSE, run the AppImage with
  `--appimage-extract-and-run`.

## Install with pip

Python 3.10 or newer. Serial Deck is not on PyPI yet; install the wheel from a
release, or from a checkout:

```bash
python -m pip install "serial-deck[app,mcp] @ https://github.com/tungpttech-ai/serial-deck/releases/download/v0.2.1/serial_deck-0.2.1-py3-none-any.whl"
```

`[app]` adds the native window (pywebview), `[mcp]` the MCP server; the base
package has the hub, Web dashboard, CLI and flashing.

From a checkout:

```bash
git clone https://github.com/tungpttech-ai/serial-deck.git
cd serial-deck
python -m venv .venv
# Linux/macOS: source .venv/bin/activate    Windows: .venv\Scripts\activate
python -m pip install -e ".[app,mcp]"
```

Platform notes:

- **Windows:** ports are named `COM3`, `COM12`, and so on. The app window uses
  the WebView2 runtime that ships with Windows 10/11. Tk ships with the
  python.org installer.
- **Linux:** your user needs access to serial devices (usually the `dialout`
  or `uucp` group). The Tk desktop needs `python3-tk` (Debian/Ubuntu) or `tk`
  (Arch). For the app window, install WebKit2GTK 4.1 and PyGObject
  (`gir1.2-webkit2-4.1 python3-gi`, or `webkit2gtk-4.1 python-gobject`) and
  create the venv with `--system-site-packages`, or use `pip install "pywebview[qt]"`.
- **macOS:** works out of the box; ports look like `/dev/cu.usbserial-*`.

## Quick start

```bash
serial-deck-web --open-browser
```

Pick a port and its baud, then press **Connect**. The default mode,
**Linux / Raw**, never sends anything to the device by itself. Switch to
**Control** only for firmware that implements the control protocol, or start
with it: `serial-deck-web --mode control` (also `serial-deck-app`).

Other front ends talk to the same hub:

```bash
serial-deck-app                                  # the Web UI in a native window
serial-deck-desktop --port COM3 --baud 115200    # Tk desktop
serial-deck --port /dev/ttyUSB0 --baud 115200 monitor
```

Every command also runs as a module, for example `python -m serial_deck.web`.

## Sharing ports, and changing baud

All clients share **one hub daemon per user**. It starts on first use and
keeps running when a UI closes; each port is a channel inside it. A port with
no clients is closed after 5 seconds (`--port-idle-timeout`). Closing a UI only
detaches it.

```bash
serial-deck-hub --status      # what is open, at which baud, by how many clients
serial-deck-hub --shutdown    # refuses while clients are attached or a flash runs
```

When a client connects at a different baud while others use the port, the UI
asks whether to change the baud for everyone, join at the live baud, or cancel.
A change retimes the open UART in place (no close/reopen, so no DTR/RTS reset
pulse), and every client follows it. The new baud must match the firmware.

The hub talks to clients over Unix sockets on Linux and macOS. On Windows it
uses loopback TCP: every connection must present a random per-run token, which
is stored in a file only your user can read. Set `SERIAL_DECK_IPC=tcp` to use
that transport on any OS. Hub files live in a private per-user directory
(`%LOCALAPPDATA%\serial-deck`, `/run/user/<uid>/serial-deck` or
`/tmp/serial-deck-<uid>`); `SERIAL_DECK_RUNTIME_DIR` overrides it.

## Devices that are not a UART

Type these in the port box ("Network (raw)") or pass them to any client:

| Endpoint | What it is |
|---|---|
| `tcp://host:port`, `udp://host:port` | UART-over-IP (ser2net, ESP-Link, telnet consoles) |
| `unix:///path/to.sock` | A local stream socket (Linux, macOS) |
| `ssh-socket://name` | A paired remote Unix socket behind an SSH tunnel (Linux, macOS) |

None of them has a baud, DTR/RTS, reset, bootloader or flashing.

**SSH devices.** Choose **+ Add SSH device...** in the port list, enter the
host, user and the absolute path of the Unix socket on it, compare the host
fingerprint, and sign in once with a password or an existing key. Serial Deck
then keeps a key of its own for that device in `~/.config/serial-deck/keys/`
(`SERIAL_DECK_CONFIG` overrides the location). On the host that key is limited
to socket tunnels and a few fixed verbs; it cannot start a shell. The password
is used once and never stored. If the host key changes, connecting is blocked
until you pair again on purpose. **Forget device...** removes the key from the
host and the profile from this machine. Needs the `ssh`, `ssh-keygen` and
`ssh-keyscan` programs on your PATH (OpenSSH).

Optional extras under *Advanced* when pairing:

- **Control socket + screen path**: a second Unix socket on the host serving
  HTTP, forwarded through the same tunnel. When the screen path returns a JPEG
  (`X-Revision`, `X-Size`, `304` when `?after=<revision>` is current), the SSH
  card shows a live preview and MCP gets `serial_screenshot`.
- **Restart command + arguments**: the command is written once to the host's
  `/etc/serial-deck/ssh.conf` (root) or `~/.config/serial-deck/ssh.conf` and is
  never kept on this machine; it runs detached with `$RESTART_ARG` set to the
  button you press. MCP gets `serial_restart` (hardware policy).

For a host whose service may move between directories, a profile can also set
`follow_socket_suffix` (the first path the helper lists with that suffix becomes
the stream socket, the same path without it the control socket),
`screen_revision_header` / `screen_size_header` (default `X-Revision` / `X-Size`)
and `restart_conf_hint` (the text shown when the host has no restart command).

Hosts paired before this helper version still stream; pair again to use
restart (the helper reports `helper_outdated`).

**Profiles.** Product-specific values (sockets, screen path, restart arguments,
MCP tool prefix, default baud and mode) live in JSON files you keep, not in
Serial Deck: `~/.config/serial-deck/profiles/<name>.json` (or the directory in
`SERIAL_DECK_PROFILE_DIR`). The pairing form then offers a *Profile* list that
fills the fields, and `serial-deck-web --profile NAME` / `serial_deck.mcp_server
--profile NAME` take the default baud, mode and tool prefix from it:

```json
{"label": "My board", "remote_socket": "/run/svc.sock.stream", "control_socket": "/run/svc.sock",
 "screen_path": "/api/screen?format=jpeg", "restart_args": ["a", "b"],
 "follow_socket_suffix": ".stream", "mcp_tool_prefix": "board",
 "default_baud": 2000000, "default_mode": "control"}
```

A profile is data only. A file with an unknown key or an invalid value is
reported and skipped (the others still load), and there is deliberately no key
that runs a command: the restart command is typed at pairing and stays on the host.

## Automation

Open **Automation** in the left bar.

**Auto-connect** is off until you switch it on, because opening a UART can reset
a board. The **Auto-reconnect** checkbox next to Connect brings a dropped device
back with the same baud and mode, following a replugged USB board to its new port
name by vid:pid and serial number. On the Automation page you can also reopen last
session's ports at start, and add **rules** ("when this USB device is plugged in,
connect it at this baud in this mode"). Settings live in
`~/.config/serial-deck/settings.json`.

**Python scripts** are files you write in `~/.config/serial-deck/scripts/`:

```python
"""Log in to a Linux board and watch for panics."""

def run(dev):
    dev.expect(r"login:", timeout=30)
    dev.send_line("root")
    dev.expect(r"# ", timeout=10)

def on_line(dev, line):
    if "Kernel panic" in line:
        dev.log("the board panicked")
```

`dev.expect(regex, timeout)`, `dev.expect_any([...])`, `dev.send(text_or_bytes)`,
`dev.send_line(text)`, `dev.send_frame(bytes)` (control mode), `dev.sleep(s)`,
`dev.flush()` and `dev.log(text)`. A script with only `on_line` keeps listening
until stopped. Run them from the Automation page, from a terminal
(`serial-deck script list|run|start|stop|status`) or through MCP. The hub runs each
script as its own process, so it keeps going with the window closed; tick "run when
this port opens" to start it on every connect. A script is code you wrote and runs
with your permissions, but it only gets the device's data stream: it cannot reset
the board, enter the bootloader or flash it. The dashboard and MCP can run and stop
scripts, never create or change one.

**JavaScript snippets** (also on the Automation page) run in an isolated sandbox
with no access to the dashboard or your files; they only send to the connected
device and read what it sends, and stop when the window closes.

## Custom metrics

Turn any number in the log (free heap, CPU %, a temperature) into a live trend, with a
warning limit, without writing code. On the **Telemetry** tab:

1. Click a log line's time to open its details and press **Track a number** on the
   value you want, or pick a field from *Fields seen in the log*.
2. Give it a label and unit, optionally a multiplier (for example `0.0009765625` turns
   bytes into KB), a warn-below or warn-above limit, and tick *Show in the status bar*
   to pin it. The editor shows how many buffered lines match before you save.

Each metric gets a card (latest value, trend, min/max, a `low`/`high` badge with icon
and text) and, if pinned, a figure in the status bar.

A rule is the exact text that comes right before the number, so `free=` reads the
`190464` in `heap: free=190464 min=1`. They live in `~/.config/serial-deck/metrics.json`
(`SERIAL_DECK_METRICS_FILE` overrides the path) and you can edit the file by hand:

```json
{"rules": [
  {"id": "free_kb", "label": "Free heap", "unit": "KB", "before": "free=",
   "scale": 0.0009765625, "warn_below": 64, "pin": true},
  {"id": "temp", "label": "Temperature", "unit": "C", "before": "temp: ", "warn_above": 80}
]}
```

| Field | Meaning |
|---|---|
| `id`, `label`, `before` | required; `id` is a lowercase letter then up to 31 lowercase letters, digits or `_` |
| `tag` | only match lines from this exact ESP-IDF tag (omit to match any line) |
| `unit`, `scale` | shown after the value; the number is multiplied by `scale` first (default 1) |
| `warn_below`, `warn_above` | in scaled units; a value equal to the limit is not a warning |
| `pin` | show in the status bar |

The number must be written plainly: an optional `-`, digits, an optional `.digits`
and an optional exponent (`-3`, `2.5`, `1e3`). The first occurrence of the text that is
followed by a number is used. Echoed `TX>` lines and symbolized `[ELF]` lines are
never measured. There is no regex on purpose, so no rule can slow the page down.

A **device profile** can ship rules too: add a `metrics` list (same fields) to the
profile JSON. Profile rules are read-only in the dashboard (use *Copy to mine* to
change one); a rule of yours with the same `id` replaces it. Limits: 32 rules after
merging, `before` up to 64 characters, `label` 40, `unit` 8, `metrics.json` 16 KiB.
`serial-deck-web --profile NAME` selects the profile; the desktop app and other
entry points read only `metrics.json`.

Trends are kept per connection in the open window (600 samples per rule), are not
saved, and are not visible to MCP or exports. Saving checks that the file did not
change meanwhile: if another window saved first, the dashboard reloads instead of
overwriting.

## Flashing ESP32 firmware

Build with ESP-IDF, then pick the **absolute** build directory in the Flash
panel (or pass `--build-dir`). Serial Deck reads `flasher_args.json`, uses the
chip it names (`esp32`, `esp32s3`, `esp32c6`, `esp32p4`, ...) and runs esptool
inside the hub, so no other program has to take the port.

```bash
serial-deck-flash --port COM5 --build-dir C:\work\app\build --baud 921600 --dry-run   # show the command
serial-deck-flash --port COM5 --build-dir C:\work\app\build --baud 921600 --yes       # flash
```

The standalone flasher above needs the port to be free. The dashboards flash
through the hub instead and reopen the console afterwards. Flash baud is
independent of console baud.

## Control protocol (optional)

Firmware can expose structured commands (queries, buttons, an info screen)
over the same UART as its logs, using COBS-framed JSON with a CRC32. Logs keep
working alongside it. The wire format is in [docs/PROTOCOL.md](docs/PROTOCOL.md).

```bash
serial-deck --port COM3 hello
serial-deck --port COM3 query snapshot
serial-deck --port COM3 button ENTER press
serial-deck --port COM3 monitor --control
```

`reset` and `bootloader` toggle DTR/RTS in the usual ESP auto-reset wiring.
Run them only when you mean it.

## MCP server for AI agents

```bash
python -m pip install "serial-deck[mcp]"
claude mcp add serial-deck -s user -- python -m serial_deck.mcp_server --allow interact
```

`--allow observe|interact|hardware` is your choice, not the agent's. Tools
outside the policy are never registered. Flashing is two-step: the agent
previews an immutable snapshot of the build and must show it to you before it
can flash. Details are in [docs/MCP.md](docs/MCP.md). The Web dashboard's MCP
page shows registration commands and live agent activity.

An agent skill for Claude Code / Codex lives in
[skills/serial-deck/](skills/serial-deck/); copy it to `~/.claude/skills/`.

## Development

```bash
python -m pip install -e ".[app,mcp]"
python -m unittest discover -s tests -t .
SERIAL_DECK_IPC=tcp python -m unittest discover -s tests -t .   # Windows transport on POSIX
```

The tests need no hardware: they run real hubs against pseudo-terminals (POSIX)
and a fake TCP UART bridge (every OS). CI runs them on Linux, macOS and Windows.
UI conventions are in [docs/DESIGN_GUIDELINES.md](docs/DESIGN_GUIDELINES.md).

## Troubleshooting

- **Garbled output:** the console baud must match the firmware. Flash baud does
  not affect it.
- **Port missing from the list:** check permissions (Linux `dialout`) and that
  no other program holds the port.
- **Queries time out but logs are fine:** the firmware does not implement the
  control protocol; stay in Linux / Raw mode.
- **Port name changed after a reset or replug:** rescan and reconnect. Prefer
  `/dev/serial/by-id/...` on Linux.
- **"socket path is over the limit" (macOS):** pass a shorter `--socket`, or set
  `SERIAL_DECK_IPC=tcp`.

## License

Apache License 2.0, see [LICENSE](LICENSE). The vendored Web UI assets keep
their own licenses, listed in
[serial_deck/web_assets/vendor/README.md](serial_deck/web_assets/vendor/README.md).
