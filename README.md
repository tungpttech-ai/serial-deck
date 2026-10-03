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
| Linux x86_64 (Ubuntu 22.04+, Debian 12+) | `serial-deck_<version>_amd64.deb` or `SerialDeck-<version>-x86_64.AppImage` | Opens the dashboard in your browser |

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
**Control** only for firmware that implements the control protocol.

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
