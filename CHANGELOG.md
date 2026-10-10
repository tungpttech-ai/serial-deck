# Changelog

## Unreleased

- Auto-connect, always off until you turn it on (opening a UART can reset a
  board):
  - **Auto-reconnect** (checkbox next to Connect): a device that is unplugged,
    reset or whose link drops comes back by itself with the same baud and mode.
    A replugged USB board is found again by its vid:pid and serial number even if
    its port name changed. A manual Disconnect is never undone, and nothing
    reconnects during a flash.
  - **Restore on start**: reopen the ports you had open last time.
  - **Device rules**: when a matching USB device is plugged in, connect it with
    the baud and mode you chose. Each plug-in is acted on once.
- Scripts (Automation page, `serial-deck script`, MCP):
  - **Python scripts** in `~/.config/serial-deck/scripts/`: `run(dev)` and/or
    `on_line(dev, line)` with `dev.expect`, `dev.send_line`, `dev.send_frame`,
    `dev.sleep`, `dev.log`. They run as separate processes under the hub, so they
    keep going with no window open, can start automatically when a port opens, and
    are stopped with the hub. They cannot reset, enter the bootloader or flash.
    Nothing in the dashboard or MCP can create or edit a script.
  - **JavaScript snippets**: quick scripts in an isolated browser sandbox that can
    only send to the connected device and read what it sends.
  - MCP: `serial_script_list`/`_status` (observe), `serial_script_run`/`_stop`
    (interact).

- Linux frozen bundles now include the Qt WebEngine backend and open the
  dashboard in a native window by default.

## Unreleased

- Devices that are not a physical UART: `unix:///path` (a local stream socket)
  next to `tcp://` and `udp://`. They have no baud, DTR/RTS, reset, bootloader
  or flashing, and every client says so instead of trying.
- SSH devices (Linux and macOS): pair a remote Unix socket once, then connect
  to `ssh-socket://<name>` like any port. The hub owns the `ssh -N -L` tunnel,
  reconnects with backoff and reports `connected / reconnecting / auth_failed /
  host_key_changed / passphrase_required / socket_missing / unreachable`.
  Pairing pins the host key after you compare its fingerprint, installs a key
  made for that device only (it can open socket tunnels and run a few fixed
  verbs, never a shell), and never stores the password. An optional passphrase
  on the device key is asked on each connect and never stored. Forgetting a
  device removes exactly its key line from the host. The Web/App dashboard has
  a grouped port picker, a pairing wizard and a link-state fix button; MCP
  lists `ssh_devices` and connects by name (pairing is dashboard-only).
- Hub hardening: sockets are owner-only and a connecting process must run as the
  same user (`SO_PEERCRED`); failed claims carry a machine-readable `code`; the
  hub refuses writes while a device link is down instead of half-sending.

## 0.2.1 (2026-10-03)

- Linux AppImage: the app could not start its hub on distributions whose
  `/bin/sh` is bash (Arch, Fedora, Manjaro, ...): the relaunch inherited the
  bundle's library path and the AppRun shell crashed. Relaunches now use the
  host's libraries. The `.deb`, Windows and macOS builds were not affected.
- Release checks now also run the AppImage on Arch Linux and Fedora.

## 0.2.0 (2026-10-02)

Native installers: no Python needed.

- Windows: per-user installer (`Setup.exe`) and a portable zip. Setup stops an
  idle hub before replacing files and refuses while Serial Deck is in use.
- macOS 15+: `.dmg` for Apple silicon and Intel.
- Linux: AppImage and `.deb` for Ubuntu 22.04+ / Debian 12+; the app opens the
  dashboard in your browser.
- One `serial-deck-cli` in every bundle runs the hub, CLI and MCP server; the
  MCP page shows the bundle's own registration command.
- `app --browser` mode with a Quit button; it never quits during a flash.
- `hub --shutdown` waits until the hub process has exited and returns
  scriptable exit codes (0 stopped, 3 not running, 4 refused, 5 timeout).
- Flashing a frozen bundle runs the bundled esptool in-process;
  `flash --self-test` checks every flasher stub.
- Release builds are reproducible from hash-locked dependencies per platform,
  smoke-tested on each OS, and signed once certificates are configured.

## 0.1.0 (2026-10-02)

First public release.

- One per-user hub daemon owns every UART; Web, native app, Tk desktop, CLI
  and MCP clients share ports at the same time. TCP/UDP UART bridges too.
- Raw/Linux console by default (nothing is sent to a device unasked), with an
  optional control mode for firmware that implements the
  [control protocol](docs/PROTOCOL.md).
- Changing the baud of a shared port asks first, then retimes the open UART in
  place (no reset pulse); every client follows the change.
- ESP-IDF flashing for any ESP32-family chip, run inside the hub so only the
  flashing port pauses; MCP flashing is two-step through an immutable snapshot.
- Linux, macOS and Windows. Hub IPC uses Unix sockets on POSIX and
  token-authenticated loopback TCP on Windows (`SERIAL_DECK_IPC=tcp` anywhere),
  with per-user private state (0700 / an owner-only Windows DACL).
