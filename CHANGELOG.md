# Changelog

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
