# Changelog

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
