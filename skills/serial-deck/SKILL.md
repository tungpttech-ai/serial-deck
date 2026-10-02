---
name: serial-deck
description: Read logs from, control, reset and flash serial devices (ESP32 boards, Linux consoles, other UARTs) through the Serial Deck shared hub, its dashboards, CLI or MCP tools. Use for serial console logs, firmware control-protocol queries, reset/bootloader, ESP-IDF flashing and post-flash checks.
---

# Serial Deck

Serial Deck is installed as the Python package `serial_deck` (commands
`serial-deck`, `serial-deck-hub`, `serial-deck-web`, `serial-deck-flash`, ...,
also runnable as `python -m serial_deck.<module>`). Every client goes through
one per-user hub daemon; only the hub opens a physical UART.

## Prefer the MCP tools

When `serial_*` MCP tools are available, use them instead of the CLI:

- Observe: `serial_status`, `serial_list_ports`, `serial_connect`,
  `serial_logs` (cursor paging, substring filters), `serial_wait_for`,
  `serial_symbolize`.
- Control-protocol firmware only: `serial_hello`, `serial_query`,
  `serial_button`, `serial_show_info`. Use `mode="raw"` for anything else.
- Hardware: `serial_reset`, `serial_bootloader`,
  `serial_flash_preview` → `serial_flash_start` → `serial_flash_status`.

The user's `--allow` policy decides which tools exist. Never ask for a higher
policy to get around a decision.

## Rules

1. Check `serial_status` (or `serial-deck-hub --status`) before starting
   anything. Reuse the running hub and its channels; never start a second hub.
2. Identify the device by USB identity (`serial_list_ports`), not by its port
   number. Port names change after replug or reset.
3. Keep a shared port's live baud. Retiming (`change_live_baud=true`) changes it
   for every client: ask the user first, and use the baud the firmware needs.
4. On `outcome: "unknown"`, do not resend. Inspect state with logs or a query
   first.
5. Flash only when the current request authorizes it. Show the
   `serial_flash_preview` summary (chip, port, images, partitions) and get
   approval before `serial_flash_start`. Never erase, write NVS or eFuses, or
   flash a device the user did not name.
6. Reset and bootloader disrupt the device; run them only when asked.
7. Pass absolute build and ELF paths: the hub runs in another working
   directory.
8. Redact credentials, tokens and session material from anything you report.

## CLI fallback

```bash
serial-deck-hub --status
serial-deck --port <PORT> --baud <BAUD> monitor            # raw; add --control for frames
serial-deck --port <PORT> query snapshot                   # control-protocol firmware
serial-deck-flash --port <PORT> --build-dir /abs/build --dry-run
```

Bound long monitors with a timeout and filter output instead of dumping an
unlimited stream.

## Completion

Report the hub status, the confirmed device and port, firmware/build identity
when known, the commands or tools used, the observed lifecycle, and a
`verified` / `partial` / `blocked` result. A flash counts as verified only after
esptool data verification plus a post-flash boot log or control-protocol check.
