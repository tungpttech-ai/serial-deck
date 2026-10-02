# MCP server

`serial_deck.mcp_server` lets AI agents (Claude Code, Claude Desktop, Codex,
Cursor, ...) watch and drive serial devices through the **shared hub**, side by
side with the Web/App dashboards.

```
            hub daemon (serial-deck-multiport-v1), owns every UART
        ▲ data + ctl            ▲ data + ctl             ▲
   Web / App / Desktop     mcp_server (agent)          CLI
```

The MCP server is just **another hub client**. It never opens a UART itself,
never starts per-port hubs and never stops the hub, so you can keep a dashboard
open on the same device while an agent works.

## Install

```bash
python -m pip install "serial-deck[mcp]"     # mcp 2.2.x
```

### Register

Claude Code (user scope, every project):

```bash
claude mcp add serial-deck -s user -- python -m serial_deck.mcp_server --allow interact
claude mcp get serial-deck        # Status: ✔ Connected
```

Codex:

```bash
codex mcp add serial-deck -- python -m serial_deck.mcp_server --allow interact
```

Claude Desktop and other clients (JSON):

```json
{
  "mcpServers": {
    "serial-deck": {
      "command": "/path/to/python",
      "args": ["-m", "serial_deck.mcp_server", "--allow", "interact"]
    }
  }
}
```

Use the interpreter that has `serial-deck` installed, for example
`.venv/bin/python` or `.venv\Scripts\python.exe`. The dashboard's **MCP** page
shows ready-to-copy commands with the right path for your machine. Tools load
when the client starts a new session.

### Command-line options

| Option | Env | Default | Meaning |
|---|---|---|---|
| `--allow observe\|interact\|hardware` | `SERIAL_DECK_MCP_ALLOW` | `observe` | Highest action level the agent may use |
| `--socket PATH` | `SERIAL_DECK_HUB_SOCKET` | per-user default hub | Shared hub endpoint |
| `--log-level` | | `WARNING` | Server log (stderr only, never stdout) |
| `--no-activity` | | | Do not publish activity to the dashboard |

## Policies

**You** pick the policy when registering; the agent cannot raise it. Tools
outside the policy are **not registered**, so the agent never sees them.
`serial_status` lists the disabled tools.

| Policy | Adds tools | Effect |
|---|---|---|
| `observe` | `serial_status`, `serial_list_ports`, `serial_connect`, `serial_disconnect`, `serial_hello`, `serial_query`, `serial_logs`, `serial_wait_for`, `serial_symbolize`, `serial_flash_preview`, `serial_flash_status` | Read only (a flash preview writes nothing to the board) |
| `interact` | `serial_button`, `serial_show_info` | Changes firmware UI state; may retime a shared port's baud |
| `hardware` | `serial_reset`, `serial_bootloader`, `serial_flash_start` | Reset, ROM bootloader, firmware writes |

This is a **guard against agent mistakes**, not a security boundary between
processes of the same user. Your MCP client's permission prompt still approves
each call. `interact` is a good everyday choice; enable `hardware` only to
flash or reset.

## Tools

Every tool returns structured JSON (`structuredContent` and `outputSchema`).
Errors come back as `isError: true` with
`{"ok": false, "error": {"code", "message", "hint"}}`. With exactly one port
connected, `port` may be omitted.

| Tool | Main arguments | Result |
|---|---|---|
| `serial_status` | – | Hub (pid, channels, flash state, `features`), policy, sessions, flash jobs, `tx_atomic` |
| `serial_list_ports` | – | Ports with product/interface names, USB `vid:pid`/serial, whether the hub has a channel. Opens nothing |
| `serial_connect` | `port`, `baud?`, `mode=control\|raw`, `change_live_baud=false` | Attach through the hub. `control` sends HELLO; `raw` only reads logs |
| `serial_disconnect` | `port?` | Detach this server only; dashboards keep streaming |
| `serial_hello` | `timeout_s` | The firmware's HELLO: transport, baud, commands |
| `serial_query` | `kind=capabilities\|identity\|fsm\|snapshot`, `redact_identity=true` | Full lifecycle `accepted → running → succeeded` and `result` |
| `serial_logs` | `cursor?`, `limit≤500`, `contains?`, `levels?`, `frames?` | Log records. Without a cursor: the latest; with one: pages via `next_cursor` |
| `serial_wait_for` | `any_of[]`, `timeout_s≤120`, `since?`, `context` | Waits for a line containing any substring, returns it with context |
| `serial_symbolize` | `text`, `elf` (absolute path) | Resolves `0x…` addresses with the ESP-IDF addr2line |
| `serial_button` | `button=HOME\|LEFT\|RIGHT\|ENTER\|ONOFF`, `action=press\|release\|long_press` | Command lifecycle |
| `serial_show_info` | – | Opens the firmware's info screen |
| `serial_reset` | `wait_for?[]`, `timeout_s` | RTS/EN reset, optionally waits for a boot marker |
| `serial_bootloader` | – | Puts an ESP chip into ROM download mode |
| `serial_flash_preview` | `build_dir` (absolute), `flash_baud=3000000` | Validates the build, snapshots it, returns images, hashes, the esptool command and a `token` |
| `serial_flash_start` | `token` | Flashes exactly the previewed snapshot |
| `serial_flash_status` | `token`, `wait_s≤60` | Progress (MCP progress notifications) and the final verdict |

`serial_query`, `serial_button`, `serial_show_info` and `serial_hello` need
firmware that implements the [control protocol](PROTOCOL.md). Everything else
works with any serial device.

## Typical flows

**Observe:**

```
serial_list_ports → serial_connect("COM3", mode="raw")
→ serial_logs(levels=["error","warning"]) → serial_wait_for(["APP_READY"])
```

**Debug a crash:**

```
serial_wait_for(["Guru Meditation","Backtrace","abort"], timeout_s=120, context=30)
→ serial_symbolize(text=<backtrace lines>, elf="/abs/build/app.elf")
```

**Reset and wait for boot** (`hardware`):

```
serial_reset(wait_for=["main_task: Calling app_main"], timeout_s=20)
```

**Flash** (`hardware`), always two steps **with you approving in between**:

```
serial_flash_preview("/abs/firmware/build")   → the agent shows you the summary
serial_flash_start(token)                     → only after you agree
serial_flash_status(token, wait_s=60)         → repeat until there is a verdict
```

## Watching from the dashboard

The **MCP** entry in the Web/App left rail (plug icon) shows:

- Setup instructions and the policy table.
- Install commands for Claude Code, Codex and JSON for Claude Desktop/Cursor,
  each with a copy button and a selectable `--allow`.
- The current Claude Code (`~/.claude.json`) and Codex
  (`~/.codex/config.toml`) registrations.
- **Running MCP servers**: pid, the client that started it (Linux), policy,
  attached ports, flash progress and the last 25 tool calls (time, redacted
  arguments, status, duration, short result). It refreshes every 1.5 s, and
  the rail shows a badge with the number of running servers.

Each server publishes its state to `<runtime dir>/mcp-activity/<pid>.json`,
inside the private per-user hub directory. It holds redacted metadata only.
The file is removed when the server exits, and files of dead processes are
cleaned up when read. Disable it with `--no-activity`.

## Behavior worth knowing

### Logs

- A ring of 5000 records per port. **Logs exist only from the moment the
  server attached**; there is no earlier history. Lines are capped at 2000
  characters and responses at 500 records or 48 KB, with `truncated` and
  `next_cursor`.
- `dropped > 0` means the ring overflowed past your cursor.
- `serial_logs` and `serial_wait_for` filter by **substring** (no regex).
- `note` records such as `[mcp] button ENTER press` or `[mcp] reset` let you
  line logs up with the agent's actions.

### Baud

`serial_connect` keeps a shared port at its live baud and says so in
`baud_note`. Retiming it changes the baud for **every** client on that port, so
the agent must ask you first and then call `serial_connect(..., change_live_baud=true)`,
which needs `interact`. Sessions log `UART baud changed A -> B` when any client
retimes the port.

### Firmware commands and `outcome`

- Firmware echoes the request `sequence` in RESPONSE frames but uses its own
  sequence for lifecycle EVENT frames. The server therefore correlates by
  `request_id` and `operation_id`, drops duplicates and stale events by
  `event_seq`, and never lets a late frame overwrite a final status.
- `outcome: "completed"`: a final status arrived (`succeeded`, `failed`,
  `rejected`, `cancelled`, `expired`).
- `outcome: "unknown"`: timeout, lost connection, or the hub could not confirm
  the write. **Do not resend**; check state with `serial_query` or
  `serial_logs` first. The server never retries by itself.

### Atomic frame writes

The hub's `write_frame` control action (listed in status `features`) writes one
whole frame at once. Web, Desktop, CLI and MCP all use it, so commands from
different clients never interleave bytes on the UART.

### Redaction

Every output is scrubbed of passwords, tokens, PSKs, `Authorization`/`Bearer`
headers, URLs with user:pass, JWTs and cookies/sessions: logs, frames, query
results, HELLO, errors, esptool lines and flash steps. `serial_query("identity")`
replaces the whole result with `[redacted N chars]` by default; set
`redact_identity=false` only when you need the value.

### Flash safety

`serial_flash_preview` refuses a build when any of these hold:

- `flasher_args.json` names no ESP32-family chip.
- An image lies outside `build_dir`, uses an absolute path, or escapes with `..`.
- An image lands outside the bootloader, the partition table, `otadata` or an
  `app` partition. This is checked against the **build's own partition
  table**, so NVS, `phy_init`, `storage`, `coredump` and unmapped regions are
  all blocked.
- Images overlap.

A valid build is copied into a private snapshot under
`<runtime dir>/flash-snapshots/<token>/`, and its manifest is rewritten to
point at those copies only. Editing `build_dir` after the preview cannot change
what will be written.

The token is single-use, expires after 10 minutes and is bound to the port,
the USB `vid:pid:serial`, the channel generation, the flash baud and every
image hash. Change any of them (another board, a recreated channel, an edited
file) and the token is refused.

The hub runs esptool on the snapshot. Only that channel pauses; other ports
keep streaming. The snapshot is deleted only once the hub confirms the flash
is over. If the reply is lost, it is kept for later cleanup.

`serial_flash_status` splits the verdict into three parts:

| Field | `true` when |
|---|---|
| `flash_verified` | esptool exited 0 **and** the number of `Hash of data verified` lines equals the number of images, read from an unbroken status stream. `null` (unknown) if events were lost |
| `uart_reopened` | The channel is back to `ready` on the same port |
| `firmware_ready` | A HELLO (or a boot log) arrived **after** the flash finished |

`verdict` is `verified`, `partial`, `unknown` or `blocked`. Cancelling a
`serial_flash_status` call never cancels the flash.

## Identifying the right port

Port numbers (`ttyACM*`, `COM*`) can change after a replug. Identify a device
by `usb_serial` and interface in `serial_list_ports`, and with `serial_hello`
for control-protocol firmware. On Linux prefer `/dev/serial/by-id/...` paths.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `hello: null` on connect | Firmware busy or booting, or it does not implement the control protocol. Retry `serial_hello`, check the baud, or use `mode=raw` |
| No logs | Wrong baud or wrong port |
| `legacy_hub` | An old single-port hub holds the socket. Disconnect its clients and stop it normally; the server will not stop it for you |
| `transport_unavailable` | USB unplugged or the hub reaped the channel. Call `serial_connect` again |
| `policy_denied` / missing tools | Re-register with a higher `--allow` |
| `token_invalid` | Token used, expired, or the device/channel/images changed. Run `serial_flash_preview` again |
| `flash_refused` | The build breaks a write rule; the message names the file and partition |
| `opened_uart: true` | The server was the port's first client, so the hub opened the UART. Opening a port can pulse DTR/RTS on some boards |

## Current limits

- No log history from before attach.
- No erase, NVS/efuse writes, raw TX, DTR/RTS toggling or BREAK from MCP.
- If firmware prints no reliable boot marker, `firmware_ready` relies on a
  post-flash HELLO.

## Tests

```bash
python -m unittest tests.test_mcp tests.test_flash_snapshot
```

They run a real hub against simulated firmware on a pseudo-terminal, with no
hardware: lifecycles, stray/duplicate/late frames, `unknown`, redaction,
cancellation, clean stdio, flashing with a fake esptool to prove only snapshot
images are read, write rules on a real ESP-IDF partition table, and flash-job
races. The pseudo-terminal suites are skipped on Windows; the portable daemon
tests cover it there.
