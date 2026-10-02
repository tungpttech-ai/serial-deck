# Control protocol v1

An optional protocol that firmware can implement to accept structured commands
over the same UART that carries its logs. Serial Deck's **Control** mode, the
`serial-deck hello|query|button|show-info` CLI commands and the MCP tools
`serial_hello`, `serial_query`, `serial_button` and `serial_show_info` use it.
Raw / Linux mode never sends any of it.

The reference host implementation is `serial_deck/uart_client.py`
(`encode_frame`, `decode_frame`, `make_request`, `validate_request`).

## Framing

Frames and plain log text share the byte stream. Each frame is
[COBS](https://en.wikipedia.org/wiki/Consistent_Overhead_Byte_Stuffing)-encoded
and terminated by a single `0x00` byte, so a frame never contains a zero
before its end. Bytes that do not decode as a valid frame are treated as log
text.

Decoded frame layout, little-endian:

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | `version` = 1 |
| 1 | 1 | `type` (see below) |
| 2 | 1 | `flags` (0) |
| 3 | 4 | `sequence` (uint32) |
| 7 | 2 | `payload_len` (uint16, at most 1536) |
| 9 | `payload_len` | payload: UTF-8 JSON object |
| 9 + `payload_len` | 4 | CRC-32 (IEEE 802.3, as `zlib.crc32`) of every preceding byte |

The encoded frame, including the trailing zero, is at most 2048 bytes.

| `type` | Name | Direction |
|---|---|---|
| 1 | HELLO | host → device, and the device's reply |
| 2 | COMMAND | host → device |
| 3 | RESPONSE | device → host, echoes the COMMAND's `sequence` |
| 4 | EVENT | device → host, the device's own `sequence` |
| 5 | ERROR | device → host, echoes the offending `sequence` |

## HELLO

Host request payload:

```json
{"type": "hello", "protocol": "serial-deck-control", "version": 1, "client_id": "serial-deck-cli-1a2b3c4d"}
```

The device replies with a HELLO frame carrying the same `sequence`:

```json
{"version": 1, "transport": "uart0", "baud": 115200, "target": "my-board",
 "commands": ["query", "input.button", "ui.show_info"]}
```

Only `version` and `commands` are required. The device may ignore the
request's fields.

## COMMAND

```json
{"version": 1, "request_id": "9f2c41d07a3b5e61", "command": "query",
 "args": {"kind": "snapshot"}, "deadline_ms": 1000}
```

| Field | Rule |
|---|---|
| `request_id` | 1-32 characters, unique per request |
| `command` | `query`, `input.button` or `ui.show_info` |
| `args` | object, at most 1024 bytes as canonical JSON |
| `deadline_ms` | 1-30000 |
| `idempotency_key` | required (1-64 chars) for state-changing commands: `input.button`, `ui.show_info` |

Arguments:

- `query`: `{"kind": "capabilities" | "identity" | "fsm" | "snapshot"}`
- `input.button`: `{"button": "HOME" | "LEFT" | "RIGHT" | "ENTER" | "ONOFF", "action": "press" | "release" | "long_press"}`
- `ui.show_info`: `{}`

## RESPONSE and EVENT

The device answers each COMMAND with a RESPONSE (same `sequence`) and may then
report progress with EVENT frames (its own `sequence`). Both carry:

```json
{"version": 1, "request_id": "9f2c41d07a3b5e61", "operation_id": "op-9f2c41",
 "status": "succeeded", "error": "", "esp_error": 0, "retryable": false,
 "event_seq": 3, "command": "query", "result": "{\"state\":\"IDLE\"}"}
```

- `status`: `accepted`, `running`, then one terminal status: `succeeded`,
  `failed`, `cancelled`, `expired` or `rejected`.
- `error`: empty, or one of `invalid_schema`, `unknown_command`,
  `unauthorized`, `forbidden`, `invalid_state`, `busy`, `deadline_exceeded`,
  `duplicate_request`, `transport_unavailable`, `hardware_unavailable`,
  `operation_not_found`, `internal_error`, `already_running`.
- `event_seq` increases per operation. Hosts drop duplicates and stale events
  by it, and match RESPONSE and EVENT frames by `request_id`.
- `result` is a string, usually JSON-encoded.

ERROR frames report requests the device could not parse. They may lack a
`request_id`, so hosts match them by `sequence`.

## Host behavior

Serial Deck writes each frame atomically through the hub (`write_frame`), so
frames from different clients never interleave on the wire. It never retries a
command whose outcome is unknown. A request that timed out may already have
run, so check device state before sending it again.
