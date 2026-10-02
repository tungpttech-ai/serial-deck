# Serial Deck — UI design guidelines

Scope: the Tk/ttk desktop UI in [`desktop.py`](../serial_deck/desktop.py)
(`ControlDeck`). Keep this file and the `_build_style()` /
design-token block at the top of that module in sync — if you change one,
update the other in the same commit.

Goal: a small, dense engineering tool (UART control + log viewer), not a
consumer app. Every rule below optimizes for legibility during a debug
session (long log lines, frequent glance-backs at connection state) over
decoration.

## 1. Design tokens

All colors are named constants at the top of `desktop.py`.
**Never hardcode a hex color in a widget call** — add or reuse a token
instead, so a future palette change is a one-line edit.

| Token           | Hex       | Use for |
|-----------------|-----------|---------|
| `BG`            | `#0b0f14` | Window background, outside all cards |
| `SURFACE`       | `#12181f` | Card background (`Panel.*` styles) |
| `SURFACE_ALT`   | `#1a222b` | Nested/hover surface, chips, pills, active tab |
| `BORDER`        | `#232d38` | 1px card border, separators |
| `TEXT`          | `#eaeef2` | Primary text |
| `MUTED`         | `#7c8a99` | Secondary text, labels, placeholders |
| `ACCENT`        | `#f2994a` | Primary action (Connect, Load, Flash) |
| `ACCENT_HOVER`  | `#ffad63` | Primary action, active/hover state |
| `DANGER`        | `#f2635a` | Hardware-affecting or destructive actions (Reset, Bootloader, ONOFF), and the `error` log tag |
| `SELECTION`     | `#2f5673` | Text selection highlight in the log/event views — must stay clearly visible against `#0a0d12` |
| `GREEN`/`RED`/`YELLOW`/`BLUE`/`PURPLE`/`CYAN` | see source | Semantic log-level tags only (see §5) — do not repurpose for UI chrome |

Spacing is a 4px-based scale, also defined as constants: `SPACE_XS=4`,
`SPACE_SM=8`, `SPACE_MD=14`, `SPACE_LG=20`. Use these instead of literal
padding numbers so spacing stays consistent across sections.

Fonts: `FONT_FAMILY = "Segoe UI"` for UI chrome, `MONO_FAMILY =
"Cascadia Mono"` for anything showing raw device output (console log,
control events, DTR/RTS raw state). Never mix them.

## 2. Building blocks — reuse, don't reinvent

- **Card** (`self._card(parent)`): a 1px `BORDER`-colored frame wrapping a
  `SURFACE` panel. This is the only container primitive for a titled
  section. Returns `(border_frame, inner_frame)` — `pack`/`grid` the
  border frame, put content in the inner frame.
- **Section header** (`self._section_header(parent, title, subtitle)`):
  uppercase bold title + muted one-line subtitle. Every card starts with
  one call to this before any control.
- **Chip / pill** (`Chip.PanelAlt.TLabel`, the header status pill): a
  `SURFACE_ALT` badge with padding, used for glanceable state (FSM
  summary, connection status). Not a button — chips are read-only.

Add a new style variant only when an existing one doesn't fit; don't
invent a one-off `.configure()` call inline in `_build_ui`.

## 3. Button hierarchy

Pick the style by what the action *does*, not by where it sits:

| Style | Meaning | Examples |
|-------|---------|----------|
| `Accent.TButton` | The primary, expected action in its card | Connect, Load (symbols), Flash |
| `Dark.TButton` | Secondary / safe / reversible action | Scan, Browse, Refresh snapshot, Read FSM |
| `Danger.TButton` / `Power.TButton` | Touches physical hardware state (reset lines, power) or is destructive | Reset, Bootloader, ONOFF |
| `Ghost.TButton` | Low-emphasis inline action, doesn't compete with content | Clear (log toolbar) |
| `Nav.TButton` | Directional/navigation control inside the D-pad cluster | HOME, LEFT, RIGHT, ENTER |

At most **one** `Accent.TButton` per card — if a card seems to need two
primary actions, it should probably be two cards.

## 4. Layout rules

Top to bottom, the window is: header (title + global connection pill) →
Connection card (full width) → a 2-column row of small cards for
peripheral setup (Symbols, Flash) → body (fixed-width sidebar card for
Control/Read/Board, expanding main area for summary + log tabs).

- The sidebar is a fixed-width card that fills the body's height even
  when its content doesn't — this keeps the log/tabs area's left edge
  aligned regardless of window size. Don't make it width-flexible.
- The main log area is always the widget that gets the extra space when
  the window is resized (`fill="both", expand=True`). Never let a
  sidebar or toolbar grow at the log's expense.
- Related controls that share one physical action (e.g. an entry + its
  Browse button + its confirm button) stay on one row, in that order:
  input → secondary action → primary action.
- The button-cluster for the five logical control events is a single
  horizontal row, left to right: `ONOFF, LEFT, ENTER, RIGHT, HOME`. Keep
  this exact order and the power/nav style split (`Power.TButton` for
  ONOFF, `Nav.TButton`/`dpad-btn` for the rest) in both Desktop
  (`desktop.py`) and Web Dashboard (`web.py`) —
  don't reorder or revert to a directional-pad grid without checking with
  whoever owns this layout preference first.

## 5. Log/event text tags

Tag colors in `log_text` map to firmware log levels and must stay fixed
so operators build muscle memory across sessions — don't repurpose them:

`error`→`RED`, `warning`→`YELLOW`, `info`→`GREEN`, `debug`→`BLUE`,
`verbose`→`PURPLE`, `elf`→`CYAN` (decoded-address / tool-internal lines).
`event_text` uses `success`→`GREEN` for `FRAME_RESPONSE` frames only.

Never rely on color alone for a state that also needs to be read at a
glance under bad lighting/screen-share compression: pair every color
with a text label (the connection pill always renders both a colored dot
and the word "Connected"/"Disconnected").

Any read-only `tk.Text` (the log/event views, and any future one) must be
built with `self._make_readonly()` and stay `state="normal"` — do **not**
toggle `-state` between `"normal"`/`"disabled"` to fake read-only. Mouse
drag-selection on a disabled `Text` widget is unreliable across Tk
builds/platforms; `_make_readonly()` blocks typing/paste with key/paste
bindings instead, which keeps selection and Ctrl+C copy working
everywhere. Give it `selectbackground=SELECTION` (not `SURFACE_ALT`) so
a selection is visibly distinct from the normal background.

## 6. Accessibility / legibility

- Body text stays at 9–10pt minimum; the title is the only large text
  (22pt) — this is a dense tool, not a poster.
- `TEXT` on `SURFACE`/`BG` and `DANGER`/`ACCENT` on their button
  backgrounds must stay at or above ~4.5:1 contrast. If you change a
  token, re-check contrast before committing.
- Every interactive control needs a visible `active`/`disabled` state in
  its `style.map(...)` — see the existing button styles for the pattern.

## 7. When adding a new section

1. Add a token if (and only if) no existing token fits — extend the
   table in §1 in the same change.
2. Build it with `self._card()` + `self._section_header()`.
3. Pick a button style from §3 by action intent, not by copy-pasting the
   nearest existing button.
4. Screenshot before/after if the change is visual — this is a
   Tk app with no automated visual test.

## 8. Web Dashboard (`serial_deck/web.py`)

The Web Dashboard uses a compact industrial visual direction. Its compact industrial palette is implemented through Tailwind
`brand-*` colors: `#111318` canvas, `#1e2024` surface, `#3b494c` border,
`#00e5ff` primary cyan, and `#fd9000` flash amber. Inter is UI chrome;
JetBrains Mono is reserved for telemetry, UART state, logs, paths, and numeric
data. Flash amber must not replace cyan for normal primary actions.

Key architectural invariants:
- Zero build tools required: serves self-contained HTML/JS/CSS directly.
- Real-time streaming via SSE (`/api/stream`) with automatic reconnection and initial replay.
- Live search and log level filters ([E], [W], [I], [D], [V], [ELF]) match desktop tags.
- Keep `RAW` as a separate filter for unclassified lines. It is off by default
  to protect rendering performance, but filtering must not remove entries from
  history or exported logs.
- D-pad virtual controls mirror physical hotkeys (WASD, Arrows, Space, Esc).
- Telemetry Inspector parses and presents real-time JSON frames cleanly.
- Keep the dense two-pane desktop layout, but stack controls above telemetry at
  widths below 900 px. Preserve every JavaScript-owned DOM ID during visual
  changes so the UART/control contract remains functional.
- Web owns no physical UART. It claims a target through the hub control socket,
  sends `flash` there, and consumes the hub's status/progress stream.
- The Connections bar below the header lets the dashboard hold several UART
  connections open at once, each in its own tab: the `default` tab (backed by
  the fixed `--socket` hub, for compatibility with other launchers) plus any
  tabs opened with the `+` button. Every tab keeps its own hub connection,
  SSE stream (`/api/stream?id=`), and log/event buffers, and streams in the
  background even while a different tab is focused. Tabs for different
  physical ports run fully independent hub processes (`HubRegistry` in
  `hub_client.py`, keyed by port). A new tab opened for the same
  port the app was launched with (`--port`) reuses the `default` tab's hub
  (pinned in `HubRegistry` at startup). If the `default` tab is later
  reconnected to a *different* port at runtime, that new port is not pinned;
  opening another tab for that same port would spawn a second, conflicting
  hub process for it — prefer the `default` tab's own connect/disconnect
  controls over opening a duplicate tab for whatever port it currently holds.
- Two ways to watch two connections at once, pick by how much screen you
  want to dedicate to it:
  - **Split console** (`splitViewBtn`, the table-columns icon in the Console
    Stream toolbar): renders a second open connection's console log beside
    the primary one, inside the same browser tab. Only the Console Stream
    view splits — Control Events, Telemetry Inspector, and the sidebar
    (D-pad/Queries/Flash) stay single and follow the primary (`connId`)
    connection. Pick the second connection from the dropdown in the split
    pane's own header; it must already be open (create it with `+` first).
  - **Native OS window split**: switching or creating a connection now
    writes its id into the URL (`?conn=<id>`, via `history.replaceState`).
    Copy the address bar into a second browser window and use the OS's own
    window-snap/tile — each window then independently shows its own
    connection with the full sidebar (D-pad, Queries, Flash) rather than
    just the log.
- The sidebar (`#sidebarPanel`) can be hidden (chevron button on the resize
  handle) and is drag-resizable (260–560px) via that same handle, to make
  room for a wide split console. Collapse/resize only apply above the
  900px breakpoint — the mobile stacked layout always shows the sidebar at
  full width.

## 9. Hub Desktop (`desktop_hub.py`)

The Hub Desktop is a native desktop application and stays separate from the Web
Dashboard in section 8. It reuses the desktop visual system and widgets from
`desktop.py`, while replacing direct UART ownership with the hub
transport. It must not start an HTTP server, open a browser, or import the Web
Dashboard frontend. Keep `desktop_direct.py` as the explicit
direct-UART launcher.

- The port selector displays physical UARTs returned by the hub. Connect sends
  the selected port and baud to the idle hub; only the hub opens the UART, while
  runtime traffic still uses its Unix endpoint.
- Disconnect asks the hub to release the UART when no other data clients remain.
- A live pre-existing hub is attached but never terminated by the desktop.
- Flash never stops the hub or opens a second UART process. The hub pauses its
  serial reader, runs esptool in-process, broadcasts progress to all clients,
  reopens the claimed UART, and resumes fan-out logs.
- Reset, bootloader, DTR/RTS, logs, queries, and button commands use the existing
  socket transport and hub control socket rather than a second serial open.
- The port selector and connection status must show the physical UART rather
  than leaking the internal `unix://` endpoint as the selected device.
- Native desktop startup must preserve idle hub startup, attach-only ownership,
  and explicit opt-in auto-connect.
