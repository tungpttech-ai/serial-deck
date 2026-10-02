#!/usr/bin/env python3
"""MCP server (stdio) for serial devices through the shared serial-deck hub.

Register with Claude Code:
    claude mcp add serial-deck -- python -m serial_deck.mcp_server --allow interact

The server is a hub client like the Web and Desktop dashboards: it never opens
a UART, never starts per-port hubs and never stops a hub. `--allow` is chosen
by the user and caps what an agent can do (observe < interact < hardware).
"""

from __future__ import annotations

import argparse
import inspect
import json
import logging
import os
import sys
import threading
import typing
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Any, AsyncIterator, Callable, Literal

import anyio
from mcp.server.mcpserver import Context, MCPServer
from mcp_types import CallToolResult, TextContent, ToolAnnotations
from pydantic import BaseModel, ConfigDict, Field

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from agent import (
        BUTTON_ACTIONS, BUTTONS, POLICIES, QUERY_KINDS, AgentError, DeckAgent)
    from web import ElfSymbolizer
    from hub_client import DEFAULT_SOCKET
else:
    from .agent import (
        BUTTON_ACTIONS, BUTTONS, POLICIES, QUERY_KINDS, AgentError, DeckAgent)
    from .web import ElfSymbolizer
    from .hub_client import DEFAULT_SOCKET

LOG = logging.getLogger("mcp_server")
SERVER_VERSION = "1.0.0"

INSTRUCTIONS = """\
Reads and controls serial devices (ESP32 boards, Linux consoles, other UARTs)
through the user's shared serial-deck UART hub. Typical flow:
1. serial_list_ports -> identify the device (do not trust the port number).
2. serial_connect(port) -> firmware implementing the control protocol answers
   HELLO in mode='control'; other consoles use mode='raw' (logs only).
3. serial_logs / serial_wait_for / serial_query to observe; records exist only from
   the moment this server attached.
4. Buttons, reset, bootloader and flash require the matching server policy
   and the user's explicit approval for that exact action.
Never re-send a command whose outcome is 'unknown'; inspect state first.
Flash: serial_flash_preview -> show the summary to the user -> serial_flash_start
-> serial_flash_status until a verdict. Only bootloader, partition table, OTA
data and app images of an ESP-IDF build can be written."""

Port = Annotated[str | None, Field(description="Device path or COM port, e.g. /dev/ttyACM0, a /dev/serial/by-id "
                                   "link or COM3; optional when exactly one port is connected")]


class Result(BaseModel):
    """Structured tool result; extra keys carry the tool-specific payload."""

    model_config = ConfigDict(extra="allow")
    ok: bool = True


def activity_summary(payload: dict[str, Any]) -> str:
    """One short line describing a result for the dashboard's MCP activity view."""
    for key in ("verdict", "outcome", "status", "matched"):
        if key in payload:
            value = payload[key]
            extra = payload.get("result") or payload.get("pattern") or payload.get("step") or ""
            return f"{key}={value}" + (f" {extra}" if extra and not isinstance(extra, (dict, list)) else "")
    if "records" in payload:
        return f"{len(payload['records'])} records"
    if "port" in payload:
        return f"{payload['port']} @ {payload.get('baud', '')}"
    return ""


def error_result(error: AgentError) -> CallToolResult:
    payload = error.payload()
    return CallToolResult(content=[TextContent(type="text", text=json.dumps(payload, ensure_ascii=False))],
                          structured_content=payload, is_error=True)


def build_server(agent: DeckAgent) -> MCPServer:
    @asynccontextmanager
    async def lifespan(_server: MCPServer) -> AsyncIterator[DeckAgent]:
        await anyio.to_thread.run_sync(agent.collect_snapshots)
        try:
            yield agent
        finally:
            await anyio.to_thread.run_sync(agent.close)

    server = MCPServer("serial-deck", title="Serial Deck", version=SERVER_VERSION,
                       instructions=INSTRUCTIONS, lifespan=lifespan)

    def tool(level: str, *, title: str, read_only: bool, destructive: bool = False,
             idempotent: bool = False) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """Register a tool only when the policy allows it; map AgentError to a structured error."""
        def decorate(fn: Callable[..., Any]) -> Callable[..., Any]:
            if not agent.allows(level):
                return fn

            defaults = {name: param.default for name, param in inspect.signature(fn).parameters.items()}

            async def wrapper(*args: Any, **kwargs: Any) -> Any:
                activity = agent.activity
                # Only arguments the caller set (defaults are noise in the activity view).
                call_args = {k: v for k, v in kwargs.items()
                             if not isinstance(v, Context) and v != defaults.get(k, inspect.Parameter.empty)}
                entry = activity.begin(fn.__name__, call_args) if activity else None
                try:
                    payload = await fn(*args, **kwargs)
                except AgentError as exc:
                    if activity:
                        activity.end(entry, "error", f"{exc.code}: {exc.message}")
                        agent.publish_activity()
                    return error_result(exc)
                except BaseException:
                    if activity:
                        activity.end(entry, "failed")
                    raise
                if activity:
                    activity.end(entry, "ok", activity_summary(payload))
                    agent.publish_activity()
                return Result(**payload)

            # The SDK derives input/output schemas from the signature and
            # type hints: keep the tool's parameters, declare Result output.
            hints = typing.get_type_hints(fn, include_extras=True)
            wrapper.__name__ = fn.__name__
            wrapper.__qualname__ = fn.__qualname__
            wrapper.__doc__ = fn.__doc__
            signature = inspect.signature(fn)
            wrapper.__signature__ = signature.replace(
                parameters=[param.replace(annotation=hints.get(name, param.annotation))
                            for name, param in signature.parameters.items()],
                return_annotation=Result)
            wrapper.__annotations__ = {**{k: v for k, v in hints.items() if k != "return"},
                                       "return": Result}
            server.tool(title=title, annotations=ToolAnnotations(
                title=title, read_only_hint=read_only, destructive_hint=destructive,
                idempotent_hint=idempotent, open_world_hint=False))(wrapper)
            return fn
        return decorate

    def run(fn: Callable[..., Any], *args: Any) -> Any:
        """Run blocking work in a worker thread; waits never outlive the call."""
        return anyio.to_thread.run_sync(lambda: fn(*args))

    async def run_cancellable(fn: Callable[..., Any], *args: Any) -> Any:
        """Like `run` for long waits: a cancelled MCP request stops the worker loop
        promptly instead of leaving it blocked for the full timeout."""
        cancelled = threading.Event()
        try:
            return await anyio.to_thread.run_sync(lambda: fn(*args, cancelled.is_set),
                                                  abandon_on_cancel=True)
        finally:
            cancelled.set()

    @tool("observe", title="Hub status", read_only=True, idempotent=True)
    async def serial_status() -> dict[str, Any]:
        """Hub daemon status (channels, flash state), this server's policy, sessions and flash jobs.
        Never touches a UART."""
        status = await run(agent.status)
        disabled = [name for name, level in TOOL_LEVELS.items() if not agent.allows(level)]
        return {**status, "disabled_tools": disabled,
                "enable_hint": "restart the MCP server with --allow interact|hardware" if disabled else ""}

    @tool("observe", title="List serial ports", read_only=True, idempotent=True)
    async def serial_list_ports() -> dict[str, Any]:
        """Accessible serial ports with product/interface names, USB vid:pid/serial and whether the hub
        already has a channel for them. Read-only: nothing is opened."""
        return await run(agent.list_ports)

    @tool("observe", title="Connect to a port", read_only=False, idempotent=True)
    async def serial_connect(
        port: Annotated[str, Field(description="Device path or tcp://host:port / udp://host:port")],
        baud: Annotated[int | None, Field(ge=9600, le=12000000, description=
                                          "Only used when the hub opens the port; a live channel keeps its baud")] = None,
        mode: Annotated[Literal["control", "raw"], Field(description=
                                                      "'control' for firmware implementing the control protocol (sends HELLO); "
                                                      "'raw' for Linux and other consoles (logs only)")] = "raw",
        change_live_baud: Annotated[bool, Field(description=
                                                "Retime a live channel to `baud` for every attached client "
                                                "(needs --allow interact and the user's explicit approval)")] = False,
    ) -> dict[str, Any]:
        """Attach this server to a port through the shared hub. If no client has the port yet the hub
        opens the UART (like selecting it in the dashboard), which can pulse modem lines on some boards;
        `opened_uart` reports this. Returns the firmware HELLO in control mode."""
        return await run(agent.connect, port, baud, mode, change_live_baud)

    @tool("observe", title="Disconnect a port", read_only=False, idempotent=True)
    async def serial_disconnect(port: Port = None) -> dict[str, Any]:
        """Detach only this server's session; other dashboards keep streaming."""
        return await run(agent.disconnect, port)

    @tool("observe", title="Firmware HELLO", read_only=True, idempotent=True)
    async def serial_hello(port: Port = None,
                         timeout_s: Annotated[float, Field(gt=0, le=30)] = 3.0) -> dict[str, Any]:
        """Ask the firmware for its control-plane HELLO (transport, baud, supported commands)."""
        return await run_cancellable(agent.hello, port, timeout_s)

    @tool("observe", title="Query device", read_only=True, idempotent=True)
    async def serial_query(
        kind: Annotated[Literal[QUERY_KINDS], Field(description="capabilities | identity | fsm | snapshot")],
        port: Port = None,
        timeout_s: Annotated[float, Field(gt=0, le=30)] = 5.0,
        redact_identity: Annotated[bool, Field(description="Hide serial/MAC-like identity fields")] = True,
    ) -> dict[str, Any]:
        """Read-only firmware query with its full lifecycle (accepted -> succeeded/failed). `outcome`
        is 'unknown' on timeout; do not assume failure."""
        return await run_cancellable(agent.query, kind, port, timeout_s, redact_identity)

    @tool("observe", title="Read logs", read_only=True, idempotent=True)
    async def serial_logs(
        port: Port = None,
        cursor: Annotated[int | None, Field(ge=1, description=
                                            "Return records with seq >= cursor (use next_cursor to page); "
                                            "omit for the most recent records")] = None,
        limit: Annotated[int, Field(ge=1, le=500)] = 200,
        contains: Annotated[list[str] | None, Field(max_length=10, description=
                                                    "Keep records containing any of these substrings")] = None,
        ignore_case: bool = True,
        levels: Annotated[list[Literal["error", "warning", "info", "debug", "verbose", "plain",
                                       "note", "frame"]] | None, Field()] = None,
        frames: Annotated[bool, Field(description="Include decoded control-plane frames")] = False,
    ) -> dict[str, Any]:
        """Console log records captured since this server attached (bounded ring, secrets redacted).
        `dropped` > 0 means the ring overflowed past your cursor."""
        session = agent.session(port)
        return await run(session.select, cursor, limit, contains, levels, frames, ignore_case)

    @tool("observe", title="Wait for log line", read_only=True)
    async def serial_wait_for(
        any_of: Annotated[list[str], Field(min_length=1, max_length=10, description=
                                           "Substrings to wait for, e.g. ['APP_READY', 'Guru Meditation']")],
        port: Port = None,
        timeout_s: Annotated[float, Field(gt=0, le=120)] = 30.0,
        since: Annotated[int | None, Field(ge=1, description=
                                           "Search from this cursor; omit to wait for new lines only")] = None,
        ignore_case: bool = False,
        context: Annotated[int, Field(ge=0, le=50)] = 5,
    ) -> dict[str, Any]:
        """Block until a log line contains one of the substrings, or time out with the latest lines."""
        session = agent.session(port)
        return await run_cancellable(session.wait_for, any_of, timeout_s, since, ignore_case, context)

    @tool("observe", title="Symbolize backtrace", read_only=True, idempotent=True)
    async def serial_symbolize(
        text: Annotated[str, Field(max_length=20000, description="Panic/backtrace text with 0x addresses")],
        elf: Annotated[str, Field(description="Absolute path to the matching application ELF")],
    ) -> dict[str, Any]:
        """Resolve 0x addresses with the ESP-IDF addr2line and the matching ELF."""
        if not Path(elf).is_absolute():
            raise AgentError("invalid_argument", "elf must be an absolute path")
        try:
            symbolizer = ElfSymbolizer(elf)
        except (ValueError, RuntimeError) as exc:
            raise AgentError("invalid_argument", str(exc)) from exc
        lines = [line for line in text.splitlines() if "0x" in line][:200]
        decoded = await run(lambda: [d for line in lines for d in symbolizer.decode(line)])
        return {"elf": symbolizer.elf_path, "frames": list(dict.fromkeys(decoded))}

    @tool("interact", title="Press a button", read_only=False)
    async def serial_button(
        button: Annotated[Literal[BUTTONS], Field(description="Logical button")],
        action: Annotated[Literal[BUTTON_ACTIONS], Field()] = "press",
        port: Port = None,
        timeout_s: Annotated[float, Field(gt=0, le=30)] = 5.0,
    ) -> dict[str, Any]:
        """Send one logical button action and return its lifecycle. Changes the device UI state."""
        return await run(agent.button, button, action, port, timeout_s)

    @tool("interact", title="Show info screen", read_only=False, idempotent=True)
    async def serial_show_info(port: Port = None,
                             timeout_s: Annotated[float, Field(gt=0, le=30)] = 5.0) -> dict[str, Any]:
        """Show the firmware info screen."""
        return await run(agent.show_info, port, timeout_s)

    @tool("hardware", title="Reset board", read_only=False, destructive=True)
    async def serial_reset(
        port: Port = None,
        wait_for: Annotated[list[str] | None, Field(max_length=10, description=
                                                    "Optional boot markers to wait for after the reset")] = None,
        timeout_s: Annotated[float, Field(gt=0, le=120)] = 15.0,
    ) -> dict[str, Any]:
        """Hardware reset via RTS/EN (interrupts the running firmware). Requires user approval."""
        return await run_cancellable(agent.reset, port, wait_for, timeout_s)

    @tool("hardware", title="Enter ROM bootloader", read_only=False, destructive=True)
    async def serial_bootloader(port: Port = None) -> dict[str, Any]:
        """Put the chip into ROM download mode via DTR/RTS; the app stops. Requires user approval."""
        return await run(agent.bootloader, port)

    @tool("observe", title="Preview firmware flash", read_only=False)
    async def serial_flash_preview(
        build_dir: Annotated[str, Field(description="Absolute ESP-IDF build directory with flasher_args.json")],
        port: Port = None,
        flash_baud: Annotated[int, Field(ge=115200, le=5000000)] = 3000000,
    ) -> dict[str, Any]:
        """Dry run: validate an ESP-IDF build (only bootloader/partition table/OTA data/app regions),
        copy it into an immutable snapshot and return the images, hashes, esptool command and a
        single-use token bound to this device. Writes nothing to the board."""
        return await run(agent.flash_preview, build_dir, port, flash_baud)

    @tool("hardware", title="Start firmware flash", read_only=False, destructive=True)
    async def serial_flash_start(
        token: Annotated[str, Field(min_length=8, max_length=64, description="Token from serial_flash_preview")],
    ) -> dict[str, Any]:
        """Flash exactly the previewed snapshot through the hub (the channel pauses; other ports keep
        streaming). Only after the user approved the preview. Never retry on outcome 'unknown'."""
        return await run(agent.flash_start, token)

    @tool("observe", title="Flash status", read_only=True, idempotent=True)
    async def serial_flash_status(
        ctx: Context,
        token: Annotated[str, Field(min_length=8, max_length=64)],
        wait_s: Annotated[float, Field(ge=0, le=60, description="Long-poll up to this many seconds")] = 30.0,
    ) -> dict[str, Any]:
        """Progress and final verdict of a flash: flash_verified (esptool hash checks), uart_reopened
        and firmware_ready (HELLO/boot after completion). Cancelling this call never cancels the flash."""
        loop_token = anyio.lowlevel.current_token()

        def progress(value: float, step: str) -> None:
            try:
                anyio.from_thread.run(ctx.report_progress, value, 100.0, step, token=loop_token)
            except Exception:  # Progress is best effort.
                pass

        return await run_cancellable(agent.flash_status, token, wait_s, progress)

    return server


TOOL_LEVELS = {
    "serial_status": "observe", "serial_list_ports": "observe", "serial_connect": "observe",
    "serial_disconnect": "observe", "serial_hello": "observe", "serial_query": "observe",
    "serial_logs": "observe", "serial_wait_for": "observe", "serial_symbolize": "observe",
    "serial_flash_preview": "observe", "serial_flash_status": "observe",
    "serial_button": "interact", "serial_show_info": "interact",
    "serial_reset": "hardware", "serial_bootloader": "hardware", "serial_flash_start": "hardware",
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Serial Deck MCP server (stdio)")
    parser.add_argument("--allow", choices=POLICIES, default=os.environ.get("SERIAL_DECK_MCP_ALLOW", "observe"),
                        help="highest action class an agent may use (default: observe)")
    parser.add_argument("--socket", default=os.environ.get("SERIAL_DECK_HUB_SOCKET", DEFAULT_SOCKET),
                        help="shared hub socket")
    parser.add_argument("--log-level", default="WARNING")
    parser.add_argument("--no-activity", action="store_true",
                        help="do not publish tool calls for the dashboard's MCP view")
    args = parser.parse_args(argv)
    logging.basicConfig(stream=sys.stderr, level=args.log_level.upper(),
                        format="%(asctime)s %(name)s %(levelname)s %(message)s")
    agent = DeckAgent(policy=args.allow, socket_path=args.socket)
    if not args.no_activity:
        agent.enable_activity(client=os.environ.get("SERIAL_DECK_MCP_CLIENT", ""))
    build_server(agent).run("stdio")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
