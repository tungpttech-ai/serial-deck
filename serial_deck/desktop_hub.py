#!/usr/bin/env python3
"""Hub-managed Serial Deck using one shared physical UART owner."""

from __future__ import annotations

import argparse
import json
import signal
import subprocess
import tkinter as tk
from tkinter import messagebox

try:
    from .desktop import ControlDeck
    from .hub_client import DEFAULT_SOCKET, BaudConflictError, HubProcessManager
    from .uart_client import is_network_port
except ImportError:
    from desktop import ControlDeck
    from hub_client import DEFAULT_SOCKET, BaudConflictError, HubProcessManager
    from uart_client import is_network_port


class HubControlDeck(ControlDeck):
    """The existing Control Deck UI pinned to a managed hub endpoint."""

    def __init__(self, root: tk.Tk, uart_port: str = "", baud: int = 2000000,
                 socket_path: str = DEFAULT_SOCKET, elf: str = "",
                 start_hub: bool = True, auto_connect: bool = False) -> None:
        self._pending_hub_logs: list[tuple[str, str | None]] = []
        self._last_flash_line = ""
        self._last_flash_done_id = 0
        self.hub_manager = HubProcessManager(uart_port, baud, socket_path)
        if start_hub:
            started = self.hub_manager.ensure_started()
        else:
            if not self.hub_manager.socket_ready():
                raise RuntimeError(f"UART hub is not listening at {socket_path}")
            started = False
        super().__init__(root, "", baud, elf)
        self.root.title("Serial Deck - Hub")
        pending_logs = self._pending_hub_logs
        self._pending_hub_logs = []
        for value, tag in pending_logs:
            self._append_log_record(value, tag)
        mode = "started" if started else "attached"
        self._append_log_record(
            f"[hub] {mode}: idle at {self.hub_manager.endpoint}", "elf")
        self._hub_callback = lambda status: self.records.put(("hub_status", status))
        if auto_connect:
            self.root.after(150, self.toggle_connection)

    def _append_hub_log(self, value: str, tag: str | None = None) -> None:
        if hasattr(self, "log_text"):
            self._append_log_record(value, tag)
            return
        self._pending_hub_logs.append((value, tag))

    def scan_ports(self) -> None:
        try:
            physical_ports = self.hub_manager.scan_ports()
        except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
            self.port_combo.configure(values=(), state="normal")
            self._append_hub_log(f"[hub] scan failed: {exc}", "error")
            return
        # The combobox stays editable so tcp://host:port / udp://host:port
        # UART-over-IP endpoints can be typed next to the scanned devices.
        selected = self.port_var.get().strip()
        values = list(physical_ports)
        if is_network_port(selected):
            values.append(selected)
        self.port_combo.configure(values=tuple(values), state="normal")
        if selected not in values:
            preferred = self.hub_manager.hub_port or self.hub_manager.uart_port
            selected = preferred if preferred in values else ""
        if not selected and values:
            selected = values[0]
        self.port_var.set(selected)
        found = ", ".join(physical_ports) if physical_ports else "none"
        self._append_hub_log(f"[hub] scan found physical UARTs: {found}", "elf")

    def toggle_connection(self) -> None:
        if self.transport is not None:
            self.disconnect()
            return
        port = self.port_var.get().strip()
        if not port or port.startswith("hub://"):
            messagebox.showwarning(
                "UART port", "Select a physical UART or type tcp://host:port / udp://host:port.")
            return
        try:
            baud = int(self.baud_var.get())
            try:
                self.hub_manager.claim_port(port, baud, "error")
            except BaudConflictError as conflict:
                # Other clients share this UART at another baud: the user decides.
                choice = messagebox.askyesnocancel(
                    "UART baud in use",
                    f"{conflict.port} is open by {conflict.client_count} other client(s) at "
                    f"{conflict.live_baud} baud.\n\n"
                    f"Yes: change the UART to {conflict.requested_baud} baud for everyone "
                    "(it must match the firmware).\n"
                    f"No: connect at the live {conflict.live_baud} baud.\n"
                    "Cancel: do not connect.")
                if choice is None:
                    return
                self.hub_manager.claim_port(port, baud, "retime" if choice else "join")
            self.baud_var.set(str(self.hub_manager.baud))
            selected_port = self.port_var.get()
            self.port_var.set(self.hub_manager.endpoint)
            super().toggle_connection()
            if self.transport is None:
                self.hub_manager.release_port()
            else:
                self.hub_manager.subscribe(self._hub_callback)
            self.port_var.set(selected_port)
        except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
            self.port_var.set(port)
            self.disconnect()
            messagebox.showerror("Connect failed", str(exc))

    def _control_board_lines(self, action: str) -> None:
        if self.transport is None:
            messagebox.showinfo("UART", "Connect a physical UART through the hub first.")
            return
        super()._control_board_lines(action)

    def disconnect(self) -> None:
        super().disconnect()
        if hasattr(self, "_hub_callback"):
            self.hub_manager.unsubscribe(self._hub_callback)
        try:
            self.hub_manager.release_port()
        except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
            self._append_log_record(f"[hub] release failed: {exc}", "warning")

    def flash_current_build(self) -> None:
        if not self.hub_manager.hub_port:
            messagebox.showerror(
                "Flash unavailable",
                "Connect a physical UART through the hub before flashing.",
            )
            return
        try:
            flash_baud = int(self.flash_baud_var.get())
            preview = self.hub_manager.preview_flash(self.build_var.get(), flash_baud)
            command = preview.get("command", [])
            if not isinstance(command, list) or not all(isinstance(arg, str) for arg in command):
                raise RuntimeError("UART hub returned an invalid flash command")
        except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
            messagebox.showerror("Flash setup", str(exc))
            return
        command_text = " ".join(command)
        flash_port = str(preview.get("port", self.hub_manager.hub_port))
        if not messagebox.askyesno(
                "Confirm Hub Flash",
                f"The hub will pause UART, write the build to {flash_port}, "
                f"then resume every connected client.\n\n{command_text}\n\nContinue?"):
            return
        self.flash_button.configure(state="disabled")
        self.flash_progress_var.set(0.0)
        self.flash_status_var.set("Queued in hub...")
        try:
            self.hub_manager.start_flash(self.build_var.get(), flash_baud)
        except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
            self.flash_button.configure(state="normal")
            self.flash_status_var.set("Flash request failed")
            messagebox.showerror("Flash failed", str(exc))

    def _handle_hub_status(self, status: object) -> None:
        if not isinstance(status, dict):
            return
        channel = status.get("channel_socket")
        if channel and channel != self.hub_manager.channel_socket:
            return  # A queued event from the previous channel must not reset this one.
        port = status.get("port")
        flash = status.get("flash")
        flashing = isinstance(flash, dict) and bool(flash.get("active"))
        if isinstance(port, str):
            self.hub_manager.hub_port = port
            self.hub_manager.uart_port = port
        baud = status.get("baud")
        if isinstance(baud, int) and baud != self.hub_manager.baud:
            if self.transport is not None:
                self._append_log_record(
                    f"[hub] UART baud changed {self.hub_manager.baud} -> {baud}", "warning")
                self.baud_var.set(str(baud))
            self.hub_manager.baud = baud
        elif self.transport is not None and not flashing:
            # The hub only reports no port while we are still attached when
            # it force-dropped a physically lost UART
            # (UartHub._handle_serial_lost) — its own `release` action
            # refuses to run while a client is connected. Reflect the loss
            # immediately instead of waiting for our own data socket to
            # notice the closed connection on its next poll.
            self._append_log_record("[hub] physical UART was lost", "error")
            self.disconnect()
            return
        if not isinstance(flash, dict):
            return
        active = bool(flash.get("active"))
        flash_id = int(flash.get("id", 0))
        progress = float(flash.get("progress", 0))
        step = str(flash.get("step", "Idle"))
        line = str(flash.get("line", ""))
        self.flash_button.configure(state="disabled" if active else "normal")
        self.flash_progress_var.set(float(progress))
        self.flash_status_var.set(f"{step} ({progress}%)" if active else step)
        if line and line != self._last_flash_line:
            self._last_flash_line = line
            self._append_log_record(f"[hub flash] {line}", "elf")
        exit_code = flash.get("exit_code")
        if not active and exit_code is not None and flash_id > self._last_flash_done_id:
            self._last_flash_done_id = flash_id
            tag = "info" if int(exit_code) == 0 else "error"
            self._append_log_record(f"[hub flash] {step}", tag)

    def _on_flash_done(self, code: int) -> None:
        """Hub status drives reconnect and completion state."""

    def close(self) -> None:
        self.disconnect()
        self.hub_manager.unsubscribe()
        self.hub_manager.stop()
        self.root.destroy()


def main(argv: list[str] | None = None) -> int | None:
    try:
        from .ipc import configure_console_streams
    except ImportError:
        from ipc import configure_console_streams
    configure_console_streams()
    parser = argparse.ArgumentParser(description="Native Serial Deck through the UART hub")
    parser.add_argument("--uart-port", "--port", default="", help="initial physical UART selection")
    parser.add_argument("--socket", default=DEFAULT_SOCKET, help="hub endpoint path")
    parser.add_argument("--baud", type=int, default=2000000)
    parser.add_argument("--elf", default="", help="application ELF for address decoding")
    parser.add_argument("--attach-only", action="store_true", help="require an existing hub")
    parser.add_argument("--smoke-test", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--auto-connect", action="store_true",
                        help="claim the selected UART and connect immediately")
    args = parser.parse_args(argv)
    root = tk.Tk()
    if args.smoke_test:
        # A real Tk window with the full deck UI (fonts, styles, widgets),
        # built without a hub or UART so it runs anywhere with a display.
        ControlDeck(root, "", args.baud, args.elf)
        root.update()
        print(f"SMOKE TK OK (Tk {root.tk.call('info', 'patchlevel')})", flush=True)
        root.destroy()
        return 0
    try:
        deck = HubControlDeck(
            root,
            args.uart_port,
            args.baud,
            args.socket,
            args.elf,
            start_hub=not args.attach_only,
            auto_connect=args.auto_connect,
        )
    except (OSError, RuntimeError, TimeoutError, ValueError) as exc:
        messagebox.showerror("Hub startup failed", str(exc))
        root.destroy()
        raise SystemExit(2) from exc

    # `kill` / closed terminal: close like the window button so the owned hub
    # is stopped. Run it from the Tk loop, not inside the signal handler.
    def _request_close(_signum: int, _frame: object) -> None:
        root.after(0, deck.close)

    for name in ("SIGINT", "SIGTERM", "SIGHUP"):
        if hasattr(signal, name):
            signal.signal(getattr(signal, name), _request_close)

    # Python runs signal handlers only between bytecodes; an idle Tk loop sits
    # in C, so wake it periodically for a pending signal to be seen promptly.
    def _signal_tick() -> None:
        root.after(250, _signal_tick)

    _signal_tick()
    root.mainloop()


if __name__ == "__main__":
    main()
