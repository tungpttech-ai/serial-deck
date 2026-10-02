#!/usr/bin/env python3
"""Serial Deck: a modern desktop UI for UART control, telemetry, and logs."""

from __future__ import annotations

import argparse
import datetime
import json
import os
import queue
import re
import shutil
import subprocess
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from pathlib import Path
from typing import Any

try:
    from .uart_client import (
        FRAME_COMMAND,
        FRAME_HELLO,
        FRAME_NAMES,
        FRAME_RESPONSE,
        FRAME_EVENT,
        FRAME_ERROR,
        discover_serial_ports,
        open_uart_transport,
        UartReader,
        encode_json_frame,
        make_request,
        send_frame,
        send_hello,
    )
    from .flash import build_flash_command, flash_build
except ImportError:
    from uart_client import (
        FRAME_COMMAND,
        FRAME_HELLO,
        FRAME_NAMES,
        FRAME_RESPONSE,
        FRAME_EVENT,
        FRAME_ERROR,
        discover_serial_ports,
        open_uart_transport,
        UartReader,
        encode_json_frame,
        make_request,
        send_frame,
        send_hello,
    )
    from flash import build_flash_command, flash_build


# Design tokens. See docs/DESIGN_GUIDELINES.md for the palette/spacing rules
# this UI must follow; keep both in sync when either changes.
BG = "#0b0f14"
SURFACE = "#12181f"
SURFACE_ALT = "#1a222b"
BORDER = "#232d38"
TEXT = "#eaeef2"
MUTED = "#7c8a99"
ACCENT = "#f2994a"
ACCENT_HOVER = "#ffad63"
ACCENT_INK = "#1a1103"
DANGER = "#f2635a"
GREEN = "#5fd487"
RED = "#f2635a"
YELLOW = "#f2c94c"
BLUE = "#63b3ed"
PURPLE = "#c9a6f0"
CYAN = "#4fd1e3"
SELECTION = "#2f5673"

FONT_FAMILY = "Segoe UI"
MONO_FAMILY = "Cascadia Mono"
SPACE_XS = 4
SPACE_SM = 8
SPACE_MD = 14
SPACE_LG = 20

LOG_LEVEL_RE = re.compile(r"(?:^|\s)([EWIDV])\s+\(")
ADDRESS_RE = re.compile(r"0x[0-9a-fA-F]{4,}")
ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
SYMBOLIZE_LOG_RE = re.compile(r"backtrace|panic|assert|guru meditation|abort\s*\(", re.IGNORECASE)
FLASH_PERCENT_RE = re.compile(r"(?:\(|\s)(\d{1,3}(?:\.\d+)?)\s*%\)?")
FLASH_STEP_RE = re.compile(r"^(Connecting|Erasing|Writing|Verifying|Leaving|Hash of data verified)", re.IGNORECASE)
LOG_FILTER_LABELS = {
    "error": "E",
    "warning": "W",
    "info": "I",
    "debug": "D",
    "verbose": "V",
    "elf": "ELF",
    "plain": "RAW",
}


def parse_flash_progress(line: str) -> tuple[float | None, str | None]:
    line = ANSI_ESCAPE_RE.sub("", line).strip()
    percent = None
    step = None
    percent_match = FLASH_PERCENT_RE.search(line)
    if percent_match:
        try:
            percent = float(percent_match.group(1))
        except ValueError:
            pass
    step_match = FLASH_STEP_RE.search(line.strip())
    if step_match:
        step = step_match.group(1)
    elif "write-flash" in line:
        step = "Initializing"
    elif "Leaving" in line or "Hard resetting" in line:
        step = "Completed"
    return percent, step


def should_symbolize_log(line: str) -> bool:
    """Avoid spawning addr2line for high-rate telemetry and protocol logs."""
    return bool(SYMBOLIZE_LOG_RE.search(line))


def log_filter_key(tag: str | None) -> str:
    return tag or "plain"


def auto_find_elf(build_dir_path: str) -> str:
    path = Path(build_dir_path).expanduser().resolve()
    if not path.is_dir():
        return ""
    candidates = sorted(path.glob("*.elf"), key=lambda p: p.stat().st_mtime, reverse=True)
    if candidates:
        return str(candidates[0])
    return ""


class ElfSymbolizer:
    """Resolve application addresses with the ESP toolchain addr2line."""

    def __init__(self, elf_path: str, tool_path: str | None = None) -> None:
        self.elf_path = str(Path(elf_path).expanduser().resolve())
        if not Path(self.elf_path).is_file():
            raise ValueError(f"ELF file does not exist: {self.elf_path}")
        self.tool_path = tool_path or self._find_addr2line()
        if self.tool_path is None:
            raise RuntimeError("ESP addr2line not found; set IDF tools PATH")

    def _find_addr2line(self) -> str | None:
        # ELF e_machine: 94 = Xtensa (esp32, -s2, -s3), 243 = RISC-V (c3, c6, h2, p4, ...).
        try:
            with open(self.elf_path, "rb") as handle:
                header = handle.read(20)
            machine = int.from_bytes(header[18:20], "little") if header[:4] == b"\x7fELF" else 0
        except OSError:
            machine = 0
        xtensa = ["xtensa-esp-elf-addr2line", "xtensa-esp32-elf-addr2line"]
        riscv = ["riscv32-esp-elf-addr2line"]
        # The ELF's own architecture first, searched everywhere, before any fallback.
        groups = [xtensa, riscv] if machine == 94 else [riscv, xtensa] if machine == 243 else [riscv + xtensa]
        suffix = ".exe" if os.name == "nt" else ""
        tools_root = Path(os.environ.get("IDF_TOOLS_PATH", Path.home() / ".espressif"))
        for names in groups:
            for name in names:
                found = shutil.which(name)
                if found:
                    return found
            for name in names:
                matches = sorted(tools_root.glob(f"*/**/bin/{name}{suffix}"), reverse=True)
                if matches:
                    return str(matches[0])
        return None

    def decode(self, line: str) -> list[str]:
        addresses = list(dict.fromkeys(ADDRESS_RE.findall(line)))
        if not addresses:
            return []
        try:
            result = subprocess.run(
                [self.tool_path, "-pfiaC", "-e", self.elf_path, *addresses],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=1.0, check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return []
        if result.returncode != 0:
            return []
        decoded = []
        for address, trace in zip(addresses, result.stdout.splitlines()):
            if trace and "?? ??:0" not in trace:
                decoded.append(f"{address}: {trace}")
        return decoded


class ControlDeck:
    def __init__(self, root: tk.Tk, port: str = "", baud: int = 2000000, elf: str = "") -> None:
        self.root = root
        self.root.title("Serial Deck")
        self.root.geometry("1240x840")
        self.root.minsize(980, 700)
        self.root.configure(bg=BG)
        self.transport: Any = None
        self.reader: UartReader | None = None
        self.reader_thread: threading.Thread | None = None
        self.stop_reader = threading.Event()
        self.records: queue.Queue[tuple[str, Any]] = queue.Queue()
        self.sequence = 1
        self.port_var = tk.StringVar(value=port)
        self.baud_var = tk.StringVar(value=str(baud))
        self.flash_baud_var = tk.StringVar(value="3000000")
        self.action_var = tk.StringVar(value="press")
        # Off by default: a raw console must not receive control frames.
        self.control_var = tk.BooleanVar(value=False)
        self.connection_var = tk.StringVar(value="Disconnected")
        self.dtr_var = tk.StringVar(value="DTR: --")
        self.rts_var = tk.StringVar(value="RTS: --")
        self._dtr_state: bool | None = None
        self._rts_state: bool | None = None
        self.fsm_var = tk.StringVar(value="FSM: --")
        self.device_var = tk.StringVar(value="Device: --")
        self.elf_var = tk.StringVar(value=elf)
        self.build_var = tk.StringVar(value="build")
        self.symbolizer: ElfSymbolizer | None = None
        self._batch_log_rendering = False

        # Enhanced modern features
        self.log_search_var = tk.StringVar(value="")
        self.auto_scroll_enabled = True
        self.unread_log_count = 0
        self.raw_logs: list[tuple[str, str, str | None]] = []  # (time, text, tag)
        self.telemetry_data: dict[str, Any] = {}
        self.level_filters = {
            "error": tk.BooleanVar(value=True),
            "warning": tk.BooleanVar(value=True),
            "info": tk.BooleanVar(value=True),
            "debug": tk.BooleanVar(value=True),
            "verbose": tk.BooleanVar(value=False),
            "elf": tk.BooleanVar(value=True),
            "plain": tk.BooleanVar(value=False),
        }
        self.flash_progress_var = tk.DoubleVar(value=0.0)
        self.flash_status_var = tk.StringVar(value="Idle")

        self._build_style()
        self._build_ui()
        self._setup_hotkeys()

        if elf:
            self.load_elf()
        elif Path("build").is_dir():
            found_elf = auto_find_elf("build")
            if found_elf:
                self.elf_var.set(found_elf)
                try:
                    self.load_elf()
                except Exception:
                    pass

        self.root.protocol("WM_DELETE_WINDOW", self.close)
        self.root.after(80, self._drain_records)

    def _build_style(self) -> None:
        style = ttk.Style(self.root)
        style.theme_use("clam")
        body_font = (FONT_FAMILY, 10)
        label_font = (FONT_FAMILY, 9)
        heading_font = (FONT_FAMILY, 11, "bold")
        eyebrow_font = (FONT_FAMILY, 9, "bold")

        style.configure("TFrame", background=BG)
        style.configure("Panel.TFrame", background=SURFACE)
        style.configure("PanelAlt.TFrame", background=SURFACE_ALT)
        style.configure("Border.TFrame", background=BORDER)

        style.configure("TLabel", background=BG, foreground=TEXT, font=body_font)
        style.configure("Panel.TLabel", background=SURFACE, foreground=TEXT, font=body_font)
        style.configure("Muted.Panel.TLabel", background=SURFACE, foreground=MUTED, font=label_font)
        style.configure("Eyebrow.Panel.TLabel", background=SURFACE, foreground=MUTED, font=eyebrow_font)
        style.configure("Heading.Panel.TLabel", background=SURFACE, foreground=TEXT, font=heading_font)
        style.configure("Title.TLabel", background=BG, foreground=TEXT, font=(FONT_FAMILY, 20, "bold"))
        style.configure("Subtitle.TLabel", background=BG, foreground=MUTED, font=body_font)
        style.configure("Value.Panel.TLabel", background=SURFACE, foreground=TEXT, font=(FONT_FAMILY, 10, "bold"))
        style.configure("Mono.Panel.TLabel", background=SURFACE, foreground=MUTED, font=(MONO_FAMILY, 9))

        style.configure("PanelAlt.TLabel", background=SURFACE_ALT, foreground=TEXT, font=body_font)
        style.configure("Muted.PanelAlt.TLabel", background=SURFACE_ALT, foreground=MUTED, font=label_font)
        style.configure("Chip.PanelAlt.TLabel", background=SURFACE_ALT, foreground=ACCENT,
                        padding=(12, 7), font=(FONT_FAMILY, 10, "bold"))
        style.configure("Dot.PanelAlt.TLabel", background=SURFACE_ALT, font=(FONT_FAMILY, 12, "bold"))

        style.configure("Accent.TButton", background=ACCENT, foreground=ACCENT_INK, padding=(16, 8),
                        borderwidth=0, font=(FONT_FAMILY, 10, "bold"))
        style.map("Accent.TButton",
                  background=[("active", ACCENT_HOVER), ("disabled", BORDER)],
                  foreground=[("disabled", MUTED)])
        style.configure("Dark.TButton", background=SURFACE_ALT, foreground=TEXT, padding=(10, 7),
                        borderwidth=0, font=body_font)
        style.map("Dark.TButton", background=[("active", "#26323e"), ("disabled", SURFACE)],
                  foreground=[("disabled", MUTED)])
        style.configure("Danger.TButton", background=SURFACE_ALT, foreground=DANGER, padding=(10, 7),
                        borderwidth=0, font=(FONT_FAMILY, 10, "bold"))
        style.map("Danger.TButton", background=[("active", DANGER), ("disabled", SURFACE)],
                  foreground=[("active", "#1a0403"), ("disabled", MUTED)])
        style.configure("Ghost.TButton", background=SURFACE, foreground=MUTED, padding=(8, 4),
                        borderwidth=0, font=label_font)
        style.map("Ghost.TButton", foreground=[("active", TEXT)])
        style.configure("Nav.TButton", background=SURFACE_ALT, foreground=TEXT, padding=(10, 12),
                        borderwidth=0, font=(FONT_FAMILY, 11, "bold"))
        style.map("Nav.TButton", background=[("active", ACCENT)], foreground=[("active", ACCENT_INK)])
        style.configure("Power.TButton", background=SURFACE_ALT, foreground=DANGER, padding=(10, 10),
                        borderwidth=0, font=(FONT_FAMILY, 10, "bold"))
        style.map("Power.TButton", background=[("active", DANGER)], foreground=[("active", "#1a0403")])

        style.configure("TEntry", fieldbackground="#0c1015", foreground=TEXT, insertcolor=TEXT,
                        borderwidth=1, relief="flat", padding=6)
        style.map("TEntry", fieldbackground=[("disabled", SURFACE)])
        style.configure("TCombobox", fieldbackground="#0c1015", background="#0c1015", foreground=TEXT,
                        arrowcolor=MUTED, borderwidth=1, padding=6)
        style.map("TCombobox", fieldbackground=[("readonly", "#0c1015")],
                  foreground=[("readonly", TEXT)])

        style.configure("TCheckbutton", background=SURFACE, foreground=TEXT, font=label_font)
        style.map("TCheckbutton", background=[("active", SURFACE)], foreground=[("active", TEXT)])

        style.configure("Flash.Horizontal.TProgressbar", troughcolor=SURFACE_ALT, background=ACCENT,
                        bordercolor=BORDER, lightcolor=ACCENT_HOVER, darkcolor=ACCENT)

        style.configure("TSeparator", background=BORDER)

        style.configure("TNotebook", background=BG, borderwidth=0, tabmargins=(0, 0, 0, 0))
        style.configure("TNotebook.Tab", background=SURFACE, foreground=MUTED, padding=(16, 8),
                        borderwidth=0, font=(FONT_FAMILY, 10, "bold"))
        style.map("TNotebook.Tab",
                  background=[("selected", SURFACE_ALT)],
                  foreground=[("selected", TEXT)])

        style.configure("Vertical.TScrollbar", background=SURFACE_ALT, troughcolor=SURFACE,
                        bordercolor=SURFACE, lightcolor=SURFACE_ALT, darkcolor=SURFACE_ALT,
                        arrowcolor=MUTED, relief="flat", borderwidth=0, width=12)
        style.map("Vertical.TScrollbar", background=[("active", BORDER)],
                  arrowcolor=[("active", TEXT)])

    def _card(self, parent: tk.Widget, *, padding: int = SPACE_MD) -> tuple[ttk.Frame, ttk.Frame]:
        border = ttk.Frame(parent, style="Border.TFrame")
        inner = ttk.Frame(border, style="Panel.TFrame", padding=padding)
        inner.pack(fill="both", expand=True, padx=1, pady=1)
        return border, inner

    def _section_header(self, parent: tk.Widget, title: str, subtitle: str = "") -> None:
        ttk.Label(parent, text=title.upper(), style="Heading.Panel.TLabel").pack(anchor="w")
        if subtitle:
            ttk.Label(parent, text=subtitle, style="Muted.Panel.TLabel").pack(anchor="w", pady=(2, SPACE_SM))
        else:
            ttk.Frame(parent, style="Panel.TFrame", height=SPACE_XS).pack(fill="x")

    def _build_ui(self) -> None:
        self.root.option_add("*Font", (FONT_FAMILY, 10))
        outer = ttk.Frame(self.root, padding=SPACE_LG)
        outer.pack(fill="both", expand=True)

        # Header
        header = ttk.Frame(outer)
        header.pack(fill="x", pady=(0, SPACE_MD))
        title_col = ttk.Frame(header)
        title_col.pack(side="left")
        ttk.Label(title_col, text="SERIAL DECK", style="Title.TLabel").pack(anchor="w")
        ttk.Label(title_col, text="UART Console, Control & ESP32 Firmware Flasher",
                  style="Subtitle.TLabel").pack(anchor="w", pady=(2, 0))

        status_pill = ttk.Frame(header, style="PanelAlt.TFrame", padding=(SPACE_MD, SPACE_SM))
        status_pill.pack(side="right", anchor="e")
        self.status_dot = ttk.Label(status_pill, text="●", style="Dot.PanelAlt.TLabel", foreground=RED)
        self.status_dot.pack(side="left", padx=(0, 8))
        self.status_label = ttk.Label(status_pill, textvariable=self.connection_var, style="PanelAlt.TLabel")
        self.status_label.pack(side="left")

        # Connection Row
        connection_border, connection = self._card(outer, padding=SPACE_SM)
        connection_border.pack(fill="x", pady=(0, SPACE_MD))
        conn_row = ttk.Frame(connection, style="Panel.TFrame")
        conn_row.pack(fill="x")

        ttk.Label(conn_row, text="PORT", style="Eyebrow.Panel.TLabel").grid(row=0, column=0, sticky="w")
        self.port_combo = ttk.Combobox(conn_row, textvariable=self.port_var, width=22)
        self.port_combo.grid(row=1, column=0, padx=(0, 6), pady=(2, 0), sticky="w")
        self.port_combo.bind("<Button-1>", lambda _event: self.scan_ports())

        ttk.Button(conn_row, text="Scan", style="Dark.TButton", command=self.scan_ports).grid(
            row=1, column=1, padx=(0, SPACE_MD), pady=(2, 0))

        ttk.Label(conn_row, text="BAUD", style="Eyebrow.Panel.TLabel").grid(row=0, column=2, sticky="w")
        self.baud_combo = ttk.Combobox(conn_row, textvariable=self.baud_var, width=10,
                                       values=("9600", "19200", "38400", "57600", "115200", "230400",
                                               "460800", "500000", "576000", "921600", "1000000",
                                               "1500000", "2000000", "3000000"))
        self.baud_combo.grid(row=1, column=2, padx=(0, SPACE_MD), pady=(2, 0), sticky="w")

        self.connect_button = ttk.Button(conn_row, text="Connect", command=self.toggle_connection,
                                         style="Accent.TButton")
        self.connect_button.grid(row=1, column=3, padx=(0, SPACE_MD), pady=(2, 0))
        ttk.Checkbutton(conn_row, text="Control protocol", variable=self.control_var,
                        command=self._on_control_toggle).grid(row=1, column=4, padx=(0, SPACE_MD),
                                                              pady=(2, 0), sticky="w")
        conn_row.columnconfigure(4, weight=1)

        line_row = ttk.Frame(conn_row, style="Panel.TFrame")
        line_row.grid(row=1, column=5, sticky="e", pady=(2, 0))
        ttk.Label(line_row, textvariable=self.dtr_var, style="Mono.Panel.TLabel").pack(side="left", padx=(0, 6))
        ttk.Button(line_row, text="DTR", style="Dark.TButton",
                   command=lambda: self.toggle_modem_line("dtr")).pack(side="left", padx=(0, SPACE_SM))
        ttk.Label(line_row, textvariable=self.rts_var, style="Mono.Panel.TLabel").pack(side="left", padx=(0, 6))
        ttk.Button(line_row, text="RTS", style="Dark.TButton",
                   command=lambda: self.toggle_modem_line("rts")).pack(side="left", padx=(0, SPACE_SM))
        self.scan_ports()

        # Tools Row (Symbols & Flash)
        tools_row = ttk.Frame(outer)
        tools_row.pack(fill="x", pady=(0, SPACE_MD))
        tools_row.columnconfigure(0, weight=1)
        tools_row.columnconfigure(1, weight=1)

        # Symbols Card
        elf_border, elf_card = self._card(tools_row, padding=SPACE_SM)
        elf_border.grid(row=0, column=0, sticky="nsew", padx=(0, SPACE_MD // 2))
        self._section_header(elf_card, "Symbols", "Decode crash backtraces with addr2line")
        elf_row = ttk.Frame(elf_card, style="Panel.TFrame")
        elf_row.pack(fill="x")
        ttk.Entry(elf_row, textvariable=self.elf_var).pack(side="left", fill="x", expand=True)
        ttk.Button(elf_row, text="Auto", style="Dark.TButton", command=self.auto_detect_elf).pack(
            side="left", padx=(SPACE_SM, 2))
        ttk.Button(elf_row, text="Browse", style="Dark.TButton", command=self.select_elf).pack(
            side="left", padx=(2, SPACE_SM))
        ttk.Button(elf_row, text="Load", style="Accent.TButton", command=self.load_elf).pack(side="left")

        # Flash Card
        flash_border, flash_card = self._card(tools_row, padding=SPACE_SM)
        flash_border.grid(row=0, column=1, sticky="nsew", padx=(SPACE_MD // 2, 0))
        self._section_header(flash_card, "Flash", "Write build binaries to target via esptool")
        flash_row = ttk.Frame(flash_card, style="Panel.TFrame")
        flash_row.pack(fill="x")
        ttk.Entry(flash_row, textvariable=self.build_var).pack(side="left", fill="x", expand=True)
        ttk.Button(flash_row, text="Browse", style="Dark.TButton", command=self.select_build).pack(
            side="left", padx=SPACE_SM)
        ttk.Combobox(flash_row, textvariable=self.flash_baud_var, state="readonly",
                     values=("115200", "230400", "460800", "921600", "1500000", "2000000", "3000000",
                              "6000000"), width=8).pack(
                                  side="left", padx=(0, SPACE_SM))
        self.flash_button = ttk.Button(flash_row, text="Flash", style="Accent.TButton",
                                       command=self.flash_current_build)
        self.flash_button.pack(side="left")

        # Progress bar container inside Flash Card
        progress_row = ttk.Frame(flash_card, style="Panel.TFrame")
        progress_row.pack(fill="x", pady=(SPACE_SM, 0))
        self.flash_progressbar = ttk.Progressbar(progress_row, orient="horizontal", mode="determinate",
                                                variable=self.flash_progress_var, style="Flash.Horizontal.TProgressbar")
        self.flash_progressbar.pack(side="left", fill="x", expand=True, padx=(0, SPACE_SM))
        self.flash_status_label = ttk.Label(progress_row, textvariable=self.flash_status_var, style="Muted.Panel.TLabel")
        self.flash_status_label.pack(side="right")

        # Body Pane
        body = ttk.Frame(outer)
        body.pack(fill="both", expand=True)

        # Left Sidebar (Controls)
        sidebar_border, controls = self._card(body, padding=SPACE_MD)
        sidebar_border.pack(side="left", fill="y", padx=(0, SPACE_MD))
        sidebar_border.configure(width=340)

        self._section_header(controls, "Robot Control", "Hotkeys: W/A/S/D, Arrows, Space, Esc")
        action_row = ttk.Frame(controls, style="Panel.TFrame")
        action_row.pack(fill="x", pady=(0, SPACE_SM))
        ttk.Label(action_row, text="Action Mode", style="Muted.Panel.TLabel").pack(side="left")
        ttk.Combobox(action_row, textvariable=self.action_var, state="readonly",
                     values=("press", "release", "long_press"), width=12).pack(side="right")

        dpad = ttk.Frame(controls, style="Panel.TFrame")
        dpad.pack(fill="x", pady=(0, SPACE_MD))
        for column in range(5):
            dpad.columnconfigure(column, weight=1)

        self.nav_buttons: dict[str, ttk.Button] = {}

        def nav_button(name: str, label: str, row: int, column: int, style: str = "Nav.TButton") -> None:
            btn = ttk.Button(dpad, text=label, style=style,
                             command=lambda b=name: self.send_button(b))
            btn.grid(row=row, column=column, sticky="nsew", padx=3, pady=3)
            self.nav_buttons[name] = btn

        nav_button("ONOFF", "⏻ ONOFF", 0, 0, style="Power.TButton")
        nav_button("LEFT", "◀ LEFT", 0, 1)
        nav_button("ENTER", "● ENTER", 0, 2)
        nav_button("RIGHT", "▶ RIGHT", 0, 3)
        nav_button("HOME", "▲ HOME", 0, 4)

        ttk.Separator(controls).pack(fill="x", pady=(0, SPACE_MD))
        self._section_header(controls, "Queries", "Request telemetry from device")
        query_grid = ttk.Frame(controls, style="Panel.TFrame")
        query_grid.pack(fill="x", pady=(0, SPACE_MD))
        query_grid.columnconfigure(0, weight=1)
        query_grid.columnconfigure(1, weight=1)

        ttk.Button(query_grid, text="Snapshot", style="Dark.TButton",
                   command=lambda: self.send_query("snapshot")).grid(row=0, column=0, sticky="ew", padx=(0, 2), pady=2)
        ttk.Button(query_grid, text="Read FSM", style="Dark.TButton",
                   command=lambda: self.send_query("fsm")).grid(row=0, column=1, sticky="ew", padx=(2, 0), pady=2)
        ttk.Button(query_grid, text="Identity", style="Dark.TButton",
                   command=lambda: self.send_query("identity")).grid(row=1, column=0, sticky="ew", padx=(0, 2), pady=2)
        ttk.Button(query_grid, text="Show Info", style="Dark.TButton",
                   command=self.show_info).grid(row=1, column=1, sticky="ew", padx=(2, 0), pady=2)

        ttk.Separator(controls).pack(fill="x", pady=(0, SPACE_MD))
        self._section_header(controls, "Hardware Lines", "Reset / ROM download mode")
        board_row = ttk.Frame(controls, style="Panel.TFrame")
        board_row.pack(fill="x")
        ttk.Button(board_row, text="⚡ Reset", style="Danger.TButton", command=self.reset_target).pack(
            side="left", fill="x", expand=True, padx=(0, 3))
        ttk.Button(board_row, text="📦 Bootloader", style="Danger.TButton", command=self.boot_target).pack(
            side="left", fill="x", expand=True, padx=(3, 0))

        # Right Main Panel
        right = ttk.Frame(body)
        right.pack(side="left", fill="both", expand=True)

        summary_border, summary = self._card(right, padding=SPACE_SM)
        summary_border.pack(fill="x", pady=(0, SPACE_MD))
        ttk.Label(summary, textvariable=self.fsm_var, style="Chip.PanelAlt.TLabel").pack(side="left")
        ttk.Label(summary, textvariable=self.device_var, style="Muted.Panel.TLabel").pack(side="right", padx=SPACE_SM)

        # Notebook tabs
        notebook = ttk.Notebook(right)
        notebook.pack(fill="both", expand=True)

        self.log_text = self._make_log_tab(notebook, "Console log")
        self.event_text = self._make_event_tab(notebook, "Control events")
        self.inspector_text = self._make_inspector_tab(notebook, "Telemetry Inspector")

        # Color tags
        self.log_text.tag_configure("error", foreground=RED, font=(MONO_FAMILY, 10, "bold"))
        self.log_text.tag_configure("warning", foreground=YELLOW)
        self.log_text.tag_configure("info", foreground=GREEN)
        self.log_text.tag_configure("debug", foreground=BLUE)
        self.log_text.tag_configure("verbose", foreground=PURPLE)
        self.log_text.tag_configure("elf", foreground=CYAN)
        self.log_text.tag_configure("time", foreground=MUTED)
        self.event_text.tag_configure("success", foreground=GREEN)
        self.event_text.tag_configure("cyan", foreground=CYAN)

    def _setup_hotkeys(self) -> None:
        def on_key(event: tk.Event) -> None:
            # Avoid triggering if focused on an Entry or Combobox
            focused = self.root.focus_get()
            if isinstance(focused, (tk.Entry, ttk.Entry, ttk.Combobox)):
                return
            key = event.keysym.lower()
            key_map = {
                "up": "HOME", "w": "HOME",
                "left": "LEFT", "a": "LEFT",
                "right": "RIGHT", "d": "RIGHT",
                "return": "ENTER", "space": "ENTER",
                "p": "ONOFF", "escape": "HOME",
            }
            if key in key_map:
                button = key_map[key]
                self.send_button(button)
                # Visual ripple on button
                btn = self.nav_buttons.get(button)
                if btn:
                    btn.state(["active"])
                    self.root.after(140, lambda: btn.state(["!active"]))

        self.root.bind("<Key>", on_key)

    def _make_log_tab(self, notebook: ttk.Notebook, title: str) -> tk.Text:
        frame = ttk.Frame(notebook, style="Panel.TFrame", padding=(SPACE_SM, SPACE_SM))
        notebook.add(frame, text=title)

        # Toolbar
        toolbar = ttk.Frame(frame, style="Panel.TFrame")
        toolbar.pack(fill="x", pady=(0, SPACE_XS))

        # Search filter
        ttk.Label(toolbar, text="Filter:", style="Muted.Panel.TLabel").pack(side="left", padx=(0, 4))
        search_entry = ttk.Entry(toolbar, textvariable=self.log_search_var, width=18)
        search_entry.pack(side="left", padx=(0, SPACE_SM))
        search_entry.bind("<KeyRelease>", lambda _e: self._reapply_log_filters())

        # Level checkboxes
        for lvl, var in self.level_filters.items():
            cb = ttk.Checkbutton(toolbar, text=LOG_FILTER_LABELS[lvl], variable=var,
                                 command=self._reapply_log_filters, style="TCheckbutton")
            cb.pack(side="left", padx=(0, 4))

        # Action buttons
        ttk.Button(toolbar, text="Clear", style="Ghost.TButton",
                   command=lambda: self._clear_logs()).pack(side="right", padx=(2, 0))
        ttk.Button(toolbar, text="Export", style="Ghost.TButton",
                   command=self.export_logs).pack(side="right", padx=(2, 0))
        self.scroll_btn = ttk.Button(toolbar, text="Follow", style="Ghost.TButton",
                                     command=self.toggle_autoscroll)
        self.scroll_btn.pack(side="right", padx=(2, 0))

        text_holder = ttk.Frame(frame, style="Panel.TFrame")
        text_holder.pack(fill="both", expand=True)
        text = tk.Text(text_holder, bg="#070a0f", fg=TEXT, insertbackground=TEXT, insertwidth=0,
                       relief="flat", wrap="none", font=(MONO_FAMILY, 10), padx=10, pady=8,
                       borderwidth=0, highlightthickness=1, highlightbackground=BORDER,
                       highlightcolor=BORDER, selectbackground=SELECTION, selectforeground=TEXT,
                       inactiveselectbackground=SELECTION, undo=False)
        text.pack(side="left", fill="both", expand=True)
        scrollbar = ttk.Scrollbar(text_holder, orient="vertical", command=text.yview)
        scrollbar.pack(side="right", fill="y")
        text.configure(yscrollcommand=scrollbar.set)
        self._make_readonly(text)
        return text

    def _make_event_tab(self, notebook: ttk.Notebook, title: str) -> tk.Text:
        frame = ttk.Frame(notebook, style="Panel.TFrame", padding=(SPACE_SM, SPACE_SM))
        notebook.add(frame, text=title)
        toolbar = ttk.Frame(frame, style="Panel.TFrame")
        toolbar.pack(fill="x", pady=(0, SPACE_XS))
        text_holder = ttk.Frame(frame, style="Panel.TFrame")
        text_holder.pack(fill="both", expand=True)
        text = tk.Text(text_holder, bg="#070a0f", fg=TEXT, insertbackground=TEXT, insertwidth=0,
                       relief="flat", wrap="none", font=(MONO_FAMILY, 10), padx=10, pady=8,
                       borderwidth=0, highlightthickness=1, highlightbackground=BORDER,
                       highlightcolor=BORDER, selectbackground=SELECTION, selectforeground=TEXT,
                       inactiveselectbackground=SELECTION, undo=False)
        text.pack(side="left", fill="both", expand=True)
        scrollbar = ttk.Scrollbar(text_holder, orient="vertical", command=text.yview)
        scrollbar.pack(side="right", fill="y")
        text.configure(yscrollcommand=scrollbar.set)
        self._make_readonly(text)
        ttk.Button(toolbar, text="Clear", style="Ghost.TButton",
                   command=lambda: self._clear_text(text)).pack(side="right")
        return text

    def _make_inspector_tab(self, notebook: ttk.Notebook, title: str) -> tk.Text:
        frame = ttk.Frame(notebook, style="Panel.TFrame", padding=(SPACE_SM, SPACE_SM))
        notebook.add(frame, text=title)
        toolbar = ttk.Frame(frame, style="Panel.TFrame")
        toolbar.pack(fill="x", pady=(0, SPACE_XS))
        ttk.Label(toolbar, text="Real-time Parsed Telemetry & State JSON", style="Muted.Panel.TLabel").pack(side="left")
        text_holder = ttk.Frame(frame, style="Panel.TFrame")
        text_holder.pack(fill="both", expand=True)
        text = tk.Text(text_holder, bg="#070a0f", fg=CYAN, insertbackground=TEXT, insertwidth=0,
                       relief="flat", wrap="none", font=(MONO_FAMILY, 10), padx=10, pady=8,
                       borderwidth=0, highlightthickness=1, highlightbackground=BORDER,
                       highlightcolor=BORDER, selectbackground=SELECTION, selectforeground=TEXT,
                       inactiveselectbackground=SELECTION, undo=False)
        text.pack(side="left", fill="both", expand=True)
        scrollbar = ttk.Scrollbar(text_holder, orient="vertical", command=text.yview)
        scrollbar.pack(side="right", fill="y")
        text.configure(yscrollcommand=scrollbar.set)
        self._make_readonly(text)
        text.insert("1.0", "{\n  \"status\": \"No telemetry received yet\"\n}")
        return text

    _NAV_KEYSYMS = frozenset({
        "Up", "Down", "Left", "Right", "Prior", "Next", "Home", "End",
        "Shift_L", "Shift_R", "Control_L", "Control_R", "Alt_L", "Alt_R", "Insert",
    })

    def _make_readonly(self, widget: tk.Text) -> None:
        def block_edit(event: tk.Event) -> str | None:
            control = bool(event.state & 0x4)
            if control and event.keysym.lower() == "c":
                return None  # let <<Copy>> fire
            if event.keysym in self._NAV_KEYSYMS or (control and event.keysym == "Insert"):
                return None  # navigation and Ctrl+Insert copy
            return "break"

        widget.bind("<Key>", block_edit)
        widget.bind("<<Paste>>", lambda _event: "break")
        widget.bind("<Button-2>", lambda _event: "break")

    def _clear_logs(self) -> None:
        self.raw_logs.clear()
        self._clear_text(self.log_text)
        self.unread_log_count = 0
        self._update_scroll_btn()

    @staticmethod
    def _clear_text(widget: tk.Text) -> None:
        widget.delete("1.0", "end")

    def toggle_autoscroll(self) -> None:
        self.auto_scroll_enabled = not self.auto_scroll_enabled
        if self.auto_scroll_enabled:
            self.unread_log_count = 0
            self.log_text.see("end")
        self._update_scroll_btn()

    def _update_scroll_btn(self) -> None:
        if self.auto_scroll_enabled:
            self.scroll_btn.configure(text="Follow")
        else:
            txt = f"Paused ({self.unread_log_count})" if self.unread_log_count > 0 else "Paused"
            self.scroll_btn.configure(text=txt)

    def _append_log_record(self, value: str, tag: str | None = None) -> None:
        time_str = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
        self.raw_logs.append((time_str, value, tag))
        if len(self.raw_logs) > 3000:
            self.raw_logs.pop(0)

        if not self.auto_scroll_enabled:
            self.unread_log_count += 1
            self._update_scroll_btn()

        if self._should_display_log(value, tag):
            self._append_rendered(time_str, value, tag)

    def _should_display_log(self, value: str, tag: str | None) -> bool:
        filter_text = self.log_search_var.get().strip().lower()
        if filter_text and filter_text not in value.lower():
            return False
        filter_key = log_filter_key(tag)
        if filter_key in self.level_filters and not self.level_filters[filter_key].get():
            return False
        return True

    def _append_rendered(self, time_str: str, value: str, tag: str | None) -> None:
        follow = self.auto_scroll_enabled and (self.log_text.yview()[1] >= 0.99)
        self.log_text.insert("end", f"[{time_str}] ", "time")
        self.log_text.insert("end", value + "\n", tag)
        if (follow or self.auto_scroll_enabled) and not self._batch_log_rendering:
            self.log_text.see("end")

    def _reapply_log_filters(self) -> None:
        self.log_text.delete("1.0", "end")
        for time_str, value, tag in self.raw_logs:
            if self._should_display_log(value, tag):
                self.log_text.insert("end", f"[{time_str}] ", "time")
                self.log_text.insert("end", value + "\n", tag)
        if self.auto_scroll_enabled:
            self.log_text.see("end")

    def _append(self, widget: tk.Text, value: str, tag: str | None = None) -> None:
        follow = widget.yview()[1] >= 0.999
        widget.insert("end", value + "\n", tag)
        if follow:
            widget.see("end")

    def export_logs(self) -> None:
        path = filedialog.asksaveasfilename(
            title="Export Console Logs",
            defaultextension=".log",
            filetypes=(("Log files", "*.log"), ("Text files", "*.txt"), ("All files", "*.*")),
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                for time_str, value, tag in self.raw_logs:
                    lvl = tag.upper() if tag else "RAW"
                    f.write(f"[{time_str}] [{lvl}] {value}\n")
            messagebox.showinfo("Export Logs", f"Saved {len(self.raw_logs)} lines to {path}")
        except Exception as exc:
            messagebox.showerror("Export Failed", str(exc))

    def _set_connected(self, connected: bool, message: str = "") -> None:
        self.connection_var.set(message or ("Connected" if connected else "Disconnected"))
        self.connect_button.configure(text="Disconnect" if connected else "Connect")
        self.status_dot.configure(foreground=GREEN if connected else RED)
        if not connected:
            self._dtr_state = None
            self._rts_state = None
            self.dtr_var.set("DTR: --")
            self.rts_var.set("RTS: --")

    def _render_line_state(self, dtr: bool | None, rts: bool | None) -> None:
        self._dtr_state = dtr
        self._rts_state = rts
        self.dtr_var.set("DTR: --" if dtr is None else f"DTR: {'HIGH' if dtr else 'LOW'}")
        self.rts_var.set("RTS: --" if rts is None else f"RTS: {'HIGH' if rts else 'LOW'}")

    def refresh_line_state(self) -> None:
        if self.transport is None:
            return
        try:
            dtr, rts = self.transport.get_modem_lines()
        except OSError as exc:
            self._render_line_state(self._dtr_state, self._rts_state)
            self._append_log_record(f"[board] modem-line readback unavailable: {exc}", "warning")
            return
        self._render_line_state(dtr, rts)

    def toggle_modem_line(self, line: str) -> None:
        if self.transport is None:
            messagebox.showinfo("UART", "Connect UART before controlling DTR/RTS lines.")
            return
        try:
            try:
                dtr, rts = self.transport.get_modem_lines()
            except OSError as exc:
                dtr, rts = self._dtr_state, self._rts_state
                if dtr is None or rts is None:
                    raise exc
            if line == "dtr":
                dtr = not dtr
                self.transport.set_modem_lines(dtr=dtr)
            else:
                rts = not rts
                self.transport.set_modem_lines(rts=rts)
            self._render_line_state(dtr, rts)
            self.refresh_line_state()
        except OSError as exc:
            messagebox.showerror("DTR/RTS", str(exc))

    def scan_ports(self) -> None:
        ports = discover_serial_ports()
        if self.port_var.get().startswith("hub://"):
            ports.insert(0, self.port_var.get())
        self.port_combo.configure(values=ports)
        if not self.port_var.get() and ports:
            self.port_var.set(ports[0])

    def _control_board_lines(self, action: str) -> None:
        port = self.port_var.get().strip()
        if not port:
            messagebox.showwarning("UART port", "Select a UART port or hub socket first.")
            return
        temporary = None
        transport = self.transport
        try:
            if transport is None:
                temporary = open_uart_transport(port, int(self.baud_var.get()), 0.1)
                transport = temporary
            if action == "reset":
                transport.hard_reset()
            else:
                transport.enter_bootloader()
            self._append_log_record(f"[board] {action} via DTR/RTS on {port}", "elf")
            self.refresh_line_state()
        except (OSError, ValueError) as exc:
            messagebox.showerror("DTR/RTS failed", str(exc))
        finally:
            if temporary is not None:
                temporary.close()

    def reset_target(self) -> None:
        self._control_board_lines("reset")

    def boot_target(self) -> None:
        if messagebox.askyesno("Enter bootloader", "Toggle DTR/RTS to enter ESP ROM download mode?"):
            self._control_board_lines("bootloader")

    def toggle_connection(self) -> None:
        if self.transport is not None:
            self.disconnect()
            return
        port = self.port_var.get().strip()
        if not port:
            messagebox.showwarning("UART port", "Enter a UART port, e.g. /dev/ttyACM0")
            return
        try:
            self.transport = open_uart_transport(port, int(self.baud_var.get()), 0.1)
        except (ValueError, RuntimeError, OSError) as exc:
            self.transport = None
            messagebox.showerror("Connect failed", str(exc))
            return
        self.reader = UartReader(self.transport, frames=self.control_var.get())
        self.stop_reader.clear()
        self.reader_thread = threading.Thread(target=self._reader_loop, daemon=True)
        self.reader_thread.start()
        self._set_connected(True)
        self.refresh_line_state()
        if self.control_var.get():
            self._send_hello()

    def _on_control_toggle(self) -> None:
        enabled = self.control_var.get()
        if self.reader is not None:
            self.reader.frames = enabled
        if enabled:
            self._send_hello()

    def disconnect(self) -> None:
        self.stop_reader.set()
        reader_thread = self.reader_thread
        self.reader_thread = None
        if reader_thread is not None and reader_thread is not threading.current_thread():
            # Wait for the reader's in-flight poll() to return before closing
            # the transport, otherwise a concurrent recv()/read() on the same
            # fd can raise "[Errno 9] Bad file descriptor".
            reader_thread.join(timeout=1.0)
        if self.transport is not None:
            self.transport.close()
        self.transport = None
        self.reader = None
        self._set_connected(False)

    def _reader_loop(self) -> None:
        reader = self.reader
        while not self.stop_reader.is_set() and reader is not None:
            try:
                for record in reader.poll():
                    self.records.put(record)
            except Exception as exc:
                self.records.put(("error", str(exc)))
                return

    def _drain_records(self) -> None:
        processed = 0
        self._batch_log_rendering = True
        while processed < 200:
            try:
                kind, value = self.records.get_nowait()
            except queue.Empty:
                break
            processed += 1
            if kind == "log":
                tag = self._log_tag(value)
                self._append_log_record(value, tag)
                if self.symbolizer is not None and should_symbolize_log(value):
                    for decoded in self.symbolizer.decode(value):
                        self._append_log_record(f"  [ELF] {decoded}", "elf")
            elif kind == "flash":
                pct, step = parse_flash_progress(value)
                if pct is not None:
                    self.flash_progress_var.set(float(pct))
                if step is not None:
                    self.flash_status_var.set(f"{step} ({pct or 0}%)")
                self._append_log_record(f"[flash] {value}", "elf")
            elif kind == "flash_done":
                self.flash_button.configure(state="normal")
                code = int(value)
                tag = "info" if code == 0 else "error"
                status_text = "Completed successfully!" if code == 0 else f"Failed (exit={code})"
                self.flash_status_var.set(status_text)
                if code == 0:
                    self.flash_progress_var.set(100.0)
                self._append_log_record(f"[flash] {status_text}", tag)
                self._on_flash_done(code)
            elif kind == "error":
                self._append_log_record(f"[serial] {value}", "error")
                self.disconnect()
            elif kind == "hub_status":
                self._handle_hub_status(value)
            else:
                frame_type, _flags, sequence, message = value
                name = FRAME_NAMES.get(frame_type, f"type-{frame_type}")
                line = f"[{name} seq={sequence}] {message}"
                self._append(self.event_text, line, "success" if frame_type == FRAME_RESPONSE else "cyan")
                self._update_summary(frame_type, message)
        self._batch_log_rendering = False
        if self.auto_scroll_enabled and processed:
            self.log_text.see("end")
        self.root.after(80, self._drain_records)

    def _handle_hub_status(self, status: Any) -> None:
        """Hook for the hub-managed launcher; direct mode has no hub state."""

    def _on_flash_done(self, code: int) -> None:
        """Reconnect the direct UART after a successful flash."""
        if code == 0 and self.transport is None and not self.port_var.get().startswith("hub://"):
            self.root.after(500, self.toggle_connection)

    @staticmethod
    def _log_tag(value: str) -> str | None:
        match = LOG_LEVEL_RE.search(value)
        if not match:
            return None
        return {"E": "error", "W": "warning", "I": "info", "D": "debug", "V": "verbose"}[match.group(1)]

    def auto_detect_elf(self) -> None:
        elf = auto_find_elf(self.build_var.get())
        if elf:
            self.elf_var.set(elf)
            self.load_elf()
        else:
            messagebox.showinfo("ELF Auto-detect", f"No .elf file found in '{self.build_var.get()}'")

    def select_elf(self) -> None:
        path = filedialog.askopenfilename(
            title="Select application ELF",
            filetypes=(("ELF files", "*.elf"), ("All files", "*.*")),
        )
        if path:
            self.elf_var.set(path)

    def load_elf(self) -> None:
        try:
            self.symbolizer = ElfSymbolizer(self.elf_var.get())
        except (RuntimeError, ValueError) as exc:
            self.symbolizer = None
            messagebox.showerror("ELF symbols", str(exc))
            return
        self._append_log_record(f"[ELF] loaded {self.symbolizer.elf_path}", "elf")

    def select_build(self) -> None:
        path = filedialog.askdirectory(title="Select ESP-IDF build directory")
        if path:
            self.build_var.set(path)
            self.auto_detect_elf()

    def flash_current_build(self) -> None:
        port = self.port_var.get().strip()
        if not port:
            messagebox.showwarning("Flash port", "Select a physical UART port first.")
            return
        if port.startswith("hub://"):
            messagebox.showerror("Flash unavailable", "Flash can only use a physical UART, not the hub socket.")
            return
        try:
            flash_baud = int(self.flash_baud_var.get())
            command = build_flash_command(port, self.build_var.get(), flash_baud)
        except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
            messagebox.showerror("Flash setup", str(exc))
            return
        command_text = " ".join(command)
        if not messagebox.askyesno(
                "Confirm Flash",
                f"This will write the build to {port}.\n\n{command_text}\n\nContinue?"):
            return
        if self.transport is not None:
            self.disconnect()
        self.flash_button.configure(state="disabled")
        self.flash_progress_var.set(0.0)
        self.flash_status_var.set("Connecting...")
        threading.Thread(target=self._flash_worker, args=(port, self.build_var.get(), flash_baud), daemon=True).start()

    def _flash_worker(self, port: str, build_dir: str, flash_baud: int) -> None:
        try:
            code = flash_build(port, build_dir, flash_baud,
                               output=lambda line: self.records.put(("flash", line)))
        except Exception as exc:
            self.records.put(("flash", str(exc)))
            code = 1
        self.records.put(("flash_done", code))

    def _update_summary(self, frame_type: int, message: Any) -> None:
        if not isinstance(message, dict):
            return
        if frame_type == FRAME_HELLO:
            commands = ", ".join(message.get("commands", []))
            self.device_var.set(f"UART {message.get('baud', '--')} | {commands}")
        result = message.get("result")
        if result:
            if isinstance(result, dict):
                self.telemetry_data.update(result)
                if "state" in result:
                    self.fsm_var.set(f"FSM: {result['state']}")
                else:
                    self.fsm_var.set(f"Result: {result}")
            else:
                self.fsm_var.set(f"Result: {result}")
        if message.get("status"):
            self.fsm_var.set(f"Status: {message['status']}")

        # Update Inspector Text tab
        self.inspector_text.delete("1.0", "end")
        self.inspector_text.insert("1.0", json.dumps(message, indent=2))

    def _send_hello(self) -> None:
        if self.transport is None:
            return
        send_hello(self.transport, self.sequence, "serial-deck-desktop")
        self.sequence += 1

    def _send(self, message: dict[str, Any]) -> None:
        if self.transport is None:
            messagebox.showinfo("Not connected", "Connect UART before sending commands.")
            return
        if not self.control_var.get():
            messagebox.showinfo("Control protocol off",
                                "Enable \"Control protocol\" for firmware that implements it.")
            return
        try:
            send_frame(self.transport, encode_json_frame(FRAME_COMMAND, self.sequence, message))
            self.sequence += 1
        except OSError as exc:
            messagebox.showerror("UART write failed", str(exc))
            self.disconnect()

    def send_button(self, button: str) -> None:
        self._send(make_request("input.button", {"button": button, "action": self.action_var.get()}))

    def send_query(self, kind: str) -> None:
        self._send(make_request("query", {"kind": kind}, deadline_ms=1000))

    def show_info(self) -> None:
        self._send(make_request("ui.show_info", {}))

    def close(self) -> None:
        self.disconnect()
        self.root.destroy()


def main() -> None:
    # Keep the historical launcher, but all device access goes through the hub.
    try:
        from .desktop_hub import main as hub_main
    except ImportError:
        from desktop_hub import main as hub_main
    hub_main()


if __name__ == "__main__":
    main()
