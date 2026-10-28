"""Opt-in auto-connect: restore last session's ports and per-device rules.

Opening a UART can pulse DTR/RTS and reset the board, so nothing here is on by
default and nothing creates a rule by itself: the user switches restore on and
adds each rule on purpose. A rule matches a USB device by `vid:pid` plus serial
number (the path changes between plugs); only a device with no USB identity is
matched by its path.
"""

from __future__ import annotations

import re
import threading
from typing import Any, Callable

try:
    from .deckconfig import JsonFile
    from .uart_client import usb_matches
except ImportError:
    from deckconfig import JsonFile
    from uart_client import usb_matches

DEFAULTS: dict[str, Any] = {"restore_on_start": False, "last_ports": [], "rules": []}
VID_PID_RE = re.compile(r"^[0-9a-fA-F]{4}:[0-9a-fA-F]{4}$")
INTERFACE_RE = re.compile(r"^[0-9a-f]{2}$")
MODES = ("control", "linux")
MAX_RULES = 32
# Opening a UART can reset the board: give up on a port after this many failed
# attempts per plug-in, and treat this many empty listings in a row as "unplugged".
MAX_OPEN_ATTEMPTS = 3
EMPTY_POLLS_BEFORE_FORGET = 2


class SettingsError(ValueError):
    pass


def clean_rule(raw: Any) -> dict[str, Any]:
    """Validate one rule from the page or the file; raise SettingsError."""
    if not isinstance(raw, dict):
        raise SettingsError("a rule must be an object")
    # Check the raw text: strip() would hide a trailing newline from the check below.
    raw_text = (f'{raw.get("usb_vid_pid", "")}{raw.get("usb_serial", "")}{raw.get("usb_interface", "")}'
                f'{raw.get("port", "")}{raw.get("label", "")}')
    if any(ord(c) < 32 or ord(c) == 127 for c in raw_text):
        raise SettingsError("values must not contain control characters")
    vid_pid = str(raw.get("usb_vid_pid", "")).strip().lower()
    serial = str(raw.get("usb_serial", "")).strip()
    interface = str(raw.get("usb_interface", "")).strip().lower()
    port = str(raw.get("port", "")).strip()
    if vid_pid and not VID_PID_RE.match(vid_pid):
        raise SettingsError("usb_vid_pid must look like 303a:1001")
    if interface and not (vid_pid and INTERFACE_RE.match(interface)):
        raise SettingsError("usb_interface must be two hex digits and needs a vid:pid")
    if not vid_pid and not port:
        raise SettingsError("a rule needs a USB vid:pid or a port")
    if len(serial) > 64 or len(port) > 256:
        raise SettingsError("serial or port is too long")
    baud = raw.get("baud", 115200)
    if type(baud) is not int or not 9600 <= baud <= 12000000:
        raise SettingsError("baud must be 9600..12000000")
    mode = raw.get("mode", "linux")
    if mode not in MODES:
        raise SettingsError(f"mode must be one of {MODES}")
    label = str(raw.get("label", "")).strip()[:48]
    return {"label": label or vid_pid or port, "usb_vid_pid": vid_pid, "usb_serial": serial,
            "usb_interface": interface, "port": "" if vid_pid else port, "baud": baud, "mode": mode,
            "enabled": bool(raw.get("enabled", True))}


class Settings:
    def __init__(self, store: JsonFile | None = None) -> None:
        self.store = store or JsonFile("settings.json", DEFAULTS)

    def get(self) -> dict[str, Any]:
        data = self.store.load()
        rules = []
        for item in data.get("rules", []) if isinstance(data.get("rules"), list) else []:
            try:
                rules.append(clean_rule(item))
            except SettingsError:
                continue  # a hand-edited bad rule never stops the app
        ports = data.get("last_ports", [])
        return {"restore_on_start": bool(data.get("restore_on_start", False)),
                "last_ports": [p for p in ports if isinstance(p, dict)][:8] if isinstance(ports, list) else [],
                "rules": rules[:MAX_RULES]}

    def update(self, **changes: Any) -> dict[str, Any]:
        with self.store.lock:
            data = self.get()
            if "restore_on_start" in changes:
                data["restore_on_start"] = bool(changes["restore_on_start"])
            if "rules" in changes:
                rules = changes["rules"]
                if not isinstance(rules, list) or len(rules) > MAX_RULES:
                    raise SettingsError(f"at most {MAX_RULES} rules")
                data["rules"] = [clean_rule(r) for r in rules]
            if "last_ports" in changes:
                data["last_ports"] = changes["last_ports"][:8]
            self.store.save(data)
            return data


def rule_matches(rule: dict[str, Any], port: str, identity: dict[str, str]) -> bool:
    if not rule.get("enabled", True):
        return False
    if rule.get("usb_vid_pid"):
        return usb_matches(rule, identity)
    return bool(rule.get("port")) and port == rule["port"]


class RuleWatcher:
    """Polls the port list and connects a device that matches a rule.

    Each plug-in is acted on once: a device that stays attached is not
    reconnected after the user disconnects it (that would fight the Disconnect
    button), only after it has been unplugged and plugged back.
    """

    def __init__(self, settings: Settings, list_ports: Callable[[], list[str]],
                 identity_of: Callable[[str], dict[str, str]],
                 is_open: Callable[[str], bool], connect: Callable[[str, dict[str, Any]], None],
                 interval: float = 2.0) -> None:
        self.settings = settings
        self.list_ports = list_ports
        self.identity_of = identity_of
        self.is_open = is_open
        self.connect = connect
        self.interval = interval
        self.stop = threading.Event()
        self.thread: threading.Thread | None = None
        self.handled: set[str] = set()  # ports acted on since they were plugged in
        self.failures: dict[str, int] = {}  # failed opens per port since it was plugged in
        self.empty_polls = 0

    def start(self) -> None:
        self.thread = threading.Thread(target=self._run, name="serial-deck-rules", daemon=True)
        self.thread.start()

    def close(self) -> None:
        self.stop.set()

    def _run(self) -> None:
        while not self.stop.wait(self.interval):
            try:
                self.poll()
            except Exception:
                pass  # a bad poll never kills the watcher

    def poll(self) -> list[str]:
        rules = [r for r in self.settings.get()["rules"] if r.get("enabled", True)]
        present = self.list_ports()
        if not present and (self.handled or self.failures):
            # An empty listing is more likely a failed enumeration than every device
            # unplugged at once: keep what was handled so a Disconnect is not undone.
            self.empty_polls += 1
            if self.empty_polls < EMPTY_POLLS_BEFORE_FORGET:
                return []
        else:
            self.empty_polls = 0
        self.handled &= set(present)  # unplugged: eligible again on the next plug
        if not rules:
            return []
        connected = []
        for port in present:
            if port in self.handled:
                continue
            if self.is_open(port):
                # Opened by the user, restore or another rule: a later Disconnect is the
                # user's choice, so this plug-in counts as acted on.
                self.handled.add(port)
                continue
            identity = self.identity_of(port)
            rule = next((r for r in rules if rule_matches(r, port, identity)), None)
            if rule is None:
                continue
            try:
                self.connect(port, rule)
            except Exception:
                # A failed open (busy, permissions) is retried on a later poll, but not
                # on every one: each attempt may pulse DTR/RTS and reset the board.
                failures = self.failures.get(port, 0) + 1
                self.failures[port] = failures
                if failures >= MAX_OPEN_ATTEMPTS:
                    self.handled.add(port)
                continue
            self.failures.pop(port, None)
            self.handled.add(port)
            connected.append(port)
        for port in list(self.failures):
            if port not in present:
                del self.failures[port]
        return connected
