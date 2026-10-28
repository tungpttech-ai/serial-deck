"""User scripts: small Python files that react to a device's data and talk back.

A script lives in `~/.config/serial-deck/scripts/NAME.py` (`SERIAL_DECK_CONFIG`
moves it) and defines either or both of:

    def run(dev):            # runs once, top to bottom; the script ends when it returns
        dev.expect(r"login:", timeout=20)
        dev.send_line("root")

    def on_line(dev, line):  # called for every line the device sends
        if "panic" in line:
            dev.log("device panicked")

With only `on_line` the script keeps listening until it is stopped. A script is a
data client of the hub like any dashboard: it reads and writes the device's
stream, and has no way to reset it, enter the bootloader or flash it.

The same module is the runner process: the hub starts
`python -m serial_deck.scripting run NAME --port P` (or `serial-deck script run`
in a bundle) and keeps its output. The scripts folder is only ever written by the
user; nothing in the dashboard or MCP can create or change a script.
"""

from __future__ import annotations

import argparse
import ast
import codecs
import importlib.util
import json
import os
import queue
import re
import signal
import sys
import threading
import time
import traceback
from pathlib import Path
from typing import Any, Callable

try:
    from .deckconfig import config_dir
except ImportError:
    from deckconfig import config_dir

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,47}$")
MAX_SCRIPT_BYTES = 256 * 1024
BUFFER_CHARS = 64 * 1024


class ScriptTimeout(TimeoutError):
    """`expect` did not see its pattern in time."""


class ScriptStopped(Exception):
    """The script was asked to stop (Stop button, hub shutdown, SIGTERM)."""


def scripts_dir() -> Path:
    return config_dir() / "scripts"


def script_path(name: str) -> Path:
    """The file behind a script name, or ValueError / FileNotFoundError.

    The name is a plain identifier and the resolved file must sit directly in the
    scripts folder, so neither `../x` nor a symlink can point a run elsewhere.
    """
    if not isinstance(name, str) or not NAME_RE.match(name):
        raise ValueError("script names are 1-48 letters, digits, '_' or '-'")
    root = scripts_dir()
    try:
        real = (root / f"{name}.py").resolve(strict=True)
    except OSError:
        raise FileNotFoundError(f"no script named {name} in {root}") from None
    if real.parent != root.resolve() or not real.is_file():
        raise ValueError("a script must be a regular file inside the scripts folder")
    if real.stat().st_size > MAX_SCRIPT_BYTES:
        raise ValueError(f"script is over {MAX_SCRIPT_BYTES // 1024} KB")
    return real


def list_scripts() -> list[dict[str, Any]]:
    """Scripts in the folder with their one-line description (read, never executed)."""
    root = scripts_dir()
    found = []
    try:
        entries = sorted(root.glob("*.py"))
    except OSError:
        return []
    for entry in entries:
        name = entry.stem
        try:
            path = script_path(name)
            tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError, SyntaxError):
            found.append({"name": name, "description": "(cannot be read or has a syntax error)", "ok": False})
            continue
        doc = (ast.get_docstring(tree) or "").strip().splitlines()
        found.append({"name": name, "description": doc[0][:120] if doc else "", "ok": True,
                      "size": path.stat().st_size,
                      "has_run": any(isinstance(n, ast.FunctionDef) and n.name == "run" for n in tree.body),
                      "has_on_line": any(isinstance(n, ast.FunctionDef) and n.name == "on_line" for n in tree.body)})
    return found


class Device:
    """What a script sees: the stream of one device, and ways to write to it."""

    def __init__(self, transport: Any, port: str, baud: int,
                 log: Callable[[str], None] = print) -> None:
        self.port = port
        self.baud = baud
        self._transport = transport
        self._log = log
        self._cond = threading.Condition()
        self._text = ""
        self._error: BaseException | None = None
        self._lines: queue.Queue[str] = queue.Queue()
        self.stop_event = threading.Event()
        self._write_lock = threading.Lock()

    # -- reading ----------------------------------------------------------

    def start(self, on_line: Callable[[Device, str], None] | None = None) -> None:
        threading.Thread(target=self._read_loop, name="script-reader", daemon=True).start()
        if on_line is not None:
            threading.Thread(target=self._dispatch, args=(on_line,), name="script-lines",
                             daemon=True).start()

    def _read_loop(self) -> None:
        decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        pending = ""
        try:
            while not self.stop_event.is_set():
                data = self._transport.read(4096)
                if not data:
                    continue
                text = decoder.decode(data)
                with self._cond:
                    self._text = (self._text + text)[-BUFFER_CHARS:]
                    self._cond.notify_all()
                pending += text
                *lines, pending = pending.split("\n")
                for line in lines:
                    self._lines.put(line.rstrip("\r"))
        except OSError as exc:
            with self._cond:
                self._error = exc
                self._cond.notify_all()

    def _dispatch(self, handler: Callable[[Device, str], None]) -> None:
        while not self.stop_event.is_set():
            try:
                line = self._lines.get(timeout=0.2)
            except queue.Empty:
                continue
            try:
                handler(self, line)
            except ScriptStopped:
                return
            except Exception:
                self.log("on_line failed:\n" + traceback.format_exc().rstrip())

    def _check_alive(self) -> None:
        if self.stop_event.is_set():
            raise ScriptStopped()
        if self._error is not None:
            raise ConnectionError(f"the device link closed: {self._error}")

    def expect(self, pattern: str | re.Pattern[str], timeout: float = 10.0) -> re.Match[str]:
        """Wait for `pattern` (a regex) in what the device sends; consume up to it."""
        index, match = self.expect_any([pattern], timeout)
        return match

    def expect_any(self, patterns: list[str | re.Pattern[str]],
                   timeout: float = 10.0) -> tuple[int, re.Match[str]]:
        """Like `expect` for several patterns: returns (index, match) of the earliest."""
        compiled = [re.compile(p) if isinstance(p, str) else p for p in patterns]
        deadline = time.monotonic() + timeout
        with self._cond:
            while True:
                best: tuple[int, re.Match[str]] | None = None
                for index, rx in enumerate(compiled):
                    match = rx.search(self._text)
                    if match is not None and (best is None or match.start() < best[1].start()):
                        best = (index, match)
                if best is not None:
                    self._text = self._text[best[1].end():]
                    return best
                self._check_alive()
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ScriptTimeout("timed out waiting for " + " | ".join(rx.pattern for rx in compiled))
                self._cond.wait(min(remaining, 0.2))

    def flush(self) -> None:
        """Forget what has arrived so far (an `expect` then only sees newer data)."""
        with self._cond:
            self._text = ""

    # -- writing ----------------------------------------------------------

    def send(self, data: str | bytes) -> None:
        raw = data.encode("utf-8") if isinstance(data, str) else bytes(data)
        self._check_alive()
        with self._write_lock:
            self._transport.write(raw)

    def send_line(self, text: str, ending: str = "\n") -> None:
        self.send(text + ending)

    def send_frame(self, frame: bytes) -> None:
        """One whole control frame, written atomically through the hub."""
        self._check_alive()
        with self._write_lock:
            writer = getattr(self._transport, "write_frame", None)
            (writer or self._transport.write)(bytes(frame))

    # -- misc -------------------------------------------------------------

    def sleep(self, seconds: float) -> None:
        if self.stop_event.wait(max(0.0, seconds)):
            raise ScriptStopped()

    def log(self, text: str) -> None:
        self._log(str(text))

    def close(self) -> None:
        self.stop_event.set()
        with self._cond:
            self._cond.notify_all()


def load_script(path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(f"deck_script_{path.stem}", path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run_script(path: Path, device: Device, out: Callable[[str], None] = print) -> int:
    """Run one script against `device`; the exit code the runner process returns."""
    try:
        module = load_script(path)
    except Exception:
        out("cannot load the script:\n" + traceback.format_exc().rstrip())
        return 2
    run = getattr(module, "run", None)
    on_line = getattr(module, "on_line", None)
    if not callable(run) and not callable(on_line):
        out("the script defines neither run(dev) nor on_line(dev, line)")
        return 2
    device.start(on_line if callable(on_line) else None)
    try:
        if callable(run):
            run(device)
        else:
            device.stop_event.wait()  # a pure watcher lives until it is stopped
    except ScriptStopped:
        out("stopped")
        return 0
    except ScriptTimeout as exc:
        out(f"timeout: {exc}")
        return 1
    except Exception:
        out("the script failed:\n" + traceback.format_exc().rstrip())
        return 1
    finally:
        device.close()
    return 0


# -- command line / runner process ----------------------------------------------

def _hub_manager(socket_path: str | None):
    try:
        from .hub_client import HubProcessManager
    except ImportError:
        from hub_client import HubProcessManager
    return HubProcessManager(socket_path=socket_path) if socket_path else HubProcessManager()


def cmd_run(args: argparse.Namespace) -> int:
    try:
        from .uart_client import open_uart_transport
    except ImportError:
        from uart_client import open_uart_transport
    try:
        path = script_path(args.name)
    except (ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    manager = _hub_manager(args.hub_socket)
    manager.ensure_started()
    manager.claim_port(args.port, args.baud)
    transport = open_uart_transport(manager.endpoint, args.baud, 0.2)
    run_id = os.environ.get("SERIAL_DECK_RUN_ID")
    if run_id:  # started by the hub: let it tell this socket from a dashboard's
        try:
            manager.request_control("runner_attached", id=run_id)
        except Exception:
            pass  # an older hub: it counts runners the old way
    device = Device(transport, args.port, args.baud, log=lambda text: print(text, flush=True))
    signal.signal(signal.SIGTERM, lambda *_: device.close())
    if hasattr(signal, "SIGINT"):
        signal.signal(signal.SIGINT, lambda *_: device.close())
    try:
        return run_script(path, device, out=lambda text: print(text, flush=True))
    finally:
        transport.close()


def _control(args: argparse.Namespace, action: str, **payload: Any) -> dict[str, Any]:
    return _hub_manager(args.hub_socket).request_control(action, **payload)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="serial-deck script", description="Run user scripts against a device")
    parser.add_argument("--hub-socket", default="", help="hub endpoint (default: this user's hub)")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list", help="scripts in the scripts folder")
    run = sub.add_parser("run", help="run a script here, in the foreground")
    run.add_argument("name")
    run.add_argument("--port", required=True)
    run.add_argument("--baud", type=int, default=115200)
    start = sub.add_parser("start", help="ask the hub to run a script in the background")
    start.add_argument("name")
    start.add_argument("--port", required=True)
    start.add_argument("--baud", type=int, default=115200)
    stop = sub.add_parser("stop", help="stop a background run")
    stop.add_argument("run_id")
    sub.add_parser("status", help="background runs")
    args = parser.parse_args(argv)
    try:
        if args.command == "list":
            for item in list_scripts():
                print(f"{item['name']:<24} {item['description']}")
            return 0
        if args.command == "run":
            return cmd_run(args)
        if args.command == "start":
            print(json.dumps(_control(args, "script_run", name=args.name, port=args.port, baud=args.baud)))
        elif args.command == "stop":
            print(json.dumps(_control(args, "script_stop", id=args.run_id)))
        else:
            print(json.dumps(_control(args, "script_status"), indent=2))
        return 0
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
