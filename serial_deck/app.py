#!/usr/bin/env python3
"""Serial Deck App: the Web dashboard in a native pywebview window.

Runs the same backend and UI as `web.py`, bound to a private
loopback port, and shows it in a desktop window instead of a browser tab.
Closing the window detaches clients; the shared multi-port daemon stays
running and reaps unused UART channels. The window refuses to close while a flash is active.
"""

from __future__ import annotations

import argparse
import http.client
import importlib
import importlib.util
import json
import os
import shutil
import signal
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable

try:
    from . import runtime
    from .hub_client import DEFAULT_SOCKET
    from .web import BrowserLifecycle, HubStartupError, WebBackend
except ImportError:
    import runtime
    from hub_client import DEFAULT_SOCKET
    from web import BrowserLifecycle, HubStartupError, WebBackend


APP_TITLE = "Serial Deck"
APP_HOST = "127.0.0.1"
SHUTDOWN_SIGNALS = ("SIGINT", "SIGTERM", "SIGHUP")
TOOL_DIR = Path(__file__).resolve().parent


def _launcher() -> Path:
    """The installed `serial-deck-app` entry point, else this interpreter."""
    found = shutil.which("serial-deck-app")
    if found:
        return Path(found)
    scripts = Path(sys.executable).parent
    for name in ("serial-deck-app", "serial-deck-app.exe"):
        if (scripts / name).is_file():
            return scripts / name
    return Path(sys.executable)


LAUNCHER = _launcher()
FLASH_CLOSE_MESSAGE = (
    "A firmware flash is in progress on {ports}. The window stays open until "
    "it finishes; closing now could leave the board unbootable."
)
FLASH_UNKNOWN_MESSAGE = (
    "Cannot confirm that no firmware flash is running on {ports}: the UART hub "
    "did not answer a status request. The window stays open; try closing again "
    "once the hub responds."
)

RUNTIME_HELP = """\
Install the optional app dependency into this environment:
    python -m pip install "serial-deck[app]"
Windows and macOS need nothing else (WebView2 / WebKit ship with the OS).
pywebview also needs a native web engine on Linux, one of:
  - GTK: WebKit2GTK 4.1 and PyGObject
      Arch/CachyOS:  sudo pacman -S webkit2gtk-4.1 python-gobject
      Debian/Ubuntu: sudo apt install gir1.2-webkit2-4.1 python3-gi
    (create the venv with --system-site-packages to use the system PyGObject)
  - Qt: python -m pip install "pywebview[qt]"
The browser dashboard needs none of this: serial-deck-web"""


def _gtk_runtime_error() -> str | None:
    try:
        import gi
        gi.require_version("Gtk", "3.0")
        try:
            gi.require_version("WebKit2", "4.1")
        except ValueError:
            gi.require_version("WebKit2", "4.0")
        importlib.import_module("gi.repository.WebKit2")
    except (ImportError, ValueError) as exc:
        return f"GTK WebKit2 unavailable: {exc}"
    return None


def _qt_runtime_error() -> str | None:
    if importlib.util.find_spec("qtpy") is None:
        return "Qt unavailable: qtpy is not installed"
    for module in ("PyQt6.QtWebEngineWidgets", "PySide6.QtWebEngineWidgets",
                   "PyQt5.QtWebEngineWidgets", "PySide2.QtWebEngineWidgets"):
        try:
            if importlib.util.find_spec(module) is not None:
                return None
        except ImportError:
            continue
    return "Qt unavailable: no Qt WebEngine binding is installed"


def check_webview_runtime() -> str | None:
    """Return an actionable error when pywebview cannot open a window."""
    if importlib.util.find_spec("webview") is None:
        return f"pywebview is not installed for {sys.executable}.\n\n{RUNTIME_HELP}"
    if not sys.platform.startswith("linux"):
        return None
    forced = os.environ.get("PYWEBVIEW_GUI", "").lower()
    checks = [_qt_runtime_error] if forced == "qt" else [_gtk_runtime_error, _qt_runtime_error]
    errors = []
    for check in checks:
        error = check()
        if error is None:
            return None
        errors.append(error)
    return "No pywebview GUI backend is usable:\n  " + "\n  ".join(errors) + f"\n\n{RUNTIME_HELP}"


def wait_for_backend(port: int, token: str, timeout: float = 5.0,
                     host: str = APP_HOST) -> None:
    """Block until our own server answers `/api/instance` with `token`.

    The token check makes sure the window never loads a different server that
    happens to answer on this port.
    """
    deadline = time.monotonic() + timeout
    last_error = "no response"
    while time.monotonic() < deadline:
        conn = http.client.HTTPConnection(host, port, timeout=1.0)
        try:
            conn.request("GET", "/api/instance")
            response = conn.getresponse()
            body = response.read()
            if response.status == 200:
                data = json.loads(body.decode("utf-8"))
                if isinstance(data, dict) and data.get("instance") == token:
                    return
                raise RuntimeError(f"another server is answering on {host}:{port}")
            last_error = f"HTTP {response.status}"
        except (OSError, http.client.HTTPException, ValueError) as exc:
            last_error = str(exc)
        finally:
            conn.close()
        time.sleep(0.05)
    raise TimeoutError(f"dashboard backend on {host}:{port} did not become ready: {last_error}")


class AppController:
    """Window close policy and signal-driven shutdown for one app window."""

    def __init__(self, backend: Any, flash_poll_interval: float = 1.0) -> None:
        self.backend = backend
        self.window: Any = None
        self.flash_poll_interval = flash_poll_interval
        self._shutdown_lock = threading.Lock()
        self._shutdown_thread: threading.Thread | None = None
        self.closed = threading.Event()

    def attach(self, window: Any) -> None:
        self.window = window
        window.events.closing += self.on_closing
        window.events.closed += self.closed.set

    def close_blocker(self) -> str | None:
        """Why the window must stay open now, or None when closing is safe.

        Fails closed: if the check itself breaks, the flash state is unknown
        and the window stays open (the user retries once hubs answer).
        """
        try:
            check = self.backend.flash_check()
        except Exception as exc:
            return FLASH_UNKNOWN_MESSAGE.format(ports=f"this app's hubs ({exc})")
        if check.active:
            return FLASH_CLOSE_MESSAGE.format(ports=", ".join(check.active))
        if check.unknown:
            return FLASH_UNKNOWN_MESSAGE.format(ports=", ".join(check.unknown))
        return None

    def on_closing(self) -> bool:
        """pywebview `closing` handler: False cancels the close."""
        blocker = self.close_blocker()
        if blocker is None:
            return True
        self._notify(blocker)
        return False

    def _notify(self, message: str) -> None:
        print(message, file=sys.stderr, flush=True)
        window = self.window
        if window is None:
            return

        # `closing` runs on the GUI thread, where evaluate_js would deadlock.
        def show() -> None:
            try:
                window.evaluate_js(f"alert({json.dumps(message)})")
            except Exception:
                pass

        threading.Thread(target=show, name="app-notice", daemon=True).start()

    def request_shutdown(self) -> None:
        """Close the window once every hub reports no flash. Safe in a signal
        handler: it only starts (at most one) worker thread, which keeps
        retrying while a flash is active or a hub's state is unknown."""
        with self._shutdown_lock:
            if self._shutdown_thread is not None:
                return
            self._shutdown_thread = threading.Thread(
                target=self._shutdown_when_idle, name="app-shutdown", daemon=True)
            self._shutdown_thread.start()

    def _shutdown_when_idle(self) -> None:
        last_reported = None
        while not self.closed.is_set():
            blocker = self.close_blocker()
            if blocker is None:
                break
            if blocker != last_reported:
                print(f"Shutdown requested; waiting. {blocker}", file=sys.stderr, flush=True)
                last_reported = blocker
            self.closed.wait(self.flash_poll_interval)
        if not self.closed.is_set() and self.window is not None:
            try:
                self.window.destroy()
            except Exception as exc:
                print(f"Could not close the window: {exc}", file=sys.stderr, flush=True)


def install_signal_handlers(controller: AppController) -> dict[int, Any]:
    """Route SIGINT/SIGTERM/SIGHUP to a flash-aware window close."""
    previous: dict[int, Any] = {}

    def _handler(_signum: int, _frame: object) -> None:
        controller.request_shutdown()

    for name in SHUTDOWN_SIGNALS:
        sig = getattr(signal, name, None)
        if sig is not None:
            previous[sig] = signal.signal(sig, _handler)
    return previous


def restore_signal_handlers(previous: dict[int, Any]) -> None:
    for sig, handler in previous.items():
        signal.signal(sig, handler)


def desktop_entry_text(launcher: Path = LAUNCHER) -> str:
    exec_path = str(launcher).replace("\\", "\\\\").replace('"', '\\"')
    command = f'"{exec_path}"'
    if Path(launcher).name.startswith("python"):
        command += " -m serial_deck.app"
    return (
        "[Desktop Entry]\n"
        "Type=Application\n"
        f"Name={APP_TITLE}\n"
        "Comment=Shared serial console, UART hub and ESP32 flashing\n"
        f"Exec={command}\n"
        "Icon=utilities-terminal\n"
        "Terminal=false\n"
        "Categories=Development;Electronics;\n"
        "StartupNotify=true\n"
    )


def install_desktop_entry(data_home: str | None = None) -> Path:
    """Write a per-user launcher entry (never a system-wide one)."""
    base = Path(data_home or os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share")
    target = base / "applications" / "serial-deck-app.desktop"
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_suffix(".desktop.tmp")
    tmp.write_text(desktop_entry_text(), encoding="utf-8")
    tmp.replace(target)
    return target


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Serial Deck in a native pywebview window")
    parser.add_argument("--port", default="", help="initial physical UART selection for the hub")
    parser.add_argument("--baud", type=int, default=2000000, help="initial UART baudrate")
    parser.add_argument("--socket", default=DEFAULT_SOCKET, help="hub endpoint path")
    parser.add_argument("--attach-only", action="store_true", help="require an existing hub")
    parser.add_argument("--elf", default="", help="application ELF file for address symbolization")
    parser.add_argument("--debug", action="store_true", help="enable pywebview developer tools")
    parser.add_argument("--check-runtime", action="store_true",
                        help="report whether pywebview can open a window, then exit")
    parser.add_argument("--install-desktop-entry", action="store_true",
                        help="add a launcher to ~/.local/share/applications, then exit")
    parser.add_argument("--browser", action="store_true",
                        help="use the default browser instead of a native window")
    parser.add_argument("--smoke-test", action="store_true", help=argparse.SUPPRESS)
    return parser


def use_browser(args: argparse.Namespace, runtime_check: Callable[[], str | None]) -> str | None:
    """Why this launch uses the browser instead of a window, or None for a window."""
    if getattr(args, "browser", False):
        return "requested with --browser"
    if runtime.frozen() and sys.platform.startswith("linux"):
        return "Linux app bundles use your browser"  # no portable GTK/WebKit in a bundle
    if runtime.frozen():
        return runtime_check()  # e.g. no WebView2 runtime: fall back instead of failing
    return None


def run_browser(args: argparse.Namespace, backend: Any,
                open_url: Callable[[str], bool] | None = None,
                poll: float = 1.0) -> int:
    """Serve the dashboard to the default browser until Quit or every tab is gone."""
    controller = AppController(backend)
    lifecycle = BrowserLifecycle(controller.close_blocker)
    backend.handler.lifecycle = lifecycle
    stop = threading.Event()
    previous = {}

    def on_signal(_signum: int, _frame: Any) -> None:
        if controller.close_blocker() is None:
            stop.set()
        else:
            print("Shutdown requested; waiting for the flash to finish.", file=sys.stderr, flush=True)
            lifecycle.quit_requested.set()

    for name in SHUTDOWN_SIGNALS:
        sig = getattr(signal, name, None)
        if sig is not None:
            try:
                previous[sig] = signal.signal(sig, on_signal)
            except (OSError, ValueError):
                pass
    try:
        backend.start_in_thread()
        wait_for_backend(backend.port, backend.instance_token)
        print(f"Serial Deck dashboard: {backend.url}", flush=True)
        opened = (open_url or runtime.open_browser)(backend.url)
        if not opened:
            print(f"Could not start a browser; open {backend.url} yourself.", file=sys.stderr, flush=True)
        while not stop.is_set():
            if (lifecycle.quit_requested.is_set() or lifecycle.idle_expired()) \
                    and controller.close_blocker() is None:
                break
            stop.wait(poll)
    finally:
        for sig, handler in previous.items():
            try:
                signal.signal(sig, handler)
            except (OSError, ValueError):
                pass
        backend.close()
    return 0


def run_app(args: argparse.Namespace,
            backend_factory: Callable[..., Any] = WebBackend,
            webview_module: Any = None,
            runtime_check: Callable[[], str | None] = check_webview_runtime) -> int:
    browser_reason = None if webview_module is not None else use_browser(args, runtime_check)
    if webview_module is None and browser_reason is None:
        error = runtime_check()
        if error:
            print(f"Serial Deck App cannot start: {error}", file=sys.stderr)
            return 3
        import webview as webview_module
    if browser_reason is not None:
        print(f"Opening the dashboard in your browser ({browser_reason.splitlines()[0]}).",
              file=sys.stderr, flush=True)
        try:
            backend = backend_factory(APP_HOST, 0, args.port, args.baud, args.socket,
                                      args.attach_only, args.elf)
        except HubStartupError as exc:
            print(f"Hub startup failed: {exc}", file=sys.stderr)
            return 2
        except OSError as exc:
            print(f"Cannot bind the dashboard on {APP_HOST}: {exc}", file=sys.stderr)
            return 2
        return run_browser(args, backend)

    # Always a fresh ephemeral loopback port: never another app's server.
    try:
        backend = backend_factory(APP_HOST, 0, args.port, args.baud, args.socket,
                                  args.attach_only, args.elf)
    except HubStartupError as exc:
        print(f"Hub startup failed: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"Cannot bind the dashboard on {APP_HOST}: {exc}", file=sys.stderr)
        return 2

    controller = AppController(backend)
    previous_signals: dict[int, Any] = {}
    try:
        backend.start_in_thread()
        wait_for_backend(backend.port, backend.instance_token)
        # "Export logs" is a download (Content-Disposition: attachment); with
        # this setting pywebview asks for a destination with a save dialog.
        webview_module.settings["ALLOW_DOWNLOADS"] = True
        # pywebview injects `body {user-select: none}` unless text_select is
        # on, which made logs, terminal output and the MCP commands
        # uncopyable in the app; the page itself marks chrome as select-none.
        window = webview_module.create_window(
            APP_TITLE, backend.url, width=1440, height=900, min_size=(960, 600),
            text_select=True)
        controller.attach(window)
        previous_signals = install_signal_handlers(controller)
        print(f"Serial Deck App backend: {backend.url}", flush=True)
        webview_module.start(debug=args.debug)
    except Exception as exc:
        print(f"Serial Deck App failed: {exc}", file=sys.stderr)
        return 1
    finally:
        restore_signal_handlers(previous_signals)
        backend.close()
    return 0


def main(argv: list[str] | None = None) -> int:
    try:
        from .ipc import configure_console_streams
    except ImportError:
        from ipc import configure_console_streams
    configure_console_streams()
    args = build_parser().parse_args(argv)
    if args.install_desktop_entry:
        print(f"Installed {install_desktop_entry()}")
        return 0
    if args.check_runtime:
        error = check_webview_runtime()
        print(error or "pywebview runtime OK")
        return 3 if error else 0
    return run_app(args)


if __name__ == "__main__":
    raise SystemExit(main())
