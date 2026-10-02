"""Where this program runs from: a pip install, or a frozen (PyInstaller) app bundle.

A frozen bundle has no separate Python interpreter: to start a hub or show an
MCP command it re-launches *itself* with a subcommand. On Windows the GUI build
is a windowed executable without stdio, so those children use the sibling
console executable. Inside an AppImage the stable path is $APPIMAGE, not the
temporary mount, and a no-FUSE launch must keep extracting on every relaunch.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

CLI_NAME = "serial-deck-cli"


def frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def bundle_dir() -> Path:
    """The directory holding the bundled executables (frozen only)."""
    return Path(sys.executable).resolve().parent


def console_executable() -> str | None:
    """The console executable of this bundle, or None when not frozen."""
    if not frozen():
        return None
    appimage = os.environ.get("APPIMAGE")
    if appimage and sys.platform.startswith("linux"):
        return appimage  # the AppImage file itself; AppRun forwards argv
    suffix = ".exe" if os.name == "nt" else ""
    cli = bundle_dir() / f"{CLI_NAME}{suffix}"
    return str(cli) if cli.is_file() else sys.executable


def self_command(*args: str) -> list[str]:
    """argv that re-runs this frozen bundle with a subcommand (`hub`, `mcp`, ...)."""
    exe = console_executable()
    if exe is None:
        raise RuntimeError("self_command() is only for frozen builds")
    command = [exe]
    # A no-FUSE launch (`--appimage-extract-and-run`, or APPIMAGE_EXTRACT_AND_RUN=1)
    # must use the same strategy for every relaunch, or the child cannot start.
    if os.environ.get("APPIMAGE") and os.environ.get("APPIMAGE_EXTRACT_AND_RUN") == "1":
        command.append("--appimage-extract-and-run")
    return [*command, *args]


def host_env() -> dict[str, str]:
    """Environment for launching *host* programs (browser, addr2line) from a bundle.

    PyInstaller points the dynamic loader at its own libraries and keeps the
    originals in `<NAME>_ORIG`; host programs must get the originals back. For a
    pip install this is just a copy of the environment.
    """
    env = dict(os.environ)
    if not frozen():
        return env
    for name in ("LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH", "DYLD_FRAMEWORK_PATH"):
        original = env.pop(f"{name}_ORIG", None)
        if original is not None:
            env[name] = original
        else:
            env.pop(name, None)
    for name in ("PYTHONHOME", "PYTHONPATH", "_MEIPASS2", "_PYI_APPLICATION_HOME_DIR",
                 "_PYI_ARCHIVE_FILE", "_PYI_PARENT_PROCESS_LEVEL"):
        env.pop(name, None)
    return env


def host_popen_kwargs() -> dict[str, object]:
    """Extra Popen arguments for host programs (see host_env)."""
    kwargs: dict[str, object] = {"env": host_env()}
    if frozen() and os.name == "nt":
        # PyInstaller calls SetDllDirectoryW(<bundle>) for itself; a child that
        # inherits it would load our DLLs. Reset it around host launches.
        kwargs["_reset_dll_directory"] = True
    return kwargs


def run_host(args: list[str], **kwargs):
    """subprocess.run for a host program, with the bundle's loader state undone."""
    import subprocess
    extra = host_popen_kwargs()
    reset = extra.pop("_reset_dll_directory", False)
    extra.update(kwargs)
    if not reset:
        return subprocess.run(args, **extra)
    import ctypes
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.SetDllDirectoryW(None)  # back to the default search order for children
    try:
        return subprocess.run(args, **extra)
    finally:
        kernel32.SetDllDirectoryW(str(Path(getattr(sys, "_MEIPASS", bundle_dir()))))


def open_browser(url: str) -> bool:
    """Open `url` in the user's browser as a host process (not inheriting the bundle)."""
    if not frozen():
        import webbrowser
        return webbrowser.open(url)
    if os.name == "nt":
        os.startfile(url)  # ShellExecute: the shell launches the browser, not us
        return True
    import subprocess
    opener = "open" if sys.platform == "darwin" else "xdg-open"
    try:
        result = run_host([opener, url], capture_output=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0
