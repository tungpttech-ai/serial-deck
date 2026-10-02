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
import threading
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
    # A no-FUSE launch must relaunch the same way, or the child cannot start.
    if appimage_extracted():
        command.append("--appimage-extract-and-run")
    return [*command, *args]


def appimage_extracted() -> bool:
    """True when this AppImage runs extracted (no FUSE), however that was requested.

    The runtime strips `--appimage-extract-and-run` before AppRun sees it, so the
    flag cannot be read back; the extraction directory name is what tells.
    """
    if not os.environ.get("APPIMAGE"):
        return False
    if os.environ.get("APPIMAGE_EXTRACT_AND_RUN") == "1":
        return True
    appdir = os.path.basename(os.environ.get("APPDIR", "").rstrip("/"))
    return appdir.startswith("appimage_extracted_")


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


_SPAWN_LOCK = threading.Lock()


def shell_quote(arg: str) -> str:
    """Quote one argument for the user's shell: PowerShell on Windows, else POSIX sh."""
    if os.name == "nt":
        if arg and all(c.isalnum() or c in "-_.:\\/=" for c in arg):
            return arg
        return "'" + arg.replace("'", "''") + "'"
    import shlex
    return shlex.quote(arg)


def shell_command(parts: list[str]) -> str:
    """A command line the user can paste; PowerShell needs `&` to call a quoted program."""
    line = " ".join(shell_quote(part) for part in parts)
    if os.name == "nt" and line.startswith("'"):
        return "& " + line
    return line


def popen_host(args: list[str], **kwargs):
    """subprocess.Popen for a *host* program, with the bundle's loader state undone.

    Environment: host_env(). Windows bundles also call SetDllDirectoryW(<bundle>)
    for themselves, and a child inherits that search path; it is cleared only
    for the instant CreateProcess runs (serialized, restored right after), so
    this process never runs without it.
    """
    import subprocess
    kwargs.setdefault("env", host_env())
    if not (frozen() and os.name == "nt"):
        return subprocess.Popen(args, **kwargs)
    import ctypes
    from ctypes import wintypes
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetDllDirectoryW.argtypes = [wintypes.DWORD, wintypes.LPWSTR]
    kernel32.GetDllDirectoryW.restype = wintypes.DWORD
    kernel32.SetDllDirectoryW.argtypes = [wintypes.LPCWSTR]
    with _SPAWN_LOCK:
        # Save the exact current value (whatever set it), clear it only for
        # CreateProcess, then put back precisely that value.
        size = kernel32.GetDllDirectoryW(0, None)
        buffer = ctypes.create_unicode_buffer(max(size, 1))
        previous = buffer.value if size and kernel32.GetDllDirectoryW(size, buffer) else None
        kernel32.SetDllDirectoryW(None)
        try:
            return subprocess.Popen(args, **kwargs)
        finally:
            kernel32.SetDllDirectoryW(previous)


def run_host(args: list[str], timeout: float | None = None, input: str | bytes | None = None, **kwargs):
    """subprocess.run equivalent built on popen_host."""
    import subprocess
    if kwargs.pop("capture_output", False):
        kwargs["stdout"] = kwargs["stderr"] = subprocess.PIPE
    if input is not None:
        kwargs["stdin"] = subprocess.PIPE
    process = popen_host(args, **kwargs)
    try:
        stdout, stderr = process.communicate(input, timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate()
        raise
    return subprocess.CompletedProcess(args, process.returncode, stdout, stderr)


def open_browser(url: str) -> bool:
    """Open `url` in the user's browser as a host process (not inheriting the bundle)."""
    if not frozen():
        import webbrowser
        return webbrowser.open(url)
    import subprocess
    if os.name == "nt":
        # rundll32 hands the URL to the user's default browser; it is started
        # through popen_host, so it inherits neither our DLL path nor env.
        opener = [str(Path(os.environ.get("SYSTEMROOT", r"C:\Windows")) / "System32" / "rundll32.exe"),
                  "url.dll,FileProtocolHandler", url]
    else:
        opener = ["open" if sys.platform == "darwin" else "xdg-open", url]
    try:
        result = run_host(opener, capture_output=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0
