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




def report_status(**fields: object) -> None:
    """Write startup facts to $SERIAL_DECK_STATUS_FILE, if set (for tests).

    A windowed Windows/macOS executable has no stdout, so a test cannot read
    the dashboard URL or the window result from it; it reads this file instead.
    """
    path = os.environ.get("SERIAL_DECK_STATUS_FILE")
    if not path:
        return
    import json
    try:
        current = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        current = {}
    current.update(fields)
    tmp = f"{path}.tmp"
    Path(tmp).write_text(json.dumps(current), encoding="utf-8")
    os.replace(tmp, path)


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
    """subprocess.Popen for a *host* program, without the bundle's loader state.

    Environment: host_env(). On Windows a PyInstaller bundle has called
    SetDllDirectoryW(<bundle>) for itself, and a direct child inherits that DLL
    search path. This process never changes it (other threads load DLLs at any
    time); instead a separate single-purpose helper, `serial-deck-cli host-exec`,
    clears it in its own process and then starts the host program, relaying
    stdio and the exit code.
    """
    import subprocess
    kwargs.setdefault("env", host_env())
    if not (frozen() and os.name == "nt"):
        return subprocess.Popen(args, **kwargs)
    kwargs.setdefault("creationflags", getattr(subprocess, "CREATE_NO_WINDOW", 0))
    return subprocess.Popen([console_executable(), "host-exec", "--", *args], **kwargs)


def host_exec(args: list[str]) -> int:
    """`host-exec -- <program> [args]`: run a host program with a clean DLL path.

    Runs in its own short-lived process, so clearing the bundle's DLL directory
    here cannot race anything else.
    """
    import subprocess
    if args and args[0] == "--":
        args = args[1:]
    if not args:
        print("usage: serial-deck-cli host-exec -- <program> [args]", file=sys.stderr)
        return 2
    if os.name == "nt":
        import ctypes
        ctypes.WinDLL("kernel32").SetDllDirectoryW(None)
        _kill_children_with_me()
    try:
        return subprocess.call(args, env=host_env())
    except OSError as exc:
        print(f"host-exec: cannot start {args[0]}: {exc}", file=sys.stderr)
        return 127


def _kill_children_with_me() -> None:
    """Put this helper in a Job Object that kills its whole tree when it dies.

    run_host() kills the helper on timeout; with JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    the host program (our child) dies with it instead of holding the pipes open.
    """
    import ctypes
    from ctypes import wintypes

    class BASIC(ctypes.Structure):
        _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64), ("PerJobUserTimeLimit", ctypes.c_int64),
                    ("LimitFlags", wintypes.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
                    ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
                    ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD),
                    ("SchedulingClass", wintypes.DWORD)]

    class IO(ctypes.Structure):
        _fields_ = [(name, ctypes.c_uint64) for name in (
            "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
            "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]

    class EXTENDED(ctypes.Structure):
        _fields_ = [("BasicLimitInformation", BASIC), ("IoInfo", IO),
                    ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
                    ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t)]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    job = kernel32.CreateJobObjectW(None, None)
    if not job:
        return
    info = EXTENDED()
    info.BasicLimitInformation.LimitFlags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    kernel32.SetInformationJobObject(wintypes.HANDLE(job), 9, ctypes.byref(info), ctypes.sizeof(info))
    # The job handle stays open for this process's lifetime; when the helper is
    # killed, the handle closes and Windows terminates every process in the job.
    kernel32.AssignProcessToJobObject(wintypes.HANDLE(job), kernel32.GetCurrentProcess())


def run_host(args: list[str], timeout: float | None = None, input: str | bytes | None = None, **kwargs):
    """subprocess.run equivalent built on popen_host."""
    import subprocess
    if kwargs.pop("capture_output", False):
        kwargs["stdout"] = kwargs["stderr"] = subprocess.PIPE
    if input is not None:
        kwargs["stdin"] = subprocess.PIPE
    if os.name != "nt":
        kwargs.setdefault("start_new_session", True)  # so the whole tree can be stopped
    process = popen_host(args, **kwargs)
    try:
        stdout, stderr = process.communicate(input, timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill_tree(process)
        try:
            process.communicate(timeout=5)  # bounded: a stray descendant must not hang us
        except subprocess.TimeoutExpired:
            pass
        raise
    return subprocess.CompletedProcess(args, process.returncode, stdout, stderr)


def _kill_tree(process) -> None:
    """Kill a host process and its descendants (POSIX: its session; Windows: the
    helper's kill-on-close Job Object takes the host program with it)."""
    if os.name != "nt":
        import signal
        try:
            os.killpg(process.pid, signal.SIGKILL)
            return
        except (ProcessLookupError, PermissionError):
            pass
    process.kill()


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
