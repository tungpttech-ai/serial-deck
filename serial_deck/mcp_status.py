#!/usr/bin/env python3
"""What the dashboards show on their MCP page: registrations and live servers.

Standard library only, so the Web/App dashboard can import it without the
MCP SDK. MCP servers publish their state in a private per-user directory
(see `agent.ActivityLog`); this module only reads it.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

try:
    from . import ipc
except ImportError:
    import ipc

ROOT = Path(__file__).resolve().parent
SERVER = ROOT / "mcp_server.py"
POLICIES = ("observe", "interact", "hardware")
TOOLS = {
    "observe": ["serial_status", "serial_list_ports", "serial_connect", "serial_disconnect", "serial_hello",
                "serial_query", "serial_logs", "serial_wait_for", "serial_symbolize", "serial_flash_preview",
                "serial_flash_status"],
    "interact": ["serial_button", "serial_show_info"],
    "hardware": ["serial_reset", "serial_bootloader", "serial_flash_start"],
}


def activity_dir() -> Path:
    """Same path for every process of this user, whatever its environment.

    MCP clients start servers with a minimal environment (often without
    XDG_RUNTIME_DIR), so the location must not depend on it.
    """
    return ipc.private_dir(ipc.runtime_dir() / "mcp-activity")


def python_executable() -> str:
    """The interpreter running this package (a checkout's .venv when present)."""
    checkout = ROOT.parent / ".venv"
    for venv in (checkout / "Scripts" / "python.exe", checkout / "bin" / "python"):
        if venv.is_file():
            return str(venv)
    return sys.executable


def _quote(arg: str) -> str:
    """Quote one argument for the user's shell: PowerShell on Windows, else POSIX sh."""
    if os.name == "nt":
        if arg and all(c.isalnum() or c in "-_.:\\/=" for c in arg):
            return arg
        return "'" + arg.replace("'", "''") + "'"
    import shlex
    return shlex.quote(arg)


def _command(parts: list[str]) -> str:
    """A runnable command line; PowerShell needs `&` to call a quoted program path."""
    line = " ".join(_quote(part) for part in parts)
    if os.name == "nt" and line.startswith("'"):
        return "& " + line
    return line


_SDK_CACHE: dict[str, tuple[float, bool]] = {}
_SDK_CACHE_S = 30.0  # re-check soon after the user runs the displayed pip command


def sdk_installed(python: str) -> bool:
    """Whether `python` can import the MCP SDK; cached (a cold start can take seconds)."""
    if python == sys.executable:
        import importlib.util
        try:
            return importlib.util.find_spec("mcp.server.mcpserver") is not None
        except ModuleNotFoundError:
            return False
    cached = _SDK_CACHE.get(python)
    now = time.monotonic()
    if cached is not None and (cached[1] or now - cached[0] < _SDK_CACHE_S):
        return cached[1]  # "installed" never goes stale; "missing" is re-probed
    found = _probe_sdk(python)
    _SDK_CACHE[python] = (now, found)
    return found


def _probe_sdk(python: str) -> bool:
    try:
        result = subprocess.run([python, "-c", "import mcp.server.mcpserver"], capture_output=True,
                                timeout=10, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def install_commands(policy: str = "interact") -> dict[str, str]:
    python = python_executable()
    # `-m` works for a checkout and an installed wheel alike.
    args = ["-m", "serial_deck.mcp_server", "--allow", policy]
    config = {"mcpServers": {"serial-deck": {"command": python, "args": args}}}
    # Arguments after `--` go to `claude`/`codex`, not the shell, so no `&` there.
    command = " ".join(_quote(part) for part in [python, *args])
    return {
        "pip": _command([python, "-m", "pip", "install", "serial-deck[mcp]"]),
        "claude": f"claude mcp add serial-deck -s user -- {command}",
        "codex": f"codex mcp add serial-deck -- {command}",
        "json": json.dumps(config, indent=2),
    }


def _policy_from_args(args: list[str]) -> str:
    for index, arg in enumerate(args):
        if arg == "--allow" and index + 1 < len(args):
            return args[index + 1]
        if arg.startswith("--allow="):
            return arg.split("=", 1)[1]
    return "observe"


def _claude_registration() -> dict[str, Any] | None:
    try:
        data = json.loads((Path.home() / ".claude.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    scopes = [("user", data.get("mcpServers") or {})]
    for project, info in (data.get("projects") or {}).items():
        if isinstance(info, dict):
            scopes.append((f"project {project}", info.get("mcpServers") or {}))
    for scope, servers in scopes:
        entry = servers.get("serial-deck") if isinstance(servers, dict) else None
        if isinstance(entry, dict):
            args = [str(a) for a in entry.get("args", [])]
            return {"scope": scope, "command": entry.get("command", ""), "args": args,
                    "policy": _policy_from_args(args)}
    return None


def _codex_registration() -> dict[str, Any] | None:
    try:
        text = (Path.home() / ".codex" / "config.toml").read_text(encoding="utf-8")
    except OSError:
        return None
    match = re.search(r'^\[mcp_servers\.(?:serial-deck|"serial-deck")\]\s*$(.*?)(?=^\[|\Z)', text, re.M | re.S)
    if not match:
        return None
    body = match.group(1)
    command = re.search(r'^command\s*=\s*"([^"]*)"', body, re.M)
    args = re.findall(r'"([^"]*)"', (re.search(r"^args\s*=\s*\[(.*?)\]", body, re.M | re.S) or [None, ""])[1])
    enabled = not re.search(r"^enabled\s*=\s*false", body, re.M)
    return {"scope": "global", "command": command.group(1) if command else "", "args": args,
            "policy": _policy_from_args(args), "enabled": enabled}


def registrations() -> dict[str, Any]:
    return {"claude": _claude_registration(), "codex": _codex_registration(),
            "claude_cli": bool(shutil.which("claude")), "codex_cli": bool(shutil.which("codex"))}


def live_servers(directory: Path | None = None, now: float | None = None) -> list[dict[str, Any]]:
    """MCP server processes that are alive, with their recent tool calls."""
    root = directory or activity_dir()
    now = time.time() if now is None else now
    servers = []
    try:
        files = list(root.glob("*.json"))
    except OSError:
        return []
    for path in files:
        try:
            pid = int(path.stem)
        except ValueError:
            continue
        if not ipc.pid_alive(pid):
            try:
                path.unlink()  # The server exited without cleaning up.
            except OSError:
                pass
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(data, dict):
            continue
        data["parent"] = _parent_name(pid)
        data["uptime_s"] = int(now - float(data.get("started", now)))
        servers.append(data)
    return sorted(servers, key=lambda item: item.get("started", 0))


def _parent_name(pid: int) -> str:
    """Which client launched a server (claude, codex, ...); Linux /proc only."""
    try:
        status = Path(f"/proc/{pid}/status").read_text(encoding="utf-8")
        ppid = int(re.search(r"^PPid:\s*(\d+)", status, re.M).group(1))
        return Path(f"/proc/{ppid}/comm").read_text(encoding="utf-8").strip()
    except (OSError, AttributeError, ValueError, UnicodeError):
        return ""


def overview() -> dict[str, Any]:
    python = python_executable()
    return {
        "server": "python -m serial_deck.mcp_server",
        "python": python,
        "sdk_installed": sdk_installed(python),
        "registrations": registrations(),
        "install": {policy: install_commands(policy) for policy in POLICIES},
        "tools": TOOLS,
        "servers": live_servers(),
    }
