"""Device profiles: JSON presets for pairing an SSH device, loaded from a directory.

A profile fills the pairing form for one kind of host (sockets, screen path,
restart arguments, ...) so product-specific knowledge lives in a file the user
keeps, not in Serial Deck. Profiles are data only: nothing in a profile file is
ever executed, and the same validation as the pairing form applies to it.

Directory: `SERIAL_DECK_PROFILE_DIR`, else `<config dir>/profiles`. One
`<name>.json` per profile:

    {"label": "My board", "remote_socket": "/run/svc.sock.stream", "control_socket": "/run/svc.sock",
     "screen_path": "/api/screen?format=jpeg", "restart_args": ["a", "b"],
     "follow_socket_suffix": ".stream", "mcp_tool_prefix": "board",
     "default_baud": 2000000, "default_mode": "control",
     "metrics": [{"id": "heap_free", "label": "Free heap", "before": "free=", "unit": "KB"}]}

`metrics` is a list of custom-metric rules (see metrics.py), read-only in the UI.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

try:
    from . import metrics, ssh_socket
    from .deckconfig import config_dir
except ImportError:
    import metrics
    import ssh_socket
    from deckconfig import config_dir

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}$")
MAX_BYTES = 16 * 1024
# What a profile may carry besides the SSH profile fields.
EXTRA_KEYS = ("label", "mcp_tool_prefix", "default_baud", "default_mode", "metrics")
PROFILE_KEYS = ("remote_socket", "control_socket", "screen_path", "restart_args", "restart_conf_hint",
                "follow_socket_suffix", "screen_revision_header", "screen_size_header", "user")


class ProfileError(ValueError):
    pass


def profile_dir() -> Path:
    override = os.environ.get("SERIAL_DECK_PROFILE_DIR", "").strip()
    return Path(override) if override else config_dir() / "profiles"


def clean(name: str, raw: Any) -> dict[str, Any]:
    """Validate one profile; raises ProfileError. Unknown keys are refused, not ignored."""
    if not NAME_RE.match(name):
        raise ProfileError("profile file names: 1-32 letters, digits, '.', '_' or '-'")
    if not isinstance(raw, dict):
        raise ProfileError("a profile must be a JSON object")
    unknown = sorted(set(raw) - set(EXTRA_KEYS) - set(PROFILE_KEYS))
    if unknown:
        raise ProfileError(f"unknown profile keys: {', '.join(unknown)}")
    # The SSH fields go through the pairing validation (placeholders stand in for the host).
    try:
        ssh_socket.validate_profile({"name": "profile", "host": "profile", "user": raw.get("user", "root"),
                                     **{k: raw[k] for k in PROFILE_KEYS if k in raw and k != "user"},
                                     "remote_socket": raw.get("remote_socket") or "/profile.sock"})
    except ssh_socket.SshSocketError as exc:
        raise ProfileError(str(exc)) from exc
    result: dict[str, Any] = {key: raw[key] for key in PROFILE_KEYS if key in raw}
    label = str(raw.get("label", name)).strip()
    if len(label) > 48 or any(ord(c) < 32 for c in label):
        raise ProfileError("label must be one short line")
    result["label"] = label or name
    prefix = raw.get("mcp_tool_prefix", "")
    if prefix and not re.fullmatch(r"[a-z][a-z0-9]{0,15}", str(prefix)):
        raise ProfileError("mcp_tool_prefix: 1-16 lowercase letters or digits, starting with a letter")
    if prefix:
        result["mcp_tool_prefix"] = prefix
    baud = raw.get("default_baud")
    if baud is not None:
        if type(baud) is not int or not 9600 <= baud <= 12000000:
            raise ProfileError("default_baud must be 9600..12000000")
        result["default_baud"] = baud
    mode = raw.get("default_mode")
    if mode is not None:
        if mode not in ("control", "linux"):
            raise ProfileError("default_mode must be control or linux")
        result["default_mode"] = mode
    if "metrics" in raw:
        try:
            result["metrics"] = metrics.clean_rules(raw["metrics"])
        except metrics.MetricsError as exc:
            raise ProfileError(f"metrics: {exc}") from exc
    result["name"] = name
    return result


def load_all(directory: Path | None = None) -> tuple[dict[str, dict[str, Any]], dict[str, str]]:
    """`(profiles by name, problems by file name)`; a broken file never hides the others."""
    directory = directory or profile_dir()
    profiles: dict[str, dict[str, Any]] = {}
    problems: dict[str, str] = {}
    try:
        files = sorted(directory.glob("*.json"))
    except OSError:
        return profiles, problems
    for path in files:
        try:
            if path.stat().st_size > MAX_BYTES:
                raise ProfileError(f"larger than {MAX_BYTES} bytes")
            profiles[path.stem] = clean(path.stem, json.loads(path.read_text(encoding="utf-8")))
        except (OSError, ValueError) as exc:  # ProfileError is a ValueError
            problems[path.name] = str(exc)
    return profiles, problems
