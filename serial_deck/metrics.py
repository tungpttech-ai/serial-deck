"""Custom metrics: rules that turn a number in a log line into a trend.

A rule names the literal text that precedes a number (`before`), plus a label,
unit, scale and warning limits. There is deliberately no user regex: the page
finds `before`, reads one number with a fixed grammar, and scales it, so Python
and JavaScript cannot disagree and no pattern can stall the dashboard.

Two layers feed the page: a profile's `metrics` list (read-only, shipped per
product) and the user's `metrics.json` (editable in the UI, wins on id clash).

    {"rules": [{"id": "heap_free", "label": "Free heap", "unit": "KB",
                "before": "free=", "tag": "my_tag", "scale": 0.0009765625,
                "warn_below": 64, "pin": true, "enabled": true, "show": "both"}]}

`enabled` false keeps the rule but stops tracking it; `show` is chart, text or both.
The order of the list is the order on screen.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
from pathlib import Path
from typing import Any

try:
    from .deckconfig import config_dir, write_private
except ImportError:
    from deckconfig import config_dir, write_private

ID_RE = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
MAX_RULES = 32
MAX_BYTES = 16 * 1024
KEYS = ("id", "label", "before", "tag", "unit", "scale", "warn_below", "warn_above", "pin", "enabled", "show")
SHOWS = ("both", "chart", "text")
REQUIRED = ("id", "label", "before")


class MetricsError(ValueError):
    pass


def _text(raw: dict[str, Any], key: str, limit: int, required: bool = False) -> str:
    value = raw.get(key, "")
    if not isinstance(value, str):
        raise MetricsError(f"{key} must be text")
    if required and not value:
        raise MetricsError(f"{key} is required")
    if len(value) > limit:
        raise MetricsError(f"{key} is longer than {limit} characters")
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise MetricsError(f"{key} must be one line without control characters")
    return value


def _number(raw: dict[str, Any], key: str, default: float | None) -> float | None:
    if key not in raw or raw[key] is None:
        return default
    value = raw[key]
    if type(value) not in (int, float):  # bool is an int subclass: refuse it too
        raise MetricsError(f"{key} must be a number")
    try:
        finite = math.isfinite(value) and math.isfinite(float(value))
    except OverflowError:  # a JSON integer too big for a float
        finite = False
    if not finite:
        raise MetricsError(f"{key} must be finite")
    return value


def clean_rule(raw: Any) -> dict[str, Any]:
    """Validate and normalise one rule; every schema key is present in the result."""
    if not isinstance(raw, dict):
        raise MetricsError("a rule must be a JSON object")
    unknown = sorted(set(raw) - set(KEYS))
    if unknown:
        raise MetricsError(f"unknown rule keys: {', '.join(unknown)}")
    for key in REQUIRED:
        if key not in raw:
            raise MetricsError(f"{key} is required")
    rule_id = raw["id"]
    if not isinstance(rule_id, str) or not ID_RE.match(rule_id):
        raise MetricsError("id: a lowercase letter, then up to 31 lowercase letters, digits or '_'")
    scale = _number(raw, "scale", 1.0)
    if scale == 0:
        raise MetricsError("scale must not be 0")
    pin = raw.get("pin", False)
    if not isinstance(pin, bool):
        raise MetricsError("pin must be true or false")
    enabled = raw.get("enabled", True)
    if not isinstance(enabled, bool):
        raise MetricsError("enabled must be true or false")
    show = raw.get("show", "both")
    if show not in SHOWS:
        raise MetricsError(f"show must be one of {', '.join(SHOWS)}")
    return {
        "id": rule_id,
        "label": _text(raw, "label", 40, required=True),
        "before": _text(raw, "before", 64, required=True),
        "tag": _text(raw, "tag", 64),
        "unit": _text(raw, "unit", 8),
        "scale": float(scale),
        "warn_below": _number(raw, "warn_below", None),
        "warn_above": _number(raw, "warn_above", None),
        "pin": pin,
        "enabled": enabled,
        "show": show,
    }


def clean_rules(raw: Any) -> list[dict[str, Any]]:
    if not isinstance(raw, list):
        raise MetricsError("rules must be a list")
    if len(raw) > MAX_RULES:
        raise MetricsError(f"at most {MAX_RULES} rules")
    rules = [clean_rule(item) for item in raw]
    seen: set[str] = set()
    for item in rules:
        if item["id"] in seen:
            raise MetricsError(f"duplicate rule id: {item['id']}")
        seen.add(item["id"])
    return rules


def clean_order(raw: Any) -> list[str]:
    """The on-screen order: rule ids, first listed first. Unknown ids are harmless, so only the shape is checked."""
    if raw is None:
        return []
    if not isinstance(raw, list) or len(raw) > 2 * MAX_RULES:
        raise MetricsError(f"order must be a list of at most {2 * MAX_RULES} rule ids")
    for item in raw:
        if not isinstance(item, str) or not ID_RE.match(item):
            raise MetricsError("order must list rule ids")
    return list(raw)

def merge_rules(profile_rules: list[dict[str, Any]], user_rules: list[dict[str, Any]],
                enforce: bool = True, order: list[str] | None = None) -> list[dict[str, Any]]:
    """Profile order first; a user rule replaces the profile rule with the same id.

    `enforce=False` lists everything even past the limit, so a reader can show the
    user's rules (and the problem) instead of hiding them.
    """
    mine = {r["id"]: r for r in user_rules}
    merged = [mine.pop(r["id"], r) for r in profile_rules]
    merged.extend(r for r in user_rules if r["id"] in mine)
    if enforce and len(merged) > MAX_RULES:
        raise MetricsError(f"{len(merged)} rules after merging; the limit is {MAX_RULES}")
    if order:  # listed ids first (in that order), everything else after, in the default order
        by_id = {r["id"]: r for r in merged}
        first = [by_id[i] for i in dict.fromkeys(order) if i in by_id]
        listed = {r["id"] for r in first}
        merged = first + [r for r in merged if r["id"] not in listed]
    return merged


def metrics_path() -> Path:
    override = os.environ.get("SERIAL_DECK_METRICS_FILE", "").strip()
    return Path(override) if override else config_dir() / "metrics.json"


def _rev(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()


def load_user_rules(path: Path | None = None) -> tuple[list[dict[str, Any]], str, str]:
    """`(rules, problem, rev)`. Any failure gives no rules and a message; the file is never trusted."""
    path = path or metrics_path()
    try:
        data = path.read_bytes()
    except FileNotFoundError:
        return [], "", ""
    except OSError as exc:
        return [], f"cannot read {path.name}: {exc}", ""
    rev = _rev(data)
    if len(data) > MAX_BYTES:
        return [], f"{path.name} is larger than {MAX_BYTES // 1024} KiB", rev
    try:
        doc = json.loads(data.decode("utf-8"))
    except ValueError as exc:  # includes UnicodeDecodeError and JSONDecodeError
        return [], f"{path.name} is not valid JSON: {exc}", rev
    if not isinstance(doc, dict) or "rules" not in doc:
        return [], f'{path.name} must be an object with a "rules" list', rev
    try:
        return clean_rules(doc["rules"]), "", rev
    except MetricsError as exc:
        return [], f"{path.name}: {exc}", rev


def load_user_order(path: Path | None = None) -> list[str]:
    """The saved on-screen order; anything unreadable or malformed is no order."""
    try:
        doc = json.loads((path or metrics_path()).read_bytes().decode("utf-8"))
        return clean_order(doc.get("order")) if isinstance(doc, dict) else []
    except (OSError, ValueError):
        return []

def save_user_rules(rules: list[dict[str, Any]], base_rev: str, path: Path | None = None,
                    order: list[str] | None = None) -> str:
    """Write the user layer; `base_rev` must match the file as the caller last read it.

    `order` None keeps the order already in the file.
    """
    path = path or metrics_path()
    cleaned = clean_rules(rules)
    kept = clean_order(order) if order is not None else load_user_order(path)
    doc: dict[str, Any] = {"rules": cleaned}
    if kept:
        doc["order"] = kept
    text = json.dumps(doc, indent=2, ensure_ascii=False) + "\n"
    if len(text.encode("utf-8")) > MAX_BYTES:
        raise MetricsError(f"rules need more than {MAX_BYTES // 1024} KiB")
    try:
        current = _rev(path.read_bytes())
    except FileNotFoundError:
        current = ""
    if current != base_rev:
        raise MetricsError("stale")
    if current:  # never overwrite a file we could not read: it may hold hand edits
        _, problem, _ = load_user_rules(path)
        if problem:
            raise MetricsError(f"{problem}; fix or delete the file first")
    write_private(path, text)
    return _rev(path.read_bytes())  # the stored bytes: Windows rewrites "\n" as "\r\n"
