"""Custom metrics: rules that turn a number in a log line into a trend.

A rule names the literal text that precedes a number (`before`), plus a label,
unit, scale and warning limits. There is deliberately no user regex: the page
finds `before`, reads one number with a fixed grammar, and scales it, so Python
and JavaScript cannot disagree and no pattern can stall the dashboard.

Two layers feed the page: a profile's `metrics` list (read-only, shipped per
product) and the user's `metrics.json` (editable in the UI, wins on id clash).

    {"rules": [{"id": "heap_free", "label": "Free heap", "unit": "KB",
                "before": "free=", "tag": "my_tag", "scale": 0.0009765625,
                "warn_below": 64, "pin": true}]}
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
KEYS = ("id", "label", "before", "tag", "unit", "scale", "warn_below", "warn_above", "pin")
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
    if not math.isfinite(value):
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


def merge_rules(profile_rules: list[dict[str, Any]], user_rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Profile order first; a user rule replaces the profile rule with the same id."""
    mine = {r["id"]: r for r in user_rules}
    merged = [mine.pop(r["id"], r) for r in profile_rules]
    merged.extend(r for r in user_rules if r["id"] in mine)
    if len(merged) > MAX_RULES:
        raise MetricsError(f"{len(merged)} rules after merging; the limit is {MAX_RULES}")
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


def save_user_rules(rules: list[dict[str, Any]], base_rev: str, path: Path | None = None) -> str:
    """Write the user layer; `base_rev` must match the file as the caller last read it."""
    path = path or metrics_path()
    cleaned = clean_rules(rules)
    text = json.dumps({"rules": cleaned}, indent=2, ensure_ascii=False) + "\n"
    if len(text.encode("utf-8")) > MAX_BYTES:
        raise MetricsError(f"rules need more than {MAX_BYTES // 1024} KiB")
    try:
        current = _rev(path.read_bytes())
    except FileNotFoundError:
        current = ""
    if current != base_rev:
        raise MetricsError("stale")
    write_private(path, text)
    return _rev(text.encode("utf-8"))
