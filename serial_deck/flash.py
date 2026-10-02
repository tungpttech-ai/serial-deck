#!/usr/bin/env python3
"""Safe host-side flash helper driven by the ESP-IDF build manifest."""

from __future__ import annotations

import argparse
import contextlib
import importlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import re
from pathlib import Path
from typing import Callable


ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


class _LineOutput:
    def __init__(self, output: Callable[[str], None] | None) -> None:
        self.output = output
        self.buffer = ""

    def write(self, value: str) -> int:
        self.buffer += value
        while True:
            delimiters = [index for index in (self.buffer.find("\n"), self.buffer.find("\r")) if index >= 0]
            if not delimiters:
                break
            index = min(delimiters)
            line = self.buffer[:index]
            self.buffer = self.buffer[index + 1:]
            if self.output is not None and line:
                self.output(ANSI_ESCAPE_RE.sub("", line))
        return len(value)

    def flush(self) -> None:
        if self.buffer and self.output is not None:
            self.output(ANSI_ESCAPE_RE.sub("", self.buffer.rstrip("\r")))
        self.buffer = ""

    def isatty(self) -> bool:
        return False


def find_esptool(build_dir: Path | None = None) -> str:
    for name in ("esptool", "esptool.py"):
        found = shutil.which(name)
        if found:
            return found
    # This interpreter's own scripts directory (venv/bin or venv\Scripts).
    scripts = Path(sys.executable).parent
    for candidate in (scripts / "esptool", scripts / "esptool.exe"):
        if candidate.is_file():
            return str(candidate)
    tools_root = Path(os.environ.get("IDF_TOOLS_PATH", Path.home() / ".espressif"))
    exe = "Scripts/esptool.exe" if os.name == "nt" else "bin/esptool"
    versioned = []
    if build_dir is not None:
        description = build_dir / "project_description.json"
        if description.is_file():
            try:
                idf_path = json.loads(description.read_text(encoding="utf-8")).get("idf_path", "")
                version = Path(idf_path).name.replace("esp-idf-", "")
                if not version.startswith("v"):
                    version = f"v{version}"
                if version.startswith("v"):
                    versioned.append(tools_root / "tools" / "python" / version / "venv" / exe)
            except (OSError, json.JSONDecodeError):
                pass
    roots = [*versioned, tools_root]
    for root in roots:
        if root.is_file():
            return str(root)
        matches = sorted([*root.glob(f"tools/python/*/venv/{exe}"),
                          *root.glob(f"python_env/*/{exe}")], reverse=True)
        if matches:
            return str(matches[0])
    raise RuntimeError("esptool not found; export ESP-IDF tools PATH or install esptool")


def manifest_chip(manifest: dict) -> str:
    """The target chip ESP-IDF recorded for this build (esp32, esp32s3, esp32p4, ...)."""
    chip = (manifest.get("extra_esptool_args") or {}).get("chip")
    if not isinstance(chip, str) or not re.fullmatch(r"esp32[a-z0-9]*", chip):
        raise ValueError(f"flash manifest names no ESP32 chip (extra_esptool_args.chip={chip!r})")
    return chip


def esptool_launcher(build: Path | None = None) -> list[str]:
    """How to run esptool: this interpreter's module when it is importable.

    `python -m esptool` works even when the Scripts/bin directory holding the
    `esptool` executable is not on PATH (common on Windows).
    """
    if importlib.util.find_spec("esptool") is not None:
        return [sys.executable, "-m", "esptool"]
    return [find_esptool(build)]


def build_flash_command(port: str, build_dir: str, flash_baud: int = 3000000) -> list[str]:
    """The esptool command line, for display and the subprocess flasher."""
    build = Path(build_dir).expanduser().resolve()
    args = esptool_args(port, build_dir, flash_baud)  # validates the build first
    return [*esptool_launcher(build), *args]


def esptool_args(port: str, build_dir: str, flash_baud: int = 3000000) -> list[str]:
    """esptool v5 arguments (no executable) for an ESP-IDF build directory."""
    build = Path(build_dir).expanduser().resolve()
    manifest_path = build / "flasher_args.json"
    if not manifest_path.is_file():
        raise ValueError(f"missing ESP-IDF flash manifest: {manifest_path}")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    settings = manifest.get("flash_settings", {})
    files = manifest.get("flash_files", {})
    if not files:
        raise ValueError("flash manifest contains no flash files")
    chip = manifest_chip(manifest)
    command = [
        "--chip", chip, "--port", port,
        "--baud", str(flash_baud), "write-flash",
    ]
    for option, key in (("--flash-mode", "flash_mode"),
                        ("--flash-freq", "flash_freq"),
                        ("--flash-size", "flash_size")):
        value = settings.get(key)
        if value:
            command.extend((option, str(value)))
    for offset, relative_path in sorted(files.items(), key=lambda item: int(item[0], 0)):
        image = build / relative_path
        if not image.is_file():
            raise ValueError(f"flash image does not exist: {image}")
        command.extend((offset, str(image)))
    return command


def flash_build(port: str, build_dir: str, flash_baud: int = 3000000,
                output: Callable[[str], None] | None = None) -> int:
    if port.startswith("hub://"):
        raise ValueError("flash requires a physical UART, not a hub:// endpoint")
    command = build_flash_command(port, build_dir, flash_baud)
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               text=True, encoding="utf-8", errors="replace",
                               cwd=str(Path(build_dir).expanduser().resolve()), bufsize=1)
    assert process.stdout is not None
    for line in process.stdout:
        if output is not None:
            output(line.rstrip("\r\n"))
    return process.wait()


def _import_esptool(build: Path):
    """esptool from this interpreter (a dependency), else an ESP-IDF venv's."""
    try:
        return importlib.import_module("esptool")
    except ImportError:
        pass
    executable = Path(find_esptool(build)).resolve()
    venv = executable.parent.parent
    for site_packages in (*venv.glob("lib/python*/site-packages"), venv / "Lib" / "site-packages"):
        path = str(site_packages)
        if site_packages.is_dir() and path not in sys.path:
            sys.path.insert(0, path)
    try:
        return importlib.import_module("esptool")
    except ImportError as exc:
        raise RuntimeError(f"cannot import esptool for in-process flash: {exc}") from exc


def flash_build_in_process(port: str, build_dir: str, flash_baud: int = 3000000,
                           output: Callable[[str], None] | None = None) -> int:
    """Run esptool inside the caller process so one hub process owns the UART."""
    if port.startswith("hub://"):
        raise ValueError("flash requires a physical UART, not a hub:// endpoint")
    args = esptool_args(port, build_dir, flash_baud)
    esptool = _import_esptool(Path(build_dir).expanduser().resolve())

    stream = _LineOutput(output)
    try:
        with contextlib.redirect_stdout(stream), contextlib.redirect_stderr(stream):
            esptool.main(args)
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else 1
        return code
    finally:
        stream.flush()
    return 0


def main() -> int:
    try:
        from .ipc import configure_console_streams
    except ImportError:
        from ipc import configure_console_streams
    configure_console_streams()
    parser = argparse.ArgumentParser(description="Flash an ESP-IDF build using its flasher_args.json manifest")
    parser.add_argument("--port", required=True)
    parser.add_argument("--build-dir", default="build")
    parser.add_argument("--baud", type=int, default=3000000)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--json", action="store_true",
                        help="print the esptool command as a JSON list")
    parser.add_argument("--yes", action="store_true", help="confirm the destructive flash operation")
    args = parser.parse_args()
    if args.port.startswith("hub://"):
        print("flash requires a physical UART, not a hub:// endpoint", file=sys.stderr)
        return 2
    try:
        command = build_flash_command(args.port, args.build_dir, args.baud)
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        print(f"flash setup failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(command) if args.json else " ".join(command), flush=True)
    if args.dry_run:
        return 0
    if not args.yes:
        print("refusing to flash without --yes", file=sys.stderr)
        return 2
    return flash_build(args.port, args.build_dir, args.baud, print)


if __name__ == "__main__":
    raise SystemExit(main())
