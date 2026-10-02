"""Smoke-test a built Serial Deck bundle, run from outside the checkout.

usage: python smoke_test.py <path-to-serial-deck-cli> [--gui <path-to-gui-exe>]

Runs with a clean, explicit environment: a private runtime directory (so no
existing hub is reused) and a PATH without Python or esptool. Each step has a
deadline; the hub it auto-spawns is shut down at the end.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

DEADLINE = 60.0


def clean_env(runtime: Path) -> dict[str, str]:
    keep = ("SYSTEMROOT", "WINDIR", "TEMP", "TMP", "HOME", "USERPROFILE", "LOCALAPPDATA", "APPDATA",
            "USERNAME", "USERDOMAIN", "LANG", "DISPLAY", "XDG_RUNTIME_DIR", "COMSPEC")
    env = {k: v for k, v in os.environ.items() if k in keep}
    system = [os.environ.get("SYSTEMROOT", r"C:\Windows") + r"\System32"] if os.name == "nt" else ["/usr/bin", "/bin"]
    env["PATH"] = os.pathsep.join(system)
    env["SERIAL_DECK_RUNTIME_DIR"] = str(runtime)
    env["PYTHONUTF8"] = "1"
    return env


def run(cli: str, env: dict[str, str], *args: str, check: bool = True, timeout: float = DEADLINE,
        stdin: str | None = None) -> subprocess.CompletedProcess:
    result = subprocess.run([cli, *args], env=env, capture_output=True, text=True, encoding="utf-8",
                            errors="replace", timeout=timeout, input=stdin)
    print(f"$ {Path(cli).name} {' '.join(args)} -> {result.returncode}")
    if check and result.returncode != 0:
        raise SystemExit(f"FAILED: {result.stdout}\n{result.stderr}")
    return result


def make_fake_build(root: Path) -> Path:
    build = root / "build"
    (build / "bootloader").mkdir(parents=True)
    (build / "partition_table").mkdir()
    (build / "bootloader" / "bootloader.bin").write_bytes(b"\xe9" * 64)
    (build / "partition_table" / "partition-table.bin").write_bytes(b"\xaa\x50" + b"\x00" * 62)
    (build / "app.bin").write_bytes(b"\xe9" * 256)
    (build / "flasher_args.json").write_text(json.dumps({
        "flash_settings": {"flash_mode": "dio", "flash_freq": "80m", "flash_size": "4MB"},
        "flash_files": {"0x1000": "bootloader/bootloader.bin",
                        "0x8000": "partition_table/partition-table.bin", "0x10000": "app.bin"},
        "extra_esptool_args": {"chip": "esp32s3"},
    }), encoding="utf-8")
    return build


def wait_url(url: str, timeout: float = DEADLINE) -> str:
    deadline = time.monotonic() + timeout
    while True:
        try:
            with urllib.request.urlopen(url, timeout=3) as response:
                return response.read().decode("utf-8", "replace")
        except OSError:
            if time.monotonic() > deadline:
                raise SystemExit(f"FAILED: {url} never answered")
            time.sleep(0.25)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("cli")
    parser.add_argument("--gui")
    args = parser.parse_args()
    cli = str(Path(args.cli).resolve())
    work = Path(tempfile.mkdtemp(prefix="sd-smoke-"))
    runtime = work / "rt"
    env = clean_env(runtime)
    for tool in ("python", "python3", "esptool"):
        found = shutil.which(tool, path=env["PATH"])
        if found and os.name != "nt":
            print(f"note: {tool} exists at {found} on the system PATH; the bundle must not use it")
    web = None
    try:
        out = run(cli, env, "--version").stdout
        assert out.startswith("serial-deck "), out
        status = run(cli, env, "hub", "--status", check=False)
        assert status.returncode == 3, f"expected 'not running' (3), got {status.returncode}: {status.stderr}"

        out = run(cli, env, "flash", "--self-test").stdout
        assert "stub files OK" in out, out
        build = make_fake_build(work)
        out = run(cli, env, "flash", "--port", "COM9" if os.name == "nt" else "/dev/ttyUSB9",
                  "--build-dir", str(build), "--dry-run").stdout
        assert "flash" in out and "--build-dir" in out and "--yes" in out, out

        # The dashboard must spawn its own hub through the frozen dispatcher.
        port = 18765
        web = subprocess.Popen([cli, "web", "--port-web", str(port)], env=env,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        page = wait_url(f"http://127.0.0.1:{port}/")
        assert "<title>Serial Deck</title>" in page
        asset = wait_url(f"http://127.0.0.1:{port}/assets/vendor/xterm/5.5.0/xterm.min.js")
        assert len(asset) > 10000
        info = json.loads(run(cli, env, "hub", "--status").stdout)
        assert info.get("protocol") == "serial-deck-multiport-v1", info
        hub_pid = info["pid"]
        print(f"hub pid {hub_pid} spawned by the bundle")

        requests = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                "protocolVersion": "2025-06-18", "capabilities": {},
                "clientInfo": {"name": "smoke", "version": "1"}}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        ]
        out = run(cli, env, "mcp", "--allow", "observe",
                  stdin="".join(json.dumps(r) + "\n" for r in requests), check=False).stdout
        replies = [json.loads(line) for line in out.splitlines() if line.strip()]
        tools = next(r for r in replies if r.get("id") == 2)["result"]["tools"]
        names = sorted(t["name"] for t in tools)
        assert "serial_connect" in names and "serial_flash_preview" in names, names
        assert "serial_reset" not in names, names  # observe policy
        assert all("inputSchema" in t for t in tools)
        print(f"mcp: {len(names)} tools")

        if args.gui:
            gui = run(args.gui, env, "app", "--check-runtime", check=False)
            print(f"gui runtime: {gui.stdout.strip() or gui.stderr.strip()}")

        web.terminate()
        web.wait(timeout=20)
        web = None
        deadline = time.monotonic() + 20
        while run(cli, env, "hub", "--shutdown", check=False).returncode == 4:  # web still detaching
            if time.monotonic() > deadline:
                raise SystemExit("FAILED: hub kept refusing shutdown")
            time.sleep(0.5)
        assert run(cli, env, "hub", "--status", check=False).returncode == 3
        print("SMOKE OK")
        return 0
    finally:
        if web is not None:
            web.kill()
        run(cli, env, "hub", "--shutdown", check=False)
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
