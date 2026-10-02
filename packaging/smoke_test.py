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


def clean_env(runtime: Path, work: Path) -> dict[str, str]:
    keep = ("SYSTEMROOT", "WINDIR", "TEMP", "TMP", "HOME", "USERPROFILE", "LOCALAPPDATA", "APPDATA",
            "USERNAME", "USERDOMAIN", "LANG", "DISPLAY", "XAUTHORITY", "XDG_RUNTIME_DIR", "COMSPEC",
            "APPIMAGE_EXTRACT_AND_RUN")
    env = {k: v for k, v in os.environ.items() if k in keep}
    # A PATH holding only an empty directory plus the OS's own tools; any
    # python/esptool that is still reachable fails the test (the bundle must not
    # depend on one).
    empty = work / "bin"
    empty.mkdir(exist_ok=True)
    system = ([os.environ.get("SYSTEMROOT", r"C:\Windows") + r"\System32"] if os.name == "nt"
              else ["/bin"] if Path("/bin/sh").exists() else ["/usr/bin"])
    env["PATH"] = os.pathsep.join([str(empty), *system])
    for tool in ("python", "python3", "esptool", "esptool.py"):
        found = shutil.which(tool, path=env["PATH"])
        if found and os.name != "nt":
            # /bin is a symlink to /usr/bin on merged-usr systems; shadow those.
            shadow = empty / tool
            shadow.write_text("#!/bin/sh\necho 'smoke: external interpreter used' >&2\nexit 97\n")
            shadow.chmod(0o755)
    env["SERIAL_DECK_RUNTIME_DIR"] = str(runtime)
    env["PYTHONUTF8"] = "1"
    return env


CWD: Path | None = None  # set to a scratch directory outside the checkout


def run(cli: str, env: dict[str, str], *args: str, check: bool = True, timeout: float = DEADLINE,
        stdin: str | None = None) -> subprocess.CompletedProcess:
    result = subprocess.run([cli, *args], env=env, capture_output=True, text=True, encoding="utf-8",
                            errors="replace", timeout=timeout, input=stdin, cwd=CWD)
    if "external interpreter used" in result.stderr:
        raise SystemExit(f"FAILED: {' '.join(args)} ran an external python/esptool")
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


def stop_group(process: subprocess.Popen) -> None:
    """Stop a process and everything it started (AppImage runtime + real program)."""
    if os.name == "nt":
        subprocess.run(["taskkill", "/T", "/F", "/PID", str(process.pid)], capture_output=True)
    else:
        import signal
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    try:
        process.wait(timeout=20)
    except subprocess.TimeoutExpired:
        process.kill()


def free_port() -> int:
    import socket
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def browser_mode_test(gui: str, env: dict[str, str], work: Path) -> None:
    """`app --browser` (the Linux default and the no-WebView2 fallback): it must
    hand the URL to the system opener, keep serving, and stop on Quit."""
    opened = work / "opened-url.txt"
    fake = work / "opener"
    fake.mkdir(exist_ok=True)
    browser_env = dict(env)
    if os.name == "nt":
        # rundll32 cannot be faked; read the URL from the app's own output instead.
        opener_log = None
    else:
        name = "open" if sys.platform == "darwin" else "xdg-open"
        script = fake / name
        script.write_text(f"#!/bin/sh\necho \"$1\" > '{opened}'\n")
        script.chmod(0o755)
        browser_env["PATH"] = os.pathsep.join([str(fake), env["PATH"]])
        opener_log = opened
    log = work / "browser-app.log"
    with log.open("w", encoding="utf-8") as out:
        process = subprocess.Popen([gui, "app", "--browser"], env=browser_env, cwd=CWD,
                                   stdout=out, stderr=subprocess.STDOUT)
    try:
        deadline = time.monotonic() + DEADLINE
        url = ""
        while not url:
            if time.monotonic() > deadline:
                raise SystemExit(f"FAILED: browser mode never opened a URL: {log.read_text()[-600:]}")
            if opener_log is not None and opener_log.exists():
                url = opener_log.read_text().strip()
            else:
                for line in log.read_text(encoding="utf-8", errors="replace").splitlines():
                    if line.startswith("Serial Deck dashboard: "):
                        url = line.split(": ", 1)[1].strip()
            time.sleep(0.25)
        base = url.rstrip("/")
        info = json.loads(wait_url(f"{base}/api/instance"))
        assert info.get("browser_mode") is True, info
        host = base.split("://", 1)[1]
        request = urllib.request.Request(f"{base}/api/quit", data=b"{}", method="POST", headers={
            "Content-Type": "application/json", "Host": host, "Origin": base})
        with urllib.request.urlopen(request, timeout=10) as response:
            assert json.loads(response.read()).get("ok") is True
        process.wait(timeout=30)
        print(f"browser mode: opened {url}, Quit stopped it (exit {process.returncode})")
    finally:
        if process.poll() is None:
            stop_group(process)


def mcp_tools(argv: list[str], env: dict[str, str]) -> list[dict]:
    """Talk to an MCP stdio server like a client does: wait for each reply."""
    import queue
    import threading
    process = subprocess.Popen(argv, env=env, cwd=CWD, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace")
    lines: queue.Queue = queue.Queue()
    errors: list[str] = []
    threading.Thread(target=lambda: [lines.put(l) for l in process.stdout] + [lines.put(None)],
                     daemon=True).start()
    threading.Thread(target=lambda: errors.extend(process.stderr), daemon=True).start()

    def send(message: dict) -> None:
        process.stdin.write(json.dumps(message) + "\n")
        process.stdin.flush()

    def reply(request_id: int) -> dict:
        deadline = time.monotonic() + DEADLINE
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise SystemExit(f"FAILED: MCP server did not answer: {''.join(errors)[-800:]}")
            try:
                line = lines.get(timeout=remaining)
            except queue.Empty:
                continue
            if line is None:
                raise SystemExit(f"FAILED: MCP server exited: {''.join(errors)[-800:]}")
            message = json.loads(line)  # every stdout line must be JSON-RPC
            if message.get("id") == request_id:
                return message

    try:
        send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "smoke", "version": "1"}}})
        reply(1)
        send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        send({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        return reply(2)["result"]["tools"]
    finally:
        process.stdin.close()
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()


def mcp_registration(port: int) -> list[str]:
    """The MCP server command the running bundle tells users to register (its MCP page)."""
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/mcp", timeout=10) as response:
        data = json.loads(response.read())
    config = json.loads(data["install"]["observe"]["json"])["mcpServers"]["serial-deck"]
    return [config["command"], *config["args"]]


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
    parser.add_argument("--window", action="store_true",
                        help="also open the real app window (needs a desktop session)")
    args = parser.parse_args()
    global CWD
    cli = str(Path(args.cli).resolve())
    if args.gui:
        args.gui = str(Path(args.gui).resolve())  # children run in a scratch cwd
    work = Path(tempfile.mkdtemp(prefix="sd-smoke-"))
    CWD = work  # never the checkout: the bundle must not read sources from cwd
    runtime = work / "rt"
    env = clean_env(runtime, work)
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
        port = free_port()  # never a dashboard left over from an earlier run
        # Own process group: an AppImage runs the real program as a child, and
        # stopping only the outer process would leave the dashboard running.
        group = ({"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == "nt"
                 else {"start_new_session": True})
        web = subprocess.Popen([cli, "web", "--port-web", str(port)], env=env, cwd=CWD,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, **group)
        page = wait_url(f"http://127.0.0.1:{port}/")
        assert "<title>Serial Deck</title>" in page
        asset = wait_url(f"http://127.0.0.1:{port}/assets/vendor/xterm/5.5.0/xterm.min.js")
        assert len(asset) > 10000
        info = json.loads(run(cli, env, "hub", "--status").stdout)
        assert info.get("protocol") == "serial-deck-multiport-v1", info
        hub_pid = info["pid"]
        print(f"hub pid {hub_pid} spawned by the bundle")

        tools = mcp_tools([cli, "mcp", "--allow", "observe"], env)
        names = sorted(t["name"] for t in tools)
        assert "serial_connect" in names and "serial_flash_preview" in names, names
        assert "serial_reset" not in names, names  # observe policy
        assert all("inputSchema" in t for t in tools)
        print(f"mcp: {len(names)} tools")

        # The generated MCP registration must itself start a working server.
        hub_cmd = json.loads(run(cli, env, "hub", "--status").stdout)
        assert hub_cmd["pid"] == hub_pid
        mcp_cmd = mcp_registration(port)
        assert Path(mcp_cmd[0]).name.startswith(("serial-deck-cli", "SerialDeck")), mcp_cmd
        mcp_cmd = [*mcp_cmd[:-1], "observe"] if mcp_cmd[-2] == "--allow" else mcp_cmd
        assert any(t["name"] == "serial_connect" for t in mcp_tools(mcp_cmd, env))
        print(f"registered MCP command works: {mcp_cmd[:2]}")

        if args.window or os.environ.get("DISPLAY") or os.name == "nt" or sys.platform == "darwin":
            tk = run(cli, env, "desktop", "--smoke-test", check=False, timeout=120)
            assert tk.returncode == 0 and "SMOKE TK OK" in tk.stdout, \
                f"Tk desktop window failed: {tk.stdout[-300:]} {tk.stderr[-600:]}"
            print(tk.stdout.strip().splitlines()[-1])

        browser_mode_test(args.gui or cli, env, work)

        if args.gui:
            gui = run(args.gui, env, "app", "--check-runtime", check=False)
            print(f"gui runtime: {gui.stdout.strip() or gui.stderr.strip()}")
            assert gui.returncode == 0, "the app's window runtime is not usable"
            if sys.platform.startswith("linux"):
                assert "browser mode" in gui.stdout, gui.stdout
            if args.window and not sys.platform.startswith("linux"):
                window = run(args.gui, env, "app", "--smoke-test", check=False, timeout=120)
                assert window.returncode == 0 and "SMOKE WINDOW OK" in window.stdout, \
                    f"app window did not load the dashboard: {window.stdout[-400:]} {window.stderr[-400:]}"
                print("app window loaded the dashboard")

        stop_group(web)
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
            stop_group(web)
        run(cli, env, "hub", "--shutdown", check=False)
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
