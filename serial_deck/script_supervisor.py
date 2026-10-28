"""The hub's side of user scripts: start runner processes, keep their output, stop them.

Every script runs in its own process (`serial_deck.scripting`), as a data client of
the hub like any dashboard, so a crash or an endless loop in a script cannot take
the hub down. The hub is the only owner: it is the single place that autoruns
scripts (several dashboards could otherwise each start the same one and send
every command twice) and the one that stops them all on shutdown.

Autorun is opt-in per script, stored in `scripts.json`. A run it starts ends when
the last client that is not itself a script leaves its port, so a script never
keeps a channel open on its own; a run started by hand lasts until the script
returns or is stopped.
"""

from __future__ import annotations

import collections
import itertools
import os
import signal
import subprocess
import sys
import threading
import time
from typing import Any, Callable

try:
    from . import runtime, scripting
    from .deckconfig import JsonFile
    from .uart_client import usb_matches
except ImportError:
    import runtime
    import scripting
    from deckconfig import JsonFile
    from uart_client import usb_matches

LOG_LINES = 500          # per run
LOG_LINE_CHARS = 2000
KEEP_FINISHED = 20
MAX_RUNNING = 8
# A stop waits this long for the runner to exit, then force-kills it and waits again. The
# control request that asked for it times out after 3 s, so on Windows (where the break
# event often does not reach a runner without a console) both waits must fit in that.
STOP_GRACE_S = 3.0 if os.name != "nt" else 1.0


class ScriptRun:
    def __init__(self, run_id: str, name: str, port: str, baud: int, autorun: bool) -> None:
        self.id = run_id
        self.name = name
        self.port = port
        self.baud = baud
        self.autorun = autorun
        self.attached = False  # its runner reported its data socket open (runner_attached)
        self.started = time.time()
        self.finished: float | None = None
        self.exit_code: int | None = None
        self.process: subprocess.Popen[str] | None = None
        self.stopping = False
        self.logs: collections.deque[tuple[int, str]] = collections.deque(maxlen=LOG_LINES)
        self.next_seq = 1
        self.lock = threading.Lock()

    def add_log(self, text: str) -> None:
        with self.lock:
            self.logs.append((self.next_seq, text[:LOG_LINE_CHARS]))
            self.next_seq += 1

    def read_logs(self, after: int = 0, limit: int = 200) -> tuple[list[dict[str, Any]], int, bool]:
        """Lines with seq > `after`, the cursor to pass next time, and `dropped`:
        whether lines between the caller's cursor and the oldest kept were lost."""
        with self.lock:
            kept = list(self.logs)
        oldest = kept[0][0] if kept else self.next_seq
        dropped = after + 1 < oldest
        items = [(seq, text) for seq, text in kept if seq > after][:limit]
        cursor = items[-1][0] if items else after
        return [{"seq": seq, "text": text} for seq, text in items], cursor, dropped

    def state(self) -> str:
        if self.finished is None:
            return "stopping" if self.stopping else "running"
        return "stopped" if self.stopping else ("done" if self.exit_code == 0 else "failed")

    def summary(self) -> dict[str, Any]:
        return {"id": self.id, "name": self.name, "port": self.port, "state": self.state(),
                "autorun": self.autorun, "started": self.started, "finished": self.finished,
                "exit_code": self.exit_code, "pid": self.process.pid if self.process else None,
                "last_seq": self.next_seq - 1}


class ScriptSupervisor:
    def __init__(self, socket_path: str, store: JsonFile | None = None,
                 command_factory: Callable[[scripting.Path, str, int], list[str]] | None = None) -> None:
        self.socket_path = socket_path
        self.store = store or JsonFile("scripts.json", {"autorun": []})
        self.command_factory = command_factory or self._default_command
        self.runs: dict[str, ScriptRun] = {}
        self.lock = threading.RLock()
        self._ids = itertools.count(1)
        self.closed = False

    # -- configuration ------------------------------------------------------

    def autorun_rules(self) -> list[dict[str, Any]]:
        rules = self.store.load().get("autorun", [])
        clean = []
        for item in rules if isinstance(rules, list) else []:
            if (isinstance(item, dict) and scripting.NAME_RE.match(str(item.get("name", "")))
                    and isinstance(item.get("match"), dict)):
                clean.append({"name": item["name"], "match": item["match"],
                              "enabled": bool(item.get("enabled", True)),
                              "baud": item.get("baud") if type(item.get("baud")) is int else 115200})
        return clean[:32]

    def set_autorun(self, name: str, enabled: bool, match: dict[str, str] | None = None,
                    baud: int | None = None) -> list[dict[str, Any]]:
        scripting.script_path(name)  # must exist
        with self.store.lock:
            rules = [r for r in self.autorun_rules() if r["name"] != name]
            if enabled:
                match = {k: str(v)[:256] for k, v in (match or {}).items()
                         if k in ("port", "usb_vid_pid", "usb_serial", "usb_interface")}
                if not match:
                    raise ValueError("an autorun rule needs a port or a USB vid:pid to attach to")
                rules.append({"name": name, "match": match, "enabled": True, "baud": baud or 115200})
            self.store.save({"autorun": rules})
        return self.autorun_rules()

    # -- running ------------------------------------------------------------

    def _default_command(self, path: Any, port: str, baud: int) -> list[str]:
        name = path.stem
        args = ["--hub-socket", self.socket_path, "run", name, "--port", port, "--baud", str(baud)]
        if runtime.frozen():
            return runtime.self_command("script", *args)
        return [sys.executable, "-m", "serial_deck.scripting", *args]

    def start(self, name: str, port: str, baud: int = 115200, autorun: bool = False) -> ScriptRun:
        if self.closed:
            raise RuntimeError("the hub is shutting down")
        path = scripting.script_path(name)
        if not isinstance(port, str) or not port or "\n" in port:
            raise ValueError("a script needs a port")
        if type(baud) is not int or not 300 <= baud <= 12000000:
            raise ValueError("baud must be 300..12000000")
        with self.lock:
            running = [r for r in self.runs.values() if r.finished is None]
            if len(running) >= MAX_RUNNING:
                raise RuntimeError(f"at most {MAX_RUNNING} scripts can run at once")
            if any(r.name == name and r.port == port for r in running):
                raise RuntimeError(f"{name} is already running on {port}")
            run = ScriptRun(f"s{next(self._ids)}", name, port, baud, autorun)
            command = self.command_factory(path, port, baud)
            detach: dict[str, Any] = (
                {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW}
                if os.name == "nt" else {"start_new_session": True})
            run.process = subprocess.Popen(
                command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, encoding="utf-8", errors="replace",
                env={**(runtime.self_command_env() if runtime.frozen() else os.environ),
                     "SERIAL_DECK_RUN_ID": run.id}, **detach)
            self.runs[run.id] = run
            self._trim()
        threading.Thread(target=self._pump, args=(run,), name=f"script-{run.id}", daemon=True).start()
        return run

    def _pump(self, run: ScriptRun) -> None:
        process = run.process
        assert process is not None and process.stdout is not None
        try:
            for line in process.stdout:
                run.add_log(line.rstrip("\n"))
        finally:
            run.exit_code = process.wait()
            run.finished = time.time()
            if run.stopping:
                run.add_log("(stopped)")

    def _trim(self) -> None:
        finished = [r for r in self.runs.values() if r.finished is not None]
        for old in sorted(finished, key=lambda r: r.finished or 0)[:-KEEP_FINISHED]:
            self.runs.pop(old.id, None)

    def get(self, run_id: str) -> ScriptRun:
        with self.lock:
            run = self.runs.get(run_id)
        if run is None:
            raise KeyError(f"no script run {run_id}")
        return run

    def stop(self, run_id: str) -> ScriptRun:
        run = self.get(run_id)
        self._terminate(run)
        return run

    def _terminate(self, run: ScriptRun) -> None:
        process = run.process
        if process is None or process.poll() is not None:
            return
        run.stopping = True
        self._signal(process, signal.SIGTERM if os.name != "nt" else signal.CTRL_BREAK_EVENT)
        try:
            process.wait(timeout=STOP_GRACE_S)
        except subprocess.TimeoutExpired:
            self._signal(process, signal.SIGKILL if os.name != "nt" else signal.SIGTERM)
            try:
                process.wait(timeout=STOP_GRACE_S)
            except subprocess.TimeoutExpired:
                pass

    @staticmethod
    def _signal(process: subprocess.Popen[str], sig: int) -> None:
        """Signal the runner's whole process group: a script may spawn children."""
        try:
            if os.name == "posix":
                os.killpg(process.pid, sig)
            else:
                process.send_signal(sig)
        except (ProcessLookupError, PermissionError, OSError):
            pass

    def status(self) -> list[dict[str, Any]]:
        with self.lock:
            runs = list(self.runs.values())
        return [r.summary() for r in sorted(runs, key=lambda r: r.started, reverse=True)]

    def running_on(self, port: str) -> list[ScriptRun]:
        with self.lock:
            return [r for r in self.runs.values() if r.port == port and r.finished is None]

    def mark_attached(self, run_id: str) -> None:
        """A runner this supervisor started reports its data socket is open."""
        run = self.get(run_id)
        if not run.autorun or run.finished is not None:
            raise KeyError(f"no running autorun {run_id}")
        run.attached = True

    def attached_autoruns_on(self, port: str) -> int:
        return sum(1 for r in self.running_on(port) if r.autorun and r.attached)

    def stop_autoruns_on(self, port: str) -> None:
        for run in self.running_on(port):
            if run.autorun:
                self._terminate(run)

    def stop_all(self) -> None:
        self.closed = True
        with self.lock:
            runs = [r for r in self.runs.values() if r.finished is None]
        for run in runs:
            self._terminate(run)

    # -- autorun ------------------------------------------------------------

    def on_channel_opened(self, port: str, baud: int, identity: dict[str, str]) -> list[ScriptRun]:
        """A port just opened (first claim or reopen after a loss): start its autoruns."""
        started = []
        for rule in self.autorun_rules():
            if not rule["enabled"] or not self._matches(rule["match"], port, identity):
                continue
            if any(r.name == rule["name"] for r in self.running_on(port)):
                continue
            try:
                started.append(self.start(rule["name"], port, rule["baud"] or baud, autorun=True))
            except (ValueError, RuntimeError, OSError, FileNotFoundError):
                continue  # a missing or broken script never blocks the claim
        return started

    @staticmethod
    def _matches(match: dict[str, str], port: str, identity: dict[str, str]) -> bool:
        if match.get("usb_vid_pid"):
            return usb_matches(match, identity)
        return bool(match.get("port")) and match["port"] == port
