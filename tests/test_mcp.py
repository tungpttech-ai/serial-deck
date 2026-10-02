"""MCP server end-to-end against a real hub and a fake firmware on a PTY."""

import asyncio
import json
import os
import select
import subprocess
import sys
import tempfile
import threading
import time
import unittest
try:
    import pty
    import tty
except ImportError:  # Windows: no pseudo-terminals
    pty = tty = None
from pathlib import Path
from unittest.mock import patch

from mcp import Client

from serial_deck import hub as uart
from serial_deck import agent as agent_mod
from serial_deck.agent import AgentError, DeckAgent, Waiter, redact_value
from serial_deck.mcp_server import build_server
from serial_deck.service import MultiPortHub
from serial_deck.hub_client import HubProcessManager
from serial_deck.uart_client import (
    FRAME_COMMAND, FRAME_ERROR, FRAME_EVENT, FRAME_HELLO, FRAME_RESPONSE, UartReader,
    encode_json_frame, open_uart_transport)
from tests.test_flash_snapshot import write_build

ROOT = Path(__file__).resolve().parents[1]

class FakeFirmware:
    """Speaks the UART control protocol on the PTY master side, like reference firmware."""

    def __init__(self, fd):
        self.fd = fd
        self.reader = UartReader(None)
        self.stop = threading.Event()
        self.commands = []
        self.hellos = 0
        self.raw_bytes = 0
        self.mode = "normal"
        self.identity_string = False
        self.event_seq = 0
        self.tx_sequence = 100
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def send(self, frame_type, sequence, message):
        os.write(self.fd, encode_json_frame(frame_type, sequence, message))

    def log(self, text):
        os.write(self.fd, text.encode() + b"\r\n")

    def lifecycle(self, request, sequence, status, result=None):
        self.event_seq += 1
        message = {"version": 1, "request_id": request["request_id"], "operation_id": "op-" + request["request_id"][:6],
                   "status": status, "error": "", "esp_error": 0, "retryable": False,
                   "event_seq": self.event_seq, "command": request["command"]}
        if result is not None:
            message["result"] = result if isinstance(result, str) else json.dumps(result)
        self.tx_sequence += 1
        return message

    def run(self):
        while not self.stop.is_set():
            if not select.select([self.fd], [], [], 0.05)[0]:
                continue
            try:
                chunk = os.read(self.fd, 65536)
            except OSError:
                return
            self.raw_bytes += len(chunk)
            for kind, value in self.reader.feed(chunk):
                if kind != "frame":
                    continue
                frame_type, _flags, sequence, message = value
                if frame_type == FRAME_HELLO:
                    self.hellos += 1
                    self.send(FRAME_HELLO, sequence, {"version": 1, "transport": "uart0", "baud": 115200,
                                                      "commands": ["query", "input.button", "ui.show_info"]})
                    continue
                if frame_type != FRAME_COMMAND:
                    continue
                self.commands.append(message)
                self.respond(message, sequence)

    def respond(self, request, sequence):
        if self.mode == "silent":
            return
        if self.mode == "schema_error":
            self.send(FRAME_ERROR, sequence, {"version": 1, "request_id": request["request_id"],
                                              "status": "rejected", "error": "invalid_schema", "esp_error": 258})
            return
        result = {"state": "IDLE", "serial": "SN-1234", "wifi_password": "hunter2"} \
            if request["args"].get("kind") in ("snapshot", "identity") else None
        if request["args"].get("kind") == "identity" and self.identity_string:
            result = "DEVICE-ID-42"
        accepted = self.lifecycle(request, sequence, "accepted")
        # Foreign lifecycle for another client with the same sequence number.
        self.send(FRAME_EVENT, self.tx_sequence, {**accepted, "request_id": "someoneelse"})
        self.send(FRAME_RESPONSE, sequence, accepted)
        running = self.lifecycle(request, sequence, "running")
        self.send(FRAME_EVENT, self.tx_sequence, running)
        self.send(FRAME_EVENT, self.tx_sequence, running)  # duplicate event_seq
        self.log("I (99) control: handled " + request["command"])
        done = self.lifecycle(request, sequence, "succeeded", result)
        self.send(FRAME_EVENT, self.tx_sequence, done)

    def close(self):
        self.stop.set()
        self.thread.join(timeout=1)

def call(client, name, args=None):
    return asyncio.get_event_loop().run_until_complete(client.call_tool(name, args or {}))

@unittest.skipIf(pty is None, "needs POSIX pseudo-terminals")
class McpEndToEndTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="pk-mcp-")
        master, slave = pty.openpty()
        tty.setraw(master)
        tty.setraw(slave)
        self.master, self.slave = master, slave
        self.port = os.ttyname(slave)
        self.scan = patch.object(uart, "discover_serial_ports", return_value=[self.port])
        self.scan.start()
        self.socket = str(Path(self.temp.name) / "hub.sock")
        self.hub = MultiPortHub(self.socket, idle_timeout=0.3)
        self.hub.start()
        self.hub_thread = threading.Thread(target=self._run_hub, daemon=True)
        self.hub_thread.start()
        self.firmware = FakeFirmware(master)
        self.store = Path(self.temp.name) / "snapshots"
        self.store.mkdir(mode=0o700)
        self.loop = asyncio.new_event_loop()

    def _run_hub(self):
        while not self.hub.stop.is_set():
            self.hub.stop.wait(0.1)
            self.hub.reap_idle()
            self.hub._publish_status()

    def tearDown(self):
        self.loop.close()
        self.firmware.close()
        self.hub.close()
        self.scan.stop()
        os.close(self.master)
        os.close(self.slave)
        self.temp.cleanup()

    def run_client(self, policy, body):
        agent = DeckAgent(policy=policy, socket_path=self.socket, snapshot_root=self.store)

        async def main():
            async with Client(build_server(agent)) as client:
                async def tool(name, args=None, **kwargs):
                    return await client.call_tool(name, args or {}, **kwargs)
                return await body(tool, agent)
        return self.loop.run_until_complete(main())

    def test_connect_query_logs_and_policy(self):
        async def body(tool, agent):
            result = await tool("serial_connect", {"port": self.port, "baud": 115200, "mode": "control"})
            self.assertFalse(result.is_error, result.content)
            data = result.structured_content
            self.assertTrue(data["opened_uart"])
            self.assertEqual(data["hello"]["commands"], ["query", "input.button", "ui.show_info"])

            query = (await tool("serial_query", {"kind": "snapshot"})).structured_content
            self.assertEqual(query["outcome"], "completed")
            self.assertEqual(query["status"], "succeeded")
            self.assertEqual(query["result"]["state"], "IDLE")
            self.assertEqual(query["result"]["wifi_password"], "[redacted]")
            self.assertEqual([f["status"] for f in query["frames"]], ["accepted", "running", "succeeded"])

            identity = (await tool("serial_query", {"kind": "identity"})).structured_content
            self.assertEqual(identity["result"]["serial"], "[redacted]")
            self.firmware.identity_string = True
            opaque = (await tool("serial_query", {"kind": "identity"})).structured_content
            self.assertEqual(opaque["result"], "[redacted 12 chars]")
            self.assertNotIn("DEVICE-ID-42", json.dumps(opaque))
            shown = (await tool("serial_query", {"kind": "identity", "redact_identity": False})).structured_content
            self.assertEqual(shown["result"], "DEVICE-ID-42")

            self.firmware.log("I (100) wifi: connect url=http://user:secret@host/x token=abc123")
            waited = (await tool("serial_wait_for", {"any_of": ["wifi:"], "since": 1})).structured_content
            self.assertTrue(waited["matched"])
            self.assertNotIn("secret", json.dumps(waited))
            self.assertNotIn("abc123", json.dumps(waited))

            logs = (await tool("serial_logs", {"contains": ["handled"]})).structured_content
            self.assertEqual(len(logs["records"]), 4)  # one per query above
            page = (await tool("serial_logs", {"cursor": 1, "limit": 1})).structured_content
            self.assertTrue(page["truncated"])
            self.assertEqual(page["next_cursor"], page["records"][0]["seq"] + 1)

            denied = await tool("serial_button", {"button": "HOME"})
            self.assertTrue(denied.is_error)  # not registered under observe
            status = (await tool("serial_status")).structured_content
            self.assertIn("serial_button", status["disabled_tools"])
            self.assertTrue(status["tx_atomic"])
            timeout = (await tool("serial_wait_for", {"any_of": ["never"], "timeout_s": 0.3})).structured_content
            self.assertFalse(timeout["matched"])
        self.run_client("observe", body)

    def test_default_raw_attach_transmits_nothing(self):
        async def body(tool, agent):
            result = (await tool("serial_connect", {"port": self.port, "baud": 115200})).structured_content
            self.assertEqual(result["mode"], "raw")
            self.assertNotIn("hello", result)
            time.sleep(0.3)
            self.assertEqual(self.firmware.raw_bytes, 0)  # not a single byte on the wire
        self.run_client("observe", body)

    def test_live_baud_is_kept_unless_retime_is_explicit(self):
        async def body(tool, agent):
            await tool("serial_connect", {"port": self.port, "baud": 115200, "mode": "control"})
            other = HubProcessManager(socket_path=self.socket)
            other.claim_port(self.port, 115200)
            data = open_uart_transport(other.endpoint, other.baud, 0.1)
            try:
                retimed = (await tool("serial_connect", {"port": self.port, "baud": 38400,
                                                       "change_live_baud": True})).structured_content
                self.assertEqual(retimed["baud"], 38400)
                deadline = time.monotonic() + 3
                while agent.status()["hub"]["channels"][0]["baud"] != 38400:
                    self.assertLess(time.monotonic(), deadline)
                    await asyncio.sleep(0.02)
                status = (await tool("serial_status")).structured_content
                self.assertEqual(status["sessions"][0]["baud"], 38400)
            finally:
                data.close()
        self.run_client("interact", body)

    def test_change_live_baud_needs_interact_policy(self):
        async def body(tool, agent):
            denied = await tool("serial_connect", {"port": self.port, "baud": 38400, "change_live_baud": True})
            self.assertTrue(denied.is_error)
            self.assertIn("policy_denied", json.dumps(denied.structured_content or str(denied.content)))
        self.run_client("observe", body)

    def test_button_lifecycle_and_unknown_outcome(self):
        async def body(tool, agent):
            await tool("serial_connect", {"port": self.port, "baud": 115200, "mode": "control"})
            pressed = (await tool("serial_button", {"button": "ENTER", "action": "long_press"})).structured_content
            self.assertEqual(pressed["status"], "succeeded")
            self.assertEqual(self.firmware.commands[-1]["args"], {"button": "ENTER", "action": "long_press"})
            self.firmware.mode = "silent"
            unknown = (await tool("serial_button", {"button": "HOME", "timeout_s": 0.3})).structured_content
            self.assertEqual(unknown["outcome"], "unknown")
            self.assertIn("do not re-send", unknown["hint"])
            self.firmware.mode = "schema_error"
            rejected = (await tool("serial_show_info")).structured_content
            self.assertEqual((rejected["status"], rejected["error"]), ("rejected", "invalid_schema"))
            reset = await tool("serial_reset")
            self.assertTrue(reset.is_error)
            logs = (await tool("serial_logs", {"levels": ["note"]})).structured_content
            self.assertIn("[mcp] button ENTER long_press", [r["text"] for r in logs["records"]])
        self.run_client("interact", body)

    def test_legacy_hub_is_refused_without_side_effects(self):
        agent = DeckAgent(policy="observe", socket_path=self.socket)
        with patch.object(agent_mod.HubProcessManager, "get_status", return_value={"protocol": None}):
            with self.assertRaises(AgentError) as caught:
                agent.connect(self.port, 115200, "control")
        self.assertEqual(caught.exception.code, "legacy_hub")

    def test_flash_preview_start_status_with_fake_esptool(self):
        build = write_build(Path(self.temp.name))
        read_paths = []

        def fake_flash(port, build_dir, flash_baud, output=None):
            manifest = json.loads((Path(build_dir) / "flasher_args.json").read_text())
            for rel in manifest["flash_files"].values():
                path = Path(build_dir) / rel
                read_paths.append(str(path.resolve()))
                path.read_bytes()
                output(f"Writing at 0x0 (50 %)")
                output("Hash of data verified.")
            return 0

        async def body(tool, agent):
            await tool("serial_connect", {"port": self.port, "baud": 115200, "mode": "control"})
            preview = await tool("serial_flash_preview", {"build_dir": str(build), "flash_baud": 460800})
            self.assertFalse(preview.is_error, preview.content)
            data = preview.structured_content
            self.assertEqual([i["role"] for i in data["images"]],
                             ["bootloader", "partition-table", "ota_data:otadata", "app:ota_0"])
            token = data["token"]
            (build / "app.bin").write_bytes(b"CHANGED")  # must not affect the snapshot
            with patch.object(uart, "flash_build_in_process", side_effect=fake_flash), \
                    patch.object(uart, "build_flash_command", return_value=["esptool"]):
                started = (await tool("serial_flash_start", {"token": token})).structured_content
                self.assertTrue(started["accepted"])
                progress = []

                async def on_progress(value, total, message):
                    progress.append(value)
                final = (await tool("serial_flash_status", {"token": token, "wait_s": 10},
                                    progress_callback=on_progress)).structured_content
            self.assertEqual(final["verdict"], "verified", final)
            self.assertTrue(final["flash_verified"])
            self.assertEqual(final["verified_images"], "4/4")
            self.assertEqual(progress, sorted(progress))
            store = self.store.resolve()  # macOS: /var is a symlink to /private/var
            self.assertTrue(all(Path(path).resolve().is_relative_to(store) for path in read_paths), read_paths)
            again = await tool("serial_flash_start", {"token": token})
            self.assertEqual(again.structured_content["error"]["code"], "token_invalid")
            self.assertEqual(list(self.store.iterdir()), [])
        self.run_client("hardware", body)

    def test_flash_refuses_nvs_and_bad_tokens(self):
        build = write_build(Path(self.temp.name), files={"0x9000": "app.bin",
                                                          "0x8000": "partition_table/partition-table.bin"})

        async def body(tool, agent):
            await tool("serial_connect", {"port": self.port, "baud": 115200, "mode": "control"})
            refused = await tool("serial_flash_preview", {"build_dir": str(build)})
            self.assertEqual(refused.structured_content["error"]["code"], "flash_refused")
            self.assertIn("nvs", refused.structured_content["error"]["message"])
            bad = await tool("serial_flash_start", {"token": "not-a-real-token"})
            self.assertEqual(bad.structured_content["error"]["code"], "token_invalid")
        self.run_client("hardware", body)

class WaiterTest(unittest.TestCase):
    def test_correlates_by_request_id_and_event_seq(self):
        waiter = Waiter("rid", 7)
        base = {"request_id": "rid", "operation_id": "op1"}
        self.assertFalse(waiter.offer(FRAME_EVENT, 7, {**base, "request_id": "other", "status": "succeeded"}))
        self.assertTrue(waiter.offer(FRAME_EVENT, 501, {**base, "status": "running", "event_seq": 2}))
        self.assertTrue(waiter.offer(FRAME_EVENT, 502, {**base, "status": "accepted", "event_seq": 1}))
        self.assertEqual(waiter.status, "running")  # stale event ignored
        self.assertFalse(waiter.offer(FRAME_EVENT, 503, {**base, "operation_id": "op2", "status": "failed",
                                                         "event_seq": 3}))
        self.assertTrue(waiter.offer(FRAME_EVENT, 504, {**base, "status": "cancelled", "event_seq": 4}))
        self.assertTrue(waiter.event.is_set())
        self.assertEqual(waiter.status, "cancelled")

    def test_error_without_request_id_matches_sequence_only(self):
        waiter = Waiter("rid", 7)
        self.assertFalse(waiter.offer(FRAME_ERROR, 8, {"status": "rejected"}))
        self.assertTrue(waiter.offer(FRAME_ERROR, 7, {"status": "rejected", "error": "invalid_schema"}))
        self.assertEqual(waiter.status, "rejected")

class WaiterOrderingTest(unittest.TestCase):
    def test_late_frames_never_override_terminal_or_running(self):
        waiter = Waiter("rid", 7)
        base = {"request_id": "rid", "operation_id": "op1"}
        waiter.offer(FRAME_EVENT, 501, {**base, "status": "running", "event_seq": 2})
        waiter.offer(FRAME_RESPONSE, 7, {**base, "status": "accepted", "event_seq": 1})
        self.assertEqual(waiter.status, "running")
        waiter.offer(FRAME_EVENT, 502, {**base, "status": "succeeded", "event_seq": 3})
        frames = len(waiter.frames)
        self.assertTrue(waiter.offer(FRAME_RESPONSE, 7, {**base, "status": "accepted"}))
        self.assertEqual((waiter.status, len(waiter.frames)), ("succeeded", frames))

class FlashJobTest(unittest.TestCase):
    """Flash correlation without a hub: events are fed to the job directly."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="pk-job-")
        root = Path(self.temp.name)
        store = root / "store"
        store.mkdir(mode=0o700)
        self.snapshot = agent_mod.snapshots.prepare_snapshot(str(write_build(root)), root=store)
        self.agent = DeckAgent(policy="hardware", socket_path=str(root / "none.sock"), snapshot_root=store)
        self.job = agent_mod.FlashJob("tok", "/dev/null", self.snapshot, started=time.time())
        self.agent.jobs["tok"] = self.job

    def tearDown(self):
        self.temp.cleanup()

    def event(self, revision, flash_id, active, line="", exit_code=None, build_dir=None):
        return {"event": "status", "revision": revision, "state": "ready", "port": "/dev/x",
                "flash": {"active": active, "id": flash_id, "line": line, "progress": 50,
                          "step": "Writing", "exit_code": exit_code, "error": "",
                          "build_dir": build_dir or str(self.snapshot.directory)}}

    def test_foreign_flash_is_ignored_and_ids_are_recovered(self):
        self.agent._on_flash_status(self.job, self.event(1, 5, False, exit_code=0, build_dir="/other"))
        self.assertIsNone(self.job.finished)
        self.assertIsNone(self.job.flash_id)
        self.agent._on_flash_status(self.job, self.event(2, 6, False, "Hash of data verified.", exit_code=0))
        self.assertEqual(self.job.flash_id, 6)  # recovered from a terminal status alone
        self.assertIsNotNone(self.job.finished)

    def test_gap_in_revisions_makes_verification_unknown_and_status_is_repeatable(self):
        for index, revision in enumerate((1, 2, 5, 6)):
            self.agent._on_flash_status(self.job, self.event(revision, 3, True, f"Hash of data verified. {index}"))
        self.agent._on_flash_status(self.job, self.event(7, 3, False, "done", exit_code=0))
        first = self.agent.flash_status("tok", 0)
        self.assertEqual((first["verdict"], first["flash_verified"], first["evidence_complete"]),
                         ("unknown", None, False))
        self.assertFalse(self.snapshot.directory.exists())
        self.assertEqual(self.agent.flash_status("tok", 0)["verdict"], "unknown")  # cached, no crash

    def test_push_lost_mid_flash_then_polled_completion_is_unknown(self):
        for revision in (1, 2, 3, 4):
            self.agent._on_flash_status(self.job, self.event(revision, 3, True, f"Hash of data verified. {revision}"))

        class Poller:
            channel_socket = None

            def get_status(inner):
                return self.event(12, 3, False, "Hard resetting", exit_code=0)

            def unsubscribe(inner):
                pass

        self.job.manager = Poller()
        result = self.agent.flash_status("tok", 1)
        self.assertEqual((result["flash_verified"], result["evidence_complete"]), (None, False))

    def test_polled_lines_are_not_counted_as_hash_evidence(self):
        pushed = [self.event(r, 3, True, f"Hash of data verified. {r}") for r in (1, 2, 3)]
        polled_last = self.event(4, 3, False, "Hash of data verified. 4", exit_code=0)
        self.agent._on_flash_status(self.job, pushed[0])
        self.agent._on_flash_status(self.job, polled_last, pushed=False)
        self.assertEqual(self.job.poll_revision, 4)  # set atomically with `finished`
        for event in pushed[1:]:
            self.agent._on_flash_status(self.job, event)
        self.agent._on_flash_status(self.job, polled_last)  # the push replays revision 4
        result = self.agent.flash_status("tok", 0)
        self.assertEqual(result["verified_images"], "4/4")
        self.assertTrue(result["evidence_complete"])
        self.assertTrue(result["flash_verified"])

    def test_three_hashes_for_four_images_never_verify(self):
        for r in (1, 2, 3):
            self.agent._on_flash_status(self.job, self.event(r, 3, True, f"Hash of data verified. {r}"))
        self.agent._on_flash_status(self.job, self.event(3, 3, True, "Hash of data verified. 3"), pushed=False)
        self.agent._on_flash_status(self.job, self.event(4, 3, False, "done", exit_code=0))
        result = self.agent.flash_status("tok", 0)
        self.assertEqual((result["verified_images"], result["flash_verified"]), ("3/4", None))

    def test_finalize_waits_for_flash_start_bookkeeping(self):
        self.job.finalize_lock.acquire()  # flash_start holds it until the reply is handled
        self.agent._on_flash_status(self.job, self.event(1, 3, False, "done", exit_code=0))
        done = threading.Event()
        threading.Thread(target=lambda: (self.agent.flash_status("tok", 0), done.set()), daemon=True).start()
        self.assertFalse(done.wait(0.3))
        self.assertTrue(self.snapshot.directory.exists())
        self.snapshot.set_state("in_use", flash_id=3)  # what flash_start does after the reply
        self.job.finalize_lock.release()
        self.assertTrue(done.wait(3))
        self.assertFalse(self.snapshot.directory.exists())

    def test_status_output_redacts_flash_step(self):
        class Root:
            def socket_ready(self):
                return True

            def get_status(self):
                return {"channels": [{"port": "/dev/x", "flash": {"step": "fail token=FAKE_SECRET"}}]}

        self.agent.manager_factory = lambda **_: Root()
        self.assertNotIn("FAKE_SECRET", json.dumps(self.agent.status()))

    def test_complete_evidence_with_wrong_count_is_not_verified(self):
        self.agent._on_flash_status(self.job, self.event(1, 3, True, "Hash of data verified."))
        self.agent._on_flash_status(self.job, self.event(2, 3, False, "done", exit_code=0))
        result = self.agent.flash_status("tok", 0)
        self.assertEqual((result["flash_verified"], result["verified_images"]), (None, "1/4"))

class CancellationTest(unittest.TestCase):
    def test_cancelled_wait_stops_worker_promptly(self):
        session = agent_mod.Session.__new__(agent_mod.Session)
        session.lock = threading.Lock()
        session.changed = threading.Condition(session.lock)
        session.records = agent_mod.deque(maxlen=10)
        session.next_seq = 1
        session.lost = None
        session.port = "/dev/x"
        flag = threading.Event()
        threading.Timer(0.2, flag.set).start()
        start = time.monotonic()
        result = session.wait_for(["never"], 60, None, False, 0, flag.is_set)
        self.assertEqual(result["reason"], "cancelled")
        self.assertLess(time.monotonic() - start, 2)

    def test_unknown_dispatch_is_reported_as_unknown(self):
        from serial_deck.uart_client import FrameDispatchUnknown

        class Transport:
            def write_frame(self, frame):
                raise FrameDispatchUnknown("timed out")

        session = agent_mod.Session.__new__(agent_mod.Session)
        session.lock = threading.Lock()
        session.mode = "control"
        session.lost = None
        session.waiters = []
        session.sequence = 1 << 30
        session.transport = Transport()
        result = session.request("ui.show_info", {}, 0.2)
        self.assertEqual(result["outcome"], "unknown")
        self.assertIn("no hub reply", result["reason"])

class RedactionTest(unittest.TestCase):
    def test_errors_and_hello_are_redacted(self):
        payload = AgentError("x", "cannot open http://u:pw@h token=abc", details_key="psk=zzz").payload()
        self.assertNotIn("pw@", json.dumps(payload))
        self.assertNotIn("abc", json.dumps(payload))
        self.assertNotIn("zzz", json.dumps(payload))

    def test_redacts_common_secret_shapes(self):
        text = redact_value('psk=abc wifi "password": "x" Authorization: Bearer abcdefghijkl '
                            'mqtt://u:p@h eyJhbGciOiJIUzI1.eyJzdWIiOiIxMjM0.SflKxwRJSMeKKF2QT4fw')
        for secret in ("abc ", '"x"', "abcdefghijkl", "u:p@", "SflKxw"):
            self.assertNotIn(secret, text)
        self.assertEqual(redact_value({"token": "t", "nested": {"api_key": "k"}, "ok": 1}),
                         {"token": "[redacted]", "nested": {"api_key": "[redacted]"}, "ok": 1})

class ActivityTest(unittest.TestCase):
    """Tool calls are published for the dashboard's MCP page."""

    def test_calls_sessions_and_cleanup_are_published(self):
        from serial_deck import mcp_status
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            agent = DeckAgent(policy="observe", socket_path=str(root / "none.sock"))
            agent.enable_activity(root)

            async def body():
                async with Client(build_server(agent)) as client:
                    await client.call_tool("serial_status", {})
                    await client.call_tool("serial_logs", {})  # not connected -> error entry
                    await client.call_tool("serial_symbolize", {"text": "token=SECRET1 0x1", "elf": "/nope.elf"})
                    return mcp_status.live_servers(root)
            servers = asyncio.run(body())
            self.assertEqual(len(servers), 1)
            calls = servers[0]["calls"]
            self.assertEqual([c["tool"] for c in calls], ["serial_status", "serial_logs", "serial_symbolize"])
            self.assertEqual([c["state"] for c in calls], ["ok", "error", "error"])
            self.assertIn("not_connected", calls[1]["summary"])
            self.assertNotIn("SECRET1", json.dumps(servers))
            self.assertEqual(servers[0]["policy"], "observe")
            # removed by the lifespan when the client disconnected
            self.assertFalse((root / f"{os.getpid()}.json").exists())

    def test_stale_files_of_dead_processes_are_removed(self):
        from serial_deck import mcp_status
        with tempfile.TemporaryDirectory() as temp:
            stale = Path(temp) / "999999.json"
            stale.write_text("{}")
            self.assertEqual(mcp_status.live_servers(Path(temp)), [])
            self.assertFalse(stale.exists())

    def test_install_commands_run_the_package_module(self):
        from serial_deck import mcp_status
        commands = mcp_status.install_commands("hardware")
        self.assertIn("-m serial_deck.mcp_server --allow hardware", commands["claude"])
        self.assertIn("claude mcp add serial-deck -s user", commands["claude"])
        self.assertIn("codex mcp add serial-deck", commands["codex"])
        self.assertEqual(json.loads(commands["json"])["mcpServers"]["serial-deck"]["args"][-1], "hardware")

class StdioTest(unittest.TestCase):
    def test_stdio_handshake_keeps_stdout_clean(self):
        request = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                "protocolVersion": "2025-06-18", "capabilities": {},
                "clientInfo": {"name": "t", "version": "1"}}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
             "params": {"name": "serial_status", "arguments": {}}},
        ]
        with tempfile.TemporaryDirectory() as temp:
            process = subprocess.Popen(
                [sys.executable, "-m", "serial_deck.mcp_server", "--allow", "observe",
                 "--socket", str(Path(temp) / "none.sock")],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                encoding="utf-8", cwd=str(ROOT),
                env={**os.environ, "SERIAL_DECK_RUNTIME_DIR": str(Path(temp) / "rt")})
            try:
                for message in request:
                    process.stdin.write(json.dumps(message) + "\n")
                    process.stdin.flush()
                lines = []
                deadline = time.monotonic() + 15
                while len([l for l in lines if '"id"' in l]) < 3 and time.monotonic() < deadline:
                    line = process.stdout.readline()
                    if not line:
                        break
                    lines.append(line)
            finally:
                process.stdin.close()
                process.wait(timeout=10)
        replies = [json.loads(line) for line in lines]  # every stdout line is JSON-RPC
        by_id = {r["id"]: r for r in replies if "id" in r}
        names = [t["name"] for t in by_id[2]["result"]["tools"]]
        self.assertIn("serial_status", names)
        self.assertNotIn("serial_reset", names)
        self.assertEqual(by_id[3]["result"]["structuredContent"]["policy"], "observe")

if __name__ == "__main__":
    unittest.main()
