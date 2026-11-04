"""Cache budgets, retention, restart recovery and MCP pagination without hardware."""
import asyncio
import http.client
import json
import re
import shutil
import subprocess
import threading
import os
import tempfile
import time
import unittest
from pathlib import Path
from http.server import ThreadingHTTPServer
from types import SimpleNamespace
from unittest.mock import patch

from serial_deck import logcache
from serial_deck.agent import select_records
from serial_deck.autoconnect import Settings, SettingsError, DEFAULTS
from serial_deck.deckconfig import JsonFile


class LogCacheTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.options = {"directory": self.temp.name, "ram_mib": 1, "disk_mib": 16}
        self.cache = logcache.LogCache(self.options)
        self.addCleanup(self.cache.close)
        self.records = logcache.CachedRecords("MCP /dev/test", self.cache)

    def test_ram_eviction_keeps_disk_history_and_pages_in_order(self):
        for seq in range(1, 81):
            self.records.append({"seq": seq, "kind": "log", "level": "info", "text": "é" * 12000})
        self.assertLessEqual(self.cache.hot_bytes, self.cache.ram_limit)
        self.assertNotIn((self.records.stream, 1), self.cache.hot)
        result = select_records(self.records, 81, 1, 2, None, None, False, True)
        self.assertEqual([r["seq"] for r in result["records"]], [1, 2])
        self.assertEqual((result["next_cursor"], result["dropped"]), (3, 0))
        self.assertTrue(result["truncated"])
        self.assertEqual([r["seq"] for r in self.records[-2:]], [79, 80])

    def test_restart_recovers_archives_and_unicode(self):
        self.records.append({"text": "Tiếng Việt", "kind": "log", "level": "info"})
        self.cache.close()
        reopened = logcache.LogCache(self.options)
        self.addCleanup(reopened.close)
        self.assertEqual(list(reopened.rows(self.records.stream))[0]["text"], "Tiếng Việt")
        self.assertEqual(reopened.archives()[0]["records"], 1)
        if os.name == "posix":
            self.assertEqual((Path(self.temp.name) / "logs.sqlite3").stat().st_mode & 0o077, 0)

    def test_age_limit_removes_old_records_from_ram_and_disk(self):
        now = time.time()
        with patch.object(logcache.time, "time", return_value=now - logcache.RETENTION_S - 1):
            self.records.append({"seq": 1, "kind": "log", "level": "info", "text": "old"})
        self.records.append({"seq": 2, "kind": "log", "level": "info", "text": "new"})
        self.assertEqual([r["seq"] for r in self.records], [2])
        self.assertNotIn((self.records.stream, 1), self.cache.hot)
        result = select_records(self.records, 3, 1, 10, None, None, False, True)
        self.assertEqual(result["dropped"], 1)
        self.assertEqual(self.cache._open().execute("SELECT COUNT(*) FROM logs").fetchone()[0], 1)

    def test_disk_quota_is_shared_and_oldest_records_go_first(self):
        other = logcache.CachedRecords("Web /dev/test", self.cache)
        for seq in range(1, 241):
            records = self.records if seq % 2 else other
            records.append({"kind": "log", "level": "info", "text": f"{seq}:" + "x" * 100000})
        self.cache._prune(force=True)
        self.assertFalse(self.cache.error)
        self.assertLessEqual(sum(p.stat().st_size for p in Path(self.temp.name).iterdir()), self.cache.disk_limit)
        self.assertEqual(self.records[-1]["text"].split(":")[0], "239")
        self.assertEqual(other[-1]["text"].split(":")[0], "240")
        self.assertNotEqual(self.records[0]["seq"], 1)
        self.assertEqual(len(self.cache.archives()), 2)

    def test_two_process_connections_share_one_archive(self):
        second = logcache.LogCache(self.options)
        self.addCleanup(second.close)
        other = logcache.CachedRecords("Web other", second)
        self.records.append({"text": "one"})
        other.append({"text": "two"})
        self.assertEqual(len(self.cache.archives()), 2)
        self.assertEqual(list(second.rows(self.records.stream))[0]["text"], "one")

    def test_unwritable_archive_keeps_recent_logs_and_reports_error(self):
        with patch.object(self.cache, "_open", side_effect=OSError("disk unavailable")):
            with self.assertLogs("serial_deck.logcache", level="ERROR"):
                self.records.append({"kind": "log", "level": "info", "text": "survives"})
            self.assertEqual(self.records[-1]["text"], "survives")
            self.assertIn("disk unavailable", self.cache.status()["error"])

    def test_transient_disk_failure_is_retried_before_new_records(self):
        with patch.object(self.cache, "_open", side_effect=OSError("disk unavailable")), self.assertLogs("serial_deck.logcache", level="ERROR"):
            self.records.append({"text": "first"})
        self.assertEqual(self.cache.status()["pending_records"], 1)
        self.records.append({"text": "second"})
        self.assertEqual(self.cache.status()["pending_records"], 0)
        self.assertFalse(self.cache.error)
        self.cache.hot.clear()
        self.assertEqual([r["text"] for r in self.records], ["first", "second"])

    def test_record_larger_than_ram_budget_is_still_archived(self):
        self.records.append({"text": "x" * (2 * logcache.MIB)})
        self.assertEqual(len(self.records[-1]["text"]), 2 * logcache.MIB)
        self.assertLessEqual(self.cache.hot_bytes, self.cache.ram_limit)
        self.assertEqual(self.cache.status()["lost_records"], 0)

    def test_ram_overflow_during_disk_failure_is_reported(self):
        with patch.object(self.cache, "_open", side_effect=OSError("disk unavailable")), self.assertLogs("serial_deck.logcache", level="ERROR"):
            for _ in range(40):
                self.records.append({"text": "x" * 50000})
        self.assertGreater(self.cache.status()["lost_records"], 0)
        self.assertLessEqual(self.cache.hot_bytes, self.cache.ram_limit)
        self.records.append({"text": "recovered"})
        self.assertEqual(self.cache.status()["pending_records"], 0)
        self.assertIn("lost before archiving", self.cache.error)

    def test_smaller_quota_reclaims_existing_database(self):
        options = {**self.options, "directory": str(Path(self.temp.name) / "shrink"), "disk_mib": 32}
        big = logcache.LogCache(options)
        records = logcache.CachedRecords("large archive", big)
        for _ in range(240):
            records.append({"text": "x" * 100000})
        big.close()
        small = logcache.LogCache({**options, "disk_mib": 16})
        self.addCleanup(small.close)
        self.assertEqual(small.archives()[0]["stream"], records.stream)
        self.assertLessEqual(sum(p.stat().st_size for p in Path(options["directory"]).iterdir()), small.disk_limit)
        self.assertEqual(next(small.rows(records.stream, reverse=True, limit=1))["seq"], 240)

    def test_filtered_pagination_and_secret_redaction(self):
        for seq in range(1, 11):
            self.records.append({"seq": seq, "kind": "log", "level": "info" if seq % 2 else "debug",
                                 "text": f"TOKEN=secret-{seq} Ready"})
        result = select_records(self.records, 11, 1, 2, ["ready"], ["info"], False, True)
        self.assertEqual([r["seq"] for r in result["records"]], [1, 3])
        self.assertEqual(result["next_cursor"], 4)
        self.assertNotIn("secret-", json.dumps(result))
        result = select_records(self.records, 11, None, 2, None, ["info"], False, True)
        self.assertEqual([r["seq"] for r in result["records"]], [7, 9])

    def test_settings_round_trip_preserves_cache_when_rules_change(self):
        settings = Settings(JsonFile("settings.json", DEFAULTS, Path(self.temp.name)))
        self.assertEqual(settings.get()["log_cache"], logcache.DEFAULTS)
        settings.update(log_cache={"directory": self.temp.name, "ram_mib": 64, "disk_mib": 1024})
        settings.update(restore_on_start=True)
        self.assertEqual(settings.get()["log_cache"]["directory"], self.temp.name)
        for bad in ({"directory": "relative"}, {"ram_mib": True}, {"ram_mib": 0}, {"disk_mib": 1},
                    {"directory": "/tmp/line\nbreak"}, []):
            with self.assertRaises(SettingsError):
                settings.update(log_cache=bad)

    def test_http_settings_export_and_restart_notice(self):
        from serial_deck.web import DeckHttpHandler, DeckWebBridge
        with patch.object(logcache, "_shared", self.cache):
            bridge = DeckWebBridge(default_port="/dev/test")
            bridge.broadcast({"type": "log", "level": "info", "text": "saved on disk"})
            settings = Settings(JsonFile("settings.json", DEFAULTS, Path(self.temp.name)))
            connections = SimpleNamespace(get=lambda _: bridge, settings=settings)
            handler = type("CacheTestHandler", (DeckHttpHandler,), {"connections": connections, "action_token": "test-token"})
            server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                def request(method, path, data=None, token="test-token"):
                    conn = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
                    try:
                        conn.request(method, path, json.dumps(data) if data is not None else None,
                                     {"Content-Type": "application/json", "X-Deck-Action": token})
                        response = conn.getresponse()
                        return response.status, response.read()
                    finally:
                        conn.close()
                status, body = request("GET", "/api/cache")
                self.assertEqual(status, 200)
                self.assertEqual(json.loads(body)["active"]["ram_mib"], 1)
                stream = bridge.history_logs.stream
                status, body = request("GET", "/api/cache/export?stream=" + stream)
                self.assertEqual(status, 200)
                self.assertEqual(json.loads(body)["text"], "saved on disk")
                self.assertEqual(request("GET", "/api/cache/export?stream=../bad")[0], 400)
                self.assertIn(b"saved on disk", request("GET", "/api/export_logs")[1])
                change = {"log_cache": {"directory": self.temp.name, "ram_mib": 64, "disk_mib": 1024}}
                self.assertEqual(request("POST", "/api/settings", change, token="bad")[0], 403)
                self.assertEqual(request("POST", "/api/settings", {"log_cache": {"ram_mib": 0}})[0], 400)
                self.assertEqual(request("POST", "/api/settings", change)[0], 200)
                self.assertEqual(settings.get()["log_cache"]["ram_mib"], 64)
                self.assertEqual(self.cache.status()["ram_mib"], 1)  # applies on restart
            finally:
                server.shutdown()
                server.server_close()
                thread.join()

    def test_mcp_reads_saved_session_without_attaching_to_hardware(self):
        from mcp import Client
        from serial_deck.agent import DeckAgent
        from serial_deck.mcp_server import build_server
        self.records.append({"seq": 1, "kind": "log", "level": "info", "text": "password=hidden saved"})
        async def check():
            agent = DeckAgent(policy="observe")
            async with Client(build_server(agent)) as client:
                archives = await client.call_tool("serial_log_archives", {})
                self.assertFalse(archives.is_error)
                self.assertEqual(archives.structured_content["archives"][0]["stream"], self.records.stream)
                logs = await client.call_tool("serial_logs", {"archive": self.records.stream, "cursor": 1})
                self.assertFalse(logs.is_error)
                self.assertEqual(logs.structured_content["records"][0]["seq"], 1)
                self.assertNotIn("hidden", json.dumps(logs.structured_content))
        with patch.object(logcache, "_shared", self.cache):
            asyncio.run(check())

    @unittest.skipUnless(shutil.which("node"), "Node needed to run browser cache functions")
    def test_browser_cache_budget_and_age_limit(self):
        from serial_deck.web import HTML_PAGE
        functions = []
        for name in ("ensureConn", "connectionCacheBytes", "trimBuffer", "pushRaw"):
            match = re.search(r"    function " + name + r"\([^)]*\) \{[\s\S]*?\n    \}", HTML_PAGE)
            self.assertIsNotNone(match)
            functions.append(match.group())
        script = "const assert = require('node:assert/strict'); const conns = {}; let connOrder = [];\n" + "\n".join(functions)
        script += """
const conn = ensureConn('a');
conn.status = {log_cache: {ram_mib: 1}};
conn.logBytes = 0;
ensureConn('b');
for (let i = 0; i < 2000; i++) conn.logsBuffer.push({_cacheBytes: 1000, created_at: Date.now()/1000, n: i});
conn.logBytes = 2000000;
trimBuffer(conn);
assert(conn.logBytes <= 1024 * 1024 / 4);
assert.equal(conn.logsBuffer.at(-1).n, 1999);
assert(conn.trimmed > 0);
conn.logsBuffer[0].created_at = Date.now()/1000 - 48 * 3600 - 1;
const previous = conn.trimmed;
trimBuffer(conn);
assert.equal(conn.trimmed, previous + 1);
ensureConn('c');
assert(conn.logBytes <= 1024 * 1024 / 6);
for (let i = 0; i < 20; i++) pushRaw(conn, new Uint8Array(65536));
assert(conn.rawBytes <= 1024 * 1024 / 4);
"""
        subprocess.run([shutil.which("node"), "-e", script], check=True, capture_output=True, text=True)


if __name__ == "__main__":
    unittest.main()
