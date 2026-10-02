import http.client
import json
import os
import re
import shutil
import signal
import sys
import socket
import tempfile
import threading
import time
import unittest
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from serial_deck import app as app
from serial_deck import web as web
from serial_deck.hub_client import HubProcessManager, HubRegistry
from serial_deck.web import (
    ASSET_ROOT,
    HTML_PAGE,
    ConnectionManager,
    FlashCheck,
    HubStartupError,
    DeckWebBridge,
    WebBackend,
    resolve_asset,
)

HUB_SCRIPT = str(Path(__file__).resolve().parents[1] / "serial_deck" / "hub.py")


class FakeHubManager:
    """Stands in for HubProcessManager: no process, no sockets, no UART."""

    def __init__(self, uart_port="", baud=2000000, socket_path="/tmp/fake.sock",
                 ready=True, fail_start=None, flash_active=False, status_error=None,
                 owns_process=False, process_alive=True, subscribe_error=None,
                 status_flash=None):
        self.uart_port = uart_port
        self.baud = baud
        self.socket_path = socket_path
        self.ready = ready
        self.fail_start = fail_start
        self.flash_active = flash_active
        self.status_error = status_error
        self.subscribe_error = subscribe_error
        self.status_flash = status_flash  # overrides the flash payload if set
        self.owns_process = owns_process
        self.process = MagicMock(pid=4242)
        self.process.poll.return_value = None if process_alive else 0
        self.started = False
        self.stopped = 0
        self.stopped_while_owned = 0
        self.status_requests = 0

    @property
    def endpoint(self):
        return f"hub://{self.socket_path}"

    def socket_ready(self):
        return self.ready

    def ensure_started(self):
        if self.fail_start is not None:
            raise self.fail_start
        self.started = True
        return True

    def subscribe(self, _callback):
        if self.subscribe_error is not None:
            raise self.subscribe_error

    def unsubscribe(self, _callback=None):
        pass

    def request_control(self, action, timeout=3.0, **_payload):
        if action != "status":
            raise AssertionError(f"unexpected hub action {action}")
        self.status_requests += 1
        if self.status_error is not None:
            raise self.status_error
        if self.status_flash is not None:
            return {"ok": True, **self.status_flash}
        return {"ok": True, "state": "idle", "flash": {"active": self.flash_active}}

    def release_port(self):
        pass

    def stop(self):
        # Mirrors HubProcessManager.stop(): only an owned process is killed.
        self.stopped += 1
        if self.owns_process:
            self.stopped_while_owned += 1
        self.owns_process = False


def http_get(port, path, headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
    try:
        conn.request("GET", path, headers=headers or {})
        response = conn.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    finally:
        conn.close()


def port_is_closed(port):
    probe = socket.socket()
    probe.settimeout(1)
    try:
        probe.connect(("127.0.0.1", port))
        return False
    except (ConnectionRefusedError, TimeoutError, socket.timeout):
        # Windows drops connects to a closed loopback port after a timeout.
        return True
    finally:
        probe.close()


class AssetTest(unittest.TestCase):
    def test_page_has_no_remote_assets(self):
        self.assertNotRegex(HTML_PAGE, r"""(?:src|href)=["']https?://""")
        self.assertNotIn("fonts.googleapis.com", HTML_PAGE)
        self.assertNotIn("cdn.", HTML_PAGE)

    def test_every_page_asset_and_css_url_is_vendored(self):
        refs = re.findall(r"""(?:src|href)=["'](/assets/[^"']+)["']""", HTML_PAGE)
        self.assertGreaterEqual(len(refs), 5)
        for ref in refs:
            asset = resolve_asset(ref)
            self.assertIsNotNone(asset, ref)
            if asset.suffix == ".css":
                for url in re.findall(r"url\(([^)]+)\)", asset.read_text(encoding="utf-8")):
                    url = url.strip("'\"").split("?")[0].split("#")[0]
                    if url.startswith("data:"):
                        continue
                    self.assertFalse(url.startswith(("http:", "https:", "//")), url)
                    self.assertTrue((asset.parent / url).resolve().is_file(), f"{ref}: {url}")

    def test_vendor_files_have_licenses_and_checksums(self):
        vendor = ASSET_ROOT / "vendor"
        listed = {line.split(None, 1)[1].strip()
                  for line in (vendor / "SHA256SUMS").read_text().splitlines() if line.strip()}
        for directory in ("tailwindcss", "fontawesome/6.4.0", "xterm/5.5.0",
                          "xterm-addon-fit/0.10.0"):
            self.assertTrue((vendor / directory / "LICENSE.txt").is_file(), directory)
        self.assertTrue((vendor / "fonts" / "LICENSE-Inter.txt").is_file())
        self.assertIn("xterm/5.5.0/xterm.min.js", listed)

    def test_resolve_asset_rejects_unsafe_paths(self):
        self.assertIsNotNone(resolve_asset("/assets/vendor/xterm/5.5.0/xterm.min.js"))
        for bad in (
            "/assets/",
            "/assets/../web.py",
            "/assets/vendor/../../web.py",
            "/assets/vendor/%2e%2e/%2e%2e/web.py",
            "/assets//etc/passwd",
            "/assets/vendor/README.md",
            "/assets/vendor/SHA256SUMS",
            "/assets/vendor/.hidden.js",
            "/assets/vendor\\..\\x.js",
            "/assets/vendor/missing.js",
            "/assets/vendor/x.js%00.css",
            "/other/vendor/xterm/5.5.0/xterm.min.js",
        ):
            self.assertIsNone(resolve_asset(bad), bad)

    def test_resolve_asset_rejects_symlink_escape(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "root"
            root.mkdir()
            outside = Path(tmp) / "secret.js"
            outside.write_text("secret")
            (root / "ok.js").write_text("ok")
            (root / "link.js").symlink_to(outside)
            self.assertEqual(resolve_asset("/assets/ok.js", root), (root / "ok.js").resolve())
            self.assertIsNone(resolve_asset("/assets/link.js", root))


class WebBackendTest(unittest.TestCase):
    def setUp(self):
        discovery = patch("serial_deck.hub_client.find_existing_hub", return_value=None)
        self.discovery = discovery.start()
        self.addCleanup(discovery.stop)

    def make_backend(self, **kwargs):
        managers = []

        def factory(uart_port, baud, socket_path):
            manager = FakeHubManager(uart_port, baud, socket_path, **kwargs)
            managers.append(manager)
            return manager

        backend = WebBackend("127.0.0.1", 0, "", 115200, "/tmp/fake.sock",
                             hub_manager_factory=factory)
        return backend, managers[0]

    def test_serves_page_assets_and_instance_on_ephemeral_loopback_port(self):
        backend, manager = self.make_backend()
        try:
            self.assertEqual(backend.server.server_address[0], "127.0.0.1")
            self.assertNotEqual(backend.port, 0)
            self.assertEqual(backend.url, f"http://127.0.0.1:{backend.port}/")
            backend.start_in_thread()
            status, _, body = http_get(backend.port, "/api/instance")
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(body)["instance"], backend.instance_token)
            status, headers, body = http_get(backend.port, "/assets/vendor/fonts/fonts.css")
            self.assertEqual(status, 200)
            self.assertTrue(headers["Content-Type"].startswith("text/css"))
            self.assertIn(b"@font-face", body)
            status, _, _ = http_get(backend.port, "/assets/../web.py")
            self.assertEqual(status, 404)
            status, _, body = http_get(backend.port, "/")
            self.assertIn(b"/assets/vendor/xterm/5.5.0/xterm.min.js", body)
        finally:
            port = backend.port
            backend.close()
        self.assertEqual(manager.stopped, 1)
        self.assertTrue(port_is_closed(port))
        backend.close()  # idempotent
        self.assertEqual(manager.stopped, 1)

    def test_hub_startup_failure_releases_web_port(self):
        managers = []

        def factory(*args):
            managers.append(FakeHubManager(*args, fail_start=TimeoutError("no hub")))
            return managers[-1]

        servers = []
        real_bind = web.bind_web_server

        def bind(host, port, **kwargs):
            servers.append(real_bind(host, port, **kwargs))
            return servers[-1]

        with patch.object(web, "bind_web_server", bind):
            with self.assertRaises(HubStartupError):
                WebBackend("127.0.0.1", 0, hub_manager_factory=factory)
        # The hub never started, so nothing is stopped; the web port is freed.
        self.assertEqual(managers[0].stopped, 0)
        self.assertEqual(servers[0].socket.fileno(), -1)

    def test_attach_only_requires_existing_hub(self):
        with self.assertRaises(HubStartupError):
            WebBackend("127.0.0.1", 0, attach_only=True,
                       hub_manager_factory=lambda *a: FakeHubManager(*a, ready=False))

    def test_two_backends_in_one_process_stay_independent(self):
        a, manager_a = self.make_backend()
        b, manager_b = self.make_backend()
        try:
            a.start_in_thread()
            b.start_in_thread()
            self.assertNotEqual(a.instance_token, b.instance_token)
            for backend in (a, b):
                _, _, body = http_get(backend.port, "/api/instance")
                self.assertEqual(json.loads(body)["instance"], backend.instance_token)
            conn = http.client.HTTPConnection("127.0.0.1", a.port, timeout=3)
            conn.request("POST", "/api/connections", body=b"{}",
                         headers={"Content-Type": "application/json", "Content-Length": "2"})
            new_id = json.loads(conn.getresponse().read())["id"]
            conn.close()
            ids = lambda backend: [c["id"] for c in json.loads(
                http_get(backend.port, "/api/connections")[2])["connections"]]
            self.assertEqual(ids(a), ["default", new_id])
            self.assertEqual(ids(b), ["default"])
        finally:
            a.close()
            b.close()
        self.assertEqual((manager_a.stopped, manager_b.stopped), (1, 1))

    def test_flash_check_asks_every_distinct_hub(self):
        backend, default_manager = self.make_backend()
        try:
            shared = FakeHubManager("/dev/ttyFAKE1", flash_active=True)
            for _ in range(2):
                _, bridge = backend.connections.create()
                bridge.hub_manager = shared
                bridge.port = "/dev/ttyFAKE1"
            check = backend.flash_check()
            self.assertEqual((check.active, check.unknown), (["/dev/ttyFAKE1"], []))
            self.assertEqual(shared.status_requests, 1)
            self.assertEqual(default_manager.status_requests, 1)
            shared.flash_active = False
            self.assertFalse(backend.flash_check().blocked)
        finally:
            backend.close()

    def silent_connections(self, **manager_kwargs):
        bridge = DeckWebBridge(default_port="/dev/ttyFAKE0")
        bridge.flashing = False  # stale cached state must not count as idle
        manager = FakeHubManager("/dev/ttyFAKE0", status_error=OSError("gone"),
                                 **manager_kwargs)
        bridge.hub_manager = manager
        return ConnectionManager(bridge, HubRegistry(), 115200, ""), manager

    def test_silent_owned_live_hub_is_unknown_despite_stale_idle_cache(self):
        connections, manager = self.silent_connections(owns_process=True)
        check = connections.flash_check()
        self.assertEqual((check.active, check.unknown), ([], ["/dev/ttyFAKE0"]))
        manager.status_error = None  # the hub answers again: recovers to idle
        self.assertFalse(connections.flash_check().blocked)

    def test_silent_hub_that_is_dead_or_not_owned_does_not_block(self):
        for kwargs in ({"owns_process": True, "process_alive": False},
                       {"owns_process": False}):
            connections, _ = self.silent_connections(**kwargs)
            self.assertFalse(connections.flash_check().blocked, kwargs)

    def test_close_leaves_flashing_or_unknown_owned_hubs_running(self):
        backend, default_manager = self.make_backend(owns_process=True, flash_active=True)
        _, bridge = backend.connections.create()
        silent = FakeHubManager("/dev/ttyFAKE1", status_error=OSError("gone"),
                                owns_process=True)
        bridge.hub_manager = silent
        bridge.port = "/dev/ttyFAKE1"
        with patch("sys.stderr") as err:
            backend.close()
        text = "".join(c.args[0] for c in err.write.call_args_list)
        self.assertIn("is flashing", text)
        self.assertIn("did not report its flash state", text)
        self.assertEqual(default_manager.stopped_while_owned, 0)
        self.assertEqual(silent.stopped_while_owned, 0)

    def subscribe_failure(self, **kwargs):
        managers, servers = [], []
        real_bind = web.bind_web_server

        def factory(*args):
            managers.append(FakeHubManager(*args, owns_process=True,
                                           subscribe_error=OSError("refused"), **kwargs))
            return managers[-1]

        def bind(host, port, **bind_kwargs):
            servers.append(real_bind(host, port, **bind_kwargs))
            return servers[-1]

        with patch.object(web, "bind_web_server", bind), patch("sys.stderr") as err:
            with self.assertRaisesRegex(HubStartupError, "subscribe"):
                WebBackend("127.0.0.1", 0, "", 115200, "/tmp/fake.sock",
                           hub_manager_factory=factory)
        self.assertEqual(servers[0].socket.fileno(), -1)  # web port always freed
        return managers[0], "".join(c.args[0] for c in err.write.call_args_list)

    def test_subscribe_failure_keeps_owned_hub_with_unknown_state(self):
        manager, text = self.subscribe_failure(status_error=OSError("outage"))
        self.assertEqual(manager.stopped_while_owned, 0)
        self.assertIn("did not report its flash state", text)

    def test_subscribe_failure_keeps_owned_flashing_hub(self):
        manager, text = self.subscribe_failure(flash_active=True)
        self.assertEqual(manager.stopped_while_owned, 0)
        self.assertIn("is flashing", text)

    def test_subscribe_failure_stops_idle_owned_hub(self):
        manager, text = self.subscribe_failure()
        self.assertEqual(manager.stopped_while_owned, 1)
        self.assertEqual(text, "")

    def test_malformed_flash_status_of_owned_live_hub_is_unknown(self):
        for payload in ({}, {"flash": None}, {"flash": {}}, {"flash": {"active": "no"}},
                        {"flash": {"active": 0}}, {"flash": ["active"]}):
            live = FakeHubManager(owns_process=True, status_flash=payload)
            self.assertEqual(web.hub_flash_state(live), "unknown", payload)
            attached = FakeHubManager(owns_process=False, status_flash=payload)
            self.assertEqual(web.hub_flash_state(attached), "idle", payload)
            dead = FakeHubManager(owns_process=True, process_alive=False, status_flash=payload)
            self.assertEqual(web.hub_flash_state(dead), "idle", payload)
        idle = FakeHubManager(owns_process=True, status_flash={"flash": {"active": False}})
        self.assertEqual(web.hub_flash_state(idle), "idle")

    def test_close_keeps_owned_hub_with_malformed_status(self):
        backend, manager = self.make_backend(owns_process=True, status_flash={"flash": {}})
        with patch("sys.stderr"):
            backend.close()
        self.assertEqual(manager.stopped_while_owned, 0)

    def test_close_stops_idle_owned_hub(self):
        backend, manager = self.make_backend(owns_process=True)
        backend.close()
        self.assertEqual(manager.stopped_while_owned, 1)

    def test_export_logs_is_a_download(self):
        backend, _ = self.make_backend()
        try:
            backend.start_in_thread()
            status, headers, _ = http_get(backend.port, "/api/export_logs")
            self.assertEqual(status, 200)
            self.assertEqual(headers["Content-Type"], "application/octet-stream")
            self.assertIn("attachment", headers["Content-Disposition"])
        finally:
            backend.close()
        self.assertNotIn("window.open('/api/export_logs", HTML_PAGE)
        self.assertIn("link.download = 'serial_console.log'", HTML_PAGE)


class WebRequestGuardTest(unittest.TestCase):
    """CSRF and DNS-rebinding guards on the dashboard API."""

    setUp = WebBackendTest.setUp
    make_backend = WebBackendTest.make_backend

    def request(self, port, method, path, body=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
        try:
            conn.request(method, path, body=body, headers=headers or {})
            response = conn.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            conn.close()

    def test_host_allowed_rules(self):
        self.assertTrue(web.host_allowed("127.0.0.1:8081", "127.0.0.1", 8081))
        self.assertTrue(web.host_allowed("localhost:8081", "127.0.0.1", 8081))
        self.assertTrue(web.host_allowed("[::1]:8081", "127.0.0.1", 8081))
        self.assertFalse(web.host_allowed("evil.example:8081", "127.0.0.1", 8081))
        self.assertFalse(web.host_allowed("127.0.0.1:9999", "127.0.0.1", 8081))
        self.assertFalse(web.host_allowed("127.0.0.1", "127.0.0.1", 8081))
        self.assertTrue(web.host_allowed("192.168.1.5:8081", "0.0.0.0", 8081))
        self.assertFalse(web.host_allowed("rebind.example:8081", "0.0.0.0", 8081))
        self.assertTrue(web.host_allowed("192.168.1.5:8081", "192.168.1.5", 8081))
        self.assertFalse(web.host_allowed("10.0.0.1:8081", "192.168.1.5", 8081))

    def test_rejects_cross_site_and_rebinding_requests(self):
        backend, _ = self.make_backend()
        try:
            backend.start_in_thread()
            port = backend.port
            host = f"127.0.0.1:{port}"
            status, _, _ = self.request(port, "POST", "/api/connections", b"{}",
                                        {"Content-Type": "text/plain", "Host": host})
            self.assertEqual(status, 415)
            status, _, _ = self.request(port, "POST", "/api/connections", b"{}",
                                        {"Content-Type": "application/json", "Host": host,
                                         "Origin": "https://evil.example"})
            self.assertEqual(status, 403)
            status, _, _ = self.request(port, "GET", "/api/connections",
                                        headers={"Host": f"evil.example:{port}"})
            self.assertEqual(status, 403)
            status, _, _ = self.request(port, "POST", "/api/connections", b"{bad",
                                        {"Content-Type": "application/json", "Host": host})
            self.assertEqual(status, 400)
            try:
                status, _, _ = self.request(port, "POST", "/api/button",
                                            b"x" * (web.MAX_POST_BODY + 1),
                                            {"Content-Type": "application/json", "Host": host})
            except ConnectionError:
                # Refused before the body was read; the unread upload turns the close into
                # a reset (macOS) or an abort (Windows) that can race the 413.
                status = 413
            self.assertEqual(status, 413)
            status, _, body = self.request(port, "POST", "/api/connections", b"{}",
                                           {"Content-Type": "application/json; charset=utf-8",
                                            "Host": host, "Origin": f"http://{host}"})
            self.assertEqual(status, 200)
            self.assertTrue(json.loads(body)["ok"])
        finally:
            backend.close()

    def test_stream_has_no_wildcard_cors(self):
        backend, _ = self.make_backend()
        try:
            backend.start_in_thread()
            conn = http.client.HTTPConnection("127.0.0.1", backend.port, timeout=3)
            conn.request("GET", "/api/stream")
            response = conn.getresponse()
            self.assertEqual(response.status, 200)
            self.assertIsNone(response.getheader("Access-Control-Allow-Origin"))
            conn.close()
        finally:
            backend.close()

    def test_page_posts_send_json_content_type(self):
        posts = re.findall(r"fetch\('[^']+',\s*\{(.*?)\}\);", HTML_PAGE, re.S)
        self.assertTrue(posts)
        for options in posts:
            if "POST" in options:
                self.assertIn("application/json", options)


class DashboardLayoutTest(unittest.TestCase):
    def test_dock_starts_hidden_and_rail_has_mcp_page(self):
        self.assertIn('id="sidebarPanel" class="collapsed', HTML_PAGE)
        self.assertIn("#sidebarPanel.collapsed { display: none; }", HTML_PAGE)
        for rail in ("console", "control", "flash", "mcp"):
            self.assertIn(f'data-rail="{rail}"', HTML_PAGE)
        self.assertIn('id="mcpPage"', HTML_PAGE)

    def test_console_can_shrink_and_terminal_copy_shortcuts(self):
        # Flex ancestors must be allowed to shrink below xterm's pixel width,
        # otherwise mouse coordinates drift after the window gets smaller.
        self.assertIn("#terminalHost { overflow: hidden; position: relative; min-width: 0;", HTML_PAGE)
        self.assertNotIn("#consolePanel { flex: none;", HTML_PAGE)
        self.assertIn("attachCustomKeyEventHandler", HTML_PAGE)
        self.assertIn("term.onSelectionChange", HTML_PAGE)

    def test_mcp_endpoint(self):
        backend, _ = WebBackendTest.make_backend(self)
        try:
            backend.start_in_thread()
            status, _, body = http_get(backend.port, "/api/mcp")
            self.assertEqual(status, 200)
            data = json.loads(body)
            self.assertIn("install", data)
            self.assertIn("serial_flash_start", data["tools"]["hardware"])
            self.assertIsInstance(data["servers"], list)
        finally:
            backend.close()

    setUp = WebBackendTest.setUp


class WaitForBackendTest(unittest.TestCase):
    def serve(self, payload):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                body = json.dumps(payload).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server.server_address[1]

    def test_accepts_own_instance(self):
        port = self.serve({"instance": "abc"})
        app.wait_for_backend(port, "abc", timeout=2)

    def test_rejects_unrelated_server(self):
        port = self.serve({"instance": "someone-else"})
        with self.assertRaisesRegex(RuntimeError, "another server"):
            app.wait_for_backend(port, "abc", timeout=2)

    def test_times_out_without_server(self):
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()
        with self.assertRaises(TimeoutError):
            app.wait_for_backend(port, "abc", timeout=0.3)


class FakeEvent:
    def __init__(self):
        self.handlers = []

    def __iadd__(self, handler):
        self.handlers.append(handler)
        return self


class FakeWindow:
    def __init__(self):
        self.events = SimpleNamespace(closing=FakeEvent(), closed=FakeEvent())
        self.destroyed = threading.Event()
        self.scripts = []

    def destroy(self):
        self.destroyed.set()
        for handler in self.events.closed.handlers:
            handler()

    def evaluate_js(self, script):
        self.scripts.append(script)


class FakeBackend:
    def __init__(self, *args, flashing=None, unknown=None):
        self.args = args
        self.flashing = list(flashing or [])
        self.unknown = list(unknown or [])
        self.port = 43210
        self.url = "http://127.0.0.1:43210/"
        self.instance_token = "tok"
        self.started = False
        self.closed = 0

    def start_in_thread(self):
        self.started = True

    def flash_check(self):
        return FlashCheck(list(self.flashing), list(self.unknown))

    def close(self):
        self.closed += 1


class AppControllerTest(unittest.TestCase):
    def test_close_refused_during_flash(self):
        backend = FakeBackend(flashing=["/dev/ttyFAKE0"])
        controller = app.AppController(backend)
        window = FakeWindow()
        controller.attach(window)
        with patch("sys.stderr"):
            self.assertFalse(controller.on_closing())
        deadline = time.monotonic() + 2
        while not window.scripts and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertIn("/dev/ttyFAKE0", window.scripts[0])
        backend.flashing = []
        self.assertTrue(controller.on_closing())

    def test_unknown_hub_state_refuses_close_until_hub_answers(self):
        backend = FakeBackend(unknown=["/dev/ttyFAKE0"])
        controller = app.AppController(backend)
        with patch("sys.stderr") as err:
            self.assertFalse(controller.on_closing())
        text = "".join(c.args[0] for c in err.write.call_args_list)
        self.assertIn("Cannot confirm", text)
        self.assertIn("/dev/ttyFAKE0", text)
        backend.unknown = []
        self.assertTrue(controller.on_closing())

    def test_flash_check_exception_fails_closed(self):
        backend = FakeBackend()
        backend.flash_check = MagicMock(side_effect=RuntimeError("boom"))
        controller = app.AppController(backend)
        with patch("sys.stderr"):
            self.assertFalse(controller.on_closing())
        self.assertIn("boom", controller.close_blocker())
        backend.flash_check = FakeBackend().flash_check
        self.assertTrue(controller.on_closing())

    def test_signal_shutdown_retries_while_state_unknown(self):
        backend = FakeBackend(unknown=["/dev/ttyFAKE0"])
        controller = app.AppController(backend, flash_poll_interval=0.02)
        window = FakeWindow()
        controller.attach(window)
        with patch("sys.stderr"):
            controller.request_shutdown()
            self.assertFalse(window.destroyed.wait(0.15))
            backend.unknown = []
            self.assertTrue(window.destroyed.wait(2))

    def test_signal_shutdown_waits_for_flash_then_closes_once(self):
        backend = FakeBackend(flashing=["/dev/ttyFAKE0"])
        controller = app.AppController(backend, flash_poll_interval=0.02)
        window = FakeWindow()
        controller.attach(window)
        with patch("sys.stderr"):
            controller.request_shutdown()
            controller.request_shutdown()
            self.assertFalse(window.destroyed.wait(0.15))
            backend.flashing = []
            self.assertTrue(window.destroyed.wait(2))
        self.assertTrue(controller.closed.is_set())

    def test_signal_handlers_are_installed_and_restored(self):
        controller = MagicMock()
        import signal
        before = signal.getsignal(signal.SIGTERM)
        previous = app.install_signal_handlers(controller)
        try:
            signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)
            controller.request_shutdown.assert_called_once()
        finally:
            app.restore_signal_handlers(previous)
        self.assertIs(signal.getsignal(signal.SIGTERM), before)


class RunAppTest(unittest.TestCase):
    def args(self, **overrides):
        args = app.build_parser().parse_args([])
        for key, value in overrides.items():
            setattr(args, key, value)
        return args

    def fake_webview(self):
        webview = MagicMock()
        webview.create_window.return_value = FakeWindow()
        return webview

    def test_runs_window_against_own_ephemeral_backend_and_closes(self):
        created = []

        def factory(*args):
            created.append(FakeBackend(*args))
            return created[-1]

        webview = self.fake_webview()
        with patch.object(app, "wait_for_backend") as wait, patch("builtins.print"):
            code = app.run_app(self.args(port="/dev/ttyFAKE0"), factory, webview)
        self.assertEqual(code, 0)
        backend = created[0]
        self.assertEqual(backend.args[:3], ("127.0.0.1", 0, "/dev/ttyFAKE0"))
        wait.assert_called_once_with(43210, "tok")
        self.assertEqual(webview.create_window.call_args.args[1], backend.url)
        self.assertTrue(webview.create_window.call_args.kwargs["text_select"])
        webview.start.assert_called_once()
        self.assertEqual(backend.closed, 1)
        webview.settings.__setitem__.assert_called_with("ALLOW_DOWNLOADS", True)

    def test_hub_startup_error_is_reported(self):
        def factory(*args):
            raise HubStartupError("hub refused")

        with patch("sys.stderr") as err:
            self.assertEqual(app.run_app(self.args(), factory, self.fake_webview()), 2)
        self.assertIn("hub refused", "".join(c.args[0] for c in err.write.call_args_list))

    def test_readiness_failure_closes_backend_without_window(self):
        backend = FakeBackend()
        webview = self.fake_webview()
        with patch.object(app, "wait_for_backend", side_effect=TimeoutError("slow")), \
                patch("sys.stderr"):
            self.assertEqual(app.run_app(self.args(), lambda *a: backend, webview), 1)
        webview.create_window.assert_not_called()
        self.assertEqual(backend.closed, 1)

    def test_gui_exception_still_closes_backend(self):
        backend = FakeBackend()
        webview = self.fake_webview()
        webview.start.side_effect = RuntimeError("no display")
        with patch.object(app, "wait_for_backend"), patch("sys.stderr"), patch("builtins.print"):
            self.assertEqual(app.run_app(self.args(), lambda *a: backend, webview), 1)
        self.assertEqual(backend.closed, 1)

    def test_missing_runtime_is_actionable_and_starts_nothing(self):
        factory = MagicMock()
        with patch("sys.stderr") as err:
            code = app.run_app(self.args(), factory, runtime_check=lambda: "pywebview missing")
        self.assertEqual(code, 3)
        factory.assert_not_called()
        self.assertIn("pywebview missing", "".join(c.args[0] for c in err.write.call_args_list))

    def test_runtime_check_names_install_command(self):
        with patch("importlib.util.find_spec", return_value=None):
            error = app.check_webview_runtime()
        self.assertIn("serial-deck[app]", error)

    @unittest.skipUnless(sys.platform.startswith("linux"), "XDG desktop entries are Linux-only")
    def test_desktop_entry_is_per_user(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = app.install_desktop_entry(tmp)
            self.assertEqual(target, Path(tmp) / "applications" / "serial-deck-app.desktop")
            text = target.read_text()
        self.assertIn(f'Exec="{app.LAUNCHER}"', text)
        self.assertIn("Terminal=false", text)
        self.assertTrue(os.access(app.LAUNCHER, os.X_OK))
        if app.LAUNCHER.name.startswith("python"):
            self.assertIn("-m serial_deck.app", text)


class HubOwnershipIntegrationTest(unittest.TestCase):
    """Real idle Python hubs on private temp sockets; no UART is claimed."""

    def setUp(self):
        discovery = patch("serial_deck.hub_client.find_existing_hub", return_value=None)
        discovery.start()
        self.addCleanup(discovery.stop)

    def factory(self, uart_port, baud, socket_path):
        return HubProcessManager(uart_port, baud, socket_path, hub_script=HUB_SCRIPT)

    def socket_path(self):
        root = tempfile.mkdtemp(prefix="sd-app-", dir=None if os.name == "nt" else "/tmp")
        self.addCleanup(shutil.rmtree, root, True)
        return os.path.join(root, "hub.sock")

    def test_backend_detaches_from_shared_daemon_it_started(self):
        path = self.socket_path()
        backend = WebBackend("127.0.0.1", 0, "", 115200, path, hub_manager_factory=self.factory)
        probe = HubProcessManager(socket_path=path)
        try:
            self.assertTrue(backend.hub_manager.owns_process)
            self.assertTrue(probe.socket_ready())
            self.assertFalse(backend.flash_check().blocked)
        finally:
            backend.close()
        self.assertTrue(probe.socket_ready())
        backend.hub_manager.shutdown()
        self.assertFalse(probe.socket_ready())

    def test_owned_hub_that_stops_answering_is_left_running(self):
        path = self.socket_path()
        backend = WebBackend("127.0.0.1", 0, "", 115200, path, hub_manager_factory=self.factory)
        process = backend.hub_manager.process

        def stop_leftover_hub():
            if process.poll() is None:
                # The hub removes its endpoints on SIGINT; Windows can only terminate.
                if os.name == "nt":
                    process.terminate()
                else:
                    process.send_signal(signal.SIGINT)
                process.wait(timeout=5)
            if process.stdout is not None:
                process.stdout.close()

        self.addCleanup(stop_leftover_hub)
        # Simulate a status outage while the owned hub process is still alive.
        with patch.object(HubProcessManager, "request_control", side_effect=OSError("outage")):
            self.assertEqual(backend.flash_check().unknown, [path])
            with patch("sys.stderr"):
                backend.close()
        self.assertIsNone(process.poll())
        self.assertTrue(HubProcessManager(socket_path=path).socket_ready())

    def test_backend_leaves_a_preexisting_hub_running(self):
        path = self.socket_path()
        existing = self.factory("", 115200, path)
        self.assertTrue(existing.ensure_started())
        self.addCleanup(existing.shutdown)
        backend = WebBackend("127.0.0.1", 0, "", 115200, path, hub_manager_factory=self.factory)
        try:
            self.assertFalse(backend.hub_manager.owns_process)
        finally:
            backend.close()
        self.assertTrue(existing.socket_ready())
        self.assertIsNone(existing.process.poll())


if __name__ == "__main__":
    unittest.main()
