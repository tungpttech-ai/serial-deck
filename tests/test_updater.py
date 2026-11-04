"""Stable-release selection, verified staging, idle guards, and native handoff."""
import hashlib
import http.client
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from serial_deck import updater as up
from serial_deck.autoconnect import RuleWatcher, Settings, SettingsError, DEFAULTS
from serial_deck.deckconfig import JsonFile

REAL_INSTALL_KIND = up.install_kind


def release(kind="pip", version="9.1.0", content=b"verified update"):
    name = up.asset_name(kind, version)
    return {"tag_name": "v" + version, "prerelease": False, "draft": False, "assets": [{
        "name": name, "size": len(content), "digest": "sha256:" + hashlib.sha256(content).hexdigest(),
        "browser_download_url": f"https://github.com/{up.REPO}/releases/download/v{version}/{name}"}]}


class UpdaterTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.settings = Settings(JsonFile("settings.json", DEFAULTS, self.root))
        self.settings.update(auto_update=True)
        self.restart, self.prepare = MagicMock(), MagicMock()
        self.manager = up.Updater(self.settings, lambda: None, self.prepare, self.restart)
        self.manager.store = JsonFile("update-state.json", {}, self.root)
        self.manager.root = self.root / "downloads"
        self.kind = patch.object(up, "install_kind", return_value="pip")
        self.kind.start()
        self.addCleanup(self.kind.stop)
        self.url = patch.object(up, "read_url", return_value=json.dumps(release()).encode())
        self.read = self.url.start()
        self.addCleanup(self.url.stop)

    def test_stable_version_and_platform_assets(self):
        self.assertGreater(up.version_tuple("v0.10.0"), up.version_tuple("0.9.9"))
        for value in ("v1.2.3-beta", "main", "1.2", "9.0.0;command", None):
            with self.assertRaises(ValueError):
                up.version_tuple(value)
        self.assertTrue(up.asset_name("windows", "1.2.3").endswith("-Setup.exe"))
        self.assertTrue(up.asset_name("deb", "1.2.3").endswith("_amd64.deb"))
        self.assertTrue(up.asset_name("appimage", "1.2.3").endswith(".AppImage"))
        for arch, wanted in (("arm64", "arm64.dmg"), ("x86_64", "x86_64.dmg")):
            with patch.object(up.platform, "machine", return_value=arch):
                self.assertTrue(up.asset_name("macos", "1.2.3").endswith(wanted))

    def test_refuses_external_sources_prereleases_and_missing_checksums(self):
        good = release()
        bad = json.loads(json.dumps(good))
        bad["assets"][0]["browser_download_url"] = "https://example.org/evil.whl"
        for item in (bad, {**good, "prerelease": True}, {**good, "draft": True}, {**good, "assets": [None]}, []):
            with self.assertRaises(ValueError):
                up.release_asset(item, "pip")
        good["assets"][0].pop("digest")
        with self.assertRaises(ValueError):
            up.release_asset(good, "pip")

    def test_checksum_manifest_fallback_matches_exact_filename(self):
        data = release()
        checksum = data["assets"][0].pop("digest")[7:]
        url = f"https://github.com/{up.REPO}/releases/download/v9.1.0/SHA256SUMS.txt"
        data["assets"].append({"name": "SHA256SUMS.txt", "browser_download_url": url})
        with patch.object(up, "read_url", return_value=f"{checksum}  {data['assets'][0]['name']}\n".encode()):
            self.assertEqual(up.release_asset(data, "pip")["sha256"], checksum)

    def test_download_is_bounded_verified_and_reused(self):
        payload = b"verified update"
        asset = up.release_asset(release(content=payload), "pip")
        with patch.object(up.urllib.request, "urlopen", return_value=io.BytesIO(payload)) as request:
            target = up.stage_download(asset, self.root)
            self.assertEqual(target.read_bytes(), payload)
            self.assertEqual(up.stage_download(asset, self.root), target)
            self.assertEqual(request.call_count, 1)
        target.unlink()
        for payload in (b"wrong", b"x" * (asset["size"] + 1)):
            with patch.object(up.urllib.request, "urlopen", return_value=io.BytesIO(payload)):
                with self.assertRaises(ValueError):
                    up.stage_download(asset, self.root)
            self.assertFalse(target.exists())
            self.assertFalse(target.with_suffix(".whl.part").exists())

    def test_disabled_checks_only_and_never_stages(self):
        self.settings.update(auto_update=False)
        with patch.object(up, "stage_download") as download:
            self.manager.check(force=True)
        self.assertEqual(self.manager.status()["state"], "available")
        download.assert_not_called()
        self.prepare.assert_not_called()

    def test_checkout_is_protected_when_egg_info_hides_editable_metadata(self):
        project = self.root / "checkout"
        project.mkdir()
        (project / "pyproject.toml").write_text("[project]\nname='serial-deck'\n")
        with patch.object(up, "__file__", str(project / "serial_deck" / "updater.py")), \
                patch.object(up.runtime, "frozen", return_value=False), \
                patch.object(up.importlib.metadata, "distribution") as distribution:
            self.assertEqual(REAL_INSTALL_KIND(), "editable")
        distribution.assert_not_called()

    def test_editable_sources_are_protected(self):
        with patch.object(up, "install_kind", return_value="editable"), patch.object(up, "stage_download") as download:
            self.manager.check(force=True)
        self.assertEqual(self.manager.status()["state"], "blocked")
        download.assert_not_called()
        self.restart.assert_not_called()

    def test_current_and_network_error_do_not_touch_installation(self):
        with patch.object(up, "read_url", return_value=json.dumps(release(version=up.__version__)).encode()):
            self.manager.check(force=True)
        self.assertEqual(self.manager.status()["state"], "current")
        with patch.object(up, "read_url", side_effect=OSError("offline")):
            self.manager.check(force=True)
        self.assertIn("offline", self.manager.status()["message"])
        self.prepare.assert_not_called()

    def test_active_device_defers_without_downloading_or_shutdown(self):
        self.manager.blocker = lambda: "device connected"
        with patch.object(up, "stage_download") as download:
            self.manager.check(force=True)
        self.assertEqual(self.manager.status()["state"], "deferred")
        download.assert_not_called()
        self.prepare.assert_not_called()

    def test_verified_idle_update_hands_off_before_restart(self):
        asset = self.root / "update.whl"
        asset.write_bytes(b"verified update")
        events = []
        self.manager.prepare = lambda: events.append("prepare")
        self.manager.restart = lambda: events.append("restart")
        with patch.object(up, "stage_download", return_value=asset), patch.object(up, "launch_installer", side_effect=lambda *a: events.append("helper") or 4321), patch.object(up.ipc, "pid_alive", side_effect=lambda pid: pid == 4321):
            self.manager.check(force=True)
            self.assertEqual(self.manager.status()["state"], "restarting")
        self.assertEqual(events, ["prepare", "helper", "restart"])

    def test_device_attaching_during_download_defers_installation(self):
        self.manager.blocker = MagicMock(side_effect=[None, "device connected"])
        with patch.object(up, "stage_download", return_value=self.root / "unused"):
            self.manager.check(force=True)
        self.assertEqual(self.manager.status()["state"], "deferred")
        self.prepare.assert_not_called()

    def test_shutdown_refusal_keeps_app_running(self):
        asset = self.root / "update.whl"
        asset.write_bytes(b"verified update")
        self.prepare.side_effect = RuntimeError("hub became busy")
        with patch.object(up, "stage_download", return_value=asset), patch.object(up, "launch_installer") as launch:
            self.manager.check(force=True)
        self.assertEqual(self.manager.status()["state"], "error")
        launch.assert_not_called()
        self.restart.assert_not_called()

    def test_failed_installer_launch_restores_app_state(self):
        asset = self.root / "update.whl"
        asset.write_bytes(b"verified update")
        self.manager.abort = MagicMock()
        with patch.object(up, "stage_download", return_value=asset), \
                patch.object(up, "launch_installer", side_effect=OSError("no helper")):
            self.manager.check(force=True)
        self.assertEqual(self.manager.status()["state"], "error")
        self.manager.abort.assert_called_once_with()
        self.restart.assert_not_called()

    def test_refused_hub_shutdown_restarts_auto_connect(self):
        from serial_deck.web import WebBackend
        deck = WebBackend.__new__(WebBackend)
        deck.hub_manager = MagicMock()
        deck.hub_manager.shutdown.side_effect = RuntimeError("hub became busy")
        deck.connections = SimpleNamespace(watcher=MagicMock(spec=RuleWatcher), settings=self.settings,
                                           start_rules=MagicMock(), lock=threading.Lock())
        old = deck.connections.watcher
        self.settings.update(rules=[{"usb_vid_pid": "1a86:55d2", "baud": 2000000, "mode": "control"}])
        with self.assertRaises(RuntimeError):
            deck.prepare_update()
        old.close.assert_called_once_with()
        self.assertIsNone(deck.connections.watcher)
        deck.connections.start_rules.assert_called_once_with()

    def test_late_update_abort_cannot_restart_watcher_after_close(self):
        from serial_deck.web import ConnectionManager
        manager = ConnectionManager.__new__(ConnectionManager)
        manager.lock, manager.watcher, manager.closing = threading.Lock(), None, False
        manager._bridges, manager._order = {}, []
        manager.close_all()
        with patch("serial_deck.web.RuleWatcher") as build:
            manager.start_rules()
        build.assert_not_called()
        self.assertIsNone(manager.watcher)

        result = self.root / "install-result.json"
        result.write_text(json.dumps({"state": "updated", "message": "installed"}), encoding="utf-8-sig")
        self.manager._set(state="restarting", helper_pid=4321, result=str(result))
        with patch.object(up.ipc, "pid_alive", return_value=False):
            self.assertEqual(self.manager.status()["state"], "updated")

    def test_setting_round_trip_keeps_cache_and_rejects_non_boolean(self):
        self.settings.update(log_cache={"ram_mib": 128})
        self.settings.update(auto_update=False)
        self.assertEqual(self.settings.get()["log_cache"]["ram_mib"], 128)
        for value in ("true", 1, None, {}):
            with self.assertRaises(SettingsError):
                self.settings.update(auto_update=value)

    def test_helpers_for_all_platforms_are_generated_without_installing(self):
        artifact = self.root / "update.dmg"
        artifact.write_bytes(b"verified update")
        app = self.root / "Serial Deck.app" / "Contents" / "MacOS" / "serial-deck"
        app.parent.mkdir(parents=True)
        for kind in ("macos", "windows", "deb", "pip"):
            with self.subTest(kind=kind), patch.object(up.subprocess, "Popen", return_value=SimpleNamespace(pid=4321)) as launch, patch.object(up.subprocess, "run", return_value=SimpleNamespace(stdout=b"4321\n")) as bootstrap, patch.object(up.runtime, "frozen", return_value=True), patch.object(up.sys, "executable", str(app)), patch.object(up.shutil, "which", return_value="/usr/bin/pkexec"), patch.object(up.subprocess, "CREATE_NO_WINDOW", 0x08000000, create=True), patch.object(up.subprocess, "DETACHED_PROCESS", 8, create=True):
                self.assertEqual(up.launch_installer(kind, artifact, self.root, "9.1.0"), 4321)
                if os.name == "nt" and kind in ("windows", "pip"):
                    command = bootstrap.call_args.args[0]
                    self.assertIn("--detach", command)
                    command = command[command.index("--") + 1:]
                else:
                    command = launch.call_args.args[0]
                if kind == "windows" or (kind == "pip" and sys.platform == "win32"):
                    self.assertEqual(Path(command[0]).name, "powershell.exe")
                    plan = json.loads((self.root / "install-plan.json").read_text())
                    if kind == "windows":
                        self.assertIn("/NORESTART", plan["arguments"])
                else:
                    script = (self.root / "install.sh").read_text()
                    self.assertIn("kill -0", script)
                    if kind == "macos":
                        self.assertIn("codesign --verify", script)
                        self.assertIn("previous-", script)
                    if kind == "deb":
                        self.assertIn("sha256sum --check --status", script)
                        self.assertIn("/tmp/serial-deck-update.XXXXXX", script)

    def test_http_settings_status_and_check_require_dashboard_token(self):
        from serial_deck.web import WebBackend
        from tests.test_app import FakeHubManager
        self.manager.start = MagicMock()
        backend = WebBackend(port_web=0, hub_manager_factory=FakeHubManager)
        backend.connections.settings = self.settings
        backend.updater = self.manager
        backend.handler.updater = self.manager
        backend.start_in_thread()
        try:
            def request(method, path, data=None, token=None):
                conn = http.client.HTTPConnection("127.0.0.1", backend.port, timeout=3)
                try:
                    headers = {"Content-Type": "application/json"}
                    if token:
                        headers["X-Deck-Action"] = token
                    conn.request(method, path, json.dumps(data) if data is not None else None, headers)
                    response = conn.getresponse()
                    return response.status, dict(response.getheaders()), response.read()
                finally:
                    conn.close()
            status, _, body = request("GET", "/api/updates")
            self.assertEqual(status, 200)
            self.assertTrue(json.loads(body)["enabled"])
            self.assertEqual(request("POST", "/api/updates/check", {})[0], 403)
            self.assertEqual(request("POST", "/api/updates/check", {}, backend.handler.action_token)[0], 200)
            self.manager.start.assert_called_with(force=True)
            self.assertEqual(request("POST", "/api/settings", {"auto_update": False}, backend.handler.action_token)[0], 200)
            self.assertFalse(self.settings.get()["auto_update"])
            self.assertEqual(request("POST", "/api/settings", {"auto_update": "yes"}, backend.handler.action_token)[0], 400)
            status, headers, _ = request("GET", "/api/updates/releases")
            self.assertEqual(status, 302)
            self.assertEqual(headers["Location"], up.RELEASE_URL)
        finally:
            backend.close()

    def test_backend_checks_other_hub_clients_and_flash_before_update(self):
        from serial_deck.web import WebBackend
        from tests.test_app import FakeHubManager
        backend = WebBackend(port_web=0, hub_manager_factory=FakeHubManager)
        try:
            for status, blocked in (({"client_count": 0, "flash": {"active": False}}, False),
                                    ({"client_count": 1, "flash": {"active": False}}, True),
                                    ({"client_count": 0, "flash": {"active": True}}, True), ({}, True)):
                with patch.object(backend.hub_manager, "request_control", return_value=status):
                    self.assertEqual(backend.update_blocker() is not None, blocked)
            with patch.object(backend.hub_manager, "request_control", side_effect=OSError("hub offline")):
                self.assertIsNotNone(backend.update_blocker())
        finally:
            backend.close()

    @unittest.skipIf(os.name == "nt", "POSIX helper integration")
    def test_appimage_helper_waits_then_replaces_and_relaunches(self):
        target = self.root / "Serial Deck.AppImage"
        target.write_text("old")
        marker = self.root / "relaunched"
        artifact = self.root / "download.AppImage"
        artifact.write_text("#!/bin/sh\nprintf done > " + str(marker) + "\n")
        child = subprocess.Popen(["sleep", "0.3"])
        try:
            with patch.dict(os.environ, {"APPIMAGE": str(target)}), patch.object(up.os, "getpid", return_value=child.pid), patch.object(up.runtime, "appimage_extracted", return_value=False):
                up.launch_installer("appimage", artifact, self.root, "9.1.0")
            self.assertEqual(target.read_text(), "old")
            child.wait(timeout=3)
            deadline = time.monotonic() + 5
            while not marker.exists() and time.monotonic() < deadline:
                time.sleep(0.05)
            self.assertTrue(marker.exists())
            up._install_helper.wait(timeout=3)
            self.assertEqual(target.read_text(), artifact.read_text())
            self.assertEqual(json.loads((self.root / "install-result.json").read_text())["state"], "updated")
        finally:
            child.wait(timeout=3)


if __name__ == "__main__":
    unittest.main()
