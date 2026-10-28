import re
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from serial_deck.web import (
    HTML_PAGE,
    DeckWebBridge,
    auto_find_elf,
    parse_flash_progress,
    parse_log_level,
    parse_tx_payload,
    should_symbolize_log,
)


class DeckWebTest(unittest.TestCase):
    def test_log_level_parsing(self):
        self.assertEqual(parse_log_level("E (123) panic: failed"), "error")
        self.assertEqual(parse_log_level("W (123) wifi: retry"), "warning")
        self.assertEqual(parse_log_level("I (123) app: ready"), "info")
        self.assertEqual(parse_log_level("D (123) app: debug info"), "debug")
        self.assertEqual(parse_log_level("V (123) app: verbose trace"), "verbose")
        self.assertEqual(parse_log_level("plain raw output"), "plain")

    def test_web_exposes_raw_filter_enabled_by_default(self):
        self.assertIn('id="lvl-plain"', HTML_PAGE)
        self.assertIn('id="lvl-elf"', HTML_PAGE)
        self.assertIn("new Set(['E', 'W', 'I', 'D', 'elf', 'tx', 'plain'])", HTML_PAGE)
        self.assertIn("if (!enabledLevels.has(lvlKey)) return false;", HTML_PAGE)

    def test_tx_payload_parsing(self):
        self.assertEqual(parse_tx_payload("help", "ascii", "lf"), b"help\n")
        self.assertEqual(parse_tx_payload("AT", "ascii", "crlf"), b"AT\r\n")
        self.assertEqual(parse_tx_payload("50 03 0xff,0A", "hex"), b"\x50\x03\xff\x0a")
        with self.assertRaises(ValueError):
            parse_tx_payload("5", "hex")
        with self.assertRaises(ValueError):
            parse_tx_payload("zz", "hex")

    def test_send_raw_writes_bytes_and_echoes_tx_log(self):
        bridge = DeckWebBridge()
        bridge.transport = MagicMock()
        bridge.connected = True
        self.assertEqual(bridge.send_raw("ping", "ascii", "lf"), 5)
        bridge.transport.write.assert_called_once_with(b"ping\n")
        self.assertEqual(bridge.history_logs[-1]["level"], "tx")
        self.assertEqual(bridge.history_logs[-1]["text"], "TX> ping\\n")

    def test_send_raw_requires_connection(self):
        with self.assertRaises(RuntimeError):
            DeckWebBridge().send_raw("ping")

    def test_linux_mode_streams_raw_bytes_and_skips_control_frames(self):
        bridge = DeckWebBridge()
        bridge.set_console_mode("linux")
        bridge.transport = MagicMock()
        bridge.connected = True
        with self.assertRaises(RuntimeError):
            bridge.send_button("ENTER")
        bridge.transport.write.assert_not_called()

        events = []
        bridge.broadcast = events.append
        bridge._broadcast_raw(b"\x1b[32mroot@board\x1b[0m:~# ")
        self.assertEqual(events[-1]["type"], "raw")
        self.assertEqual(json.loads(json.dumps(events[-1]))["data"],
                         "G1szMm1yb290QGJvYXJkG1swbTp+IyA=")
        self.assertEqual(bytes(bridge.raw_history), b"\x1b[32mroot@board\x1b[0m:~# ")

        bridge.send_term_input(b"\x03")
        bridge.transport.write.assert_called_once_with(b"\x03")

    def test_unknown_console_mode_is_rejected(self):
        with self.assertRaises(ValueError):
            DeckWebBridge().set_console_mode("windows")

    def test_initial_console_mode(self):
        self.assertEqual(DeckWebBridge().console_mode, "linux")
        self.assertEqual(DeckWebBridge(default_mode="control").console_mode, "control")
        self.assertEqual(DeckWebBridge(default_mode="windows").console_mode, "linux")

    def test_flash_progress_parsing(self):
        pct, step = parse_flash_progress("Writing at 0x00010000... (45 %)")
        self.assertEqual(pct, 45)
        self.assertEqual(step, "Writing")

        pct, step = parse_flash_progress("\x1b[KWriting at 0x0034ed24 ... 66.8%\x1b[K")
        self.assertEqual(pct, 66.8)
        self.assertEqual(step, "Writing")

        pct, step = parse_flash_progress("Erasing flash (this may take a while)...")
        self.assertIsNone(pct)
        self.assertEqual(step, "Erasing")

        pct, step = parse_flash_progress("Hash of data verified.")
        self.assertEqual(step, "Hash of data verified")

    def test_symbolizer_only_runs_for_crash_logs(self):
        self.assertFalse(should_symbolize_log('{"tag":"ws_rx","payload":{"hex":"5003"}}'))
        self.assertTrue(should_symbolize_log("assert failed: Backtrace: 0x40001234"))

    def test_auto_find_elf(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            elf1 = tmp / "firmware.elf"
            elf1.touch()
            self.assertEqual(auto_find_elf(str(tmp)), str(elf1.resolve()))

            non_existent = tmp / "missing_dir"
            self.assertEqual(auto_find_elf(str(non_existent)), "")

    def test_bridge_status_and_telemetry(self):
        bridge = DeckWebBridge(default_port="/dev/ttyMock", default_baud=115200)
        status = bridge.get_status()
        self.assertFalse(status["connected"])
        self.assertEqual(status["port"], "/dev/ttyMock")
        self.assertEqual(status["baud"], 115200)
        self.assertEqual(status["fsm"], "UNKNOWN")

        # Simulate frame telemetry update
        bridge._update_telemetry(1, {"commands": ["input.button", "query"], "target": "demo-board", "baud": 115200})
        status = bridge.get_status()
        self.assertIn("demo-board", status["device"])

        bridge._update_telemetry(3, {"result": {"state": "VOICE_ACTIVE", "heap_free": 123456}})
        status = bridge.get_status()
        self.assertEqual(status["fsm"], "VOICE_ACTIVE")
        self.assertEqual(status["telemetry"].get("heap_free"), 123456)

    def test_bridge_flash_is_delegated_to_hub(self):
        hub = MagicMock()
        hub.endpoint = "hub:///tmp/serial-deck-test.sock"
        bridge = DeckWebBridge(default_port="/dev/ttyMock", hub_manager=hub)

        bridge.start_flash("build", 460800)

        hub.preview_flash.assert_called_once_with("build", 460800)
        hub.start_flash.assert_called_once_with("build", 460800)

    def test_hub_status_is_rebroadcast_to_web_clients(self):
        hub = MagicMock()
        bridge = DeckWebBridge(default_port="/dev/ttyMock", hub_manager=hub)
        client = bridge.register_client()

        bridge._handle_hub_status({
            "state": "flashing",
            "port": "/dev/ttyACM0",
            "flash": {"active": True, "id": 3, "progress": 55, "step": "Writing", "exit_code": None, "line": "Writing"},
        })

        events = [client.get_nowait() for _ in range(3)]
        self.assertEqual(events[0]["type"], "flash")
        self.assertEqual(events[0]["percent"], 55)
        self.assertEqual(events[1]["type"], "status")
        self.assertEqual(events[2]["type"], "log")
        self.assertIn("[hub flash] Writing", events[2]["text"])

        bridge._handle_hub_status({
            "state": "flashing",
            "port": "/dev/ttyACM0",
            "flash": {"active": True, "id": 3, "progress": 55, "step": "Writing", "exit_code": None, "line": "Writing"},
        })
        self.assertEqual(client.qsize(), 2)

    def test_hub_status_reports_lost_port_as_immediate_disconnect(self):
        # UartHub._handle_serial_lost force-drops a physically lost UART and
        # its status payload then carries port=None while a data client is
        # still attached (a normal `release` action refuses that). The
        # bridge must reflect the disconnect right away instead of waiting
        # for its own data socket to notice the closed connection.
        hub = MagicMock()
        bridge = DeckWebBridge(default_port="/dev/ttyACM0", hub_manager=hub)
        bridge.connected = True
        bridge.port = "/dev/ttyACM0"
        client = bridge.register_client()

        bridge._handle_hub_status({
            "state": "idle",
            "port": None,
            "flash": {"active": False, "id": 0, "progress": 0, "step": "Idle", "exit_code": None, "line": ""},
        })

        self.assertFalse(bridge.connected)
        hub.release_port.assert_called_once()
        events = [client.get_nowait() for _ in range(2)]
        self.assertEqual(events[0]["type"], "log")
        self.assertEqual(events[0]["level"], "error")
        self.assertIn("physical UART was lost", events[0]["text"])
        self.assertEqual(events[1]["type"], "status")
        self.assertFalse(events[1]["connected"])
        self.assertTrue(client.empty())

    def test_hub_status_with_no_port_is_a_noop_when_already_disconnected(self):
        hub = MagicMock()
        bridge = DeckWebBridge(default_port="/dev/ttyACM0", hub_manager=hub)
        client = bridge.register_client()

        bridge._handle_hub_status({
            "state": "idle",
            "port": None,
            "flash": {"active": False, "id": 0, "progress": 0, "step": "Idle", "exit_code": None, "line": ""},
        })

        hub.release_port.assert_not_called()
        self.assertEqual(client.qsize(), 2)  # flash + status broadcast, no extra [hub] log


if __name__ == "__main__":
    unittest.main()


class ConsoleUxTest(unittest.TestCase):
    """The console keeps every control it had; the redesign only moved and relabelled them."""

    def test_device_actions_menu_keeps_every_line_control(self):
        menu = HTML_PAGE.split('id="deviceActions"', 1)[1].split("</details>", 1)[0]
        for action in ("reset", "bootloader", "toggle_dtr", "toggle_rts"):
            self.assertIn(f"deviceAction('{action}')", menu)
        self.assertIn('id="dtrStatus"', menu)  # real line state shown next to its toggle
        self.assertIn('id="rtsStatus"', menu)
        self.assertIn("controlLine(action)", HTML_PAGE)  # same /api/lines call as before

    def test_filter_and_find_are_separate_and_regex_is_validated(self):
        self.assertIn('id="logSearchInput"', HTML_PAGE)  # filter: hides lines
        self.assertIn('id="findInput"', HTML_PAGE)  # find: highlights, hides nothing
        self.assertIn('id="tagMenu"', HTML_PAGE)  # searchable multi-select over observed tags
        self.assertIn('id="tagSearch"', HTML_PAGE)
        self.assertIn("new RegExp(text, 'i')", HTML_PAGE)
        self.assertIn('id="filterError"', HTML_PAGE)

    def test_raw_and_structured_modes_never_drop_unparsed_lines(self):
        self.assertIn("setViewMode('raw')", HTML_PAGE)
        self.assertIn("setViewMode('structured')", HTML_PAGE)
        # A line that is not "L (tick) tag: msg" is drawn whole, in both modes.
        self.assertIn("escapeHtml(entry.text || '')", HTML_PAGE)

    def test_pause_and_follow_are_distinct(self):
        self.assertIn("function togglePause()", HTML_PAGE)
        self.assertIn("function toggleAutoScroll()", HTML_PAGE)
        self.assertIn('id="jumpLatest"', HTML_PAGE)  # obvious way back after scrolling up

    def test_log_rendering_is_bounded(self):
        self.assertIn("const BUFFER_MAX = 20000;", HTML_PAGE)
        self.assertIn("const DOM_MAX = 3000;", HTML_PAGE)
        self.assertIn("requestAnimationFrame(flushRows)", HTML_PAGE)

    def test_collapsing_tx_keeps_the_draft(self):
        body = HTML_PAGE.split("function applyTxCollapsed()", 1)[1].split("function toggleTx()", 1)[0]
        self.assertNotIn(".value", body)  # only hides the row, never clears the input
        self.assertIn('id="txInput"', HTML_PAGE)
        self.assertIn("txHistoryKey(event)", HTML_PAGE)

    def test_connection_state_is_text_and_icon_not_color_alone(self):
        state = HTML_PAGE.split("function connState(conn)", 1)[1].split("function fmtBaud", 1)[0]
        for text in ("Connecting…", "Reconnecting…", "Disconnected", "'Connected"):
            self.assertIn(text, state)
        self.assertEqual(state.count("icon:"), 6)  # every state carries an icon next to its text
        self.assertEqual(HTML_PAGE.count('id="connLabel"'), 1)  # port and state are not repeated

    def test_status_bar_uses_measured_values_only(self):
        self.assertIn("c.rate = c.lines - c.lastLines", HTML_PAGE)  # a real counter
        self.assertNotIn("Drops", HTML_PAGE.split('id="statusBar"', 1)[1].split("</div>", 1)[0])


class ConsoleP1Test(unittest.TestCase):
    def test_fsm_timeline_only_reads_real_transitions(self):
        self.assertIn('id="fsmTimeline"', HTML_PAGE)
        self.assertIn("FSM_ARROW_RE", HTML_PAGE)
        self.assertIn("/fsm/i.test(p.tag)", HTML_PAGE)  # only lines from an fsm-tagged source
        self.assertIn("prev.to === t.from", HTML_PAGE)  # a duration only when the previous state matches

    def test_split_pane_is_resizable_and_remembered(self):
        self.assertIn('id="splitHandle"', HTML_PAGE)
        self.assertIn("serialdeck.splitWidth", HTML_PAGE)
        self.assertIn("ArrowLeft", HTML_PAGE.split("setupSplitResize", 1)[1])  # keyboard resize too

    def test_filter_presets_and_levels_persist_without_connection_state(self):
        self.assertIn("serialdeck.filterPresets", HTML_PAGE)
        self.assertIn("serialdeck.levels", HTML_PAGE)
        preset = HTML_PAGE.split("function currentPreset(name)", 1)[1].split("}", 1)[0]
        for key in ("filter", "regex", "tags", "levels"):
            self.assertIn(key, preset)
        self.assertNotIn("connected", preset)  # never a stale session

    def test_menus_survive_their_own_rerender(self):
        self.assertIn("e.composedPath()", HTML_PAGE)  # clicking a re-rendered tag row must not close the menu


class ConsoleP2Test(unittest.TestCase):
    def test_query_syntax_is_opt_in_and_validated(self):
        self.assertIn("function parseQuery(text)", HTML_PAGE)
        self.assertIn("if (!clauses.length) return null;", HTML_PAGE)  # no key:value term: plain text as before
        self.assertIn("level: expects error, warning", HTML_PAGE)  # a bad value is reported, not ignored
        self.assertIn("if (!isRegex) {", HTML_PAGE)  # regex mode never reinterprets the text

    def test_export_offers_shown_buffer_and_hub_history(self):
        menu = HTML_PAGE.split('id="exportMenu"', 1)[1].split("</details>", 1)[0]
        for call in ("exportBuffer('filtered')", "exportBuffer('all')", "exportLogs()"):
            self.assertIn(call, menu)
        self.assertIn("link.download = 'serial_console.log'", HTML_PAGE)  # hub history path unchanged

    def test_counters_come_from_bytes_this_window_handled(self):
        self.assertIn("conn.rxBytes += bytes.length", HTML_PAGE)
        self.assertIn("conn0().txBytes += out.bytes || 0", HTML_PAGE)
        self.assertNotIn("Drops", HTML_PAGE)  # no counter exists for it, so none is shown

    def test_telemetry_trends_use_numeric_fields_only(self):
        self.assertIn("typeof tel[k] !== 'number'", HTML_PAGE)
        self.assertIn('id="telSpark"', HTML_PAGE)
        self.assertIn("function tagColor(tag)", HTML_PAGE)


class SmallWindowLogLayoutTest(unittest.TestCase):
    """Shrinking the window made the log grow to every line instead of scrolling."""

    def test_log_panes_can_shrink_and_scroll(self):
        self.assertRegex(HTML_PAGE, r"#logsPanePrimary[^{]*\{\s*min-height: 0")

    def test_small_window_console_keeps_its_height_instead_of_growing_with_the_log(self):
        # `flex: 1 1 0%` in a column of indefinite height ignores `height` and
        # sizes the panel to its content (all log lines).
        match = re.search(r"#consolePanel \{([^}]*)\}", HTML_PAGE.split("(max-height: 620px)", 1)[1])
        self.assertIsNotNone(match)
        self.assertIn("flex: 0 0 auto", match.group(1))
        self.assertIn("height: max(520px, 80vh)", match.group(1))


def served_page(token="tok"):
    """The page as do_GET serves it: token and sandbox document substituted."""
    import json
    from serial_deck.web import SANDBOX_DOCUMENT
    return HTML_PAGE.replace("__DECK_ACTION_TOKEN__", token).replace(
        "__DECK_SANDBOX_DOC__", json.dumps(SANDBOX_DOCUMENT).replace("</", "<\\/"))


class PageScriptSyntaxTest(unittest.TestCase):
    """The page is one big Python string: a stray `\\n` there breaks the whole dashboard."""

    def test_the_inline_script_parses(self):
        import shutil
        import subprocess
        node = shutil.which("node")
        if node is None:
            self.skipTest("node is not installed")
        script = re.findall(r"<script>(.*?)</script>", served_page(), re.S)[-1]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "page.js"
            path.write_text(script, encoding="utf-8")
            result = subprocess.run([node, "--check", str(path)], capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr[-600:])


class SandboxTest(unittest.TestCase):
    """User JavaScript must never reach the dashboard's origin or its action token."""

    def test_the_iframe_is_sandboxed_without_same_origin(self):
        page = served_page()
        # Every place the page sets a sandbox attribute, whatever its value.
        values = re.findall(r"setAttribute\(\s*['\"]sandbox['\"]\s*,\s*['\"]([^'\"]*)['\"]", page)
        self.assertEqual(values, ["allow-scripts"])
        self.assertNotRegex(page, r"\.sandbox\s*[.=\[]")  # no other way of setting it
        self.assertNotRegex(page, r"sandbox=['\"][^'\"]*allow-(same-origin|top-navigation|popups|forms|modals)")

    def test_the_sandbox_document_is_self_contained_and_holds_no_secret(self):
        from serial_deck.web import SANDBOX_DOCUMENT
        self.assertNotIn("__DECK_ACTION_TOKEN__", SANDBOX_DOCUMENT)
        self.assertNotIn("DECK_ACTION_TOKEN", SANDBOX_DOCUMENT)
        self.assertNotIn("fetch(", SANDBOX_DOCUMENT)  # its only way out is postMessage
        self.assertNotIn("XMLHttpRequest", SANDBOX_DOCUMENT)

    def test_the_parent_only_listens_to_its_own_frame_and_a_fixed_set_of_verbs(self):
        page = served_page()
        self.assertIn("event.source !== jsFrame.contentWindow", page)
        for verb in ("'log'", "'error'", "'done'", "'stopped'", "'send'"):
            self.assertIn(f"msg.type === {verb}", page)

    def test_sandbox_markup_cannot_close_the_script_tag_early(self):
        page = served_page()
        self.assertNotIn("</script>", page.split("const SANDBOX_DOC = ", 1)[1].split("\n", 1)[0])

    def test_a_sandboxed_post_is_refused_as_cross_origin(self):
        # A sandboxed frame without allow-same-origin sends `Origin: null`.
        from serial_deck import web
        sent = []
        handler = type("H", (), {"headers": {"Content-Type": "application/json", "Origin": "null",
                                             "Host": "127.0.0.1:1"},
                                 "_reject": lambda self, status, error: sent.append(status)})()
        self.assertFalse(web.DeckHttpHandler._post_ok(handler))
        self.assertEqual(sent, [web.HTTPStatus.FORBIDDEN])

    def test_script_actions_that_make_a_device_act_need_the_page_token(self):
        from serial_deck import web
        handler = type("H", (), {"headers": {"X-Deck-Action": ""}, "action_token": "tok",
                                 "connections": None})()
        handler._action_token_ok = lambda: web.DeckHttpHandler._action_token_ok(handler)
        for name in web.SCRIPT_TOKEN_ACTIONS:
            _, status = web.DeckHttpHandler._script_request(handler, name, {"name": "x"})
            self.assertEqual(status, web.HTTPStatus.FORBIDDEN, name)
        self.assertNotIn("save", web.SCRIPT_WEB_ACTIONS)
        self.assertNotIn("write", web.SCRIPT_WEB_ACTIONS)
