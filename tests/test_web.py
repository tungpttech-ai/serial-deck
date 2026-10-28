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


JS_METRIC_CASES = r"""
const R = o => Object.assign({id: 'r', label: 'R', before: '', tag: '', unit: '', scale: 1, warn_below: null, warn_above: null, pin: false}, o);
const L = (text, level = 'info') => ({text, level, time: '12:00:00.000'});
const N = (text, n, level = 'plain') => Object.assign(L(text, level), {_n: n});
const results = {};
const line = 'I (1) sys_monitor: heap: internal_free=190464 internal_min=1';
results.heap = extractMetric(R({before: 'internal_free=', tag: 'sys_monitor'}), L(line));
results.heapKb = extractMetric(R({before: 'internal_free=', tag: 'sys_monitor', scale: 1 / 1024}), L(line));
results.otherTag = extractMetric(R({before: 'internal_free=', tag: 'wifi'}), L(line));
results.plain = extractMetric(R({before: 'temp='}), L('temp=25', 'plain'));
results.taggedOnPlain = extractMetric(R({before: 'temp=', tag: 'x'}), L('temp=25', 'plain'));
results.notNumbers = ['temp=abc', 'x=', 'x=1e999', 'x=-', 'x=+5', 'x=.5']
  .map(t => extractMetric(R({before: t.slice(0, t.indexOf('=') + 1)}), L(t, 'plain')));
results.shapes = ['x=-3', 'x=2.5', 'x=1e3', 'x=12345', 'x=12.', 'x=1e', 'x=007']
  .map(t => extractMetric(R({before: 'x='}), L(t, 'plain')));
results.firstValid = extractMetric(R({before: 'temp='}), L('temp=n/a temp=7', 'plain'));
results.txElf = ['tx', 'elf'].map(lv => extractMetric(R({before: 'temp='}), L('temp=5', lv)));
results.overflowAfterScale = extractMetric(R({before: 'x=', scale: 1e308}), L('x=1e10', 'plain'));
results.noText = extractMetric(R({before: 'x='}), {level: 'info'});
results.state = [metricState(R({warn_below: 64}), 64), metricState(R({warn_below: 64}), 63.9),
  metricState(R({warn_above: 90}), 90), metricState(R({warn_above: 90}), 90.1), metricState(R({}), 5)];

const buf = n => Array.from({length: n}, (_, i) => N('I (' + i + ') t: a=' + i + ' b=' + (i * 2), i + 1, 'info'));
conns.a = {logsBuffer: buf(5), metrics: {}};
conns.b = {logsBuffer: buf(3), metrics: {}};
const ra = R({id: 'ra', before: 'a='}), rb = R({id: 'rb', before: 'b='});
setMetricRules([ra]);
results.rescan = [conns.a.metrics.ra.samples.map(s => s.v), conns.b.metrics.ra.samples.map(s => s.v), conns.a.metrics.ra.last];
const kept = conns.a.metrics.ra;
setMetricRules([ra, rb]);
results.unchangedRuleNotRescanned = conns.a.metrics.ra === kept;
results.addedRule = conns.a.metrics.rb.samples.map(s => s.v);
setMetricRules([ra, Object.assign({}, rb, {before: 'a='})]);
results.changedRuleReplaced = conns.a.metrics.rb.samples.map(s => s.v);
setMetricRules([rb]);
results.afterRemoval = [Object.keys(conns.a.metrics), Object.keys(conns.b.metrics)];

setMetricRules([ra]);
const live = {logsBuffer: [], metrics: {}};
[1, 2, 3].forEach(i => noteMetrics(live, N('a=' + i, i)));
results.live = [live.metrics.ra.samples.map(s => [s.n, s.v, s.time]), live.metrics.ra.last];
const big = {logsBuffer: [], metrics: {}};
for (let i = 1; i <= 700; i++) noteMetrics(big, N('a=' + i, i));
results.cap = [big.metrics.ra.samples.length, big.metrics.ra.samples[0].v, big.metrics.ra.last];
const replay = {logsBuffer: [], metrics: {}};
const events = [1, 2, 3].map(i => N('a=' + i, i));
events.forEach(e => noteMetrics(replay, e));
resetMetrics(replay);
events.forEach(e => noteMetrics(replay, e));
results.replaySamples = replay.metrics.ra.samples.length;
const c1 = {logsBuffer: [], metrics: {}}, c2 = {logsBuffer: [], metrics: {}};
noteMetrics(c1, N('a=1', 1));
results.separate = [Object.keys(c1.metrics).length, Object.keys(c2.metrics).length];

const rules32 = Array.from({length: 32}, (_, i) => R({id: 'k' + i, before: 'k' + i + '='}));
conns.big = {logsBuffer: Array.from({length: 21000}, (_, i) =>
  N('I (' + i + ') sys: k0=' + i + ' k5=' + (i % 7) + ' k31=1.5 padding padding padding', i + 1, 'info')), metrics: {}};
let t0 = Date.now();
setMetricRules(rules32);
results.rescanMs = Date.now() - t0;
results.bigKeys = Object.keys(conns.big.metrics).sort().join();
results.bigSamples = conns.big.metrics.k0.samples.length;
t0 = Date.now();
results.hugeNoMatch = extractMetric(R({before: 'temp='}), L('x'.repeat(100000), 'plain'));
results.hugeMs = Date.now() - t0;
t0 = Date.now();
results.worstNoNumber = extractMetric(R({before: 'a'}), L('a'.repeat(100000), 'plain'));
results.worstMs = Date.now() - t0;
console.log(JSON.stringify(results));
"""

class MetricsEngineTest(unittest.TestCase):
    """The page's metric engine, run in node with the real page source."""

    @classmethod
    def setUpClass(cls):
        import shutil
        import subprocess
        node = shutil.which("node")
        if node is None:
            raise unittest.SkipTest("node is not installed")
        cls.script = re.findall(r"<script>(.*?)</script>", served_page(), re.S)[-1]
        if "METRICS-ENGINE-BEGIN" not in cls.script:
            raise AssertionError("the page has no metric engine block yet")
        idf = re.search(r"    const IDF_RE = .*?;\n", cls.script).group(0)
        parsed = cls.script[cls.script.index("    function parsedLine(entry) {"):]
        parsed = parsed[:parsed.index("\n    }\n") + 7]
        engine = cls.script.split("// METRICS-ENGINE-BEGIN", 1)[1].split("// METRICS-ENGINE-END", 1)[0]
        program = "const conns = {};\n" + idf + parsed + engine + JS_METRIC_CASES
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "engine.js"
            path.write_text(program, encoding="utf-8")
            done = subprocess.run([node, str(path)], capture_output=True, text=True, timeout=120)
        if done.returncode != 0:
            raise AssertionError(done.stderr[-800:])
        cls.r = json.loads(done.stdout.strip().splitlines()[-1])
        print(f"\nmetrics worst case: rescan 21000 lines x 32 rules {cls.r['rescanMs']} ms, "
              f"100 KB no-match line {cls.r['hugeMs']} ms, 100 KB repeated-prefix line {cls.r['worstMs']} ms")

    def test_extracts_the_number_after_the_text_on_a_tagged_line(self):
        self.assertEqual(self.r["heap"], 190464)
        self.assertEqual(self.r["heapKb"], 186)

    def test_tag_must_match_and_untagged_rules_read_plain_lines(self):
        self.assertIsNone(self.r["otherTag"])
        self.assertIsNone(self.r["taggedOnPlain"])
        self.assertEqual(self.r["plain"], 25)

    def test_non_numbers_and_overflow_are_skipped(self):
        self.assertEqual(self.r["notNumbers"], [None] * 6)
        self.assertIsNone(self.r["overflowAfterScale"])
        self.assertIsNone(self.r["noText"])

    def test_number_grammar_signs_decimals_exponents_and_line_end(self):
        self.assertEqual(self.r["shapes"], [-3, 2.5, 1000, 12345, 12, 1, 7])

    def test_first_valid_occurrence_wins(self):
        self.assertEqual(self.r["firstValid"], 7)

    def test_tx_echo_and_symbolized_lines_are_never_measured(self):
        self.assertEqual(self.r["txElf"], [None, None])

    def test_state_boundaries_are_strict(self):
        self.assertEqual(self.r["state"], ["ok", "low", "ok", "high", "ok"])

    def test_set_rules_rescans_only_added_or_changed_rules_and_drops_removed(self):
        self.assertEqual(self.r["rescan"], [[0, 1, 2, 3, 4], [0, 1, 2], 4])
        self.assertTrue(self.r["unchangedRuleNotRescanned"])
        self.assertEqual(self.r["addedRule"], [0, 2, 4, 6, 8])
        self.assertEqual(self.r["changedRuleReplaced"], [0, 1, 2, 3, 4])  # replaced, not appended
        self.assertEqual(self.r["afterRemoval"], [["rb"], ["rb"]])

    def test_live_samples_keep_line_number_time_and_cap_at_600(self):
        self.assertEqual(self.r["live"], [[[1, 1, "12:00:00.000"], [2, 2, "12:00:00.000"], [3, 3, "12:00:00.000"]],
                                          3])
        self.assertEqual(self.r["cap"], [600, 101, 700])

    def test_init_replay_does_not_duplicate_and_connections_stay_separate(self):
        self.assertEqual(self.r["replaySamples"], 3)
        self.assertEqual(self.r["separate"], [1, 0])

    def test_worst_case_rescan_and_huge_lines_stay_fast(self):
        self.assertEqual(self.r["bigKeys"], "k0,k31,k5")
        self.assertEqual(self.r["bigSamples"], 600)
        self.assertLess(self.r["rescanMs"], 2000)
        self.assertIsNone(self.r["hugeNoMatch"])
        self.assertIsNone(self.r["worstNoNumber"])
        self.assertLess(self.r["hugeMs"], 500)
        self.assertLess(self.r["worstMs"], 500)

    def test_lifecycle_hooks_are_wired(self):
        script = self.script
        self.assertIn("noteMetrics(conn, entry);", script.split("function adopt(conn, entry) {", 1)[1].split("\n    }\n", 1)[0])
        init = script.split("if (event.type === 'init') {", 1)[1].split("} else if (event.type === 'status')", 1)[0]
        self.assertLess(init.index("resetMetrics(conn)"), init.index("conn.logsBuffer.forEach(e => adopt(conn, e))"))
        self.assertIn("metrics: {}", script.split("function ensureConn(id) {", 1)[1].split("\n    }\n", 1)[0])
        for name in ("clearCurrentLogs", "clearSplitLogs", "trimBuffer"):
            body = script.split(f"function {name}(", 1)[1].split("\n    }\n", 1)[0]
            self.assertNotIn("metrics", body, name)  # samples are trends, not log lines


JS_EDITOR_CASES = r"""
const E = (text, level = 'info') => ({text, level, time: 't'});
const R = o => Object.assign({id: 'r', label: 'R', before: '', tag: '', unit: '', scale: 1, warn_below: null, warn_above: null, pin: false}, o);
const at = (e, needle) => e.text.indexOf(needle);
const drafts = e => numberSpans(e.text).map(s => draftFromNumber(e, s.start, null)).filter(Boolean);
const results = {};
const heap = E('I (30000) sys_monitor: heap: internal_free=190464 internal_min=1');
results.heap = draftFromNumber(heap, at(heap, '190464'), null);
results.tickNotOffered = draftFromNumber(heap, at(heap, '30000'), null);
results.tsDrafts = drafts(E('12:00:01.123 uptime=1234')).map(d => d.before);
results.colon = (() => { const e = E('temp: 25', 'plain'); const d = draftFromNumber(e, 6, null); return [d.before, extractMetric(R({before: d.before}), e)]; })();
results.spaced = (() => { const e = E('temp = 25', 'plain'); const d = draftFromNumber(e, 7, null); return [d.before, extractMetric(R({before: d.before}), e)]; })();
results.roundTrip = [['x=-3', -3], ['x=2.5', 2.5], ['pressure=1013', 1013]].map(([t, v]) => {
  const e = E(t, 'plain'); const d = draftFromNumber(e, t.indexOf('=') + 1, null); return extractMetric(d, e) === v; });
results.noKey = ['task 5', 'temp25', '5', 'a-5', '(7)'].map(t => drafts(E(t, 'plain')).length);
results.idLabel = [results.heap.id, results.heap.label, results.heap.tag];
results.idUnique = draftFromNumber(heap, at(heap, '190464'), new Set(['internal_free'])).id;
results.idUnderscoreStart = [draftFromNumber(E('_x=1', 'plain'), 3, null).id, draftFromNumber(E('_9=1', 'plain'), 3, null).id];
results.tagSepNotAKey = drafts(E('I (1) sys_monitor: 5 tasks')).length;
results.longKeyRefused = draftFromNumber(E('k'.repeat(70) + '=5', 'plain'), 71, null);
const conn = {logsBuffer: [E('I (1) sys_monitor: internal_free=10 internal_min=5'), E('I (2) sys_monitor: internal_free=20'),
  E('I (3) sys_monitor: internal_free=30'), E('I (4) other: internal_free=7')], metrics: {}};
results.found = discoverFields(conn).map(f => [f.tag, f.before, f.count, f.last]).sort();
results.cap = discoverFields({logsBuffer: Array.from({length: 300}, (_, i) => E('I (' + i + ') t: key' + i + '=' + i)), metrics: {}}).length;
results.skipsTxElf = discoverFields({logsBuffer: [E('a=1', 'tx'), E('a=2', 'elf')], metrics: {}}).length;
const t0 = Date.now();
results.hugeFields = discoverFields({logsBuffer: [E('a'.repeat(100000), 'plain')], metrics: {}}).length;
results.hugeMs = Date.now() - t0;
results.spanCap = numberSpans(Array.from({length: 100}, (_, i) => 'a' + i + '=' + i).join(' ')).length;
results.fieldDraft = [draftFromField({before: 'internal_free=', tag: 'sys_monitor', count: 3, last: 30}, null),
  draftFromField({before: 'temp: ', tag: '', count: 1, last: 1}, null),
  draftFromField({before: 'temp: ', tag: '', count: 1, last: 1}, new Set(['temp', 'temp_2'])),
  draftFromField({before: 'a = ', tag: '', count: 1, last: 1}, null)].map(d => [d.id, d.label, d.before, d.tag]);
console.log(JSON.stringify(results));
"""

def page_script():
    return re.findall(r"<script>(.*?)</script>", served_page(), re.S)[-1]

def page_block(script, name):
    return script.split(f"// {name}-BEGIN", 1)[1].split(f"// {name}-END", 1)[0]

def run_page_js(script, blocks, cases):
    """Run page blocks plus `cases` in node; returns the JSON the cases print last."""
    import shutil
    import subprocess
    node = shutil.which("node")
    if node is None:
        raise unittest.SkipTest("node is not installed")
    idf = re.search(r"    const IDF_RE = .*?;\n", script).group(0)
    parsed = script[script.index("    function parsedLine(entry) {"):]
    parsed = parsed[:parsed.index("\n    }\n") + 7]
    program = "const conns = {};\n" + idf + parsed + "".join(page_block(script, b) for b in blocks) + cases
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "page_cases.js"
        path.write_text(program, encoding="utf-8")
        done = subprocess.run([node, str(path)], capture_output=True, text=True, timeout=120)
    if done.returncode != 0:
        raise AssertionError(done.stderr[-800:])
    return json.loads(done.stdout.strip().splitlines()[-1])

class MetricsEditorTest(unittest.TestCase):
    """Track-a-number: drafts and field discovery run in node; the form is checked by markup."""

    @classmethod
    def setUpClass(cls):
        cls.script = page_script()
        if "METRICS-DRAFT-BEGIN" not in cls.script:
            raise AssertionError("the page has no draft/discovery block yet")
        cls.r = run_page_js(cls.script, ("METRICS-ENGINE", "METRICS-DRAFT"), JS_EDITOR_CASES)

    def test_draft_takes_the_key_text_tag_and_names_from_the_line(self):
        d = self.r["heap"]
        self.assertEqual((d["before"], d["tag"], d["id"], d["label"]), ("internal_free=", "sys_monitor", "internal_free", "internal_free"))
        self.assertEqual((d["unit"], d["scale"], d["warn_below"], d["warn_above"], d["pin"]), ("", 1, None, None, False))

    def test_draft_never_includes_timestamps_or_the_tick(self):
        self.assertIsNone(self.r["tickNotOffered"])
        self.assertEqual(self.r["tsDrafts"], ["uptime="])

    def test_colon_and_spaced_separators_keep_their_spaces_and_round_trip(self):
        self.assertEqual(self.r["colon"], ["temp: ", 25])
        self.assertEqual(self.r["spaced"], ["temp = ", 25])
        self.assertEqual(self.r["roundTrip"], [True, True, True])

    def test_numbers_without_a_key_separator_are_not_offered(self):
        self.assertEqual(self.r["noKey"], [0, 0, 0, 0, 0])
        self.assertEqual(self.r["tagSepNotAKey"], 0)  # "sys_monitor: 5 tasks": the colon belongs to the tag
        self.assertIsNone(self.r["longKeyRefused"])

    def test_ids_are_valid_and_unique(self):
        self.assertEqual(self.r["idUnique"], "internal_free_2")
        self.assertEqual(self.r["idUnderscoreStart"], ["x", "m_9"])  # leading "_" is dropped; an id must start with a letter

    def test_field_draft_names_the_rule_from_the_key_and_keeps_the_exact_before_text(self):
        self.assertEqual(self.r["fieldDraft"], [["internal_free", "internal_free", "internal_free=", "sys_monitor"],
                                                ["temp", "temp", "temp: ", ""], ["temp_3", "temp", "temp: ", ""],
                                                ["a", "a", "a = ", ""]])

    def test_discovery_groups_by_tag_and_key_and_counts(self):
        self.assertEqual(self.r["found"], [["other", "internal_free=", 1, 7], ["sys_monitor", "internal_free=", 3, 30],
                                           ["sys_monitor", "internal_min=", 1, 5]])

    def test_discovery_is_capped_skips_tx_and_elf_and_stays_linear(self):
        self.assertEqual(self.r["cap"], 200)
        self.assertEqual(self.r["skipsTxElf"], 0)
        self.assertEqual(self.r["hugeFields"], 0)
        self.assertLess(self.r["hugeMs"], 500)
        self.assertEqual(self.r["spanCap"], 40)

    def test_page_has_the_editor_elements_and_line_detail_track_buttons(self):
        page = served_page()
        for element in ("metricEditor", "metricDiscovery", "metricProblems", "metricReloadBtn", "metricCards",
                        "metricRulesList"):
            self.assertIn(f'id="{element}"', page)
        detail = self.script.split("function toggleDetail(row) {", 1)[1].split("\n    }\n", 1)[0]
        self.assertIn("Track a number", detail)
        self.assertIn("numberSpans(entry.text)", detail)

    def test_save_posts_json_with_the_page_token_and_base_rev_and_handles_stale(self):
        save = self.script.split("async function saveUserRules(", 1)[1].split("\n    }\n", 1)[0]
        for needle in ("'/api/metrics_rules'", "'X-Deck-Action': DECK_ACTION_TOKEN", "'Content-Type': 'application/json'",
                       "base_rev: metricConfig.rev", "res.status === 409"):
            self.assertIn(needle, save)

    def test_user_controlled_text_never_reaches_innerhtml(self):
        ui = page_block(self.script, "METRICS-UI")
        self.assertNotIn("innerHTML", ui)
        self.assertIn("textContent", ui)


JS_CARD_CASES = r"""
const R = o => Object.assign({id: 'r', label: 'R', before: 'x=', tag: '', unit: '', scale: 1, warn_below: null, warn_above: null, pin: false}, o);
const M = (...vs) => ({samples: vs.map((v, i) => ({n: i + 1, time: 't', v})), last: vs[vs.length - 1]});
const results = {};
results.fmt = [186, 175.8046875, 0.5, 0.0123, 190464.4, -3, 0, 99.999, 1000.4, 2.5, 12.25, -0.0456].map(fmtMetric);
results.low = metricCardModel(R({id: 'heap', label: 'Free', unit: 'KB', warn_below: 64}), M(100, 70, 50), 'user');
results.boundary = metricCardModel(R({warn_below: 64}), M(70, 64), 'profile').state;
results.high = metricCardModel(R({warn_above: 90}), M(10, 95), 'profile');
results.empty = metricCardModel(R({label: 'Idle'}), undefined, 'user');
results.raw = metricCardModel(R({label: '<img src=x onerror=alert(1)>', unit: '<b>'}), M(1), 'user');
const rules = [R({id: 'a'}), R({id: 'b'})];
results.stale = metricCardList(rules, {a: M(1), gone: M(9)}, new Map([['a', 'user']])).map(c => [c.id, c.count, c.source]);
const c1 = {a: M(1, 2)}, c2 = {a: M(7)};
results.twoConnections = [metricCardList(rules, c1, new Map()).map(c => c.valueText), metricCardList(rules, c2, new Map()).map(c => c.valueText)];
results.order = metricCardList([R({id: 'z'}), R({id: 'a'})], {}, new Map()).map(c => c.id);
console.log(JSON.stringify(results));
"""

class MetricsUiTest(unittest.TestCase):
    """Metric cards: the model is pure and runs in node; drawing is checked by markup."""

    @classmethod
    def setUpClass(cls):
        cls.script = page_script()
        if "METRICS-CARD-BEGIN" not in cls.script:
            raise AssertionError("the page has no card model block yet")
        cls.r = run_page_js(cls.script, ("METRICS-ENGINE", "METRICS-CARD"), JS_CARD_CASES)

    def test_value_formatting_is_short_and_keeps_the_sign(self):
        self.assertEqual(self.r["fmt"], ["186", "175.8", "0.5", "0.012", "190464", "-3", "0", "100", "1000", "2.5",
                                         "12.25", "-0.046"])

    def test_a_value_below_warn_below_is_low_with_text_and_icon_and_min_max_count(self):
        m = self.r["low"]
        self.assertEqual((m["state"], m["badge"], m["valueText"], m["unit"], m["min"], m["max"], m["count"], m["source"]),
                         ("low", "low", "50", "KB", 50, 100, 3, "yours"))
        self.assertTrue(m["icon"])  # the badge is never colour alone

    def test_the_limit_itself_is_not_a_warning_and_high_works(self):
        self.assertEqual(self.r["boundary"], "ok")
        self.assertEqual((self.r["high"]["state"], self.r["high"]["badge"], self.r["high"]["source"]), ("high", "high", "profile"))

    def test_a_rule_with_no_samples_shows_a_dash_not_a_value(self):
        e = self.r["empty"]
        self.assertEqual((e["valueText"], e["state"], e["count"], e["badge"], e["values"]), ("--", "ok", 0, "", []))

    def test_model_keeps_user_text_raw_for_textcontent_to_escape(self):
        self.assertEqual(self.r["raw"]["label"], "<img src=x onerror=alert(1)>")
        self.assertEqual(self.r["raw"]["unit"], "<b>")

    def test_card_list_follows_the_rules_so_a_deleted_rules_card_disappears(self):
        self.assertEqual(self.r["stale"], [["a", 1, "yours"], ["b", 0, "yours"]])  # "gone" has samples but no rule
        self.assertEqual(self.r["order"], ["z", "a"])

    def test_each_connection_shows_its_own_samples(self):
        self.assertEqual(self.r["twoConnections"], [["2", "--"], ["7", "--"]])

    def test_cards_are_drawn_once_a_second_while_the_tab_is_open_and_on_tab_and_connection_switch(self):
        tick = self.script.split("setInterval(() => {", 1)[1].split("}, 1000);", 1)[0]
        self.assertIn("renderMetrics()", tick)
        self.assertIn("activeTab === 'inspector'", tick)
        switch = self.script.split("function switchConnection(id) {", 1)[1].split("\n    }\n", 1)[0]
        self.assertIn("renderMetricsUi()", switch)
        self.assertIn("renderMetrics();", page_block(self.script, "METRICS-UI").split("function renderMetricsUi() {", 1)[1])

    def test_card_drawing_uses_the_card_model_and_dom_nodes(self):
        ui = page_block(self.script, "METRICS-UI").split("function renderMetrics() {", 1)[1].split("\n    }\n", 1)[0]
        self.assertIn("metricCardList(", ui)
        self.assertIn("textContent", ui + page_block(self.script, "METRICS-UI"))
        self.assertIn("createElementNS", page_block(self.script, "METRICS-UI"))  # sparkline without innerHTML


JS_PIN_CASES = r"""
const R = o => Object.assign({id: 'r', label: 'R', before: 'x=', tag: '', unit: '', scale: 1, warn_below: null, warn_above: null, pin: false}, o);
const M = (...vs) => ({samples: vs.map((v, i) => ({n: i + 1, time: 't', v})), last: vs[vs.length - 1]});
const results = {};
const rules = [R({id: 'heap', label: 'Free', unit: 'KB', pin: true, warn_below: 64}), R({id: 'quiet', label: 'Quiet', pin: false}),
               R({id: 'cpu', label: 'CPU', unit: '%', pin: true, warn_above: 90}), R({id: 'new', label: 'New', pin: true})];
const metrics = {heap: M(100, 50), quiet: M(1), cpu: M(95)};
results.pins = metricPinList(rules, metrics, new Map()).map(p => [p.id, p.text, p.state, p.badge]);
results.none = metricPinList([R({id: 'a'})], {a: M(1)}, new Map()).length;
results.hostile = metricPinList([R({id: 'e', label: '<img src=x onerror=1>', unit: '<b>', pin: true})], {e: M(5)}, new Map())[0].text;
results.ok = metricPinList([R({id: 'ok', label: 'Ok', unit: 'KB', pin: true, warn_below: 10})], {ok: M(10)}, new Map())[0].badge;
console.log(JSON.stringify(results));
"""

class MetricsPinTest(unittest.TestCase):
    """Pinned metrics in the status bar reuse the card model."""

    @classmethod
    def setUpClass(cls):
        cls.script = page_script()
        if "function metricPinList(" not in cls.script:
            raise AssertionError("the page has no pin list yet")
        cls.r = run_page_js(cls.script, ("METRICS-ENGINE", "METRICS-CARD"), JS_PIN_CASES)

    def test_only_pinned_rules_appear_with_label_value_and_unit(self):
        self.assertEqual([p[0] for p in self.r["pins"]], ["heap", "cpu", "new"])
        self.assertEqual(self.r["pins"][0][1], "Free 50 KB")
        self.assertEqual(self.r["pins"][2][1], "New --")  # pinned but no value yet: shown as --, never hidden
        self.assertEqual(self.r["none"], 0)

    def test_an_out_of_range_pin_carries_its_badge_text(self):
        self.assertEqual((self.r["pins"][0][2], self.r["pins"][0][3]), ("low", "low"))
        self.assertEqual((self.r["pins"][1][2], self.r["pins"][1][3]), ("high", "high"))
        self.assertEqual(self.r["ok"], "")

    def test_pin_text_keeps_user_text_raw_for_textcontent(self):
        self.assertEqual(self.r["hostile"], "<img src=x onerror=1> 5 <b>")

    def test_status_bar_has_the_pin_slot_and_draws_it_with_dom_nodes_on_the_one_second_tick(self):
        page = served_page()
        self.assertIn('id="sbPins"', page)
        status = self.script.split("function renderStatusBar() {", 1)[1].split("\n    }\n", 1)[0]
        self.assertIn("renderPins()", status)
        pins = self.script.split("function renderPins() {", 1)[1].split("\n    }\n", 1)[0]
        self.assertIn("metricPinList(", pins)
        self.assertIn("mkEl('span'", pins)  # mkEl sets textContent
        self.assertIn("createTextNode(", pins)
        self.assertNotIn("innerHTML", pins)

    def test_pins_follow_the_active_connection(self):
        pins = self.script.split("function renderPins() {", 1)[1].split("\n    }\n", 1)[0]
        self.assertIn("ensureConn(connId).metrics", pins)


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
