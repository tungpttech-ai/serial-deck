//! Agent-facing control core (agent.py): per-port sessions, request lifecycles,
//! log paging, flash jobs and the dashboard activity file.

use crate::codec::{self, FRAME_COMMAND, FRAME_ERROR, FRAME_EVENT, FRAME_HELLO, FRAME_RESPONSE, Reader, Rec};
use crate::hub::{HubError, Manager, MULTIPORT_PROTOCOL, Transport, WriteError};
use crate::logcache::Records;
use crate::snapshot::{self, Snapshot};
use crate::util::{self, get, merge, obj, port_identity, py_dumps, py_int, py_str, redact, redact_value, truthy};
use regex::Regex;
use serde_json::{Map, Value, json};
use std::collections::{HashMap, VecDeque};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, LazyLock, Mutex, Weak};
use std::time::{Duration, Instant};

pub const POLICIES: [&str; 3] = ["observe", "interact", "hardware"];
const TERMINAL: [&str; 5] = ["succeeded", "failed", "cancelled", "expired", "rejected"];
pub const BUTTONS: [&str; 5] = ["HOME", "LEFT", "RIGHT", "ENTER", "ONOFF"];
pub const BUTTON_ACTIONS: [&str; 4] = ["click", "press", "release", "long_press"];
pub const QUERY_KINDS: [&str; 4] = ["capabilities", "identity", "fsm", "snapshot"];
const LINE_CHARS: usize = 2000;
const RESPONSE_RECORDS: usize = 500;
const RESPONSE_BYTES: usize = 48 * 1024;
const MAX_SESSIONS: usize = 4;
const MAX_WAITERS: usize = 32;
const MAX_WAIT_S: f64 = 120.0;
const MAX_FLASH_WAIT_S: f64 = 60.0;
const ACTIVITY_LIMIT: usize = 200;
const ACTIVITY_FLUSH_S: f64 = 0.5;

static LOG_LEVEL_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?:^|\s)([EWIDV])\s+\(").unwrap());
static ANSI_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\x1b\[[0-?]*[ -/]*[@-~]").unwrap());
static FLASH_VERIFIED_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)Hash of data verified").unwrap());

pub type Cancel = Arc<AtomicBool>;
pub type Payload = Map<String, Value>;

// ------------------------------------------------------------- errors

#[derive(Debug, Clone)]
pub struct AgentError {
    pub code: String,
    pub message: String,
    pub hint: String,
    pub details: Payload,
}

impl AgentError {
    pub fn new(code: &str, message: impl Into<String>, hint: impl Into<String>) -> Self {
        AgentError { code: code.into(), message: message.into(), hint: hint.into(), details: Map::new() }
    }

    pub fn payload(&self) -> Value {
        let mut error = obj(json!({"code": self.code, "message": redact(&self.message)}));
        if !self.hint.is_empty() {
            error.insert("hint".into(), json!(self.hint));
        }
        error.extend(obj(redact_value(&Value::Object(self.details.clone()), false)));
        json!({"ok": false, "error": error})
    }
}

pub type AResult<T = Payload> = Result<T, AgentError>;

fn err<T>(code: &str, message: impl Into<String>, hint: impl Into<String>) -> AResult<T> {
    Err(AgentError::new(code, message, hint))
}

fn hub_err(e: &HubError) -> String {
    e.to_string()
}

// ------------------------------------------------------------- activity file

pub struct ActivityLog {
    inner: Mutex<ActivityInner>,
    path: Option<PathBuf>,
}

struct ActivityInner {
    entries: VecDeque<Value>,
    next_id: i64,
    info: Payload,
    sessions: Vec<Value>,
    flash_jobs: Vec<Value>,
    last_flush: Option<Instant>,
}

impl ActivityLog {
    fn new(policy: &str, socket: &str, client: &str) -> Self {
        let path = util::runtime_dir()
            .and_then(|d| util::private_dir(&d.join("mcp-activity")))
            .ok()
            .map(|d| d.join(format!("{}.json", std::process::id())));
        let log = ActivityLog {
            inner: Mutex::new(ActivityInner {
                entries: VecDeque::new(),
                next_id: 1,
                info: obj(json!({"pid": std::process::id(), "policy": policy, "hub_socket": socket,
                                 "client": client, "started": util::now(), "server": "rust"})),
                sessions: Vec::new(),
                flash_jobs: Vec::new(),
                last_flush: None,
            }),
            path,
        };
        log.flush(true);
        log
    }

    pub fn begin(&self, tool: &str, args: &Payload) -> i64 {
        let id = {
            let mut i = self.inner.lock().unwrap();
            let id = i.next_id;
            i.next_id += 1;
            i.entries.push_back(json!({"id": id, "tool": tool, "args": redact_value(&Value::Object(args.clone()), false),
                                       "started": util::now(), "state": "running"}));
            if i.entries.len() > ACTIVITY_LIMIT {
                i.entries.pop_front();
            }
            id
        };
        self.flush(true);
        id
    }

    pub fn end(&self, id: i64, outcome: &str, summary: &str) {
        {
            let mut i = self.inner.lock().unwrap();
            if let Some(Value::Object(e)) = i.entries.iter_mut().rev().find(|e| e["id"] == id) {
                let started = e.get("started").and_then(Value::as_f64).unwrap_or(0.0);
                let summary: String = redact(summary).chars().take(300).collect();
                e.insert("state".into(), json!(outcome));
                e.insert("ended".into(), json!(util::now()));
                e.insert("summary".into(), json!(summary));
                e.insert("duration_ms".into(), json!(((util::now() - started) * 1000.0) as i64));
            }
        }
        self.flush(true);
    }

    fn update_state(&self, sessions: Vec<Value>, jobs: Vec<Value>) {
        {
            let mut i = self.inner.lock().unwrap();
            i.sessions = sessions;
            i.flash_jobs = jobs;
        }
        self.flush(false);
    }

    fn flush(&self, force: bool) {
        let Some(path) = &self.path else { return };
        let snapshot = {
            let mut i = self.inner.lock().unwrap();
            if !force && i.last_flush.is_some_and(|t| t.elapsed().as_secs_f64() < ACTIVITY_FLUSH_S) {
                return;
            }
            i.last_flush = Some(Instant::now());
            let mut s = i.info.clone();
            s.insert("updated".into(), json!(util::now()));
            s.insert("sessions".into(), Value::Array(i.sessions.clone()));
            s.insert("flash_jobs".into(), Value::Array(i.flash_jobs.clone()));
            s.insert("calls".into(), Value::Array(i.entries.iter().cloned().collect()));
            Value::Object(s)
        };
        let temp = path.with_file_name(format!(".{}.tmp", path.file_name().unwrap().to_string_lossy()));
        if std::fs::write(&temp, serde_json::to_string(&snapshot).unwrap_or_default()).is_ok() {
            let _ = std::fs::rename(temp, path);
        }
    }

    fn close(&self) {
        if let Some(p) = &self.path {
            let _ = std::fs::remove_file(p);
        }
    }
}

// ------------------------------------------------------------- records helpers

fn parse_level(line: &str) -> &'static str {
    match LOG_LEVEL_RE.captures(line).map(|c| c[1].to_string()).as_deref() {
        Some("E") => "error",
        Some("W") => "warning",
        Some("I") => "info",
        Some("D") => "debug",
        Some("V") => "verbose",
        _ => "plain",
    }
}

fn clip(text: &str) -> String {
    let n = text.chars().count();
    if n <= LINE_CHARS {
        return text.to_string();
    }
    let head: String = text.chars().take(LINE_CHARS).collect();
    format!("{head}…[+{} chars]", n - LINE_CHARS)
}

fn seq_of(r: &Payload) -> i64 {
    r.get("seq").and_then(Value::as_i64).unwrap_or(0)
}

/// Bounded pages from RAM or disk without copying the archive (select_records).
#[allow(clippy::too_many_arguments)]
pub fn select_records(records: &Records, end: i64, cursor: Option<i64>, limit: i64, contains: &[String],
                      levels: &[String], frames: bool, ignore_case: bool) -> Payload {
    let limit = limit.clamp(1, RESPONSE_RECORDS as i64) as usize;
    let needles: Vec<String> = contains.iter().filter(|n| !n.is_empty())
        .map(|n| if ignore_case { n.to_lowercase() } else { n.clone() }).collect();
    let first = records.iter(0, false, Some(1), Some(end)).next().map_or(end, |r| seq_of(&r));
    let mut matched = Vec::new();
    for record in records.iter(cursor.unwrap_or(0), cursor.is_none(), None, Some(end)) {
        let kind = record.get("kind").or_else(|| record.get("type")).and_then(Value::as_str).unwrap_or("");
        if kind == "raw" || (kind == "frame" && !frames) {
            continue;
        }
        if !levels.is_empty() && !levels.iter().any(|l| record.get("level").and_then(Value::as_str).unwrap_or("plain") == l) {
            continue;
        }
        if !needles.is_empty() {
            let text = match record.get("text") {
                Some(t) if truthy(t) => py_str(t),
                _ => py_dumps(record.get("frame").unwrap_or(&Value::Null)),
            };
            let hay = if ignore_case { text.to_lowercase() } else { text };
            if !needles.iter().any(|n| hay.contains(n.as_str())) {
                continue;
            }
        }
        matched.push(record);
        if matched.len() > limit {
            break;
        }
    }
    let mut truncated = cursor.is_some() && matched.len() > limit;
    matched.truncate(limit);
    if cursor.is_none() {
        matched.reverse();
    }
    let mut next_cursor = if truncated { seq_of(matched.last().unwrap()) + 1 } else { end };
    let (mut out, mut size) = (Vec::new(), 0usize);
    for record in matched {
        let record = redact_value(&Value::Object(record), false);
        size += py_dumps(&record).len();
        if !out.is_empty() && size > RESPONSE_BYTES {
            truncated = true;
            next_cursor = record["seq"].as_i64().unwrap_or(next_cursor);
            break;
        }
        out.push(record);
    }
    obj(json!({"records": out, "next_cursor": next_cursor, "truncated": truncated,
               "dropped": cursor.map_or(0, |c| (first - c).max(0)), "oldest_seq": first}))
}

// ------------------------------------------------------------- waiter

#[derive(Default)]
struct Waiter {
    id: u64,
    request_id: Option<String>,
    sequence: u32,
    hello: bool,
    frames: Vec<Value>,
    operation_id: Option<Value>,
    last_event_seq: i64,
    status: Option<String>,
    terminal: Option<Value>,
    done: bool,
}

fn rank(status: &str) -> i32 {
    match status {
        "accepted" => 0,
        "running" => 1,
        _ => 2,
    }
}

fn framed(frame_type: u8, message: &Value) -> Value {
    let name = codec::frame_name(frame_type).map_or(frame_type.to_string(), str::to_string);
    let mut m = obj(json!({"frame": name}));
    match message {
        Value::Object(o) => m.extend(o.clone()),
        other => {
            m.insert("payload".into(), other.clone());
        }
    }
    Value::Object(m)
}

impl Waiter {
    /// Apply a frame; true when it belonged to this request.
    fn offer(&mut self, frame_type: u8, sequence: u32, message: &Value) -> bool {
        if self.hello {
            if (frame_type == FRAME_HELLO || frame_type == FRAME_ERROR) && sequence == self.sequence {
                self.finish(frame_type, message, if frame_type == FRAME_HELLO { "succeeded" } else { "rejected" }, false);
                return true;
            }
            return false;
        }
        let Value::Object(_) = message else { return false };
        let request_id = get(message, "request_id");
        let mine = self.request_id.as_deref().is_some_and(|r| request_id == r);
        if self.terminal.is_some() {
            return mine;
        }
        if frame_type == FRAME_ERROR {
            if mine || (!truthy(request_id) && sequence == self.sequence) {
                self.finish(frame_type, message, "rejected", false);
                return true;
            }
            return false;
        }
        if !(frame_type == FRAME_RESPONSE || frame_type == FRAME_EVENT) || !mine {
            return false;
        }
        let operation_id = Some(get(message, "operation_id").clone()).filter(truthy);
        if self.operation_id.is_some() && operation_id.is_some() && operation_id != self.operation_id {
            return false;
        }
        if frame_type == FRAME_EVENT {
            if let Some(event_seq) = get(message, "event_seq").as_i64() {
                if event_seq <= self.last_event_seq {
                    return true;
                }
                self.last_event_seq = event_seq;
            }
        }
        if self.operation_id.is_none() {
            self.operation_id = operation_id;
        }
        let status = match get(message, "status") {
            Value::Null => String::new(),
            s => py_str(s),
        };
        self.frames.push(framed(frame_type, message));
        if !status.is_empty() && rank(&status) >= self.status.as_deref().map_or(-1, rank) {
            self.status = Some(status.clone());
        }
        if TERMINAL.contains(&status.as_str()) {
            self.finish(frame_type, message, &status, true);
        }
        true
    }

    fn finish(&mut self, frame_type: u8, message: &Value, status: &str, recorded: bool) {
        if self.terminal.is_none() {
            if !recorded {
                self.frames.push(framed(frame_type, message));
            }
            self.status = Some(status.into());
            self.terminal = Some(if message.is_object() { message.clone() } else { json!({"payload": message}) });
        }
        self.done = true;
    }
}

// ------------------------------------------------------------- session

struct SessionState {
    next_seq: i64,
    waiters: Vec<Waiter>,
    sequence: u32,
    lost: Option<String>,
}

pub struct Session {
    pub manager: Arc<Manager>,
    pub port: String,
    pub mode: String,
    pub generation: String,
    transport: Transport,
    pub records: Records,
    state: Mutex<SessionState>,
    changed: Condvar,
    stop: AtomicBool,
    sub_id: Mutex<Option<u64>>,
}

impl Session {
    fn open(manager: Arc<Manager>, port: &str, mode: &str) -> Result<Arc<Session>, String> {
        let status = manager.status().map_err(|e| hub_err(&e))?;
        let generation = format!("{}:{}", py_str(status.get("pid").unwrap_or(&Value::Null)), manager.channel());
        let transport = Transport::open(&manager.data_endpoint()).map_err(|e| e.to_string())?;
        let mut stream = transport.reader().map_err(|e| e.to_string())?;
        let session = Arc::new(Session {
            manager: manager.clone(),
            port: port.into(),
            mode: mode.into(),
            generation,
            transport,
            records: Records::new(&format!("MCP {port}"), None),
            state: Mutex::new(SessionState { next_seq: 1, waiters: Vec::new(), sequence: (util::random_u32() % (1 << 30)) + (1 << 30), lost: None }),
            changed: Condvar::new(),
            stop: AtomicBool::new(false),
            sub_id: Mutex::new(None),
        });
        let reader_session = Arc::downgrade(&session);
        let frames = mode == "control";
        std::thread::Builder::new().name(format!("mcp-{port}")).stack_size(256 * 1024).spawn(move || {
            let mut reader = Reader::new(frames);
            let mut buf = vec![0u8; 4096];
            loop {
                let result = stream.read(&mut buf);
                let Some(s) = reader_session.upgrade() else { return };
                if s.stop.load(Ordering::SeqCst) {
                    return;
                }
                let n = match result {
                    Ok(0) => {
                        s.mark_lost("hub data socket closed: UART hub data socket closed");
                        return;
                    }
                    Ok(n) => n,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(e) => {
                        s.mark_lost(&format!("hub data socket closed: {e}"));
                        return;
                    }
                };
                for rec in reader.feed(&buf[..n]) {
                    s.on_record(rec);
                }
            }
        }).map_err(|e| e.to_string())?;
        let weak = Arc::downgrade(&session);
        let cb = Arc::new(move |event: &Value| {
            if let Some(s) = weak.upgrade() {
                s.on_hub_status(event);
            }
        });
        if let Ok(id) = manager.subscribe(cb) {
            *session.sub_id.lock().unwrap() = Some(id);
        }
        Ok(session)
    }

    fn on_hub_status(&self, status: &Value) {
        if let Some(baud) = util::strict_int(get(status, "baud")) {
            let old = self.manager.baud();
            if baud != old {
                self.note(&format!("UART baud changed {old} -> {baud} by another client"), "warning");
                *self.manager.baud.lock().unwrap() = baud;
            }
        }
    }

    fn on_record(&self, rec: Rec) {
        match rec {
            Rec::Log(text) => {
                let text = ANSI_RE.replace_all(&text, "").into_owned();
                self.append("log", parse_level(&text), &text, None);
            }
            Rec::Frame(frame_type, sequence, message) => {
                let name = codec::frame_name(frame_type).map_or(format!("type-{frame_type}"), str::to_string);
                let level = if frame_type == FRAME_ERROR { "error" } else { "frame" };
                self.append("frame", level, "", Some(json!({"type": name, "sequence": sequence, "message": message})));
                let mut st = self.state.lock().unwrap();
                if st.waiters.iter_mut().any(|w| w.offer(frame_type, sequence, &message)) {
                    self.changed.notify_all();
                }
            }
        }
    }

    pub fn append(&self, kind: &str, level: &str, text: &str, frame: Option<Value>) -> i64 {
        let mut st = self.state.lock().unwrap();
        let seq = st.next_seq;
        st.next_seq += 1;
        let mut record = obj(json!({"seq": seq, "time": util::iso_now(), "kind": kind, "level": level}));
        match frame {
            Some(f) => record.insert("frame".into(), f),
            None => record.insert("text".into(), json!(clip(text))),
        };
        self.records.append(&obj(redact_value(&Value::Object(record), false)));
        self.changed.notify_all();
        seq
    }

    pub fn note(&self, text: &str, level: &str) -> i64 {
        self.append("note", level, &format!("[mcp] {text}"), None)
    }

    fn mark_lost(&self, reason: &str) {
        {
            let mut st = self.state.lock().unwrap();
            st.lost = Some(reason.into());
            for w in st.waiters.iter_mut() {
                w.done = true;
            }
            self.changed.notify_all();
        }
        self.note(reason, "error");
    }

    pub fn lost(&self) -> Option<String> {
        self.state.lock().unwrap().lost.clone()
    }

    pub fn cursor(&self) -> i64 {
        self.state.lock().unwrap().next_seq
    }

    pub fn ensure_alive(&self) -> AResult<()> {
        match self.lost() {
            Some(l) => err("transport_unavailable", format!("{}: {l}", self.port), "call serial_connect again to reattach"),
            None => Ok(()),
        }
    }

    fn close(&self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(id) = self.sub_id.lock().unwrap().take() {
            self.manager.unsubscribe(id);
        }
        self.transport.close();
        self.changed.notify_all();
    }

    /// Send HELLO (command None) or a command and collect its lifecycle.
    pub fn request(&self, command: Option<&str>, args: Value, timeout: f64, cancel: Option<&Cancel>) -> AResult {
        self.ensure_alive()?;
        if self.mode != "control" {
            return err("invalid_state", "firmware commands are disabled in raw console mode", "reconnect with mode='control'");
        }
        let id = util::random_u32() as u64;
        let (sequence, frame, request_id) = {
            let mut st = self.state.lock().unwrap();
            st.sequence = (st.sequence + 1) & 0x7FFF_FFFF;
            if st.sequence == 0 {
                st.sequence = 1 << 30;
            }
            let sequence = st.sequence;
            let (frame, request_id) = match command {
                None => (codec::encode_json_frame(FRAME_HELLO, sequence, &json!({"type": "hello", "protocol": "serial-deck-control",
                         "version": codec::PROTOCOL_VERSION, "client_id": format!("serial-deck-mcp-{}", std::process::id())})), None),
                Some(cmd) => {
                    let rid = util::random_hex(16);
                    let mut req = obj(json!({"version": codec::PROTOCOL_VERSION, "request_id": rid, "command": cmd, "args": args,
                                             "deadline_ms": ((timeout * 1000.0) as i64).clamp(1, 30000)}));
                    if cmd == "input.button" || cmd == "ui.show_info" {
                        req.insert("idempotency_key".into(), json!(rid));
                    }
                    (codec::encode_json_frame(FRAME_COMMAND, sequence, &Value::Object(req)), Some(rid))
                }
            };
            if st.waiters.len() >= MAX_WAITERS {
                return err("busy", "too many firmware requests in flight", "");
            }
            st.waiters.push(Waiter { id, request_id: request_id.clone(), sequence, hello: command.is_none(), last_event_seq: -1, ..Default::default() });
            (sequence, frame, request_id)
        };
        let frame = match frame {
            Ok(f) => f,
            Err(e) => {
                self.state.lock().unwrap().waiters.retain(|w| w.id != id);
                return err("invalid_argument", e, "");
            }
        };
        let dispatch_error = match self.transport.write_frame(&frame) {
            Ok(()) => String::new(),
            Err(WriteError::Unknown(m)) => m,
            Err(WriteError::Refused(m)) => {
                self.state.lock().unwrap().waiters.retain(|w| w.id != id);
                return err("transport_unavailable", format!("write refused: {m}"), "the hub rejected the write before sending it");
            }
        };
        let deadline = Instant::now() + Duration::from_secs_f64(timeout.max(0.0));
        let mut st = self.state.lock().unwrap();
        let finished = loop {
            let done = st.waiters.iter().find(|w| w.id == id).is_none_or(|w| w.done);
            let now = Instant::now();
            if done || now >= deadline || cancel.is_some_and(|c| c.load(Ordering::SeqCst)) {
                break done;
            }
            st = self.changed.wait_timeout(st, (deadline - now).min(Duration::from_millis(250))).unwrap().0;
        };
        let pos = st.waiters.iter().position(|w| w.id == id);
        let waiter = pos.map(|p| st.waiters.remove(p)).unwrap_or_default();
        let lost = st.lost.clone();
        drop(st);
        let frames: Vec<Value> = waiter.frames[waiter.frames.len().saturating_sub(8)..].to_vec();
        let mut result = obj(json!({"request_id": request_id, "sequence": sequence, "operation_id": waiter.operation_id,
                                    "status": waiter.status, "frames": frames}));
        if let Some(terminal) = waiter.terminal {
            result.insert("outcome".into(), json!("completed"));
            if truthy(get(&terminal, "error")) {
                result.insert("error".into(), terminal["error"].clone());
            }
            if let Some(raw) = terminal.get("result") {
                let parsed = match raw {
                    Value::String(s) => serde_json::from_str(s).unwrap_or_else(|_| raw.clone()),
                    other => other.clone(),
                };
                result.insert("result".into(), parsed);
            }
            if command.is_none() {
                result.insert("hello".into(), terminal);
            }
            return Ok(obj(redact_value(&Value::Object(result), false)));
        }
        result.insert("outcome".into(), json!("unknown"));
        let reason = lost.unwrap_or_else(|| {
            if !dispatch_error.is_empty() {
                format!("no hub reply to the write: {dispatch_error}")
            } else if !finished {
                "timeout".into()
            } else {
                "no terminal status".into()
            }
        });
        result.insert("reason".into(), json!(reason));
        result.insert("hint".into(), json!("the device may or may not have executed it; do not re-send, check state with serial_query or serial_logs first"));
        Ok(obj(redact_value(&Value::Object(result), false)))
    }

    pub fn select(&self, cursor: Option<i64>, limit: i64, contains: &[String], levels: &[String], frames: bool, ignore_case: bool) -> Payload {
        let end = self.cursor();
        let mut result = select_records(&self.records, end, cursor, limit, contains, levels, frames, ignore_case);
        let mut cache = obj(json!({"stream": self.records.stream}));
        cache.extend(self.records.cache.status());
        result.insert("cache".into(), Value::Object(cache));
        result
    }

    pub fn wait_for(&self, any_of: &[String], timeout: f64, since: Option<i64>, ignore_case: bool, context: i64, cancel: Option<&Cancel>) -> AResult {
        let needles: Vec<&String> = any_of.iter().filter(|n| !n.is_empty()).collect();
        if needles.is_empty() {
            return err("invalid_argument", "any_of needs at least one non-empty string", "");
        }
        let folded: Vec<String> = needles.iter().map(|n| if ignore_case { n.to_lowercase() } else { n.to_string() }).collect();
        let deadline = Instant::now() + Duration::from_secs_f64(timeout.clamp(0.0, MAX_WAIT_S));
        let cancelled = || cancel.is_some_and(|c| c.load(Ordering::SeqCst));
        let mut cursor = since.unwrap_or_else(|| self.cursor());
        loop {
            let mut end = self.cursor();
            for record in self.records.iter(cursor, false, None, Some(end)) {
                if cancelled() || Instant::now() >= deadline {
                    end = seq_of(&record);
                    break;
                }
                if record.get("kind").and_then(Value::as_str) == Some("frame") {
                    continue;
                }
                let text = record.get("text").map(py_str).unwrap_or_default();
                let hay = if ignore_case { text.to_lowercase() } else { text };
                if let Some(i) = folded.iter().position(|f| hay.contains(f.as_str())) {
                    let mut before: Vec<Value> = self.records.iter(0, true, Some(context as usize), Some(seq_of(&record)))
                        .map(Value::Object).collect();
                    before.reverse();
                    let next = seq_of(&record) + 1;
                    return Ok(obj(json!({"matched": true, "pattern": needles[i], "record": redact_value(&Value::Object(record), false),
                                         "context": redact_value(&Value::Array(before), false), "next_cursor": next})));
                }
            }
            cursor = end;
            let st = self.state.lock().unwrap();
            if let Some(l) = &st.lost {
                return err("transport_unavailable", format!("{}: {l}", self.port), "");
            }
            let now = Instant::now();
            if cancelled() {
                return Ok(obj(json!({"matched": false, "reason": "cancelled", "next_cursor": end})));
            }
            if now >= deadline {
                drop(st);
                let mut tail: Vec<Value> = self.records.iter(0, true, Some(context.max(1) as usize), None).map(Value::Object).collect();
                tail.reverse();
                return Ok(obj(json!({"matched": false, "reason": "timeout", "tail": redact_value(&Value::Array(tail), false), "next_cursor": end})));
            }
            if st.next_seq == end {
                let _ = self.changed.wait_timeout(st, (deadline - now).min(Duration::from_millis(500))).unwrap();
            }
        }
    }
}

// ------------------------------------------------------------- flash jobs

#[derive(Default)]
struct JobState {
    flash_id: Option<i64>,
    events: Vec<Value>,
    last_revision: Option<i64>,
    gaps: i64,
    finished: Option<Value>,
    completion_cursor: Option<i64>,
    verified_transitions: usize,
    last_line: String,
    verdict: Option<Payload>,
    poll_revision: Option<i64>,
}

pub struct FlashJob {
    token: String,
    session_port: String,
    snapshot: Snapshot,
    started: f64,
    manager: Mutex<Option<Arc<Manager>>>,
    state: Mutex<JobState>,
    finalize: Mutex<()>,
}

impl FlashJob {
    fn owns(&self, flash: &Value) -> bool {
        truthy(get(flash, "build_dir"))
            && util::realpath(Path::new(&py_str(&flash["build_dir"]))) == util::realpath(&self.snapshot.directory)
    }

    fn summary(&self) -> Value {
        let s = self.state.lock().unwrap();
        let last = s.events.last().cloned().unwrap_or(json!({}));
        json!({"token": self.token, "flash_id": s.flash_id, "port": self.session_port,
               "progress": last.get("progress").cloned().unwrap_or(json!(0)),
               "step": last.get("step").cloned().unwrap_or(json!("Queued")), "finished": s.finished.is_some()})
    }
}

fn push_caught_up(s: &JobState) -> bool {
    match s.poll_revision {
        None => true,
        Some(p) => s.last_revision.is_some_and(|l| p >= 0 && l >= p),
    }
}

// ------------------------------------------------------------- agent

#[derive(Default)]
struct AgentState {
    sessions: Vec<(String, Arc<Session>)>,
    pending: HashMap<String, (Snapshot, Value)>,
    jobs: HashMap<String, Arc<FlashJob>>,
}

pub struct Agent {
    pub policy: String,
    pub socket_path: String,
    state: Mutex<AgentState>,
    pub activity: Option<ActivityLog>,
    me: Weak<Agent>,
}

impl Agent {
    pub fn new(policy: &str, socket_path: &str, activity_client: Option<&str>) -> Arc<Agent> {
        Arc::new_cyclic(|me| Agent {
            policy: policy.into(),
            socket_path: socket_path.into(),
            state: Mutex::default(),
            activity: activity_client.map(|c| ActivityLog::new(policy, socket_path, c)),
            me: me.clone(),
        })
    }

    pub fn publish_activity(&self) {
        let Some(a) = &self.activity else { return };
        let (sessions, jobs) = {
            let st = self.state.lock().unwrap();
            (st.sessions.iter().map(|(_, s)| s.clone()).collect::<Vec<_>>(), st.jobs.values().cloned().collect::<Vec<_>>())
        };
        let sessions = sessions.iter().map(|s| json!({"port": s.port, "mode": s.mode, "baud": s.manager.baud(), "lost": s.lost(),
                                                     "records": s.cursor() - 1})).collect();
        a.update_state(sessions, jobs.iter().map(|j| j.summary()).collect());
    }

    pub fn allows(&self, level: &str) -> bool {
        let idx = |p: &str| POLICIES.iter().position(|x| *x == p).unwrap_or(usize::MAX);
        idx(&self.policy) >= idx(level)
    }

    fn require(&self, level: &str) -> AResult<()> {
        if self.allows(level) {
            return Ok(());
        }
        err("policy_denied", format!("this server runs with policy '{}'", self.policy),
            format!("the user must restart the MCP server with --allow {level}"))
    }

    fn manager(&self, socket: &str) -> Manager {
        Manager::new(if socket.is_empty() { &self.socket_path } else { socket })
    }

    fn root(&self) -> AResult<Manager> {
        let mut m = self.manager("");
        m.ensure_started().map_err(|e| AgentError::new("transport_unavailable", e.to_string(), ""))?;
        let status = m.status().map_err(|e| AgentError::new("transport_unavailable", e.to_string(), ""))?;
        if status.get("protocol").and_then(Value::as_str) != Some(MULTIPORT_PROTOCOL) {
            return err("legacy_hub", "a legacy single-port hub owns the control socket",
                       "disconnect its clients and stop it normally; this server never starts or stops hubs to work around it");
        }
        Ok(m)
    }

    pub fn session(&self, port: Option<&str>) -> AResult<Arc<Session>> {
        let st = self.state.lock().unwrap();
        let Some(port) = port else {
            if st.sessions.len() == 1 {
                return Ok(st.sessions[0].1.clone());
            }
            if st.sessions.is_empty() {
                return err("not_connected", "no port is connected", "call serial_connect first");
            }
            let names: Vec<&str> = st.sessions.iter().map(|(_, s)| s.port.as_str()).collect();
            return err("ambiguous_port", "specify port", format!("connected: {}", names.join(", ")));
        };
        let key = port_identity(port);
        match st.sessions.iter().find(|(k, _)| *k == key) {
            Some((_, s)) => Ok(s.clone()),
            None => err("not_connected", format!("{port} is not connected"), "call serial_connect first"),
        }
    }

    fn job_summaries(&self) -> Vec<Value> {
        let jobs: Vec<Arc<FlashJob>> = self.state.lock().unwrap().jobs.values().cloned().collect();
        jobs.iter().map(|j| j.summary()).collect()
    }

    pub fn status(&self) -> AResult {
        let sessions: Vec<Arc<Session>> = self.state.lock().unwrap().sessions.iter().map(|(_, s)| s.clone()).collect();
        let sessions: Vec<Value> = sessions.iter().map(|s| json!({"port": s.port, "mode": s.mode, "baud": s.manager.baud(),
            "generation": s.generation, "cursor": s.cursor(), "lost": s.lost()})).collect();
        let m = self.manager("");
        let hub = if m.socket_ready() {
            match m.status() {
                Ok(h) => Some(Value::Object(h)),
                Err(e) => Some(json!({"error": e.to_string()})),
            }
        } else {
            None
        };
        let hub = hub.map(|h| {
            if let Some(e) = h.get("error") {
                return json!({"error": redact(&py_str(e))});
            }
            if h.get("channels").is_none() {
                return h;
            }
            let channels: Vec<Value> = get(&h, "channels").as_array().cloned().unwrap_or_default().iter().map(|c| {
                let flash = get(c, "flash");
                let f: Payload = ["active", "id", "progress", "step", "exit_code"].iter().map(|k| (k.to_string(), get(flash, k).clone())).collect();
                json!({"port": get(c, "port"), "baud": get(c, "baud"), "state": get(c, "state"), "client_count": get(c, "client_count"),
                       "flash": redact_value(&Value::Object(f), false)})
            }).collect();
            json!({"protocol": get(&h, "protocol"), "pid": get(&h, "pid"), "state": get(&h, "state"),
                   "features": h.get("features").cloned().unwrap_or(json!([])), "channels": channels})
        });
        let tx_atomic = hub.as_ref().is_some_and(|h| get(h, "features").as_array().is_some_and(|f| f.iter().any(|x| x == "write_frame")));
        Ok(obj(json!({"policy": self.policy, "hub_socket": self.socket_path, "hub": hub, "tx_atomic": tx_atomic,
                      "sessions": sessions, "flash_jobs": self.job_summaries()})))
    }

    // ---- ports

    fn ssh_store() -> Payload {
        let path = util::config_dir().join("devices.json");
        let data: Value = std::fs::read_to_string(path).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or(Value::Null);
        let name_re = Regex::new(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}$").unwrap();
        obj(get(&data, "devices").clone()).into_iter().filter(|(k, v)| name_re.is_match(k) && v.is_object()).collect()
    }

    pub fn resolve_port(&self, port: &str) -> String {
        if port.is_empty() || port.starts_with('/') || port.contains("://") {
            return port.into();
        }
        match Self::ssh_store().keys().find(|k| k.to_lowercase() == port.to_lowercase()) {
            Some(name) => format!("{}{name}", util::SSH_SCHEME),
            None => port.into(),
        }
    }

    fn ssh_devices(&self) -> Vec<Value> {
        let m = self.manager("");
        if m.socket_ready() {
            if let Ok(r) = m.request("ssh_devices", 3.0, Map::new()) {
                return r.get("devices").and_then(Value::as_array).cloned().unwrap_or_default();
            }
        }
        let keep = ["name", "host", "port", "user", "remote_socket", "control_socket", "screen_path", "restart_args",
                    "follow_socket_suffix", "screen_revision_header", "screen_size_header", "restart_conf_hint", "paired_at",
                    "fingerprint", "installer", "key_protected"];
        let mut store: Vec<(String, Value)> = Self::ssh_store().into_iter().collect();
        store.sort_by(|a, b| a.0.cmp(&b.0));
        store.into_iter().map(|(name, d)| {
            let mut p: Payload = keep.iter().filter_map(|k| d.get(*k).map(|v| (k.to_string(), v.clone()))).collect();
            p.insert("port_url".into(), json!(format!("{}{name}", util::SSH_SCHEME)));
            p.insert("link".into(), Value::Null);
            Value::Object(p)
        }).collect()
    }

    pub fn list_ports(&self) -> AResult {
        let mut claimed: HashMap<String, Value> = HashMap::new();
        let m = self.manager("");
        if m.socket_ready() {
            if let Ok(s) = m.status() {
                for c in s.get("channels").and_then(Value::as_array).cloned().unwrap_or_default() {
                    if let Some(p) = c.get("port").and_then(Value::as_str).filter(|p| !p.is_empty()) {
                        claimed.insert(port_identity(p), c.clone());
                    }
                }
            }
        }
        let ports: Vec<Value> = crate::ports::discover().into_iter().map(|item| {
            let device = item["device"].as_str().unwrap_or("").to_string();
            let mut info = merge(item.clone(), crate::ports::usb_identity(&device));
            let channel = claimed.get(&port_identity(&device));
            info.insert("hub_channel".into(), channel.map_or(Value::Null, |c| json!({"baud": get(c, "baud"), "clients": get(c, "client_count")})));
            let text = py_str(&item["description"]).to_lowercase();
            let hint = if text.contains("jtag") || text.contains("usb serial") { "possibly an ESP32 USB console (confirm with serial_hello)" } else { "" };
            info.insert("hint".into(), json!(hint));
            Value::Object(info)
        }).collect();
        let remote: Vec<Value> = self.ssh_devices().iter().map(|d| {
            let link = get(d, "link");
            json!({"device": get(d, "name"), "port": get(d, "port_url"), "kind": "ssh-socket",
                   "host": format!("{}@{}", py_str(get(d, "user")), py_str(get(d, "host"))),
                   "remote_socket": get(d, "remote_socket"), "link_state": get(link, "state"),
                   "hint": "remote Unix socket over SSH; connect with its name"})
        }).collect();
        Ok(obj(json!({"ports": ports, "ssh_devices": remote})))
    }

    pub fn connect(&self, port: &str, baud: Option<i64>, mode: &str, change_live_baud: bool) -> AResult {
        if mode != "control" && mode != "raw" {
            return err("invalid_argument", "mode must be 'control' or 'raw'", "");
        }
        let port = self.resolve_port(port);
        if port.is_empty() || !(util::is_device_port(&port) || util::is_non_serial_port(&port)) {
            return err("invalid_argument", "port must be a device path, COM port, a tcp:// / udp:// / unix:// endpoint or a paired SSH device name", "");
        }
        if change_live_baud {
            if baud.is_none_or(|b| b == 0) {
                return err("invalid_argument", "change_live_baud needs an explicit baud", "");
            }
            self.require("interact")?;
        }
        let on_conflict = if change_live_baud { "retime" } else { "error" };
        let key = port_identity(&port);
        let mut st = self.state.lock().unwrap();
        let existing = st.sessions.iter().find(|(k, _)| *k == key).map(|(_, s)| s.clone());
        if let Some(ex) = &existing {
            if ex.lost().is_none() && ex.mode == mode {
                if change_live_baud && baud != Some(ex.manager.baud()) {
                    ex.manager.claim(&port, baud.unwrap(), on_conflict)
                        .map_err(|e| AgentError::new("transport_unavailable", format!("cannot retime {port}: {e}"), ""))?;
                    ex.note(&format!("UART baud set to {} for every client", ex.manager.baud()), "note");
                }
                return Ok(obj(json!({"port": ex.port, "baud": ex.manager.baud(), "mode": mode, "already_connected": true,
                                     "opened_uart": false, "generation": ex.generation, "cursor": ex.cursor()})));
            }
            ex.close();
            st.sessions.retain(|(k, _)| *k != key);
        }
        if st.sessions.len() >= MAX_SESSIONS {
            return err("busy", format!("at most {MAX_SESSIONS} ports can be connected"), "");
        }
        let root = self.root()?;
        let live = root.status().map_err(|e| AgentError::new("transport_unavailable", format!("cannot connect {port}: {e}"), ""))?;
        let channel = live.get("channels").and_then(Value::as_array).cloned().unwrap_or_default().into_iter()
            .find(|c| c.get("port").and_then(Value::as_str).is_some_and(|p| !p.is_empty() && port_identity(p) == key));
        let manager = Arc::new(Manager::new(&root.socket_path));
        let requested = match baud {
            Some(b) if b != 0 => b,
            _ => channel.as_ref().and_then(|c| py_int(get(c, "baud"))).unwrap_or(2_000_000),
        };
        let opened = channel.is_none();
        let session = (|| -> Result<Arc<Session>, String> {
            match manager.claim(&port, requested, on_conflict) {
                Err(HubError::Refused { baud_conflict: true, .. }) => manager.claim(&port, requested, "join").map_err(|e| hub_err(&e))?,
                other => other.map_err(|e| hub_err(&e))?,
            }
            Session::open(manager.clone(), &port, mode)
        })().map_err(|e| AgentError::new("transport_unavailable", format!("cannot connect {port}: {e}"), ""))?;
        st.sessions.push((key, session.clone()));
        drop(st);
        session.note(&format!("attached to {port} @ {} baud ({mode})", manager.baud()), "note");
        let mut result = obj(json!({"port": port, "baud": manager.baud(), "mode": mode, "already_connected": false,
            "opened_uart": opened, "generation": session.generation, "cursor": session.cursor(),
            "history": "records are kept only from this attach onwards"}));
        if let Some(b) = baud.filter(|b| *b != 0 && *b != manager.baud()) {
            result.insert("baud_note".into(), json!(format!("hub kept the live baud {}; requested {b} was not applied. Ask the user before retrying with change_live_baud=true: it changes the baud for every client on this port", manager.baud())));
        }
        if mode == "control" {
            let hello = session.request(None, Value::Null, 2.0, None)?;
            let h = if hello.get("outcome").and_then(Value::as_str) == Some("completed") { hello.get("hello").cloned().unwrap_or(Value::Null) } else { Value::Null };
            if h.is_null() {
                result.insert("hello".into(), Value::Null);
                result.insert("hello_note".into(), json!("no HELLO reply within 2 s (firmware without control plane, or busy)"));
            } else {
                result.insert("hello".into(), h);
            }
        }
        Ok(result)
    }

    pub fn disconnect(&self, port: Option<&str>) -> AResult {
        let session = self.session(port)?;
        let key = port_identity(&session.port);
        self.state.lock().unwrap().sessions.retain(|(k, _)| *k != key);
        session.close();
        Ok(obj(json!({"port": session.port, "disconnected": true})))
    }

    pub fn close(&self) {
        let (sessions, jobs, pending) = {
            let mut st = self.state.lock().unwrap();
            let s: Vec<_> = st.sessions.drain(..).map(|(_, s)| s).collect();
            let j: Vec<_> = st.jobs.values().cloned().collect();
            let p: Vec<_> = st.pending.drain().map(|(_, (snap, _))| snap).collect();
            (s, j, p)
        };
        for s in sessions {
            s.close();
        }
        for j in jobs {
            if let Some(m) = j.manager.lock().unwrap().take() {
                m.unsubscribe_all();
            }
        }
        for snap in pending {
            if snap.state().get("state").and_then(Value::as_str) == Some("prepared") {
                snap.remove();
            }
        }
        self.collect_snapshots();
        if let Some(a) = &self.activity {
            a.close();
        }
    }

    // ---- firmware

    pub fn hello(&self, port: Option<&str>, timeout: f64, cancel: &Cancel) -> AResult {
        self.session(port)?.request(None, Value::Null, timeout, Some(cancel))
    }

    pub fn query(&self, kind: &str, port: Option<&str>, timeout: f64, redact_identity: bool, cancel: &Cancel) -> AResult {
        if !QUERY_KINDS.contains(&kind) {
            return err("invalid_argument", format!("kind must be one of {}", QUERY_KINDS.join(", ")), "");
        }
        let mut result = self.session(port)?.request(Some("query"), json!({"kind": kind}), timeout, Some(cancel))?;
        if kind == "identity" && redact_identity {
            if let Some(v @ (Value::String(_) | Value::Number(_))) = result.get("result") {
                let n = py_str(v).chars().count();
                result.insert("result".into(), json!(format!("[redacted {n} chars]")));
            }
            if let Some(Value::Array(frames)) = result.get_mut("frames") {
                for f in frames.iter_mut() {
                    if let Some(o) = f.as_object_mut().filter(|o| o.contains_key("result")) {
                        o.insert("result".into(), json!("[redacted]"));
                    }
                }
            }
            return Ok(obj(redact_value(&Value::Object(result), true)));
        }
        Ok(result)
    }

    pub fn button(&self, button: &str, action: &str, port: Option<&str>, timeout: f64) -> AResult {
        self.require("interact")?;
        if !BUTTONS.contains(&button) || !BUTTON_ACTIONS.contains(&action) {
            return err("invalid_argument", format!("button in {BUTTONS:?}, action in {BUTTON_ACTIONS:?}"), "");
        }
        let s = self.session(port)?;
        s.note(&format!("button {button} {action}"), "note");
        if action != "click" {
            return s.request(Some("input.button"), json!({"button": button, "action": action}), timeout, None);
        }
        let pressed = s.request(Some("input.button"), json!({"button": button, "action": "press"}), timeout, None)?;
        if pressed.get("status").and_then(Value::as_str) != Some("succeeded") {
            return Ok(pressed);
        }
        s.request(Some("input.button"), json!({"button": button, "action": "release"}), timeout, None)
    }

    pub fn show_info(&self, port: Option<&str>, timeout: f64) -> AResult {
        self.require("interact")?;
        let s = self.session(port)?;
        s.note("ui.show_info", "note");
        s.request(Some("ui.show_info"), json!({}), timeout, None)
    }

    // ---- scripts

    fn script_control(&self, action: &str, payload: Value) -> AResult {
        let root = self.root()?;
        root.request(action, 3.0, obj(payload)).map_err(|e| {
            let m = e.to_string();
            let code = if m.to_lowercase().contains("script") { "invalid_argument" } else { "transport_unavailable" };
            AgentError::new(code, redact(&m), "")
        })
    }

    pub fn script_list(&self) -> AResult {
        let r = self.script_control("script_list", json!({}))?;
        let runs = self.script_control("script_status", json!({}))?;
        Ok(obj(json!({"scripts": get(&Value::Object(r.clone()), "scripts"), "autorun": r.get("autorun"), "folder": r.get("folder"), "runs": runs.get("runs")})))
    }

    pub fn script_run(&self, name: &str, port: Option<&str>, baud: Option<i64>) -> AResult {
        self.require("interact")?;
        let s = self.session(port)?;
        s.note(&format!("script run {name}"), "note");
        let baud = baud.filter(|b| *b != 0).unwrap_or_else(|| s.manager.baud());
        let r = self.script_control("script_run", json!({"name": name, "port": s.port, "baud": baud}))?;
        Ok(obj(json!({"run": r.get("run"), "next": "poll script_status(run_id) for its output"})))
    }

    pub fn script_stop(&self, run_id: &str) -> AResult {
        self.require("interact")?;
        let r = self.script_control("script_stop", json!({"id": run_id}))?;
        Ok(obj(json!({"run": r.get("run")})))
    }

    pub fn script_status(&self, run_id: Option<&str>, after: i64, limit: i64) -> AResult {
        let Some(id) = run_id else {
            let r = self.script_control("script_status", json!({}))?;
            return Ok(obj(json!({"runs": r.get("runs")})));
        };
        let r = Value::Object(self.script_control("script_logs", json!({"id": id, "after": after, "limit": limit}))?);
        let lines: Vec<Value> = get(&r, "lines").as_array().cloned().unwrap_or_default().iter()
            .map(|l| json!({"seq": get(l, "seq"), "text": redact(&py_str(get(l, "text")))})).collect();
        Ok(obj(json!({"run": get(&r, "run"), "lines": lines, "cursor": get(&r, "cursor"), "dropped": get(&r, "dropped")})))
    }

    // ---- ssh devices

    fn ssh_session_name(&self, port: Option<&str>, what: &str) -> AResult<(Arc<Session>, String)> {
        let s = self.session(port)?;
        s.ensure_alive()?;
        let name = s.port.strip_prefix(util::SSH_SCHEME).map(str::to_string);
        match name {
            Some(n) if Regex::new(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}$").unwrap().is_match(&n) => Ok((s, n)),
            Some(_) => err("invalid_argument", format!("invalid SSH device: {}", s.port), ""),
            None => err("not_supported", format!("{what} needs a paired SSH device"), ""),
        }
    }

    pub fn screenshot(&self, port: Option<&str>, after_revision: Option<i64>) -> AResult {
        let (s, name) = self.ssh_session_name(port, "a screenshot")?;
        s.manager.request("ssh_screen", 8.0, obj(json!({"name": name, "after_revision": after_revision})))
            .map_err(|e| AgentError::new("transport_unavailable", format!("screen frame failed: {e}"), "pair the device with a control_socket and screen_path"))
    }

    pub fn restart(&self, port: Option<&str>, arg: &str) -> AResult {
        self.require("hardware")?;
        let (s, name) = self.ssh_session_name(port, "restart")?;
        s.note(&format!("restart {arg}"), "note");
        s.manager.request("ssh_restart", 30.0, obj(json!({"name": name, "arg": arg}))).map_err(|e| {
            let code = match &e {
                HubError::Refused { code, .. } if !code.is_empty() => code.clone(),
                _ => "transport_unavailable".into(),
            };
            AgentError::new(&code, format!("restart failed: {e}"), "")
        })
    }

    pub fn reset(&self, port: Option<&str>, wait_for: &[String], timeout: f64, cancel: &Cancel) -> AResult {
        self.require("hardware")?;
        let s = self.session(port)?;
        s.ensure_alive()?;
        if util::is_non_serial_port(&s.port) {
            return err("invalid_state", "reset needs a physical UART, not a network/socket endpoint", "");
        }
        let cursor = s.cursor();
        s.note("reset (RTS/EN pulse)", "note");
        s.manager.request("reset", 3.0, Map::new()).map_err(|e| AgentError::new("hardware_unavailable", format!("reset failed: {e}"), ""))?;
        let mut result = obj(json!({"reset": true, "cursor": cursor}));
        if !wait_for.is_empty() {
            result.insert("boot".into(), Value::Object(s.wait_for(wait_for, timeout, Some(cursor), false, 10, Some(cancel))?));
        }
        Ok(result)
    }

    pub fn bootloader(&self, port: Option<&str>) -> AResult {
        self.require("hardware")?;
        let s = self.session(port)?;
        s.ensure_alive()?;
        if util::is_non_serial_port(&s.port) {
            return err("invalid_state", "bootloader needs a physical UART, not a network/socket endpoint", "");
        }
        s.note("enter ROM bootloader (DTR/RTS)", "note");
        s.manager.request("bootloader", 3.0, Map::new()).map_err(|e| AgentError::new("hardware_unavailable", format!("bootloader entry failed: {e}"), ""))?;
        Ok(obj(json!({"bootloader": true, "note": "the app stops until the next reset or flash"})))
    }

    // ---- flash

    pub fn collect_snapshots(&self) -> Vec<String> {
        let keep: Vec<String> = {
            let st = self.state.lock().unwrap();
            st.pending.keys().cloned().chain(st.jobs.values().filter(|j| j.state.lock().unwrap().finished.is_none()).map(|j| j.token.clone())).collect()
        };
        let hub_status = |socket: &str| -> Result<Option<Value>, ()> {
            let m = self.manager(socket);
            if !m.socket_ready() {
                return Ok(None);
            }
            m.status().map(|s| Some(Value::Object(s))).map_err(|_| ())
        };
        snapshot::collect_snapshots(&hub_status, None, &keep)
    }

    fn binding(session: &Session, flash_baud: i64, snap: &Snapshot) -> Value {
        json!({"port": port_identity(&session.port), "usb": crate::ports::usb_identity(&session.port),
               "generation": session.generation, "flash_baud": flash_baud,
               "hashes": snap.images.iter().map(|i| i.sha256.clone()).collect::<Vec<_>>()})
    }

    pub fn flash_preview(&self, build_dir: &str, port: Option<&str>, flash_baud: i64) -> AResult {
        let s = self.session(port)?;
        s.ensure_alive()?;
        if util::is_non_serial_port(&s.port) {
            return err("invalid_state", "flash needs a physical UART", "");
        }
        if !(115_200..=5_000_000).contains(&flash_baud) {
            return err("invalid_argument", "flash_baud must be between 115200 and 5000000", "");
        }
        self.collect_snapshots();
        let snap = snapshot::prepare_snapshot(build_dir, None).map_err(|e| match e {
            snapshot::PrepareError::Policy(m) => AgentError::new("flash_refused", m, ""),
            snapshot::PrepareError::Io(m) => AgentError::new("invalid_argument", format!("cannot read build: {m}"), ""),
        })?;
        let preview = s.manager.request("flash_preview", 3.0, obj(json!({"build_dir": snap.directory.to_string_lossy(), "flash_baud": flash_baud})));
        let command: Vec<String> = match preview {
            Err(e) => {
                snap.remove();
                return err("flash_refused", format!("hub preview failed: {e}"), "");
            }
            Ok(p) => p.get("command").and_then(Value::as_array).cloned().unwrap_or_default().iter().map(py_str).collect(),
        };
        if !snapshot::command_paths_inside(&command, &snap.directory) {
            snap.remove();
            return err("flash_refused", "hub preview does not point at the snapshot", "");
        }
        let binding = Self::binding(&s, flash_baud, &snap);
        let result = obj(json!({"token": snap.token, "expires_in_s": (snap.expires - util::now()) as i64, "port": s.port,
            "device": binding["usb"], "flash_baud": flash_baud, "build_dir": snap.build_dir, "project": snap.project,
            "images": snap.images.iter().map(|i| i.summary()).collect::<Vec<_>>(),
            "command": command.iter().map(|c| redact(c)).collect::<Vec<_>>(),
            "next": "show this to the user; after explicit approval call serial_flash_start(token)"}));
        self.state.lock().unwrap().pending.insert(snap.token.clone(), (snap, binding));
        Ok(result)
    }

    pub fn flash_start(&self, token: &str) -> AResult {
        self.require("hardware")?;
        let Some((snap, binding)) = self.state.lock().unwrap().pending.remove(token) else {
            return err("token_invalid", "unknown, used or expired flash token", "call serial_flash_preview again");
        };
        let checked = (|| -> AResult<(Arc<Session>, Payload)> {
            if util::now() > snap.expires {
                return err("token_invalid", "flash token expired", "call serial_flash_preview again");
            }
            let s = self.session(binding["port"].as_str())?;
            s.ensure_alive()?;
            let current = Self::binding(&s, binding["flash_baud"].as_i64().unwrap_or(0), &snap);
            if current != binding {
                let mut changed: Vec<String> = obj(binding.clone()).keys().filter(|k| binding[k.as_str()] != current[k.as_str()]).cloned().collect();
                changed.sort();
                let list = changed.iter().map(|k| format!("'{k}'")).collect::<Vec<_>>().join(", ");
                return err("token_invalid", format!("device or channel changed since preview: [{list}]"), "call serial_flash_preview again");
            }
            snap.verify().map_err(|e| AgentError::new("token_invalid", e.0, ""))?;
            let status = s.manager.status().map_err(|e| AgentError::new("transport_unavailable", e.to_string(), ""))?;
            if truthy(get(get(&Value::Object(status.clone()), "flash"), "active")) {
                return err("busy", "a flash is already running on this channel", "");
            }
            Ok((s, status))
        })();
        let (s, status) = match checked {
            Ok(v) => v,
            Err(e) => {
                snap.remove();
                return Err(e);
            }
        };
        let flash_id_before = py_int(get(get(&Value::Object(status.clone()), "flash"), "id")).unwrap_or(0);
        let manager = Arc::new(Manager::new(&s.manager.socket_path));
        *manager.channel_socket.lock().unwrap() = s.manager.channel();
        let n_images = snap.images.len();
        let build = snap.build_dir.clone();
        let directory = snap.directory.to_string_lossy().into_owned();
        let job = Arc::new(FlashJob {
            token: token.into(),
            session_port: port_identity(&s.port),
            snapshot: snap,
            started: util::now(),
            manager: Mutex::new(Some(manager.clone())),
            state: Mutex::default(),
            finalize: Mutex::new(()),
        });
        let (weak_job, weak_agent) = (Arc::downgrade(&job), self.me.clone());
        let subscribed = manager.subscribe(Arc::new(move |event: &Value| {
            if let (Some(j), Some(a)) = (weak_job.upgrade(), weak_agent.upgrade()) {
                a.on_flash_status(&j, event, true);
            }
        }));
        if let Err(e) = subscribed {
            job.snapshot.remove();
            return err("transport_unavailable", format!("cannot watch the flash: {e}"), "nothing was flashed; call serial_flash_preview again");
        }
        let guard = job.finalize.lock().unwrap();
        job.snapshot.set_state("sending", obj(json!({"hub_pid": status.get("pid"), "hub_socket": s.manager.socket_path,
            "channel_socket": s.manager.channel(), "flash_id_before": flash_id_before})));
        self.state.lock().unwrap().jobs.insert(token.into(), job.clone());
        s.note(&format!("flash start {build} ({n_images} images)"), "note");
        let accepted = s.manager.request("flash", 3.0, obj(json!({"build_dir": directory, "flash_baud": binding["flash_baud"]})));
        let accepted = match accepted {
            Ok(a) => a,
            Err(e) => {
                drop(guard);
                return Ok(obj(json!({"token": token, "accepted": null, "outcome": "unknown", "reason": redact(&e.to_string()),
                                     "hint": "do not retry; call serial_flash_status to learn whether it started"})));
            }
        };
        let flash_id = {
            let mut js = job.state.lock().unwrap();
            if js.flash_id.is_none() {
                js.flash_id = py_int(get(&Value::Object(accepted), "flash_id")).filter(|i| *i != 0);
            }
            js.flash_id
        };
        job.snapshot.set_state("in_use", obj(json!({"flash_id": flash_id.unwrap_or(0)})));
        drop(guard);
        Ok(obj(json!({"token": token, "accepted": true, "flash_id": flash_id, "port": s.port,
                      "next": "call serial_flash_status(token, wait_s=...) until it finishes"})))
    }

    fn on_flash_status(&self, job: &FlashJob, event: &Value, pushed: bool) {
        if get(event, "event") != "status" {
            return;
        }
        let channel = get(event, "channel_socket");
        if let (false, Some(m)) = (channel.is_null(), job.manager.lock().unwrap().as_ref()) {
            if channel != &json!(m.channel()) {
                return;
            }
        }
        let flash = get(event, "flash");
        if !flash.is_object() || !job.owns(flash) {
            return;
        }
        // Only for a finished flash, like Python, and before the job lock: the push
        // thread never waits on agent/session locks per progress event.
        let completion_cursor = if !truthy(get(flash, "active")) && !get(flash, "exit_code").is_null() {
            let session = self.state.lock().unwrap().sessions.iter().find(|(k, _)| *k == job.session_port).map(|(_, x)| x.clone());
            session.map(|x| x.cursor())
        } else {
            None
        };
        let mut s = job.state.lock().unwrap();
        let revision = get(event, "revision").as_i64();
        if pushed {
            if let Some(r) = revision {
                if s.last_revision.is_some_and(|l| r > l + 1) {
                    s.gaps += 1;
                }
                s.last_revision = Some(r.max(s.last_revision.unwrap_or(0)));
            }
        }
        let flash_id = py_int(get(flash, "id")).unwrap_or(0);
        match s.flash_id {
            None => s.flash_id = Some(flash_id),
            Some(id) if id != flash_id => return,
            _ => {}
        }
        let line = match get(flash, "line") {
            Value::Null => String::new(),
            l => py_str(l),
        };
        if pushed && !line.is_empty() && line != s.last_line {
            if FLASH_VERIFIED_RE.is_match(&line) {
                s.verified_transitions += 1;
            }
            s.last_line = line;
        }
        s.events.push(json!({"progress": get(flash, "progress"), "step": redact(&py_str(get(flash, "step")))}));
        let n = s.events.len();
        if n > 50 {
            s.events.drain(..n - 50);
        }
        if !truthy(get(flash, "active")) && !get(flash, "exit_code").is_null() && s.finished.is_none() {
            if !pushed {
                s.poll_revision = Some(revision.unwrap_or(-1));
            }
            s.finished = Some(json!({"exit_code": get(flash, "exit_code"), "error": flash.get("error").cloned().unwrap_or(json!("")),
                                      "step": get(flash, "step"), "state": get(event, "state"), "port": get(event, "port")}));
            s.completion_cursor = completion_cursor;
        }
    }

    fn poll_job(&self, job: &FlashJob) {
        let manager = job.manager.lock().unwrap().clone();
        let Some(m) = manager else { return };
        if job.state.lock().unwrap().finished.is_some() {
            return;
        }
        let Ok(status) = m.status() else { return };
        let status = Value::Object(status);
        let flash = get(&status, "flash");
        {
            let mut s = job.state.lock().unwrap();
            let unowned = flash.is_object() && !job.owns(flash) && !truthy(get(flash, "active"));
            if unowned && s.flash_id.is_none() && s.events.is_empty() && util::now() - job.started > snapshot::UNACCEPTED_GRACE {
                s.finished = Some(json!({"exit_code": null, "error": "the hub never started this flash", "step": "not started",
                                          "state": get(&status, "state"), "port": get(&status, "port")}));
                return;
            }
        }
        self.on_flash_status(job, &status, false);
    }

    pub fn flash_status(&self, token: &str, wait_s: f64, progress: &dyn Fn(f64, &str), cancel: &Cancel) -> AResult {
        let Some(job) = self.state.lock().unwrap().jobs.get(token).cloned() else {
            return err("token_invalid", "no flash job for this token", "");
        };
        let deadline = Instant::now() + Duration::from_secs_f64(wait_s.clamp(0.0, MAX_FLASH_WAIT_S));
        let mut reported = -1.0;
        let summary = loop {
            self.poll_job(&job);
            let summary = job.summary();
            let value = summary["progress"].as_f64().unwrap_or(0.0);
            if value > reported {
                reported = value;
                progress(value, &py_str(&summary["step"]));
            }
            if job.state.lock().unwrap().finished.is_some() {
                let wait = Instant::now() + Duration::from_secs(1);
                while Instant::now() < wait && !push_caught_up(&job.state.lock().unwrap()) {
                    std::thread::sleep(Duration::from_millis(50));
                }
                break summary;
            }
            if Instant::now() >= deadline || cancel.load(Ordering::SeqCst) {
                break summary;
            }
            std::thread::sleep(Duration::from_millis(250));
        };
        let summary = obj(summary);
        if job.state.lock().unwrap().finished.is_none() {
            return Ok(merge(summary, obj(json!({"verdict": "running", "hint": "call again with wait_s to keep waiting"}))));
        }
        Ok(merge(summary, self.finalize(&job)))
    }

    fn finalize(&self, job: &FlashJob) -> Payload {
        let _g = job.finalize.lock().unwrap();
        if let Some(v) = job.state.lock().unwrap().verdict.clone() {
            return v;
        }
        let verdict = self.verdict(job);
        job.state.lock().unwrap().verdict = Some(verdict.clone());
        if let Some(m) = job.manager.lock().unwrap().as_ref() {
            m.unsubscribe_all();
        }
        job.snapshot.set_state("done", Map::new());
        job.snapshot.remove();
        verdict
    }

    fn verdict(&self, job: &FlashJob) -> Payload {
        let (finished, transitions, evidence_complete, completion_cursor) = {
            let s = job.state.lock().unwrap();
            (s.finished.clone().unwrap_or(json!({})), s.verified_transitions, s.gaps == 0 && push_caught_up(&s), s.completion_cursor)
        };
        let exit_ok = finished["exit_code"] == 0 && !truthy(get(&finished, "error"));
        let images = job.snapshot.images.len();
        let flash_verified = if !exit_ok { Some(false) } else if evidence_complete && transitions == images { Some(true) } else { None };
        let session = self.session(Some(&job.session_port)).ok();
        let uart_reopened = session.as_ref().is_some_and(|s| s.lost().is_none())
            && ["ready", "flashing"].iter().any(|x| get(&finished, "state") == *x)
            && truthy(get(&finished, "port"));
        let mut firmware_ready: Option<bool> = None;
        let mut boot_evidence = Value::Null;
        if let (Some(s), Some(cursor)) = (&session, completion_cursor) {
            if s.lost().is_none() && exit_ok {
                if s.mode == "control" {
                    firmware_ready = Some(s.request(None, Value::Null, 3.0, None).is_ok_and(|h| {
                        h.get("outcome").and_then(Value::as_str) == Some("completed") && h.get("status").and_then(Value::as_str) == Some("succeeded")
                    }));
                }
                if firmware_ready != Some(true) {
                    let found = s.select(Some(cursor), 20, &[], &[], false, false);
                    let texts: Vec<Value> = found["records"].as_array().cloned().unwrap_or_default().iter().map(|r| get(r, "text").clone()).collect();
                    let tail = texts[texts.len().saturating_sub(5)..].to_vec();
                    boot_evidence = if tail.is_empty() { Value::Null } else { Value::Array(tail) };
                    firmware_ready = if s.mode == "control" { Some(false) } else if texts.is_empty() { None } else { Some(true) };
                }
            }
        }
        let verdict = if flash_verified == Some(true) && uart_reopened && firmware_ready == Some(true) {
            "verified"
        } else if flash_verified == Some(false) {
            "blocked"
        } else if flash_verified.is_none() {
            "unknown"
        } else {
            "partial"
        };
        let text = |v: &Value| if truthy(v) { redact(&py_str(v)) } else { String::new() };
        obj(json!({"verdict": verdict, "flash_verified": flash_verified, "verified_images": format!("{transitions}/{images}"),
                   "evidence_complete": evidence_complete, "uart_reopened": uart_reopened, "firmware_ready": firmware_ready,
                   "boot_evidence": boot_evidence, "exit_code": get(&finished, "exit_code"),
                   "error": text(get(&finished, "error")), "step": text(get(&finished, "step"))}))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w(rid: &str) -> Waiter {
        Waiter { request_id: Some(rid.into()), sequence: 9, last_event_seq: -1, ..Default::default() }
    }

    #[test]
    fn waiter_lifecycle() {
        let mut a = w("r1");
        assert!(!a.offer(FRAME_RESPONSE, 9, &json!({"request_id": "other", "status": "succeeded"})));
        assert!(a.offer(FRAME_EVENT, 9, &json!({"request_id": "r1", "status": "running", "event_seq": 2, "operation_id": "op"})));
        assert!(a.offer(FRAME_EVENT, 9, &json!({"request_id": "r1", "status": "accepted", "event_seq": 1})));
        assert_eq!(a.status.as_deref(), Some("running"));
        assert!(a.offer(FRAME_EVENT, 9, &json!({"request_id": "r1", "status": "accepted", "event_seq": 3, "operation_id": "op"})));
        assert_eq!(a.status.as_deref(), Some("running"));
        assert!(!a.offer(FRAME_RESPONSE, 9, &json!({"request_id": "r1", "status": "succeeded", "operation_id": "zz"})));
        assert!(a.offer(FRAME_RESPONSE, 9, &json!({"request_id": "r1", "status": "succeeded", "result": "{}"})));
        assert!(a.done && a.status.as_deref() == Some("succeeded"));
        assert!(a.offer(FRAME_EVENT, 9, &json!({"request_id": "r1", "status": "failed"})));
        assert_eq!(a.status.as_deref(), Some("succeeded"));
        let mut e = w("r2");
        assert!(e.offer(FRAME_ERROR, 9, &json!({"error": "invalid_schema"})));
        assert_eq!(e.status.as_deref(), Some("rejected"));
        let mut h = Waiter { hello: true, sequence: 4, ..Default::default() };
        assert!(!h.offer(FRAME_HELLO, 5, &json!({})));
        assert!(h.offer(FRAME_HELLO, 4, &json!({"type": "hello"})));
        assert_eq!(h.status.as_deref(), Some("succeeded"));
    }

    #[test]
    fn levels_and_clip() {
        assert_eq!(parse_level("E (12) app: boom"), "error");
        assert_eq!(parse_level("x W (1) y"), "warning");
        assert_eq!(parse_level("hello"), "plain");
        let long = "é".repeat(2005);
        assert!(clip(&long).ends_with("…[+5 chars]"));
    }

    #[test]
    fn select_pages() {
        let r = Records::new("MCP test", None);
        for seq in 1..=10i64 {
            let kind = if seq == 5 { "frame" } else { "log" };
            r.append(&obj(json!({"seq": seq, "kind": kind, "level": if seq == 3 { "error" } else { "plain" }, "text": format!("n{seq} token=abc")})));
        }
        let latest = select_records(&r, 11, None, 3, &[], &[], false, true);
        assert_eq!(latest["records"].as_array().unwrap().iter().map(|x| x["seq"].clone()).collect::<Vec<_>>(), [json!(8), json!(9), json!(10)]);
        assert_eq!(latest["records"][0]["text"], json!("n8 token=[redacted]"));
        let page = select_records(&r, 11, Some(4), 2, &[], &[], false, true);
        assert_eq!(page["records"].as_array().unwrap().iter().map(|x| x["seq"].clone()).collect::<Vec<_>>(), [json!(4), json!(6)]);
        assert_eq!(page["next_cursor"], json!(7));
        assert_eq!(page["truncated"], json!(true));
        let errs = select_records(&r, 11, Some(1), 50, &[], &["error".into()], false, true);
        assert_eq!(errs["records"].as_array().unwrap().len(), 1);
        let hits = select_records(&r, 11, Some(1), 50, &["N1 ".into()], &[], false, true);
        assert_eq!(hits["records"].as_array().unwrap().len(), 1);
    }
}
