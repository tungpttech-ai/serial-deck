//! serial-deck MCP server (stdio) in Rust: a drop-in for `python -m serial_deck.mcp_server`.
//!
//! Hand-rolled JSON-RPC over newline-delimited stdin/stdout. Every `tools/call`
//! runs on its own thread so long waits never block `ping` or cancellation.

mod agent;
mod codec;
mod hub;
mod logcache;
mod ports;
mod snapshot;
mod util;

use agent::{AResult, Agent, AgentError, Cancel, Payload};
use regex::Regex;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::io::{BufRead, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use util::{get, obj, py_str, redact};

const SERVER_VERSION: &str = "1.0.0";
const HANDSHAKE_VERSIONS: [&str; 4] = ["2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"];
static SPEC: LazyLock<Value> = LazyLock::new(|| serde_json::from_str(include_str!("tools.json")).unwrap());

/// Policy level that registers each tool (the `@tool(level, ...)` decorators).
fn tool_level(name: &str) -> &'static str {
    match name {
        "serial_button" | "serial_script_run" | "serial_script_stop" | "serial_show_info" => "interact",
        "serial_restart" | "serial_reset" | "serial_bootloader" | "serial_flash_start" => "hardware",
        _ => "observe",
    }
}

/// The `TOOL_LEVELS` table behind `status.disabled_tools` (it omits a few tools, as in Python).
const STATUS_LEVELS: [(&str, &str); 20] = [
    ("serial_status", "observe"), ("serial_list_ports", "observe"), ("serial_connect", "observe"),
    ("serial_disconnect", "observe"), ("serial_hello", "observe"), ("serial_query", "observe"),
    ("serial_logs", "observe"), ("serial_wait_for", "observe"), ("serial_symbolize", "observe"),
    ("serial_flash_preview", "observe"), ("serial_flash_status", "observe"),
    ("serial_script_list", "observe"), ("serial_script_status", "observe"),
    ("serial_script_run", "interact"), ("serial_script_stop", "interact"),
    ("serial_button", "interact"), ("serial_show_info", "interact"),
    ("serial_reset", "hardware"), ("serial_bootloader", "hardware"), ("serial_flash_start", "hardware"),
];

struct Server {
    agent: Arc<Agent>,
    prefix: String,
    out: Mutex<std::io::Stdout>,
    calls: Mutex<HashMap<String, Cancel>>,
}

impl Server {
    fn send(&self, msg: &Value) {
        let mut line = serde_json::to_vec(msg).unwrap_or_default();
        line.push(b'\n');
        let mut out = self.out.lock().unwrap();
        let _ = out.write_all(&line);
        let _ = out.flush();
    }

    fn renamed(&self, text: &str) -> String {
        if self.prefix == "serial" {
            return text.to_string();
        }
        static RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bserial_([a-z])").unwrap());
        RE.replace_all(text, format!("{}_$1", self.prefix)).into_owned()
    }

    fn external(&self, name: &str) -> String {
        format!("{}{}", self.prefix, &name["serial".len()..])
    }

    fn internal(&self, name: &str) -> Option<String> {
        name.strip_prefix(&format!("{}_", self.prefix)).map(|rest| format!("serial_{rest}"))
    }

    fn tools(&self) -> Vec<Value> {
        SPEC["tools"].as_array().unwrap().iter().filter(|t| self.agent.allows(tool_level(t["name"].as_str().unwrap()))).map(|t| {
            let mut t = t.clone();
            let name = self.external(t["name"].as_str().unwrap());
            t["name"] = json!(name);
            t
        }).collect()
    }

    fn handle(self: &Arc<Self>, msg: Value) {
        let id = msg.get("id").cloned();
        let method = msg.get("method").and_then(Value::as_str).unwrap_or("");
        let params = msg.get("params").cloned().unwrap_or(json!({}));
        let reply = |result: Value| json!({"jsonrpc": "2.0", "id": id, "result": result});
        match method {
            "initialize" => {
                let asked = get(&params, "protocolVersion").as_str().unwrap_or("");
                let version = if HANDSHAKE_VERSIONS.contains(&asked) { asked } else { HANDSHAKE_VERSIONS[3] };
                self.send(&reply(json!({
                    "capabilities": {"prompts": {"listChanged": false}, "resources": {"listChanged": false, "subscribe": false},
                                     "tools": {"listChanged": false}},
                    "instructions": self.renamed(SPEC["instructions"].as_str().unwrap()),
                    "protocolVersion": version,
                    "serverInfo": {"name": "serial-deck", "title": "Serial Deck", "version": SERVER_VERSION}})));
            }
            "ping" => self.send(&reply(json!({}))),
            "tools/list" => self.send(&reply(json!({"tools": self.tools()}))),
            "resources/list" => self.send(&reply(json!({"resources": []}))),
            "resources/templates/list" => self.send(&reply(json!({"resourceTemplates": []}))),
            "prompts/list" => self.send(&reply(json!({"prompts": []}))),
            "notifications/cancelled" => {
                let rid = get(&params, "requestId");
                if let Some(c) = self.calls.lock().unwrap().get(&rid.to_string()) {
                    c.store(true, Ordering::SeqCst);
                }
            }
            "tools/call" => {
                let Some(id) = id else { return };
                let cancel: Cancel = Arc::new(AtomicBool::new(false));
                self.calls.lock().unwrap().insert(id.to_string(), cancel.clone());
                let me = self.clone();
                let spawned = std::thread::Builder::new().stack_size(1 << 20).spawn(move || {
                    let result = me.call(&params, &cancel);
                    me.calls.lock().unwrap().remove(&id.to_string());
                    me.send(&json!({"jsonrpc": "2.0", "id": id, "result": result}));
                });
                if spawned.is_err() {
                    self.send(&json!({"jsonrpc": "2.0", "id": msg.get("id"), "error": {"code": -32603, "message": "cannot start worker"}}));
                }
            }
            m if m.starts_with("notifications/") => {}
            _ if id.is_some() => self.send(&json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32601, "message": "Method not found"}})),
            _ => {}
        }
    }

    fn call(&self, params: &Value, cancel: &Cancel) -> Value {
        let external = get(params, "name").as_str().unwrap_or("").to_string();
        let args = obj(params.get("arguments").cloned().unwrap_or(json!({})));
        let spec = self.internal(&external).and_then(|n| {
            SPEC["tools"].as_array().unwrap().iter().find(|t| t["name"] == n.as_str()).cloned()
        }).filter(|t| self.agent.allows(tool_level(t["name"].as_str().unwrap())));
        let Some(spec) = spec else {
            return json!({"content": [{"type": "text", "text": format!("Unknown tool: {external}")}], "isError": true});
        };
        let name = spec["name"].as_str().unwrap().to_string();
        let args = match validate(&spec["inputSchema"], args) {
            Ok(a) => a,
            Err(e) => {
                return json!({"content": [{"type": "text", "text": format!("Error executing tool {external}: {e}")}], "isError": true});
            }
        };
        let schema_props = obj(spec["inputSchema"]["properties"].clone());
        let call_args: Payload = args.iter().filter(|(k, v)| schema_props.get(*k).and_then(|p| p.get("default")) != Some(*v))
            .map(|(k, v)| (k.clone(), v.clone())).collect();
        let entry = self.agent.activity.as_ref().map(|a| a.begin(&external, &call_args));
        let progress_token = get(get(params, "_meta"), "progressToken").clone();
        let result = self.dispatch(&name, &args, cancel, &progress_token);
        let activity = self.agent.activity.as_ref();
        match result {
            Err(mut e) => {
                e.message = self.renamed(&e.message);
                e.hint = self.renamed(&e.hint);
                if let (Some(a), Some(id)) = (activity, entry) {
                    a.end(id, "error", &format!("{}: {}", e.code, e.message));
                    self.agent.publish_activity();
                }
                let payload = e.payload();
                json!({"content": [{"type": "text", "text": util::py_dumps(&payload)}], "structuredContent": payload, "isError": true})
            }
            Ok(Reply::Raw(v)) => {
                if let (Some(a), Some(id)) = (activity, entry) {
                    a.end(id, "ok", "");
                    self.agent.publish_activity();
                }
                v
            }
            Ok(Reply::Data(mut payload)) => {
                if let (Some(a), Some(id)) = (activity, entry) {
                    a.end(id, "ok", &activity_summary(&payload));
                    self.agent.publish_activity();
                }
                for key in ["hint", "next"] {
                    if let Some(Value::String(s)) = payload.get(key) {
                        let r = self.renamed(s);
                        payload.insert(key.into(), json!(r));
                    }
                }
                let mut structured = obj(json!({"ok": true}));
                structured.extend(payload);
                let structured = Value::Object(structured);
                let text = serde_json::to_string_pretty(&structured).unwrap_or_default();
                json!({"content": [{"type": "text", "text": text}], "isError": false, "structuredContent": structured})
            }
        }
    }

    fn dispatch(&self, name: &str, a: &Payload, cancel: &Cancel, progress_token: &Value) -> Result<Reply, AgentError> {
        let ag = &self.agent;
        let s = |k: &str| a.get(k).and_then(Value::as_str);
        let f = |k: &str| a.get(k).and_then(Value::as_f64).unwrap_or(0.0);
        let i = |k: &str| a.get(k).and_then(Value::as_i64);
        let b = |k: &str| a.get(k).and_then(Value::as_bool).unwrap_or(false);
        let list = |k: &str| a.get(k).and_then(Value::as_array).map(|v| v.iter().map(py_str).collect::<Vec<_>>()).unwrap_or_default();
        let port = s("port");
        let data = |r: AResult| r.map(Reply::Data);
        match name {
            "serial_status" => {
                let mut status = ag.status()?;
                let disabled: Vec<String> = STATUS_LEVELS.iter().filter(|(_, l)| !ag.allows(l)).map(|(n, _)| self.external(n)).collect();
                let hint = if disabled.is_empty() { "" } else { "restart the MCP server with --allow interact|hardware" };
                status.insert("disabled_tools".into(), json!(disabled));
                status.insert("enable_hint".into(), json!(hint));
                Ok(Reply::Data(status))
            }
            "serial_list_ports" => data(ag.list_ports()),
            "serial_connect" => data(ag.connect(s("port").unwrap_or(""), i("baud"), s("mode").unwrap_or("raw"), b("change_live_baud"))),
            "serial_disconnect" => data(ag.disconnect(port)),
            "serial_hello" => data(ag.hello(port, f("timeout_s"), cancel)),
            "serial_query" => data(ag.query(s("kind").unwrap_or(""), port, f("timeout_s"), b("redact_identity"), cancel)),
            "serial_log_archives" => {
                let cache = logcache::shared_cache();
                Ok(Reply::Data(obj(json!({"archives": cache.archives(), "cache": cache.status()}))))
            }
            "serial_logs" => {
                let (contains, levels) = (list("contains"), list("levels"));
                let (limit, frames, ic) = (i("limit").unwrap_or(200), b("frames"), b("ignore_case"));
                if let Some(archive) = s("archive") {
                    let records = logcache::Records::new("archive", Some(archive.to_string()));
                    let last = records.iter(0, true, Some(1), None).next();
                    let end = last.map_or(1, |r| r["seq"].as_i64().unwrap_or(0) + 1);
                    let mut result = agent::select_records(&records, end, i("cursor"), limit, &contains, &levels, frames, ic);
                    let mut cache = obj(json!({"stream": archive}));
                    cache.extend(records.cache.status());
                    result.insert("cache".into(), Value::Object(cache));
                    return Ok(Reply::Data(result));
                }
                Ok(Reply::Data(ag.session(port)?.select(i("cursor"), limit, &contains, &levels, frames, ic)))
            }
            "serial_wait_for" => {
                let session = ag.session(port)?;
                data(session.wait_for(&list("any_of"), f("timeout_s"), i("since"), b("ignore_case"), i("context").unwrap_or(5), Some(cancel)))
            }
            "serial_symbolize" => data(symbolize(s("text").unwrap_or(""), s("elf").unwrap_or(""))),
            "serial_button" => data(ag.button(s("button").unwrap_or(""), s("action").unwrap_or("click"), port, f("timeout_s"))),
            "serial_script_list" => data(ag.script_list()),
            "serial_script_run" => data(ag.script_run(s("name").unwrap_or(""), port, i("baud"))),
            "serial_script_stop" => data(ag.script_stop(s("run_id").unwrap_or(""))),
            "serial_script_status" => data(ag.script_status(s("run_id"), i("after").unwrap_or(0), i("limit").unwrap_or(200))),
            "serial_screenshot" => {
                let frame = Value::Object(ag.screenshot(port, i("after_revision"))?);
                let meta = json!({"revision": get(&frame, "revision"), "changed": util::truthy(get(&frame, "changed")),
                                  "size": frame.get("size").cloned().unwrap_or(json!("")), "bytes": frame.get("bytes").cloned().unwrap_or(json!(0))});
                let mut content = vec![json!({"type": "text", "text": serde_json::to_string(&meta).unwrap_or_default().replace(",\"", ", \"").replace("\":", "\": ")})];
                if util::truthy(get(&frame, "changed")) && util::truthy(get(&frame, "data")) {
                    content.push(json!({"type": "image", "data": frame["data"], "mimeType": "image/jpeg"}));
                }
                let mut structured = obj(json!({"ok": true}));
                structured.extend(obj(meta));
                Ok(Reply::Raw(json!({"content": content, "structuredContent": structured, "isError": false})))
            }
            "serial_restart" => data(ag.restart(port, s("arg").unwrap_or(""))),
            "serial_show_info" => data(ag.show_info(port, f("timeout_s"))),
            "serial_reset" => data(ag.reset(port, &list("wait_for"), f("timeout_s"), cancel)),
            "serial_bootloader" => data(ag.bootloader(port)),
            "serial_flash_preview" => data(ag.flash_preview(s("build_dir").unwrap_or(""), port, i("flash_baud").unwrap_or(3_000_000))),
            "serial_flash_start" => data(ag.flash_start(s("token").unwrap_or(""))),
            "serial_flash_status" => {
                let progress = |value: f64, step: &str| {
                    if !progress_token.is_null() {
                        self.send(&json!({"jsonrpc": "2.0", "method": "notifications/progress",
                            "params": {"progressToken": progress_token, "progress": value, "total": 100.0, "message": step}}));
                    }
                };
                data(ag.flash_status(s("token").unwrap_or(""), f("wait_s"), &progress, cancel))
            }
            _ => Err(AgentError::new("invalid_argument", format!("unknown tool {name}"), "")),
        }
    }
}

enum Reply {
    Data(Payload),
    Raw(Value),
}

fn activity_summary(p: &Payload) -> String {
    for key in ["verdict", "outcome", "status", "matched"] {
        if let Some(v) = p.get(key) {
            let extra = ["result", "pattern", "step"].iter().filter_map(|k| p.get(*k)).find(|v| util::truthy(v));
            let extra = match extra {
                Some(e) if !e.is_object() && !e.is_array() => format!(" {}", py_str(e)),
                _ => String::new(),
            };
            return format!("{key}={}{extra}", py_str(v));
        }
    }
    if let Some(Value::Array(r)) = p.get("records") {
        return format!("{} records", r.len());
    }
    if let Some(port) = p.get("port") {
        return format!("{} @ {}", py_str(port), p.get("baud").map(py_str).unwrap_or_default());
    }
    String::new()
}

/// Validate and fill defaults for exactly the JSON Schema keywords the tool specs use.
fn validate(schema: &Value, mut args: Payload) -> Result<Payload, String> {
    let props = obj(schema["properties"].clone());
    let mut errors = Vec::new();
    for req in schema.get("required").and_then(Value::as_array).into_iter().flatten() {
        let k = req.as_str().unwrap_or("");
        if !args.contains_key(k) {
            errors.push(format!("{k}\n  Field required"));
        }
    }
    for (k, prop) in &props {
        match args.get(k) {
            Some(v) => {
                if let Err(e) = check(prop, v) {
                    errors.push(format!("{k}\n  {e}"));
                }
            }
            None => {
                if let Some(d) = prop.get("default") {
                    args.insert(k.clone(), d.clone());
                }
            }
        }
    }
    args.retain(|k, _| props.contains_key(k));
    if errors.is_empty() {
        Ok(args)
    } else {
        Err(format!("{} validation error{}\n{}", errors.len(), if errors.len() == 1 { "" } else { "s" }, errors.join("\n")))
    }
}

fn check(s: &Value, v: &Value) -> Result<(), String> {
    if let Some(any) = s.get("anyOf").and_then(Value::as_array) {
        return any.iter().find_map(|alt| check(alt, v).ok()).ok_or_else(|| {
            any.iter().filter_map(|alt| check(alt, v).err()).next().unwrap_or_else(|| "Invalid value".into())
        });
    }
    let ty = s.get("type").and_then(Value::as_str).unwrap_or("");
    let num = |name: &str| s.get(name).and_then(Value::as_f64);
    match ty {
        "null" if !v.is_null() => return Err("Input should be None".into()),
        "string" => {
            let Some(text) = v.as_str() else { return Err("Input should be a valid string".into()) };
            let n = text.chars().count() as f64;
            if num("minLength").is_some_and(|m| n < m) {
                return Err(format!("String should have at least {} characters", num("minLength").unwrap()));
            }
            if num("maxLength").is_some_and(|m| n > m) {
                return Err(format!("String should have at most {} characters", num("maxLength").unwrap()));
            }
            if let Some(p) = s.get("pattern").and_then(Value::as_str) {
                if !Regex::new(p).is_ok_and(|r| r.is_match(text)) {
                    return Err(format!("String should match pattern '{p}'"));
                }
            }
        }
        "integer" => {
            let ok = v.as_i64().is_some() || v.as_f64().is_some_and(|f| f.fract() == 0.0);
            if !ok || v.is_boolean() {
                return Err("Input should be a valid integer".into());
            }
        }
        "number" if !v.is_number() => return Err("Input should be a valid number".into()),
        "boolean" if !v.is_boolean() => return Err("Input should be a valid boolean".into()),
        "array" => {
            let Some(items) = v.as_array() else { return Err("Input should be a valid list".into()) };
            let n = items.len() as f64;
            if num("minItems").is_some_and(|m| n < m) || num("maxItems").is_some_and(|m| n > m) {
                return Err("List length out of range".into());
            }
            if let Some(item) = s.get("items") {
                items.iter().try_for_each(|x| check(item, x))?;
            }
        }
        _ => {}
    }
    if let Some(e) = s.get("enum").and_then(Value::as_array) {
        if !e.contains(v) {
            return Err(format!("Input should be {}", e.iter().map(|x| format!("'{}'", py_str(x))).collect::<Vec<_>>().join(" or ")));
        }
    }
    if let Some(x) = v.as_f64() {
        if num("minimum").is_some_and(|m| x < m) {
            return Err(format!("Input should be greater than or equal to {}", s["minimum"]));
        }
        if num("maximum").is_some_and(|m| x > m) {
            return Err(format!("Input should be less than or equal to {}", s["maximum"]));
        }
        if num("exclusiveMinimum").is_some_and(|m| x <= m) {
            return Err(format!("Input should be greater than {}", s["exclusiveMinimum"]));
        }
    }
    Ok(())
}

// ------------------------------------------------------------- symbolize

fn find_addr2line(elf: &std::path::Path) -> Option<String> {
    let mut header = [0u8; 20];
    let machine = std::fs::File::open(elf).ok().and_then(|mut f| {
        use std::io::Read;
        f.read_exact(&mut header).ok()?;
        (header[..4] == *b"\x7fELF").then(|| u16::from_le_bytes([header[18], header[19]]))
    }).unwrap_or(0);
    let xtensa = ["xtensa-esp-elf-addr2line", "xtensa-esp32-elf-addr2line"];
    let riscv = ["riscv32-esp-elf-addr2line"];
    let groups: Vec<Vec<&str>> = match machine {
        94 => vec![xtensa.to_vec(), riscv.to_vec()],
        243 => vec![riscv.to_vec(), xtensa.to_vec()],
        _ => vec![[&riscv[..], &xtensa[..]].concat()],
    };
    let path = std::env::var_os("PATH").unwrap_or_default();
    let root = std::env::var_os("IDF_TOOLS_PATH").map(std::path::PathBuf::from).unwrap_or_else(|| util::home().join(".espressif"));
    for names in groups {
        for name in &names {
            if let Some(p) = std::env::split_paths(&path).map(|d| d.join(name)).find(|p| p.is_file()) {
                return Some(p.to_string_lossy().into_owned());
            }
        }
        for name in &names {
            let mut found = Vec::new();
            walk(&root, name, 0, &mut found);
            found.sort();
            if let Some(p) = found.pop() {
                return Some(p);
            }
        }
    }
    None
}

/// `glob("*/**/bin/<name>")` under the IDF tools root.
fn walk(dir: &std::path::Path, name: &str, depth: usize, found: &mut Vec<String>) {
    if depth > 8 {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for e in entries.flatten() {
        let p = e.path();
        if e.file_type().is_ok_and(|t| t.is_dir()) {
            walk(&p, name, depth + 1, found);
        } else if depth >= 2 && p.file_name().is_some_and(|n| n == name) && dir.file_name().is_some_and(|d| d == "bin") {
            found.push(p.to_string_lossy().into_owned());
        }
    }
}

fn symbolize(text: &str, elf: &str) -> AResult {
    if !std::path::Path::new(elf).is_absolute() {
        return Err(AgentError::new("invalid_argument", "elf must be an absolute path", ""));
    }
    let elf_path = util::realpath(&util::expanduser(elf));
    if !elf_path.is_file() {
        return Err(AgentError::new("invalid_argument", format!("ELF file does not exist: {}", elf_path.display()), ""));
    }
    let Some(tool) = find_addr2line(&elf_path) else {
        return Err(AgentError::new("invalid_argument", "ESP addr2line not found; set IDF tools PATH", ""));
    };
    static ADDR: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"0x[0-9a-fA-F]{4,}").unwrap());
    let mut frames: Vec<String> = Vec::new();
    for line in text.lines().filter(|l| l.contains("0x")).take(200) {
        let mut addresses: Vec<&str> = Vec::new();
        for m in ADDR.find_iter(line) {
            if !addresses.contains(&m.as_str()) {
                addresses.push(m.as_str());
            }
        }
        if addresses.is_empty() {
            continue;
        }
        let Some(out) = run_timeout(&tool, &[&["-pfiaC", "-e", &elf_path.to_string_lossy()], &addresses[..]].concat(), 1.0) else { continue };
        for (address, trace) in addresses.iter().zip(out.lines()) {
            let entry = format!("{address}: {trace}");
            if !trace.is_empty() && !trace.contains("?? ??:0") && !frames.contains(&entry) {
                frames.push(entry);
            }
        }
    }
    Ok(obj(json!({"elf": elf_path.to_string_lossy(), "frames": frames})))
}

fn run_timeout(tool: &str, args: &[&str], timeout: f64) -> Option<String> {
    use std::process::{Command, Stdio};
    let mut child = Command::new(tool).args(args).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().ok()?;
    let mut stdout = child.stdout.take()?;
    let reader = std::thread::spawn(move || {
        let mut s = Vec::new();
        use std::io::Read;
        let _ = stdout.read_to_end(&mut s);
        s
    });
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs_f64(timeout);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let out = reader.join().ok()?;
                return status.success().then(|| String::from_utf8_lossy(&out).into_owned());
            }
            Ok(None) if std::time::Instant::now() < deadline => std::thread::sleep(std::time::Duration::from_millis(10)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
}

// ------------------------------------------------------------- main

fn usage() -> ! {
    eprintln!("usage: serial-deck-mcp-rs [--allow observe|interact|hardware] [--socket PATH] [--tool-prefix P] [--profile NAME] [--no-activity]");
    std::process::exit(2);
}

fn main() {
    let env = |k: &str, d: &str| std::env::var(k).ok().filter(|v| !v.is_empty()).unwrap_or_else(|| d.to_string());
    let mut policy = env("SERIAL_DECK_MCP_ALLOW", "observe");
    let mut socket = std::env::var("SERIAL_DECK_HUB_SOCKET").ok().filter(|v| !v.is_empty()).unwrap_or_else(util::default_hub_path);
    let mut prefix = env("SERIAL_DECK_MCP_TOOL_PREFIX", "serial");
    let mut profile = String::new();
    let mut activity = true;
    let mut argv = std::env::args().skip(1);
    while let Some(a) = argv.next() {
        let (key, inline) = match a.split_once('=') {
            Some((k, v)) if k.starts_with("--") => (k.to_string(), Some(v.to_string())),
            _ => (a.clone(), None),
        };
        let mut value = || inline.clone().or_else(|| argv.next()).unwrap_or_else(|| usage());
        match key.as_str() {
            "--allow" => policy = value(),
            "--socket" => socket = value(),
            "--tool-prefix" => prefix = value(),
            "--profile" => profile = value(),
            "--log-level" => {
                value();
            }
            "--no-activity" => activity = false,
            "-h" | "--help" => usage(),
            _ => usage(),
        }
    }
    if !agent::POLICIES.contains(&policy.as_str()) {
        eprintln!("--allow must be one of observe, interact, hardware");
        std::process::exit(2);
    }
    if !profile.is_empty() {
        let dir = std::env::var("SERIAL_DECK_PROFILE_DIR").ok().filter(|v| !v.trim().is_empty())
            .map(std::path::PathBuf::from).unwrap_or_else(|| util::config_dir().join("profiles"));
        let data: Option<Value> = std::fs::read_to_string(dir.join(format!("{profile}.json"))).ok().and_then(|s| serde_json::from_str(&s).ok());
        let Some(data) = data else {
            eprintln!("unknown profile '{profile}' (looked in {})", dir.display());
            std::process::exit(2);
        };
        if prefix == "serial" {
            if let Some(p) = data.get("mcp_tool_prefix").and_then(Value::as_str).filter(|p| !p.is_empty()) {
                prefix = p.to_string();
            }
        }
    }
    if !Regex::new(r"^[a-z][a-z0-9]{0,15}$").unwrap().is_match(&prefix) {
        eprintln!("tool prefix: 1-16 lowercase letters or digits, starting with a letter");
        std::process::exit(2);
    }
    let client = std::env::var("SERIAL_DECK_MCP_CLIENT").unwrap_or_default();
    let agent = Agent::new(&policy, &socket, activity.then_some(client.as_str()));
    agent.collect_snapshots();
    let server = Arc::new(Server { agent: agent.clone(), prefix, out: Mutex::new(std::io::stdout()), calls: Mutex::default() });
    let debug = std::env::var_os("SERIAL_DECK_MCP_DEBUG").is_some();
    for line in std::io::stdin().lock().lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        if debug {
            eprintln!("<- {}", redact(&line));
        }
        match serde_json::from_str::<Value>(&line) {
            Ok(Value::Array(batch)) => batch.into_iter().for_each(|m| server.handle(m)),
            Ok(msg @ Value::Object(_)) => server.handle(msg),
            _ => server.send(&json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32700, "message": "Parse error"}})),
        }
    }
    // stdin closed: the client is gone. Release sessions and snapshots, then exit
    // without waiting for in-flight calls (their replies have nowhere to go).
    agent.close();
    std::process::exit(0);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_validation() {
        let spec = SPEC["tools"].as_array().unwrap().iter().find(|t| t["name"] == "serial_logs").unwrap();
        let ok = validate(&spec["inputSchema"], obj(json!({"limit": 5}))).unwrap();
        assert_eq!(ok["limit"], json!(5));
        assert_eq!(ok["ignore_case"], json!(true));
        assert!(ok.contains_key("port"));
        assert!(validate(&spec["inputSchema"], obj(json!({"limit": 0}))).unwrap_err().contains("greater than or equal to 1"));
        assert!(validate(&spec["inputSchema"], obj(json!({"levels": ["nope"]}))).is_err());
        assert!(validate(&spec["inputSchema"], obj(json!({"archive": "xyz"}))).is_err());
        let connect = SPEC["tools"].as_array().unwrap().iter().find(|t| t["name"] == "serial_connect").unwrap();
        assert!(validate(&connect["inputSchema"], obj(json!({}))).unwrap_err().contains("Field required"));
        assert!(validate(&connect["inputSchema"], obj(json!({"port": "/dev/x", "baud": 100}))).is_err());
        assert!(validate(&connect["inputSchema"], obj(json!({"port": "/dev/x", "baud": null}))).is_ok());
    }
}
