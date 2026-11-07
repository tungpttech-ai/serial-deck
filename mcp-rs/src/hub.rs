//! Shared hub client (hub_client.py HubProcessManager, multi-port subset).

use crate::util::{self, get, is_socket, py_int, py_str, strict_int, truthy};
use serde_json::{Map, Value, json};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub const MULTIPORT_PROTOCOL: &str = "serial-deck-multiport-v1";
const ROOT_ACTIONS: [&str; 19] = [
    "claim", "scan", "shutdown", "ssh_devices", "ssh_fingerprint", "ssh_pair", "ssh_forget", "ssh_retry", "ssh_unlock",
    "ssh_restart", "ssh_screen", "ssh_profiles", "script_list", "script_run", "script_stop", "script_status",
    "script_logs", "script_autorun", "runner_attached",
];

#[derive(Debug)]
pub enum HubError {
    Io(String),
    /// Hub answered `ok: false`.
    Refused { message: String, code: String, baud_conflict: bool, dispatch_unknown: bool },
}

impl std::fmt::Display for HubError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            HubError::Io(m) => f.write_str(m),
            HubError::Refused { message, .. } => f.write_str(message),
        }
    }
}

impl From<io::Error> for HubError {
    fn from(e: io::Error) -> Self {
        HubError::Io(e.to_string())
    }
}

pub type HubResult<T> = Result<T, HubError>;

pub fn connect(path: &str, timeout: f64) -> io::Result<UnixStream> {
    let s = UnixStream::connect(path)?;
    let t = Some(Duration::from_secs_f64(timeout.max(0.001)));
    s.set_read_timeout(t)?;
    s.set_write_timeout(t)?;
    Ok(s)
}

/// One newline-delimited JSON request/response on a control endpoint.
pub fn control(endpoint: &str, request: &Value, timeout: f64, limit: usize) -> HubResult<Map<String, Value>> {
    let mut s = connect(endpoint, timeout)?;
    let mut line = serde_json::to_vec(request).unwrap_or_default();
    line.push(b'\n');
    s.write_all(&line)?;
    let mut buf = Vec::new();
    let read = BufReader::new(&s).take(limit as u64 + 1).read_until(b'\n', &mut buf);
    match read {
        Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {
            return Err(HubError::Io("timed out waiting for a reply".into()));
        }
        Err(e) => return Err(e.into()),
        Ok(_) if buf.len() > limit => return Err(HubError::Io("UART hub response too large".into())),
        Ok(_) if !buf.ends_with(b"\n") => return Err(HubError::Io("UART hub closed without a response".into())),
        Ok(_) => {}
    }
    let response: Value = serde_json::from_slice(&buf).map_err(|e| HubError::Io(e.to_string()))?;
    let Value::Object(map) = response else {
        return Err(HubError::Io("invalid response from UART hub".into()));
    };
    if !truthy(get(&Value::Object(map.clone()), "ok")) {
        let v = Value::Object(map);
        let message = match get(&v, "error") {
            Value::Null => "UART hub request failed".to_string(),
            e => py_str(e),
        };
        return Err(HubError::Refused {
            message,
            code: v.get("code").filter(|c| truthy(c)).map(py_str).unwrap_or_default(),
            baud_conflict: get(&v, "baud_conflict").is_object(),
            dispatch_unknown: get(&v, "dispatch") == "unknown",
        });
    }
    Ok(map)
}

type Callback = Arc<dyn Fn(&Value) + Send + Sync>;

#[derive(Default)]
struct Subscription {
    callbacks: Vec<(u64, Callback)>,
    stop: Option<Arc<AtomicBool>>,
    stream: Option<UnixStream>,
}

/// A client of one hub channel (or of the root daemon when `channel_socket` is empty).
pub struct Manager {
    pub socket_path: String,
    pub channel_socket: Mutex<String>,
    pub baud: Mutex<i64>,
    sub: Arc<Mutex<Subscription>>,
}

impl Manager {
    pub fn new(socket_path: &str) -> Self {
        Manager {
            socket_path: util::expanduser(socket_path).to_string_lossy().into_owned(),
            channel_socket: Mutex::new(String::new()),
            baud: Mutex::new(2_000_000),
            sub: Arc::default(),
        }
    }

    pub fn baud(&self) -> i64 {
        *self.baud.lock().unwrap()
    }

    pub fn channel(&self) -> String {
        self.channel_socket.lock().unwrap().clone()
    }

    pub fn data_endpoint(&self) -> String {
        let c = self.channel();
        if c.is_empty() { self.socket_path.clone() } else { c }
    }

    pub fn control_endpoint(&self) -> String {
        format!("{}.ctl", self.data_endpoint())
    }

    pub fn socket_ready(&self) -> bool {
        connect(&format!("{}.ctl", self.socket_path), 0.2).is_ok()
    }

    pub fn request(&self, action: &str, timeout: f64, payload: Map<String, Value>) -> HubResult<Map<String, Value>> {
        let endpoint = if ROOT_ACTIONS.contains(&action) {
            format!("{}.ctl", self.socket_path)
        } else {
            self.control_endpoint()
        };
        let mut request = Map::new();
        request.insert("action".into(), json!(action));
        request.extend(payload);
        control(&endpoint, &Value::Object(request), timeout, 4 * 1024 * 1024)
    }

    pub fn status(&self) -> HubResult<Map<String, Value>> {
        self.request("status", 3.0, Map::new())
    }

    /// `on_conflict`: "join" keeps the live baud, "error" refuses, "retime" changes it for everyone.
    pub fn claim(&self, port: &str, baud: i64, on_conflict: &str) -> HubResult<()> {
        let mut payload = util::obj(json!({"port": port, "baud": baud}));
        if on_conflict != "join" {
            payload.insert("on_baud_conflict".into(), json!(on_conflict));
        }
        let response = self.request("claim", 3.0, payload)?;
        let r = Value::Object(response);
        if !matches!(get(&r, "claimed"), Value::Bool(_) | Value::Null) {
            return Err(HubError::Io("UART hub returned an invalid claim state".into()));
        }
        *self.baud.lock().unwrap() = py_int(get(&r, "baud")).unwrap_or(baud);
        if let Value::String(channel) = get(&r, "channel_socket") {
            if *channel != self.channel() {
                let callbacks = std::mem::take(&mut self.sub.lock().unwrap().callbacks);
                self.unsubscribe_all();
                *self.channel_socket.lock().unwrap() = channel.clone();
                for (id, cb) in callbacks {
                    self.subscribe_with_id(id, cb)?;
                }
            }
        }
        Ok(())
    }

    pub fn subscribe(&self, cb: Callback) -> io::Result<u64> {
        let id = util::random_u32() as u64;
        self.subscribe_with_id(id, cb)?;
        Ok(id)
    }

    fn subscribe_with_id(&self, id: u64, cb: Callback) -> io::Result<()> {
        let mut sub = self.sub.lock().unwrap();
        sub.callbacks.push((id, cb));
        if sub.stream.is_some() {
            return Ok(());
        }
        let mut client = match connect(&self.control_endpoint(), 1.0) {
            Ok(c) => c,
            Err(e) => {
                sub.callbacks.retain(|(i, _)| *i != id);
                return Err(e);
            }
        };
        client.write_all(b"{\"action\":\"subscribe\"}\n")?;
        client.set_read_timeout(None)?;
        let stop = Arc::new(AtomicBool::new(false));
        sub.stop = Some(stop.clone());
        sub.stream = Some(client.try_clone()?);
        let shared = self.sub.clone();
        std::thread::Builder::new().name("hub-subscribe".into()).stack_size(128 * 1024).spawn(move || {
            let reader = BufReader::new(client);
            for line in reader.split(b'\n') {
                if stop.load(Ordering::SeqCst) {
                    break;
                }
                let Ok(line) = line else { break };
                let Ok(event @ Value::Object(_)) = serde_json::from_slice::<Value>(&line) else { continue };
                let callbacks: Vec<Callback> = shared.lock().unwrap().callbacks.iter().map(|(_, c)| c.clone()).collect();
                for cb in callbacks {
                    cb(&event);
                }
            }
        })?;
        Ok(())
    }

    /// Drop one callback; the shared subscription closes with the last one.
    pub fn unsubscribe(&self, id: u64) {
        let empty = {
            let mut sub = self.sub.lock().unwrap();
            sub.callbacks.retain(|(i, _)| *i != id);
            sub.callbacks.is_empty()
        };
        if empty {
            self.unsubscribe_all();
        }
    }

    pub fn unsubscribe_all(&self) {
        let mut sub = self.sub.lock().unwrap();
        sub.callbacks.clear();
        if let Some(stop) = sub.stop.take() {
            stop.store(true, Ordering::SeqCst);
        }
        if let Some(s) = sub.stream.take() {
            let _ = s.shutdown(std::net::Shutdown::Both);
        }
    }

    /// Attach to a running multi-port daemon; never spawns one.
    // ponytail: no hub autostart (Python spawns `serial_deck.hub` under routing.lock).
    // Start the dashboard/hub first; add autostart when the Rust server ships without Python.
    pub fn ensure_started(&mut self) -> HubResult<()> {
        if !self.socket_ready() {
            match find_existing_hub() {
                Some(path) => self.socket_path = path,
                None => {
                    return Err(HubError::Io(format!(
                        "no serial-deck hub at {}; start the dashboard or `serial-deck-hub` first",
                        self.socket_path
                    )));
                }
            }
        }
        let status = Value::Object(self.request("status", 2.0, Map::new())?);
        if !valid_hub_status(&status) {
            let protocol = get(&status, "protocol");
            return Err(HubError::Io(format!(
                "{} is not a serial-deck hub{}; stop it or pass a different --socket",
                self.socket_path,
                if truthy(protocol) { format!(" (protocol '{}')", py_str(protocol)) } else { String::new() }
            )));
        }
        Ok(())
    }
}

impl Drop for Manager {
    fn drop(&mut self) {
        self.unsubscribe_all();
    }
}

pub fn valid_hub_status(s: &Value) -> bool {
    let claimed = get(s, "port");
    let flash = get(s, "flash");
    get(s, "event") == "status"
        && ["ready", "idle", "flashing"].iter().any(|x| get(s, "state") == *x)
        && strict_int(get(s, "baud")).is_some_and(|b| b > 0)
        && get(flash, "active").is_boolean()
        && (claimed.is_null() || claimed.is_string())
        && (get(s, "protocol").is_null() || get(s, "protocol") == MULTIPORT_PROTOCOL)
}

/// Root hubs of this user advertised in `<runtime>/registry` (ipc.registered), multi-port only.
fn find_existing_hub() -> Option<String> {
    let registry = util::runtime_dir().ok()?.join("registry");
    let mut entries: Vec<_> = std::fs::read_dir(registry).ok()?.flatten().map(|e| e.path()).collect();
    entries.sort();
    for entry in entries {
        if entry.file_name()?.to_string_lossy().starts_with('.') {
            continue;
        }
        let Ok(path) = std::fs::read_to_string(&entry) else { continue };
        let path = path.trim().to_string();
        if !(is_socket(&path) && is_socket(&format!("{path}.ctl"))) {
            continue;
        }
        let Ok(status) = control(&format!("{path}.ctl"), &json!({"action": "status"}), 0.2, 65536) else { continue };
        let status = Value::Object(status);
        if truthy(get(&status, "channel_socket")) || !valid_hub_status(&status) {
            continue;
        }
        if get(&status, "protocol") == MULTIPORT_PROTOCOL {
            return Some(path);
        }
    }
    None
}

/// Raw stream of one hub channel, with atomic frame writes through its control socket.
pub struct Transport {
    data: UnixStream,
    endpoint: String,
    frame_control: AtomicBool,
}

pub enum WriteError {
    /// The hub may already have written the frame.
    Unknown(String),
    Refused(String),
}

impl Transport {
    pub fn open(endpoint: &str) -> io::Result<Self> {
        let data = connect(endpoint, 1.0)?;
        data.set_read_timeout(None)?;
        Ok(Transport { data, endpoint: endpoint.into(), frame_control: AtomicBool::new(true) })
    }

    pub fn reader(&self) -> io::Result<UnixStream> {
        self.data.try_clone()
    }

    pub fn write_frame(&self, frame: &[u8]) -> Result<(), WriteError> {
        if self.frame_control.load(Ordering::SeqCst) {
            let request = json!({"action": "write_frame", "data": util::b64(frame, false)});
            match control(&format!("{}.ctl", self.endpoint), &request, 1.0, 65536) {
                Ok(_) => return Ok(()),
                Err(HubError::Refused { dispatch_unknown: true, message, .. }) => return Err(WriteError::Unknown(message)),
                Err(HubError::Refused { message, .. }) if !message.contains("unknown control action") => {
                    return Err(WriteError::Refused(message));
                }
                Err(HubError::Refused { .. }) => self.frame_control.store(false, Ordering::SeqCst),
                Err(HubError::Io(m)) => return Err(WriteError::Unknown(m)),
            }
        }
        (&self.data).write_all(frame).map_err(|e| WriteError::Refused(e.to_string()))
    }

    pub fn close(&self) {
        let _ = self.data.shutdown(std::net::Shutdown::Both);
    }
}
