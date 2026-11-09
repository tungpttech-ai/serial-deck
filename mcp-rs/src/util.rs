//! Shared helpers: Python-compatible JSON text, redaction, paths, time, randomness.

use regex::{Captures, Regex};
use serde_json::{Map, Value};
use std::fs;
use std::io::{self, Read};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::time::{SystemTime, UNIX_EPOCH};

pub static NULL: Value = Value::Null;

pub fn get<'a>(v: &'a Value, key: &str) -> &'a Value {
    v.get(key).unwrap_or(&NULL)
}

/// Python truthiness of a JSON value.
pub fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

/// Python `str(value)` for JSON values.
pub fn py_str(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => "None".into(),
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        other => py_dumps(other),
    }
}

/// Python `int(value)` for the shapes the hub sends (int, float, numeric string).
pub fn py_int(v: &Value) -> Option<i64> {
    match v {
        Value::Number(n) => n.as_i64().or_else(|| n.as_f64().map(|f| f as i64)),
        Value::String(s) => s.trim().parse().ok(),
        Value::Bool(b) => Some(*b as i64),
        _ => None,
    }
}

/// `type(v) is int` (bools excluded).
pub fn strict_int(v: &Value) -> Option<i64> {
    match v {
        Value::Number(n) => n.as_i64(),
        _ => None,
    }
}

/// `json.dumps(v, ensure_ascii=False)` with Python's default `", "` / `": "` separators.
pub fn py_dumps(v: &Value) -> String {
    let mut out = String::new();
    dump(v, &mut out);
    out
}

fn dump(v: &Value, out: &mut String) {
    match v {
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                dump(x, out);
            }
            out.push(']');
        }
        Value::Object(o) => {
            out.push('{');
            for (i, (k, x)) in o.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                out.push_str(&serde_json::to_string(k).unwrap_or_default());
                out.push_str(": ");
                dump(x, out);
            }
            out.push('}');
        }
        other => out.push_str(&serde_json::to_string(other).unwrap_or_default()),
    }
}

pub fn obj(v: Value) -> Map<String, Value> {
    match v {
        Value::Object(m) => m,
        _ => Map::new(),
    }
}

/// `{**a, **b}`.
pub fn merge(mut a: Map<String, Value>, b: Map<String, Value>) -> Map<String, Value> {
    for (k, v) in b {
        a.insert(k, v);
    }
    a
}

// ------------------------------------------------------------- redaction

const SECRET_KEY: &str = r"password|passwd|pass|psk|token|secret|api[_-]?key|authorization|auth_tag|bearer|cookie|session(?:_id|id)?|credential|challenge|private[_-]?key";

struct Redactions {
    bearer: Regex,
    json_key: Regex,
    key_value: Regex,
    url_auth: Regex,
    jwt: Regex,
    secret_key: Regex,
    identity_key: Regex,
}

static RX: LazyLock<Redactions> = LazyLock::new(|| Redactions {
    bearer: Regex::new(r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{8,}").unwrap(),
    json_key: Regex::new(&format!(r#"(?i)("(?:[\w-]*(?:{SECRET_KEY})[\w-]*)"\s*:\s*)"(?:[^"\\]|\\.)*""#)).unwrap(),
    // Python has a lookahead `(?!\[redacted\]|(?:Bearer|Basic)\s)` before group 3;
    // the replacement closure applies it instead (Rust regex has no lookaround).
    key_value: Regex::new(&format!(r#"(?i)\b([\w-]*(?:{SECRET_KEY})[\w-]*)(\s*[=:]\s*)([^\s,;&"']+)"#)).unwrap(),
    url_auth: Regex::new(r"(?i)\b([a-z][a-z0-9+.-]*://)[^/\s:@]+:[^/\s@]+@").unwrap(),
    jwt: Regex::new(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}").unwrap(),
    secret_key: Regex::new(&format!(r"(?i)^[\w-]*(?:{SECRET_KEY})[\w-]*$")).unwrap(),
    identity_key: Regex::new(r"(?i)serial|mac|uuid|device_id|chip_id|imei|sn$|key").unwrap(),
});

pub fn redact(text: &str) -> String {
    let r = &*RX;
    let t = r.bearer.replace_all(text, "$1 [redacted]");
    let t = r.json_key.replace_all(&t, "${1}\"[redacted]\"").into_owned();
    let t = r
        .key_value
        .replace_all(&t, |c: &Captures| {
            let whole = c.get(0).unwrap();
            let value = &c[3];
            let next_is_space = t[whole.end()..].chars().next().is_some_and(char::is_whitespace);
            let lower = value.to_lowercase();
            if lower.starts_with("[redacted]") || ((lower == "bearer" || lower == "basic") && next_is_space) {
                whole.as_str().to_string()
            } else {
                format!("{}{}[redacted]", &c[1], &c[2])
            }
        })
        .into_owned();
    let t = r.url_auth.replace_all(&t, "${1}[redacted]@");
    r.jwt.replace_all(&t, "[redacted-jwt]").into_owned()
}

/// Redact secrets in any JSON value; `identity` also hides serial/MAC-like fields.
pub fn redact_value(v: &Value, identity: bool) -> Value {
    match v {
        Value::String(s) => {
            let stripped = s.trim();
            if stripped.is_empty() || stripped.starts_with('{') || stripped.starts_with('[') {
                if let Ok(parsed) = serde_json::from_str::<Value>(stripped) {
                    return Value::String(py_dumps(&redact_value(&parsed, identity)));
                }
            }
            Value::String(redact(s))
        }
        Value::Array(a) => Value::Array(a.iter().map(|x| redact_value(x, identity)).collect()),
        Value::Object(o) => {
            let mut out = Map::new();
            for (k, item) in o {
                let leaf = !item.is_object() && !item.is_array();
                if leaf && (RX.secret_key.is_match(k) || (identity && RX.identity_key.is_match(k))) {
                    out.insert(k.clone(), Value::String("[redacted]".into()));
                } else {
                    out.insert(k.clone(), redact_value(item, identity));
                }
            }
            Value::Object(out)
        }
        other => other.clone(),
    }
}

// ------------------------------------------------------------- ports

static COM_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)^(?:\\\\\.\\)?(COM[0-9]+)$").unwrap());
const NON_SERIAL_SCHEMES: [&str; 4] = ["tcp", "udp", "unix", "ssh-socket"];
pub const SSH_SCHEME: &str = "ssh-socket://";

pub fn is_device_port(port: &str) -> bool {
    port.starts_with('/') || COM_RE.is_match(port)
}

pub fn is_non_serial_port(port: &str) -> bool {
    port.split_once("://").is_some_and(|(s, _)| NON_SERIAL_SCHEMES.contains(&s.to_lowercase().as_str()))
}

/// Resolve device aliases without opening the UART.
pub fn port_identity(port: &str) -> String {
    if let Some(c) = COM_RE.captures(port) {
        return c[1].to_uppercase();
    }
    if port.starts_with('/') {
        if let Ok(p) = fs::canonicalize(port) {
            return p.to_string_lossy().into_owned();
        }
    }
    port.to_string()
}

// ------------------------------------------------------------- paths

pub fn uid() -> u32 {
    unsafe { libc::getuid() }
}

pub fn home() -> PathBuf {
    std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("/"))
}

fn env_path(name: &str) -> Option<PathBuf> {
    std::env::var(name).ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).map(PathBuf::from)
}

pub fn expanduser(p: &str) -> PathBuf {
    match p.strip_prefix('~') {
        Some(rest) if rest.is_empty() || rest.starts_with('/') => home().join(rest.trim_start_matches('/')),
        _ => PathBuf::from(p),
    }
}

/// A 0700 directory owned by this user and not a symlink (ipc.private_dir).
pub fn private_dir(path: &Path) -> io::Result<PathBuf> {
    match fs::DirBuilder::new().recursive(true).mode(0o700).create(path) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }
    let info = fs::symlink_metadata(path)?;
    if info.file_type().is_symlink() {
        return Err(io::Error::other(format!("refusing link/reparse point as private directory: {}", path.display())));
    }
    if !info.is_dir() {
        return Err(io::Error::other(format!("not a directory: {}", path.display())));
    }
    if info.uid() != uid() {
        return Err(io::Error::other(format!("{} belongs to another user", path.display())));
    }
    if info.mode() & 0o077 != 0 {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(path.to_path_buf())
}

pub fn runtime_dir() -> io::Result<PathBuf> {
    if let Some(p) = env_path("SERIAL_DECK_RUNTIME_DIR") {
        return private_dir(&expanduser(&p.to_string_lossy()));
    }
    let run_user = PathBuf::from(format!("/run/user/{}", uid()));
    let c = std::ffi::CString::new(run_user.to_string_lossy().as_bytes()).unwrap();
    if run_user.is_dir() && unsafe { libc::access(c.as_ptr(), libc::W_OK) } == 0 {
        return private_dir(&run_user.join("serial-deck"));
    }
    private_dir(&PathBuf::from(format!("/tmp/serial-deck-{}", uid())))
}

pub fn default_hub_path() -> String {
    runtime_dir()
        .map(|d| d.join("hub.sock"))
        .unwrap_or_else(|_| PathBuf::from(format!("/tmp/serial-deck-{}/hub.sock", uid())))
        .to_string_lossy()
        .into_owned()
}

pub fn config_dir() -> PathBuf {
    if let Some(p) = env_path("SERIAL_DECK_CONFIG") {
        return p;
    }
    env_path("XDG_CONFIG_HOME").unwrap_or_else(|| home().join(".config")).join("serial-deck")
}

pub fn is_socket(path: &str) -> bool {
    use std::os::unix::fs::FileTypeExt;
    fs::metadata(path).is_ok_and(|m| m.file_type().is_socket())
}

/// `os.path.realpath` (non-strict).
pub fn realpath(p: &Path) -> PathBuf {
    fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf())
}

pub fn pid_alive(pid: &Value) -> bool {
    match strict_int(pid) {
        Some(pid) if pid > 0 && pid <= i32::MAX as i64 => {
            unsafe { libc::kill(pid as i32, 0) == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM) }
        }
        _ => false,
    }
}

// ------------------------------------------------------------- time and randomness

pub fn now() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

/// `datetime.now().isoformat(timespec="milliseconds")` in local time.
pub fn iso_now() -> String {
    let d = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = d.as_secs() as libc::time_t;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe { libc::localtime_r(&secs, &mut tm) };
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec,
        d.subsec_millis()
    )
}

pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut buf)).expect("/dev/urandom");
    buf
}

pub fn random_hex(chars: usize) -> String {
    random_bytes(chars.div_ceil(2)).iter().map(|b| format!("{b:02x}")).collect::<String>()[..chars].to_string()
}

pub fn random_u32() -> u32 {
    u32::from_le_bytes(random_bytes(4).try_into().unwrap())
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn b64(data: &[u8], url_safe: bool) -> String {
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let n = chunk.iter().enumerate().fold(0u32, |acc, (i, b)| acc | (*b as u32) << (16 - 8 * i));
        for i in 0..=chunk.len() {
            let c = B64[((n >> (18 - 6 * i)) & 63) as usize];
            out.push(match (url_safe, c) {
                (true, b'+') => '-',
                (true, b'/') => '_',
                _ => c as char,
            });
        }
        if !url_safe {
            out.extend(std::iter::repeat_n('=', 3 - chunk.len()));
        }
    }
    out
}

/// `secrets.token_urlsafe(n)`.
pub fn token_urlsafe(n: usize) -> String {
    b64(&random_bytes(n), true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn redaction_matches_python() {
        assert_eq!(redact("Authorization: Bearer abcdefgh123"), "Authorization: Bearer [redacted]");
        assert_eq!(redact(r#"{"wifi_password": "hunter22", "x": 1}"#), r#"{"wifi_password": "[redacted]", "x": 1}"#);
        assert_eq!(redact("psk=abc123 ok"), "psk=[redacted] ok");
        assert_eq!(redact("token=[redacted] x"), "token=[redacted] x");
        assert_eq!(redact("mqtt://user:pw@host"), "mqtt://[redacted]@host");
        assert_eq!(redact("passkey: secret1"), "passkey: [redacted]");
        assert_eq!(redact("I (12) wifi: connected"), "I (12) wifi: connected");
        let v = redact_value(&json!({"serial": "abc", "token": "t", "n": {"mac": "aa"}}), true);
        assert_eq!(v, json!({"serial": "[redacted]", "token": "[redacted]", "n": {"mac": "[redacted]"}}));
        assert_eq!(redact_value(&json!("{\"token\":\"x\"}"), false), json!("{\"token\": \"[redacted]\"}"));
    }

    #[test]
    fn base64_and_dumps() {
        assert_eq!(b64(b"hello", false), "aGVsbG8=");
        assert_eq!(b64(&[0xfb, 0xff], true), "-_8");
        assert_eq!(py_dumps(&json!({"a": [1, "é"], "b": null})), r#"{"a": [1, "é"], "b": null}"#);
    }
}
