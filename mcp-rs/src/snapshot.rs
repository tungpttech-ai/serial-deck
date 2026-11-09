//! Immutable, policy-checked flash snapshots (flash_snapshot.py).
//!
//! Shares `<runtime>/flash-snapshots/` and `state.json` with the Python servers,
//! so the collector follows the same "never by age alone" evidence rules.

use crate::util::{self, get, now, pid_alive, py_int, py_str, truthy};
use regex::Regex;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

pub const SNAPSHOT_TTL: f64 = 600.0;
pub const UNACCEPTED_GRACE: f64 = 60.0;
const STATE_FILE: &str = "state.json";
const PARTITION_TABLE_MAX: u64 = 0x1000;

#[derive(Debug)]
pub struct PolicyError(pub String);

fn err<T>(m: impl Into<String>) -> Result<T, PolicyError> {
    Err(PolicyError(m.into()))
}

#[derive(Debug, Clone)]
pub struct Partition {
    pub name: String,
    pub ptype: u8,
    pub subtype: u8,
    pub offset: u64,
    pub size: u64,
}

impl Partition {
    fn end(&self) -> u64 {
        self.offset + self.size
    }
    fn kind(&self) -> &'static str {
        match (self.ptype, self.subtype) {
            (0, _) => "app",
            (1, 0) => "ota_data",
            _ => "data",
        }
    }
}

pub fn parse_partition_table(data: &[u8]) -> Result<Vec<Partition>, PolicyError> {
    let mut parts = Vec::new();
    for index in (0..data.len().saturating_sub(31)).step_by(32) {
        let e = &data[index..index + 32];
        if e[..2] == [0xff, 0xff] {
            break;
        }
        if e[..2] == [0xeb, 0xeb] {
            continue;
        }
        if u16::from_le_bytes([e[0], e[1]]) != 0x50AA {
            return err(format!("invalid partition entry at byte {index}"));
        }
        let name: Vec<u8> = e[12..28].iter().copied().collect::<Vec<_>>();
        let end = name.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
        parts.push(Partition {
            name: String::from_utf8_lossy(&name[..end]).into_owned(),
            ptype: e[2],
            subtype: e[3],
            offset: u32::from_le_bytes(e[4..8].try_into().unwrap()) as u64,
            size: u32::from_le_bytes(e[8..12].try_into().unwrap()) as u64,
        });
    }
    if parts.is_empty() {
        return err("partition table has no entries");
    }
    Ok(parts)
}

/// Python `int(str(value), 0)`.
fn offset(v: &Value) -> Result<u64, PolicyError> {
    let s = py_str(v);
    let t = s.trim().replace('_', "");
    let parsed = if let Some(h) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u64::from_str_radix(h, 16).ok()
    } else if let Some(o) = t.strip_prefix("0o").or_else(|| t.strip_prefix("0O")) {
        u64::from_str_radix(o, 8).ok()
    } else if let Some(b) = t.strip_prefix("0b").or_else(|| t.strip_prefix("0B")) {
        u64::from_str_radix(b, 2).ok()
    } else if t.len() > 1 && t.starts_with('0') && t.chars().any(|c| c != '0') {
        None
    } else {
        t.parse().ok()
    };
    parsed.ok_or_else(|| PolicyError(format!("invalid flash offset: {}", py_repr(&s))))
}

fn py_repr(s: &str) -> String {
    if s.contains('\'') && !s.contains('"') { format!("\"{s}\"") } else { format!("'{}'", s.replace('\'', "\\'")) }
}

fn file_name(p: &str) -> String {
    Path::new(p).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()
}

#[derive(Debug, Clone)]
pub struct FlashImage {
    pub offset: u64,
    pub role: String,
    pub source: String,
    pub path: String,
    pub size: u64,
    pub sha256: String,
    pub partition: String,
}

impl FlashImage {
    pub fn summary(&self) -> Value {
        json!({"offset": format!("{:#x}", self.offset), "role": self.role, "partition": self.partition,
               "file": file_name(&self.source), "size": self.size, "sha256": self.sha256})
    }
}

pub fn classify_images(manifest: &Value, images: &[(u64, String, u64)], partitions: &[Partition]) -> Result<Vec<String>, PolicyError> {
    let section = |name: &str| -> Result<(Option<u64>, String), PolicyError> {
        let info = get(manifest, name);
        if !info.is_object() {
            return Ok((None, String::new()));
        }
        let encrypted = info.get("encrypted").map(py_str).unwrap_or_else(|| "false".into());
        if encrypted.to_lowercase() == "true" {
            return err(format!("encrypted {name} images are not supported"));
        }
        let off = match info.get("offset") {
            Some(v) => Some(offset(v)?),
            None => None,
        };
        Ok((off, info.get("file").map(py_str).unwrap_or_default()))
    };
    let (table_offset, table_file) = section("partition-table")?;
    let Some(table_offset) = table_offset else { return err("manifest has no partition-table offset") };
    let (boot_offset, boot_file) = section("bootloader")?;
    section("app")?;
    section("otadata")?;
    let mut labels = Vec::new();
    let mut spans: Vec<(u64, u64, String)> = Vec::new();
    for (off, relative, size) in images {
        let end = off + size;
        let label = if boot_offset == Some(*off) && file_name(&boot_file) == *relative {
            if end > table_offset {
                return err("bootloader image overlaps the partition table");
            }
            "bootloader".to_string()
        } else if *off == table_offset && file_name(&table_file) == *relative {
            if *size > PARTITION_TABLE_MAX {
                return err("partition table image is too large");
            }
            "partition-table".to_string()
        } else {
            let owner = partitions.iter().find(|p| p.offset <= *off && end <= p.end());
            match owner {
                Some(p) if matches!(p.kind(), "app" | "ota_data") => format!("{}:{}", p.kind(), p.name),
                _ => {
                    let place = owner.map_or("an unmapped region".to_string(), |p| format!("partition '{}'", p.name));
                    return err(format!(
                        "refusing to write {relative} at {off:#x}: it lands in {place}; only bootloader, partition table, OTA data and app partitions are allowed"
                    ));
                }
            }
        };
        if let Some((_, _, other)) = spans.iter().find(|(s, e, _)| *off < *e && *s < end) {
            return err(format!("{relative} overlaps {other}"));
        }
        spans.push((*off, end, relative.clone()));
        labels.push(label);
    }
    Ok(labels)
}

pub fn snapshot_root() -> std::io::Result<PathBuf> {
    util::private_dir(&util::runtime_dir()?.join("flash-snapshots"))
}

fn sha256_file(path: &Path) -> std::io::Result<String> {
    let mut f = fs::File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

pub fn read_state(dir: &Path) -> Map<String, Value> {
    fs::read_to_string(dir.join(STATE_FILE)).ok().and_then(|s| serde_json::from_str(&s).ok()).map(util::obj).unwrap_or_default()
}

pub fn write_state(dir: &Path, state: &Map<String, Value>) -> std::io::Result<()> {
    let temp = dir.join(format!(".{STATE_FILE}.tmp"));
    fs::write(&temp, util::py_dumps(&Value::Object(state.clone())))?;
    fs::rename(temp, dir.join(STATE_FILE))
}

#[derive(Debug)]
pub struct Snapshot {
    pub token: String,
    pub directory: PathBuf,
    pub build_dir: String,
    pub images: Vec<FlashImage>,
    pub project: Value,
    pub expires: f64,
}

impl Snapshot {
    pub fn state(&self) -> Map<String, Value> {
        read_state(&self.directory)
    }

    pub fn set_state(&self, state: &str, info: Map<String, Value>) {
        let mut s = self.state();
        s.extend(info);
        s.insert("state".into(), json!(state));
        s.insert("updated".into(), json!(now()));
        let _ = write_state(&self.directory, &s);
    }

    pub fn verify(&self) -> Result<(), PolicyError> {
        for image in &self.images {
            let path = Path::new(&image.path);
            if !path.is_file() || sha256_file(path).ok().as_deref() != Some(image.sha256.as_str()) {
                return err(format!("snapshot image changed: {}", file_name(&image.path)));
            }
        }
        Ok(())
    }

    pub fn remove(&self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn inside(path: &Path, root: &Path) -> bool {
    path.starts_with(root)
}

pub enum PrepareError {
    Policy(String),
    Io(String),
}

impl From<PolicyError> for PrepareError {
    fn from(e: PolicyError) -> Self {
        PrepareError::Policy(e.0)
    }
}

fn io_err(e: std::io::Error) -> PrepareError {
    PrepareError::Io(e.to_string())
}

pub fn prepare_snapshot(build_dir: &str, root: Option<&Path>) -> Result<Snapshot, PrepareError> {
    let build = util::expanduser(build_dir);
    if !build.is_absolute() {
        return Err(PolicyError("build_dir must be an absolute path".into()).into());
    }
    let build = util::realpath(&build);
    let manifest_path = build.join("flasher_args.json");
    let text = match fs::read_to_string(&manifest_path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(PolicyError(format!("missing ESP-IDF flash manifest: {}", manifest_path.display())).into());
        }
        Err(e) => return Err(io_err(e)),
    };
    let manifest: Value = serde_json::from_str(&text).map_err(|e| PolicyError(format!("invalid flash manifest: {e}")))?;
    let chip = get(get(&manifest, "extra_esptool_args"), "chip");
    let chip_ok = chip.as_str().is_some_and(|c| Regex::new(r"^esp32[a-z0-9]*$").unwrap().is_match(c));
    if !chip_ok {
        let shown = chip.as_str().map(py_repr).unwrap_or_else(|| py_str(chip));
        return Err(PolicyError(format!("manifest chip is {shown}; an ESP32-family chip is required")).into());
    }
    let files = match get(&manifest, "flash_files") {
        Value::Object(m) if !m.is_empty() => m.clone(),
        _ => return Err(PolicyError("flash manifest contains no flash files".into()).into()),
    };
    let mut entries: Vec<(u64, String)> = Vec::new();
    for (k, v) in &files {
        entries.push((offset(&json!(k))?, py_str(v)));
    }
    entries.sort_by_key(|e| e.0);
    let mut sources = Vec::new();
    for (off, relative) in entries {
        let source = util::realpath(&build.join(&relative));
        if Path::new(&relative).is_absolute() || !inside(&source, &build) || !source.is_file() {
            return Err(PolicyError(format!("flash image must be a file inside build_dir: {relative}")).into());
        }
        sources.push((off, source));
    }
    let table_file = get(get(&manifest, "partition-table"), "file");
    let table_source = util::realpath(&build.join(py_str(table_file)));
    if !truthy(table_file) || !inside(&table_source, &build) || !table_source.is_file() {
        return Err(PolicyError("manifest partition table image is missing".into()).into());
    }

    let token = util::token_urlsafe(18);
    let root = match root {
        Some(r) => r.to_path_buf(),
        None => snapshot_root().map_err(io_err)?,
    };
    let directory = root.join(&token);
    std::fs::DirBuilder::new().recursive(true).create(directory.join("images")).map_err(io_err)?;
    {
        use std::os::unix::fs::PermissionsExt;
        for d in [&directory, &directory.join("images")] {
            fs::set_permissions(d, fs::Permissions::from_mode(0o700)).map_err(io_err)?;
        }
    }
    let created = now();
    write_state(&directory, &util::obj(json!({"state": "prepared", "token": token, "created": created,
                                               "expires": created + SNAPSHOT_TTL, "build_dir": build.to_string_lossy()})))
    .map_err(io_err)?;
    let result = (|| -> Result<Snapshot, PrepareError> {
        let mut copies = Vec::new();
        for (index, (off, source)) in sources.iter().enumerate() {
            let target = directory.join("images").join(format!("{index}-{}", file_name(&source.to_string_lossy())));
            fs::copy(source, &target).map_err(io_err)?;
            copies.push((*off, source.clone(), target));
        }
        let table_copy = match copies.iter().find(|(_, s, _)| *s == table_source) {
            Some((_, _, t)) => t.clone(),
            None => {
                let t = directory.join("partition-table.bin");
                fs::copy(&table_source, &t).map_err(io_err)?;
                t
            }
        };
        let partitions = parse_partition_table(&fs::read(&table_copy).map_err(io_err)?)?;
        let mut listed = Vec::new();
        for (off, source, target) in &copies {
            listed.push((*off, file_name(&source.to_string_lossy()), fs::metadata(target).map_err(io_err)?.len()));
        }
        let labels = classify_images(&manifest, &listed, &partitions)?;
        let mut images = Vec::new();
        for ((off, source, target), label) in copies.iter().zip(labels) {
            images.push(FlashImage {
                offset: *off,
                partition: label.split_once(':').map(|(_, p)| p.to_string()).unwrap_or_default(),
                role: label,
                source: source.to_string_lossy().into_owned(),
                path: target.to_string_lossy().into_owned(),
                size: fs::metadata(target).map_err(io_err)?.len(),
                sha256: sha256_file(target).map_err(io_err)?,
            });
        }
        let mut rewritten = util::obj(manifest.clone());
        let flash_files: Map<String, Value> = images
            .iter()
            .map(|i| (format!("{:#x}", i.offset), json!(format!("images/{}", file_name(&i.path)))))
            .collect();
        rewritten.insert("flash_files".into(), Value::Object(flash_files));
        fs::write(directory.join("flasher_args.json"), serde_json::to_string_pretty(&rewritten).unwrap_or_default())
            .map_err(io_err)?;
        let description = build.join("project_description.json");
        let mut project = Map::new();
        if description.is_file() {
            fs::copy(&description, directory.join("project_description.json")).map_err(io_err)?;
            if let Ok(Value::Object(data)) = fs::read_to_string(&description).map(|t| serde_json::from_str(&t).unwrap_or_default()) {
                for key in ["project_name", "project_version", "target", "idf_ver"] {
                    if let Some(v) = data.get(key) {
                        project.insert(key.into(), v.clone());
                    }
                }
            }
        }
        Ok(Snapshot {
            token: token.clone(),
            directory: directory.clone(),
            build_dir: build.to_string_lossy().into_owned(),
            images,
            project: Value::Object(project),
            expires: created + SNAPSHOT_TTL,
        })
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&directory);
    }
    result
}

/// True when every image argument of an esptool command is inside `directory`.
pub fn command_paths_inside(command: &[String], directory: &Path) -> bool {
    let Some(start) = command.iter().position(|a| a == "write-flash") else { return false };
    let args = &command[start + 1..];
    let images: Vec<&String> = (1..args.len()).filter(|&i| args[i - 1].starts_with("0x")).map(|i| &args[i]).collect();
    let root = util::realpath(directory);
    !images.is_empty() && images.iter().all(|a| inside(&util::realpath(Path::new(a)), &root))
}

/// Decide from evidence (never age alone) whether the hub may still read a snapshot.
pub fn snapshot_collectable(state: &Map<String, Value>, hub_status: &dyn Fn(&str) -> Result<Option<Value>, ()>, t: f64) -> bool {
    let s = Value::Object(state.clone());
    let f = |k: &str| get(&s, k).as_f64().or_else(|| py_int(get(&s, k)).map(|i| i as f64));
    let kind = get(&s, "state").as_str().unwrap_or("");
    match kind {
        "done" => return true,
        "prepared" => return t > f("expires").unwrap_or(0.0),
        "sending" | "in_use" => {}
        _ => return false,
    }
    if !pid_alive(get(&s, "hub_pid")) {
        return true;
    }
    let Ok(Some(status)) = hub_status(&py_str(get(&s, "hub_socket")).replace("None", "")) else { return false };
    if get(&status, "pid") != get(&s, "hub_pid") {
        return false;
    }
    let channels = get(&status, "channels").as_array().cloned().unwrap_or_default();
    let Some(channel) = channels.iter().find(|c| get(c, "channel_socket") == get(&s, "channel_socket")) else {
        return true;
    };
    let flash = get(channel, "flash");
    if truthy(get(flash, "active")) {
        return false;
    }
    let current = py_int(get(flash, "id")).unwrap_or(0);
    if kind == "in_use" {
        return current >= py_int(get(&s, "flash_id")).unwrap_or(0);
    }
    let before = py_int(get(&s, "flash_id_before")).unwrap_or(0);
    current > before || t - f("updated").unwrap_or(t) > UNACCEPTED_GRACE
}

/// Remove snapshots that are provably unused; return removed tokens.
pub fn collect_snapshots(hub_status: &dyn Fn(&str) -> Result<Option<Value>, ()>, root: Option<&Path>, keep: &[String]) -> Vec<String> {
    let root = match root {
        Some(r) => r.to_path_buf(),
        None => match snapshot_root() {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        },
    };
    let mut removed = Vec::new();
    let Ok(entries) = fs::read_dir(&root) else { return removed };
    for entry in entries.flatten() {
        let dir = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        if !dir.is_dir() || keep.contains(&name) {
            continue;
        }
        if snapshot_collectable(&read_state(&dir), hub_status, now()) {
            let _ = fs::remove_dir_all(&dir);
            removed.push(name);
        }
    }
    removed
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str, ptype: u8, subtype: u8, off: u32, size: u32) -> Vec<u8> {
        let mut e = vec![0xAA, 0x50, ptype, subtype];
        e.extend_from_slice(&off.to_le_bytes());
        e.extend_from_slice(&size.to_le_bytes());
        let mut n = name.as_bytes().to_vec();
        n.resize(16, 0);
        e.extend(n);
        e.extend_from_slice(&0u32.to_le_bytes());
        e
    }

    fn table() -> Vec<u8> {
        let mut t = [entry("nvs", 1, 2, 0x9000, 0x6000), entry("otadata", 1, 0, 0xf000, 0x2000), entry("ota_0", 0, 0x10, 0x20000, 0x100000)].concat();
        t.extend([0xEB, 0xEB]);
        t.extend(vec![0xFF; 30]);
        t.extend(vec![0xFF; 32]);
        t
    }

    fn manifest() -> Value {
        json!({"partition-table": {"offset": "0x8000", "file": "partition_table/partition-table.bin"},
               "bootloader": {"offset": "0x2000", "file": "bootloader/bootloader.bin"}})
    }

    #[test]
    fn classify_policy() {
        let parts = parse_partition_table(&table()).unwrap();
        assert_eq!(parts.len(), 3);
        let ok = classify_images(&manifest(), &[(0x2000, "bootloader.bin".into(), 0x5000), (0x8000, "partition-table.bin".into(), 0xc00),
                                                (0xf000, "ota_data_initial.bin".into(), 0x2000), (0x20000, "app.bin".into(), 0x1000)], &parts).unwrap();
        assert_eq!(ok, ["bootloader", "partition-table", "ota_data:otadata", "app:ota_0"]);
        let nvs = classify_images(&manifest(), &[(0x9000, "nvs.bin".into(), 0x10)], &parts).unwrap_err();
        assert!(nvs.0.contains("partition 'nvs'"));
        assert!(classify_images(&manifest(), &[(0x400000, "x.bin".into(), 1)], &parts).unwrap_err().0.contains("unmapped"));
        assert!(classify_images(&manifest(), &[(0x20000, "a.bin".into(), 0x10), (0x20008, "b.bin".into(), 0x10)], &parts)
            .unwrap_err().0.contains("overlaps a.bin"));
        assert_eq!(offset(&json!("0x10")).unwrap(), 16);
        assert!(offset(&json!("010")).is_err());
    }

    #[test]
    fn collectable_needs_evidence() {
        let none = |_: &str| -> Result<Option<Value>, ()> { Ok(None) };
        let t = now();
        let st = |v: Value| util::obj(v);
        assert!(snapshot_collectable(&st(json!({"state": "done"})), &none, t));
        assert!(!snapshot_collectable(&st(json!({"state": "prepared", "expires": t + 5.0})), &none, t));
        assert!(snapshot_collectable(&st(json!({"state": "prepared", "expires": t - 5.0})), &none, t));
        assert!(!snapshot_collectable(&st(json!({})), &none, t));
        // Dead hub pid: collectable.
        assert!(snapshot_collectable(&st(json!({"state": "in_use", "hub_pid": 999_999_999})), &none, t));
        let me = std::process::id();
        // Live hub but unreachable status: keep.
        assert!(!snapshot_collectable(&st(json!({"state": "in_use", "hub_pid": me})), &none, t));
        let active = |_: &str| -> Result<Option<Value>, ()> {
            Ok(Some(json!({"pid": std::process::id(), "channels": [{"channel_socket": "c", "flash": {"active": true, "id": 3}}]})))
        };
        assert!(!snapshot_collectable(&st(json!({"state": "in_use", "hub_pid": me, "channel_socket": "c", "flash_id": 3})), &active, t));
        let idle = |_: &str| -> Result<Option<Value>, ()> {
            Ok(Some(json!({"pid": std::process::id(), "channels": [{"channel_socket": "c", "flash": {"active": false, "id": 3}}]})))
        };
        assert!(snapshot_collectable(&st(json!({"state": "in_use", "hub_pid": me, "channel_socket": "c", "flash_id": 3})), &idle, t));
        assert!(!snapshot_collectable(&st(json!({"state": "sending", "hub_pid": me, "channel_socket": "c", "flash_id_before": 3, "updated": t})), &idle, t));
        assert!(snapshot_collectable(&st(json!({"state": "sending", "hub_pid": me, "channel_socket": "c", "flash_id_before": 2, "updated": t})), &idle, t));
    }

    #[test]
    fn command_paths() {
        let d = std::env::temp_dir().join(format!("sd-paths-{}", util::random_hex(8)));
        fs::create_dir(&d).unwrap();
        fs::write(d.join("x.bin"), b"test").unwrap();
        let inside = d.join("x.bin").to_string_lossy().into_owned();
        let cmd = |p: &str| vec!["esptool".into(), "write-flash".into(), "0x0".into(), p.to_string()];
        assert!(command_paths_inside(&cmd(&inside), &d));
        assert!(!command_paths_inside(&cmd("/etc/passwd"), &d));
        assert!(!command_paths_inside(&["x".to_string()], &d));
        fs::remove_dir_all(d).unwrap();
    }
}
