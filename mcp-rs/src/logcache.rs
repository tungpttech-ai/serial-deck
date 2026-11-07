//! Disk-backed log archive shared with the Python processes (logcache.py).
//!
//! Same SQLite file, table, indexes and pragmas, so the dashboard's archive view
//! reads streams written here.

use crate::util::{config_dir, home, now};
use rusqlite::{Connection, ErrorCode, params};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

const MIB: i64 = 1024 * 1024;
const RETENTION_S: f64 = 48.0 * 3600.0;

struct Inner {
    db: Option<Connection>,
    max_pages: i64,
    last_prune: f64,
    /// Records not yet archived, in arrival order: (stream, seq) -> (created, label, payload).
    // ponytail: unlike Python, RAM holds only unarchived records (no 64 MiB hot
    // mirror); reads fall back to it only while the disk is failing.
    pending: BTreeMap<u64, (String, i64, f64, String, String)>,
    pending_bytes: i64,
    next_order: u64,
    lost_records: i64,
    error: String,
}

pub struct LogCache {
    directory: PathBuf,
    ram_mib: i64,
    disk_mib: i64,
    inner: Mutex<Inner>,
}

fn is_full(e: &rusqlite::Error) -> bool {
    matches!(e, rusqlite::Error::SqliteFailure(f, _) if f.code == ErrorCode::DiskFull)
}

fn settings() -> (String, i64, i64) {
    let path = config_dir().join("settings.json");
    let raw: Value = std::fs::read_to_string(path).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or(Value::Null);
    let cache = raw.get("log_cache").cloned().unwrap_or(Value::Null);
    let int = |k: &str, d: i64, lo: i64, hi: i64| {
        cache.get(k).and_then(Value::as_i64).filter(|v| (lo..=hi).contains(v)).unwrap_or(d)
    };
    let dir = cache.get("directory").and_then(Value::as_str).unwrap_or("").to_string();
    (dir, int("ram_mib", 64, 1, 4096), int("disk_mib", 1024, 16, 1_048_576))
}

impl LogCache {
    pub fn new(directory: &str, ram_mib: i64, disk_mib: i64) -> Self {
        let directory = if directory.is_empty() {
            std::env::var_os("XDG_CACHE_HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|| home().join(".cache"))
                .join("serial-deck")
                .join("logs")
        } else {
            crate::util::expanduser(directory)
        };
        LogCache {
            directory,
            ram_mib,
            disk_mib,
            inner: Mutex::new(Inner {
                db: None,
                max_pages: 0,
                last_prune: 0.0,
                pending: BTreeMap::new(),
                pending_bytes: 0,
                next_order: 0,
                lost_records: 0,
                error: String::new(),
            }),
        }
    }

    fn open<'a>(&self, inner: &'a mut Inner) -> rusqlite::Result<&'a Connection> {
        if inner.db.is_none() {
            let to_err = |e: std::io::Error| rusqlite::Error::ToSqlConversionFailure(Box::new(e));
            std::fs::create_dir_all(&self.directory).map_err(to_err)?;
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&self.directory, std::fs::Permissions::from_mode(0o700)).map_err(to_err)?;
            let path = self.directory.join("logs.sqlite3");
            {
                use std::os::unix::fs::OpenOptionsExt;
                std::fs::OpenOptions::new().create(true).append(true).mode(0o600).open(&path).map_err(to_err)?;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).map_err(to_err)?;
            }
            let db = Connection::open(&path)?;
            db.busy_timeout(std::time::Duration::from_secs(5))?;
            db.execute_batch(
                "PRAGMA auto_vacuum=INCREMENTAL; PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;
                 PRAGMA cache_size=-1024; PRAGMA wal_autocheckpoint=64; PRAGMA journal_size_limit=0;",
            )?;
            let page_size: i64 = db.query_row("PRAGMA page_size", [], |r| r.get(0))?;
            inner.max_pages = (self.disk_mib * MIB) * 85 / 100 / page_size;
            db.execute_batch(&format!(
                "PRAGMA max_page_count={};
                 CREATE TABLE IF NOT EXISTS logs (id INTEGER PRIMARY KEY, stream TEXT NOT NULL, seq INTEGER NOT NULL, created REAL NOT NULL, label TEXT NOT NULL, data BLOB NOT NULL);
                 CREATE UNIQUE INDEX IF NOT EXISTS stream_seq ON logs(stream, seq);
                 CREATE INDEX IF NOT EXISTS log_age ON logs(created);",
                inner.max_pages
            ))?;
            inner.db = Some(db);
        }
        Ok(inner.db.as_ref().unwrap())
    }

    fn prune(&self, inner: &mut Inner, force: bool) -> rusqlite::Result<()> {
        let t = now();
        if !force && t - inner.last_prune < 1.0 {
            self.open(inner)?;
            return Ok(());
        }
        let max_pages = {
            self.open(inner)?;
            inner.max_pages
        };
        let db = inner.db.as_ref().unwrap();
        let q = |sql: &str| db.query_row(sql, [], |r| r.get::<_, i64>(0));
        loop {
            let deleted = db.execute(
                "DELETE FROM logs WHERE id IN (SELECT id FROM logs WHERE created < ? LIMIT 256)",
                params![t - RETENTION_S],
            )?;
            if deleted < 256 {
                break;
            }
        }
        let target = max_pages * if force { 80 } else { 95 } / 100;
        loop {
            let used = q("PRAGMA page_count")? - q("PRAGMA freelist_count")?;
            if used <= target {
                break;
            }
            let count = q("SELECT COUNT(*) FROM logs")?;
            let batch = 256.min(1.max((count * (used - target) + used - 1) / used));
            let deleted = db.execute(
                "DELETE FROM logs WHERE id IN (SELECT id FROM logs ORDER BY created LIMIT ?)",
                params![batch],
            )?;
            if deleted == 0 {
                break;
            }
        }
        while q("PRAGMA page_count")? > max_pages && q("PRAGMA freelist_count")? > 0 {
            let mut stmt = db.prepare("PRAGMA incremental_vacuum(256)")?;
            let mut rows = stmt.query([])?;
            while rows.next()?.is_some() {}
        }
        db.execute_batch(&format!("PRAGMA max_page_count={max_pages};"))?;
        db.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))?;
        inner.last_prune = t;
        Ok(())
    }

    fn failed(inner: &mut Inner, e: &dyn std::fmt::Display) {
        let message = e.to_string();
        if message != inner.error {
            eprintln!("Log archive unavailable; keeping recent logs in RAM: {message}");
        }
        inner.error = message;
    }

    pub fn append(&self, stream: &str, seq: i64, label: &str, record: &Map<String, Value>) {
        let t = now();
        let mut payload = Map::new();
        payload.insert("created_at".into(), json!(t));
        for (k, v) in record {
            payload.insert(k.clone(), v.clone());
        }
        let payload = serde_json::to_string(&payload).unwrap_or_default();
        let mut guard = self.inner.lock().unwrap();
        let inner = &mut *guard;
        inner.pending_bytes += (payload.len() + stream.len() + label.len() + 512) as i64;
        inner.pending.insert(inner.next_order, (stream.into(), seq, t, label.into(), payload));
        inner.next_order += 1;
        let result = (|| -> rusqlite::Result<()> {
            self.prune(inner, false)?;
            while let Some((&order, (s, q, created, l, p))) = inner.pending.iter().next() {
                if *created < t - RETENTION_S {
                    let charge = (p.len() + s.len() + l.len() + 512) as i64;
                    inner.pending.remove(&order);
                    inner.pending_bytes -= charge;
                    continue;
                }
                let values = (s.clone(), *q, *created, l.clone(), p.clone());
                let db = inner.db.as_ref().unwrap();
                let insert = |db: &Connection| {
                    db.execute(
                        "INSERT OR IGNORE INTO logs(stream,seq,created,label,data) VALUES (?,?,?,?,?)",
                        params![values.0, values.1, values.2, values.3, values.4.as_bytes()],
                    )
                };
                if let Err(e) = insert(db) {
                    if !is_full(&e) {
                        return Err(e);
                    }
                    self.prune(inner, true)?;
                    insert(inner.db.as_ref().unwrap())?;
                }
                let charge = (values.4.len() + values.0.len() + values.3.len() + 512) as i64;
                inner.pending.remove(&order);
                inner.pending_bytes -= charge;
            }
            Ok(())
        })();
        match result {
            Ok(()) => {
                inner.error = if inner.lost_records > 0 {
                    format!("{} records lost before archiving during disk failure", inner.lost_records)
                } else {
                    String::new()
                }
            }
            Err(e) => Self::failed(inner, &e),
        }
        while inner.pending_bytes > self.ram_mib * MIB {
            let Some((&order, _)) = inner.pending.iter().next() else { break };
            let (s, _, created, l, p) = inner.pending.remove(&order).unwrap();
            inner.pending_bytes -= (p.len() + s.len() + l.len() + 512) as i64;
            if created >= t - RETENTION_S {
                inner.lost_records += 1;
            }
        }
    }

    /// Records of `stream` with cursor <= seq < before, ascending or descending.
    pub fn rows(&self, stream: &str, cursor: i64, reverse: bool, limit: Option<usize>, before: Option<i64>) -> RowIter<'_> {
        RowIter {
            cache: self,
            stream: stream.to_string(),
            cursor,
            reverse,
            limit,
            before,
            position: if reverse { before.unwrap_or(i64::MAX) } else { cursor - 1 },
            count: 0,
            batch: Vec::new(),
            done: false,
        }
    }

    fn batch(&self, it: &RowIter) -> Vec<(i64, String)> {
        let size = it.limit.map_or(128, |l| 128.min(l - it.count)) as i64;
        let mut guard = self.inner.lock().unwrap();
        let inner = &mut *guard;
        let (op, order) = if it.reverse { ("<", "DESC") } else { (">", "ASC") };
        let before = it.before.unwrap_or(i64::MAX);
        let mut batch: Vec<(i64, String)> = match self.open(inner).and_then(|db| {
            let mut stmt = db.prepare(&format!(
                "SELECT seq,data FROM logs WHERE stream=? AND seq {op} ? AND seq>=? AND seq<? AND created>=? ORDER BY seq {order} LIMIT ?"
            ))?;
            stmt.query_map(params![it.stream, it.position, it.cursor, before, now() - RETENTION_S, size], |r| {
                let data: Vec<u8> = r.get(1)?;
                Ok((r.get(0)?, String::from_utf8_lossy(&data).into_owned()))
            })?
            .collect()
        }) {
            Ok(rows) => rows,
            Err(e) => {
                Self::failed(inner, &e);
                Vec::new()
            }
        };
        if !inner.error.is_empty() {
            let cutoff = now() - RETENTION_S;
            let mut merged: BTreeMap<i64, String> = batch.into_iter().collect();
            for (s, q, created, _, p) in inner.pending.values() {
                let in_range = if it.reverse { *q < it.position } else { *q > it.position };
                if s == &it.stream && *created >= cutoff && *q >= it.cursor && *q < before && in_range {
                    merged.insert(*q, p.clone());
                }
            }
            batch = merged.into_iter().collect();
            if it.reverse {
                batch.reverse();
            }
            batch.truncate(size as usize);
        }
        batch
    }

    pub fn archives(&self) -> Vec<Value> {
        let mut guard = self.inner.lock().unwrap();
        let inner = &mut *guard;
        let result = self.prune(inner, false).and_then(|_| {
            let db = inner.db.as_ref().unwrap();
            let mut stmt = db.prepare(
                "SELECT stream,label,MIN(created),MAX(created),COUNT(*) FROM logs WHERE created>=? GROUP BY stream ORDER BY MAX(created) DESC",
            )?;
            stmt.query_map(params![now() - RETENTION_S], |r| {
                Ok(json!({"stream": r.get::<_, String>(0)?, "label": r.get::<_, String>(1)?,
                          "first": r.get::<_, f64>(2)?, "last": r.get::<_, f64>(3)?, "records": r.get::<_, i64>(4)?}))
            })?
            .collect()
        });
        result.unwrap_or_else(|e| {
            Self::failed(inner, &e);
            Vec::new()
        })
    }

    pub fn status(&self) -> Map<String, Value> {
        let inner = self.inner.lock().unwrap();
        let v = json!({"directory": self.directory.to_string_lossy(), "ram_mib": self.ram_mib, "disk_mib": self.disk_mib,
                       "retention_hours": 48, "ram_used_bytes": inner.pending_bytes,
                       "pending_records": inner.pending.len(), "lost_records": inner.lost_records, "error": inner.error});
        crate::util::obj(v)
    }

    #[allow(dead_code)]
    pub fn directory(&self) -> &Path {
        &self.directory
    }
}

pub struct RowIter<'a> {
    cache: &'a LogCache,
    stream: String,
    cursor: i64,
    reverse: bool,
    limit: Option<usize>,
    before: Option<i64>,
    position: i64,
    count: usize,
    batch: Vec<(i64, String)>,
    done: bool,
}

impl Iterator for RowIter<'_> {
    type Item = Map<String, Value>;
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.done || self.limit.is_some_and(|l| self.count >= l) {
                return None;
            }
            if self.batch.is_empty() {
                let mut batch = self.cache.batch(self);
                if batch.is_empty() {
                    self.done = true;
                    return None;
                }
                self.position = batch.last().unwrap().0;
                batch.reverse();
                self.batch = batch;
            }
            let (_, payload) = self.batch.pop().unwrap();
            if let Ok(Value::Object(m)) = serde_json::from_str(&payload) {
                self.count += 1;
                return Some(m);
            }
        }
    }
}

pub fn shared_cache() -> Arc<LogCache> {
    static SHARED: OnceLock<Arc<LogCache>> = OnceLock::new();
    SHARED
        .get_or_init(|| {
            let (dir, ram, disk) = settings();
            Arc::new(LogCache::new(&dir, ram, disk))
        })
        .clone()
}

/// A session's records in the shared cache (CachedRecords).
pub struct Records {
    pub cache: Arc<LogCache>,
    pub stream: String,
    label: String,
}

impl Records {
    pub fn new(label: &str, stream: Option<String>) -> Self {
        Records { cache: shared_cache(), stream: stream.unwrap_or_else(|| crate::util::random_hex(32)), label: label.into() }
    }

    pub fn append(&self, record: &Map<String, Value>) {
        let seq = record.get("seq").and_then(Value::as_i64).unwrap_or(0);
        self.cache.append(&self.stream, seq, &self.label, record);
    }

    pub fn iter(&self, cursor: i64, reverse: bool, limit: Option<usize>, before: Option<i64>) -> RowIter<'_> {
        self.cache.rows(&self.stream, cursor, reverse, limit, before)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_and_page() {
        let dir = std::env::temp_dir().join(format!("sdmcp-cache-{}", crate::util::random_hex(8)));
        let cache = LogCache::new(dir.to_str().unwrap(), 1, 16);
        for seq in 1..=300 {
            let rec = crate::util::obj(json!({"seq": seq, "kind": "log", "text": format!("line {seq}")}));
            cache.append("s1", seq, "MCP test", &rec);
        }
        let all: Vec<_> = cache.rows("s1", 0, false, None, None).collect();
        assert_eq!(all.len(), 300);
        assert_eq!(all[0]["seq"], json!(1));
        assert!(all[0].contains_key("created_at"));
        let last: Vec<_> = cache.rows("s1", 0, true, Some(3), Some(299)).map(|r| r["seq"].clone()).collect();
        assert_eq!(last, vec![json!(298), json!(297), json!(296)]);
        let mid: Vec<_> = cache.rows("s1", 150, false, Some(2), None).map(|r| r["seq"].clone()).collect();
        assert_eq!(mid, vec![json!(150), json!(151)]);
        assert_eq!(cache.archives()[0]["records"], json!(300));
        assert_eq!(cache.status()["pending_records"], json!(0));
        std::fs::remove_dir_all(dir).ok();
    }
}
