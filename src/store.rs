//! store.rs — thread-safe device registry, parameter cache, and task queue.
//! Devices, discovered parameters, the task queue/history,
//! events, captured credentials, the diagnostic wire log, and settings all
//! persist incrementally to an embedded SQLite database (`acs.db`) in the data
//! dir. The in-memory model is kept as the single source of truth for reads; we
//! write through to SQLite on every mutation (best-effort — DB errors are
//! logged, never fatal). The SQLite database is the sole durable store.

use parking_lot::{Mutex, RwLock};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::settings::Settings;

static TASK_SEQ: AtomicU64 = AtomicU64::new(1);

/// Max number of wire-log frames kept in the in-memory ring buffer (SQLite
/// keeps a larger durable window — see `WIRE_DB_CAP`).
const WIRE_CAP: usize = 300;

/// Max number of wire-log rows retained in SQLite before old rows are pruned.
const WIRE_DB_CAP: i64 = 5000;

/// Max number of event rows retained in SQLite before old rows are pruned.
const EVENT_DB_CAP: i64 = 1000;
/// Max distinct deduped credentials kept per in-memory capture list.
const CAPTURE_CAP: usize = 200;

pub fn now_iso() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

fn next_task_id() -> u64 {
    TASK_SEQ.fetch_add(1, Ordering::SeqCst)
}

/// Advance `TASK_SEQ` so the next allocated id is strictly greater than any id
/// already loaded from the DB (prevents id collisions with persisted tasks).
fn bump_task_seq(max_loaded: u64) {
    let want = max_loaded + 1;
    // monotonic compare-and-bump; spin only on concurrent startup writers (none
    // exist at load time, so this resolves on the first iteration in practice).
    let mut cur = TASK_SEQ.load(Ordering::SeqCst);
    while cur < want {
        match TASK_SEQ.compare_exchange(cur, want, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => break,
            Err(observed) => cur = observed,
        }
    }
}

/// Pull the dedup identity out of a freshly-built capture record:
/// (scheme, username, secret) where secret is the password for Basic and the
/// digest response otherwise. Missing fields read as "".
fn capture_identity(rec: &Value) -> (String, String, String) {
    let gs = |k: &str| {
        rec.get(k)
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    };
    let scheme = gs("scheme");
    let username = gs("username");
    let secret = if scheme == "basic" {
        gs("password")
    } else {
        gs("response")
    };
    (scheme, username, secret)
}

/// True when an already-stored capture record matches the given identity.
fn capture_matches(rec: &Value, scheme: &str, username: &str, secret: &str) -> bool {
    let (s, u, sec) = capture_identity(rec);
    s == scheme && u == username && sec == secret
}

/// Bump an existing deduped capture: count += 1, last = now.
fn bump_capture(rec: &mut Value, now: &str) {
    if let Some(obj) = rec.as_object_mut() {
        let next = obj.get("count").and_then(|v| v.as_u64()).unwrap_or(1) + 1;
        obj.insert("count".to_string(), json!(next));
        obj.insert("last".to_string(), json!(now));
    }
}

/// Dedup a capture into `list`: bump an existing match's count/`last`, else push
/// a fresh record (count=1, first=last=now) and cap the list at `CAPTURE_CAP`.
/// Returns the snapshot to persist. Runs under the caller's inner lock.
fn merge_capture(
    list: &mut Vec<Value>,
    scheme: &str,
    username: &str,
    identity: &str,
    key: &str,
    now: &str,
    rec: Value,
) -> Value {
    if let Some(existing) = list
        .iter_mut()
        .find(|c| capture_matches(c, scheme, username, identity))
    {
        bump_capture(existing, now);
        return existing.clone();
    }
    let mut fresh = rec;
    if let Some(obj) = fresh.as_object_mut() {
        obj.remove("ts");
        obj.insert("key".to_string(), json!(key));
        obj.insert("first".to_string(), json!(now));
        obj.insert("last".to_string(), json!(now));
        obj.insert("count".to_string(), json!(1u64));
    }
    list.push(fresh.clone());
    if list.len() > CAPTURE_CAP {
        let start = list.len() - CAPTURE_CAP;
        list.drain(0..start);
    }
    fresh
}

/// One queued ACS->CPE RPC (or a discovery walk node).
#[derive(Debug, Clone)]
pub struct Task {
    pub id: u64,
    pub type_: String,
    pub args: Value, // JSON object
    pub label: String,
    pub status: String, // pending|inflight|done|fault|error
    pub result: Value,  // null or object
    pub fault: Value,   // null or object
    pub created: String,
    pub updated: String,
    pub cwmp_id: Option<String>,
    pub walk_id: Option<u64>,
    pub walk_depth: u32,
}

impl Task {
    pub fn new(
        type_: &str,
        args: Value,
        label: Option<&str>,
        walk_id: Option<u64>,
        walk_depth: u32,
    ) -> Task {
        let id = next_task_id();
        let created = now_iso();
        let label = label
            .map(|s| s.to_string())
            .unwrap_or_else(|| type_.to_string());
        Task {
            id,
            type_: type_.to_string(),
            args,
            label,
            status: "pending".to_string(),
            result: Value::Null,
            fault: Value::Null,
            created: created.clone(),
            updated: created,
            cwmp_id: None,
            walk_id,
            walk_depth,
        }
    }

    pub fn to_value(&self) -> Value {
        json!({
            "id": self.id,
            "type": self.type_,
            "args": self.args,
            "label": self.label,
            "status": self.status,
            "result": self.result,
            "fault": self.fault,
            "created": self.created,
            "updated": self.updated,
            "walk_id": self.walk_id,
        })
    }

    /// Full lossless serialization for the SQLite `tasks.data` column (every
    /// field, including the ones `to_value` drops for the UI). Reversible via
    /// `from_persist`.
    pub fn to_persist(&self) -> Value {
        json!({
            "id": self.id,
            "type": self.type_,
            "args": self.args,
            "label": self.label,
            "status": self.status,
            "result": self.result,
            "fault": self.fault,
            "created": self.created,
            "updated": self.updated,
            "cwmp_id": self.cwmp_id,
            "walk_id": self.walk_id,
            "walk_depth": self.walk_depth,
        })
    }

    /// Reconstruct a Task from `to_persist` output, defaulting any missing
    /// fields (forward/backward compatible with schema drift).
    pub fn from_persist(d: &Value) -> Task {
        let gs = |k: &str| d.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
        let id = d.get("id").and_then(|v| v.as_u64()).unwrap_or(0);
        let type_ = gs("type");
        Task {
            id,
            type_: type_.clone(),
            args: d.get("args").cloned().unwrap_or(Value::Null),
            label: {
                let l = gs("label");
                if l.is_empty() { type_ } else { l }
            },
            status: {
                let s = gs("status");
                if s.is_empty() {
                    "pending".to_string()
                } else {
                    s
                }
            },
            result: d.get("result").cloned().unwrap_or(Value::Null),
            fault: d.get("fault").cloned().unwrap_or(Value::Null),
            created: gs("created"),
            updated: gs("updated"),
            cwmp_id: d
                .get("cwmp_id")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            walk_id: d.get("walk_id").and_then(|v| v.as_u64()),
            walk_depth: d.get("walk_depth").and_then(|v| v.as_u64()).unwrap_or(0) as u32,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ParamEntry {
    #[serde(default)]
    pub value: String,
    #[serde(rename = "type", default)]
    pub type_: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub writable: Option<String>,
    #[serde(default)]
    pub ts: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AttrEntry {
    #[serde(default)]
    pub notification: String,
    #[serde(default)]
    pub access_list: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Device {
    pub key: String,
    pub oui: String,
    pub serial: String,
    pub product_class: String,
    pub manufacturer: String,
    pub model: String,
    pub software_version: String,
    pub ip: String,
    pub cwmp_ns: String,
    pub root: String,
    pub connection_request_url: String,
    pub last_inform: Value, // null or object
    pub last_seen: String,
    pub online_hint: bool,
    pub parameters: BTreeMap<String, ParamEntry>,
    pub attributes: BTreeMap<String, AttrEntry>,
    pub rpc_methods: Vec<String>,
    // transient
    pub queue: Vec<Task>,
    pub history: Vec<Task>,
    pub captures: Vec<Value>,
}

impl Device {
    pub fn new(key: &str) -> Device {
        Device {
            key: key.to_string(),
            oui: String::new(),
            serial: String::new(),
            product_class: String::new(),
            manufacturer: String::new(),
            model: String::new(),
            software_version: String::new(),
            ip: String::new(),
            cwmp_ns: "urn:dslforum-org:cwmp-1-0".to_string(),
            root: "InternetGatewayDevice.".to_string(),
            connection_request_url: String::new(),
            last_inform: Value::Null,
            last_seen: String::new(),
            online_hint: false,
            parameters: BTreeMap::new(),
            attributes: BTreeMap::new(),
            rpc_methods: Vec::new(),
            queue: Vec::new(),
            history: Vec::new(),
            captures: Vec::new(),
        }
    }

    fn params_value(&self) -> Value {
        let mut m = Map::new();
        for (k, v) in &self.parameters {
            m.insert(k.clone(), serde_json::to_value(v).unwrap_or(Value::Null));
        }
        Value::Object(m)
    }

    fn attrs_value(&self) -> Value {
        let mut m = Map::new();
        for (k, v) in &self.attributes {
            m.insert(k.clone(), serde_json::to_value(v).unwrap_or(Value::Null));
        }
        Value::Object(m)
    }

    pub fn to_persist(&self) -> Value {
        json!({
            "key": self.key,
            "oui": self.oui,
            "serial": self.serial,
            "product_class": self.product_class,
            "manufacturer": self.manufacturer,
            "model": self.model,
            "software_version": self.software_version,
            "ip": self.ip,
            "cwmp_ns": self.cwmp_ns,
            "root": self.root,
            "connection_request_url": self.connection_request_url,
            "last_inform": self.last_inform,
            "last_seen": self.last_seen,
            "parameters": self.params_value(),
            "attributes": self.attrs_value(),
            "rpc_methods": self.rpc_methods,
        })
    }

    pub fn to_view(&self) -> Value {
        let mut v = self.to_persist();
        let obj = v.as_object_mut().unwrap();
        obj.insert("online_hint".to_string(), json!(self.online_hint));
        obj.insert(
            "queue".to_string(),
            Value::Array(self.queue.iter().map(|t| t.to_value()).collect()),
        );
        let hist_start = self.history.len().saturating_sub(60);
        obj.insert(
            "history".to_string(),
            Value::Array(
                self.history[hist_start..]
                    .iter()
                    .map(|t| t.to_value())
                    .collect(),
            ),
        );
        obj.insert("param_count".to_string(), json!(self.parameters.len()));
        obj.insert("captures".to_string(), Value::Array(self.captures.clone()));
        v
    }

    /// Full device detail view (adds sorted parameters/attributes arrays).
    pub fn to_detail(&self) -> Value {
        let mut view = self.to_view();
        let obj = view.as_object_mut().unwrap();
        // parameters: sorted by name (BTreeMap is already sorted)
        let params: Vec<Value> = self
            .parameters
            .iter()
            .map(|(n, e)| {
                let mut m = Map::new();
                m.insert("name".to_string(), json!(n));
                m.insert("value".to_string(), json!(e.value));
                m.insert("type".to_string(), json!(e.type_));
                if let Some(w) = &e.writable {
                    m.insert("writable".to_string(), json!(w));
                }
                m.insert("ts".to_string(), json!(e.ts));
                Value::Object(m)
            })
            .collect();
        let attrs: Vec<Value> = self
            .attributes
            .iter()
            .map(|(n, e)| {
                json!({
                    "name": n,
                    "notification": e.notification,
                    "access_list": e.access_list,
                })
            })
            .collect();
        obj.insert("parameters".to_string(), Value::Array(params));
        obj.insert("attributes".to_string(), Value::Array(attrs));
        view
    }
}

#[derive(Debug, Clone)]
pub struct Walk {
    pub max_depth: u32,
    pub max_nodes: u32,
    pub count: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct LogEntry {
    pub ts: String,
    pub msg: String,
    pub key: Option<String>,
    pub level: String,
}

/// One captured frame of the CWMP wire log (diagnostic). `dir` is "in" for a
/// request the CPE sent us and "out" for a response we sent the CPE. Header
/// values for secrets (Authorization) are masked before this is constructed.
#[derive(Debug, Clone, Serialize)]
pub struct WireEntry {
    pub id: u64,
    pub ts: String,
    pub dir: String, // "in" | "out"
    pub client_ip: String,
    pub session_key: Option<String>,
    pub summary: String,
    pub headers: BTreeMap<String, String>,
    pub body: String,
}

struct Inner {
    devices: BTreeMap<String, Device>,
    log: Vec<LogEntry>,
    walks: BTreeMap<u64, Walk>,
    captures: Vec<Value>,
    walk_seq: u64,
}

pub struct Store {
    /// Embedded SQLite connection (the durable store of record). Wrapped in a
    /// Mutex so the synchronous rusqlite handle is shared safely across tasks.
    db: Mutex<Connection>,
    inner: Mutex<Inner>,
    /// Diagnostic CWMP wire-log ring buffer (most-recent WIRE_CAP frames).
    wire: Mutex<VecDeque<WireEntry>>,
    /// Monotonic id assigned to each wire frame.
    wire_seq: AtomicU64,
    /// Runtime-mutable, web-editable, persisted settings.
    settings: RwLock<Settings>,
    /// Host (no :port) most recently learned from a CPE Inform's Host header.
    learned_host: RwLock<Option<String>>,
    /// Auto-detected/explicit advertise IP fallback and whether it was explicit.
    advertise_ip: String,
    advertise_ip_explicit: bool,
}

/// CREATE-IF-NOT-EXISTS schema for the embedded DB.
const SCHEMA_SQL: &str = "
CREATE TABLE IF NOT EXISTS devices (
    key TEXT PRIMARY KEY,
    oui TEXT, serial TEXT, product_class TEXT, manufacturer TEXT,
    model TEXT, software_version TEXT, ip TEXT, cwmp_ns TEXT, root TEXT,
    connection_request_url TEXT, last_inform TEXT, last_seen TEXT,
    rpc_methods TEXT
);
CREATE TABLE IF NOT EXISTS parameters (
    device_key TEXT, name TEXT, value TEXT, type TEXT, writable TEXT, ts TEXT,
    PRIMARY KEY(device_key, name)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS attributes (
    device_key TEXT, name TEXT, notification TEXT, access_list TEXT,
    PRIMARY KEY(device_key, name)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS tasks (
    id INTEGER PRIMARY KEY,
    device_key TEXT, queued INTEGER, data TEXT, created TEXT, updated TEXT
);
CREATE INDEX IF NOT EXISTS idx_tasks_dev ON tasks(device_key);
CREATE TABLE IF NOT EXISTS captures (
    device_key TEXT, scheme TEXT, username TEXT, secret TEXT, data TEXT,
    PRIMARY KEY(device_key, scheme, username, secret)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT, device_key TEXT, level TEXT, message TEXT
);
CREATE TABLE IF NOT EXISTS wire (
    id INTEGER PRIMARY KEY,
    ts TEXT, dir TEXT, client_ip TEXT, session_key TEXT, summary TEXT,
    headers TEXT, body TEXT
);
CREATE TABLE IF NOT EXISTS settings (k INTEGER PRIMARY KEY, v TEXT);
";

/// Open (creating if needed) the SQLite DB, apply pragmas, and create the
/// schema. On any failure we fall back to an in-memory DB so the server still
/// runs (persistence is best-effort, never fatal).
fn open_db(path: &std::path::Path) -> Connection {
    let conn = match Connection::open(path) {
        Ok(c) => c,
        Err(e) => {
            println!(
                "[store] db: open {} failed: {e}; using in-memory",
                path.display()
            );
            Connection::open_in_memory().expect("in-memory sqlite must open")
        }
    };
    // WAL for concurrent readers + crash safety; NORMAL sync is the WAL-recommended
    // durability/speed balance; enforce foreign keys.
    if let Err(e) = conn.execute_batch(
        "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA foreign_keys=ON;",
    ) {
        println!("[store] db: pragma failed: {e}");
    }
    if let Err(e) = conn.execute_batch(SCHEMA_SQL) {
        println!("[store] db: schema failed: {e}");
    }
    conn
}

impl Store {
    /// `seed` is the startup settings (from CLI/env). Persisted settings live in
    /// `<data_dir>/acs.db` and override the seed (UI changes win and persist).
    pub fn new(
        data_dir: std::path::PathBuf,
        seed: Settings,
        advertise_ip: String,
        advertise_ip_explicit: bool,
    ) -> Store {
        let db = open_db(&data_dir.join("acs.db"));

        let store = Store {
            db: Mutex::new(db),
            inner: Mutex::new(Inner {
                devices: BTreeMap::new(),
                log: Vec::new(),
                walks: BTreeMap::new(),
                captures: Vec::new(),
                walk_seq: 1,
            }),
            wire: Mutex::new(VecDeque::new()),
            wire_seq: AtomicU64::new(1),
            settings: RwLock::new(seed),
            learned_host: RwLock::new(None),
            advertise_ip,
            advertise_ip_explicit,
        };
        // Load all state (devices, params, attrs, tasks, captures, events, wire,
        // settings) from the DB into memory.
        store.load_from_db();
        store
    }

    // ---------- diagnostic wire log ----------
    /// Next monotonic wire frame id.
    fn next_wire_id(&self) -> u64 {
        self.wire_seq.fetch_add(1, Ordering::SeqCst)
    }

    /// Build + record a wire frame: assigns the id/ts, pushes into the capped
    /// in-memory ring buffer, and INSERTs a durable row into the `wire` table
    /// (pruned to the newest `WIRE_DB_CAP` rows). DB I/O happens OUTSIDE the
    /// ring-buffer lock (short critical section only).
    pub fn wire_push(
        &self,
        dir: &str,
        client_ip: &str,
        session_key: Option<&str>,
        summary: &str,
        headers: BTreeMap<String, String>,
        body: &str,
    ) {
        let entry = WireEntry {
            id: self.next_wire_id(),
            ts: now_iso(),
            dir: dir.to_string(),
            client_ip: client_ip.to_string(),
            session_key: session_key.map(|s| s.to_string()),
            summary: summary.to_string(),
            headers,
            body: body.to_string(),
        };
        // Serialize headers before taking any lock.
        let headers_json =
            serde_json::to_string(&entry.headers).unwrap_or_else(|_| "{}".to_string());
        {
            let mut q = self.wire.lock();
            q.push_back(entry.clone());
            while q.len() > WIRE_CAP {
                q.pop_front();
            }
        }
        // Persist outside the ring-buffer lock.
        let conn = self.db.lock();
        let r = conn.execute(
            "INSERT OR REPLACE INTO wire(id,ts,dir,client_ip,session_key,summary,headers,body)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            rusqlite::params![
                entry.id as i64,
                entry.ts,
                entry.dir,
                entry.client_ip,
                entry.session_key,
                entry.summary,
                headers_json,
                entry.body,
            ],
        );
        if let Err(e) = r {
            println!("[store] db: wire insert: {e}");
        } else if let Err(e) = conn.execute(
            "DELETE FROM wire WHERE id NOT IN
             (SELECT id FROM wire ORDER BY id DESC LIMIT ?1)",
            rusqlite::params![WIRE_DB_CAP],
        ) {
            println!("[store] db: wire prune: {e}");
        }
    }

    /// Clone the ring buffer (oldest-first) for the API.
    pub fn wire_entries(&self) -> Vec<WireEntry> {
        let q = self.wire.lock();
        q.iter().cloned().collect()
    }

    /// Clear the in-memory ring buffer and the durable `wire` table.
    pub fn wire_clear(&self) {
        {
            let mut q = self.wire.lock();
            q.clear();
        }
        if let Err(e) = self.db.lock().execute("DELETE FROM wire", []) {
            println!("[store] db: wire clear: {e}");
        }
    }

    // ---------- runtime settings ----------
    /// Snapshot of the current settings (cheap clone; never held across .await).
    pub fn settings(&self) -> Settings {
        self.settings.read().clone()
    }

    /// Run a read closure against the live settings without cloning the whole
    /// struct.
    pub fn with_settings<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&Settings) -> R,
    {
        f(&self.settings.read())
    }

    /// Mutate the settings under the write lock, then persist them to acs.db.
    /// The closure runs with the lock held; do NOT .await inside it.
    pub fn update_settings<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut Settings) -> R,
    {
        let r = {
            let mut g = self.settings.write();
            f(&mut g)
        };
        self.save_settings();
        r
    }

    /// Record the host (no :port) the CPE used to reach us, learned from the
    /// Inform request's Host header. Updated on every Inform.
    pub fn set_learned_host(&self, host: &str) {
        let h = host.trim();
        if h.is_empty() {
            return;
        }
        *self.learned_host.write() = Some(h.to_string());
    }

    pub fn learned_host(&self) -> Option<String> {
        self.learned_host.read().clone()
    }

    /// The configured advertise_host, else the CPE-learned host — the two tiers
    /// shared by `advertise_host` and `advertise_effective`. None when neither set.
    fn preferred_host(&self) -> Option<String> {
        let configured = self.with_settings(|s| s.advertise_host.trim().to_string());
        if !configured.is_empty() {
            return Some(configured);
        }
        self.learned_host().filter(|h| !h.is_empty())
    }

    /// Resolve the host (no :port) that file/upload URLs should advertise.
    /// Precedence: settings.advertise_host (if non-empty) -> CPE-learned host ->
    /// explicit --advertise-ip (if it was set) -> auto-detected IP.
    ///
    /// `advertise_ip` already holds either the explicit --advertise-ip value or
    /// the auto-detected LAN IP, so it serves as the final fallback for both the
    /// "explicit" and "auto-detected" tiers; `advertise_ip_explicit` only
    /// documents which one it is.
    pub fn advertise_host(&self) -> String {
        self.preferred_host()
            .unwrap_or_else(|| self.advertise_ip.clone())
    }

    /// The resolved advertise host to *report* in the API, or "" when nothing
    /// has been configured/learned/explicitly set yet (the URL builder still
    /// falls back to the auto-detected IP, but we don't claim that guess as
    /// "effective" until a CPE Informs or the admin sets it). Precedence:
    /// settings.advertise_host -> CPE-learned host -> explicit --advertise-ip.
    pub fn advertise_effective(&self) -> String {
        self.preferred_host().unwrap_or_else(|| {
            if self.advertise_ip_explicit {
                self.advertise_ip.clone()
            } else {
                String::new()
            }
        })
    }

    fn save_settings(&self) {
        let data = {
            let g = self.settings.read();
            serde_json::to_string(&*g).unwrap_or_default()
        };
        if let Err(e) = self.db.lock().execute(
            "INSERT INTO settings(k,v) VALUES (0,?1)
             ON CONFLICT(k) DO UPDATE SET v=excluded.v",
            rusqlite::params![data],
        ) {
            println!("[store] db: settings save: {e}");
        }
    }

    /// Load the single settings row (k=0) from the DB into memory, if present.
    fn load_settings_from_db(&self) {
        let text: Option<String> = {
            let conn = self.db.lock();
            conn.query_row("SELECT v FROM settings WHERE k=0", [], |r| r.get(0))
                .ok()
        };
        if let Some(text) = text {
            match serde_json::from_str::<Settings>(&text) {
                Ok(s) => *self.settings.write() = s,
                Err(e) => println!("[store] db: settings parse: {e}"),
            }
        }
    }

    // ---------- captured credentials ----------
    /// Record a captured credential, DEDUPED. Identity = (scheme, username,
    /// password for Basic | response for Digest). On a repeat we bump `count`
    /// and refresh `last`; we never append a duplicate row (in memory or in the
    /// DB). A genuinely new credential is pushed (count=1, first=last=now). The
    /// deduped in-memory list (global + per-device) is capped at ~200 distinct
    /// creds. Both the global ('' device_key) and the per-device records are
    /// UPSERTed into the `captures` table (PK dedups; `data` holds the full,
    /// count-bumped JSON).
    pub fn add_capture(&self, key: &str, rec: Value) {
        let now = now_iso();
        let (scheme, username, identity) = capture_identity(&rec);
        // Snapshots of the (possibly bumped) records to write through to SQLite.
        // `global_persist` is assigned in every branch below (deferred init).
        let global_persist: Value;
        let mut device_persist: Option<Value> = None;
        {
            let mut g = self.inner.lock();
            // Global list ('' device_key), then this device's list — same dedup.
            global_persist = merge_capture(
                &mut g.captures,
                &scheme,
                &username,
                &identity,
                key,
                &now,
                rec.clone(),
            );
            if let Some(dev) = g.devices.get_mut(key) {
                device_persist = Some(merge_capture(
                    &mut dev.captures,
                    &scheme,
                    &username,
                    &identity,
                    key,
                    &now,
                    rec,
                ));
            }
        }
        // Write through to SQLite: global record keyed by '' + per-device record.
        self.db_upsert_capture("", &scheme, &username, &identity, &global_persist);
        if let Some(rec) = &device_persist {
            self.db_upsert_capture(key, &scheme, &username, &identity, rec);
        }
    }

    /// UPSERT one capture row (PK = device_key,scheme,username,secret).
    fn db_upsert_capture(
        &self,
        device_key: &str,
        scheme: &str,
        username: &str,
        secret: &str,
        rec: &Value,
    ) {
        let data = serde_json::to_string(rec).unwrap_or_default();
        if let Err(e) = self.db.lock().execute(
            "INSERT INTO captures(device_key,scheme,username,secret,data)
             VALUES (?1,?2,?3,?4,?5)
             ON CONFLICT(device_key,scheme,username,secret) DO UPDATE SET data=excluded.data",
            rusqlite::params![device_key, scheme, username, secret, data],
        ) {
            println!("[store] db: capture upsert: {e}");
        }
    }

    /// Clear all captured credentials: global list, every device's list, and the
    /// durable `captures` table.
    pub fn captures_clear(&self) {
        {
            let mut g = self.inner.lock();
            g.captures.clear();
            for dev in g.devices.values_mut() {
                dev.captures.clear();
            }
        }
        if let Err(e) = self.db.lock().execute("DELETE FROM captures", []) {
            println!("[store] db: captures clear: {e}");
        }
    }

    /// Clear the in-memory event log and the durable `events` table.
    pub fn log_clear(&self) {
        {
            let mut g = self.inner.lock();
            g.log.clear();
        }
        if let Err(e) = self.db.lock().execute("DELETE FROM events", []) {
            println!("[store] db: events clear: {e}");
        }
    }

    // ---------- discovery walks ----------
    pub fn register_walk(&self, max_depth: u32, max_nodes: u32) -> u64 {
        let mut g = self.inner.lock();
        let wid = g.walk_seq;
        g.walk_seq += 1;
        g.walks.insert(
            wid,
            Walk {
                max_depth,
                max_nodes,
                count: 1,
            },
        );
        wid
    }

    /// Return true (and increment) if the walk may enqueue one more node.
    pub fn walk_expand(&self, wid: u64) -> bool {
        let mut g = self.inner.lock();
        match g.walks.get_mut(&wid) {
            Some(w) if w.count < w.max_nodes => {
                w.count += 1;
                true
            }
            _ => false,
        }
    }

    pub fn walk_info(&self, wid: u64) -> Option<Walk> {
        let g = self.inner.lock();
        g.walks.get(&wid).cloned()
    }

    // ---------- logging ----------
    pub fn event(&self, msg: &str, key: Option<&str>, level: &str) {
        let ts = now_iso();
        {
            let mut g = self.inner.lock();
            g.log.push(LogEntry {
                ts: ts.clone(),
                msg: msg.to_string(),
                key: key.map(|s| s.to_string()),
                level: level.to_string(),
            });
            if g.log.len() > 1000 {
                let start = g.log.len() - 1000;
                g.log.drain(0..start);
            }
        }
        // Persist to the durable `events` table and prune to the newest rows.
        {
            let conn = self.db.lock();
            let r = conn.execute(
                "INSERT INTO events(ts,device_key,level,message) VALUES (?1,?2,?3,?4)",
                rusqlite::params![ts, key, level, msg],
            );
            if let Err(e) = r {
                println!("[store] db: event insert: {e}");
            } else if let Err(e) = conn.execute(
                "DELETE FROM events WHERE id NOT IN
                 (SELECT id FROM events ORDER BY id DESC LIMIT ?1)",
                rusqlite::params![EVENT_DB_CAP],
            ) {
                println!("[store] db: event prune: {e}");
            }
        }
        let kp = key.map(|k| format!("[{}] ", k)).unwrap_or_default();
        println!("[{}] {}{}", ts, kp, msg);
    }

    pub fn event_info(&self, msg: &str, key: Option<&str>) {
        self.event(msg, key, "info");
    }

    // ---------- device registry ----------
    pub fn get_or_create<F, R>(&self, key: &str, f: F) -> R
    where
        F: FnOnce(&mut Device) -> R,
    {
        let (r, snapshot) = {
            let mut g = self.inner.lock();
            let dev = g
                .devices
                .entry(key.to_string())
                .or_insert_with(|| Device::new(key));
            let r = f(dev);
            (r, dev.clone())
        };
        self.persist_device(&snapshot);
        r
    }

    pub fn list_views(&self) -> Vec<Value> {
        let g = self.inner.lock();
        g.devices.values().map(|d| d.to_view()).collect()
    }

    pub fn device_detail(&self, key: &str) -> Option<Value> {
        let g = self.inner.lock();
        g.devices.get(key).map(|d| d.to_detail())
    }

    pub fn device_field<F, R>(&self, key: &str, f: F) -> Option<R>
    where
        F: FnOnce(&Device) -> R,
    {
        let g = self.inner.lock();
        g.devices.get(key).map(f)
    }

    pub fn log_tail(&self, n: usize) -> Vec<Value> {
        let g = self.inner.lock();
        let start = g.log.len().saturating_sub(n);
        g.log[start..]
            .iter()
            .map(|l| serde_json::to_value(l).unwrap_or(Value::Null))
            .collect()
    }

    pub fn captures_tail(&self, n: usize) -> Vec<Value> {
        let g = self.inner.lock();
        let start = g.captures.len().saturating_sub(n);
        g.captures[start..].to_vec()
    }

    // ---------- task queue ----------
    pub fn enqueue(&self, key: &str, task: Task) -> u64 {
        let id = task.id;
        let label = task.label.clone();
        self.get_or_create(key, move |dev| dev.queue.push(task));
        self.event(&format!("queued task #{} {}", id, label), Some(key), "info");
        id
    }

    pub fn pop_next(&self, key: &str) -> Option<Task> {
        let (task, snapshot) = {
            let mut g = self.inner.lock();
            let dev = g.devices.get_mut(key)?;
            if dev.queue.is_empty() {
                return None;
            }
            let mut t = dev.queue.remove(0);
            t.status = "inflight".to_string();
            t.updated = now_iso();
            (t, dev.clone())
        };
        // Persist the queue minus the now-inflight task (inflight tasks live in
        // the session's `inflight` slot and are not durably tracked — same
        // semantics as before the SQLite migration).
        self.persist_device(&snapshot);
        Some(task)
    }

    pub fn finish_task(
        &self,
        key: &str,
        mut task: Task,
        status: &str,
        result: Value,
        fault: Value,
    ) {
        let snapshot = {
            let mut g = self.inner.lock();
            task.status = status.to_string();
            task.result = result;
            task.fault = fault;
            task.updated = now_iso();
            if let Some(dev) = g.devices.get_mut(key) {
                dev.history.push(task);
                if dev.history.len() > 500 {
                    let start = dev.history.len() - 500;
                    dev.history.drain(0..start);
                }
                Some(dev.clone())
            } else {
                None
            }
        };
        if let Some(dev) = snapshot {
            self.persist_device(&dev);
        }
    }

    pub fn pending_count(&self, key: &str) -> usize {
        let g = self.inner.lock();
        g.devices.get(key).map(|d| d.queue.len()).unwrap_or(0)
    }

    // ---------- parameter cache ----------
    pub fn update_parameters(&self, key: &str, pairs: &[crate::cwmp::ParamValue]) {
        self.get_or_create(key, |dev| {
            let ts = now_iso();
            for p in pairs {
                let ent = dev.parameters.entry(p.name.clone()).or_default();
                ent.value = p.value.clone();
                ent.type_ = p.type_.clone();
                ent.ts = ts.clone();
            }
        });
    }

    pub fn update_names(&self, key: &str, names: &[crate::cwmp::ParamName]) {
        self.get_or_create(key, |dev| {
            let ts = now_iso();
            for n in names {
                let ent = dev.parameters.entry(n.name.clone()).or_default();
                ent.writable = Some(n.writable.clone());
                ent.ts = ts.clone();
            }
        });
    }

    pub fn update_attributes(&self, key: &str, attrs: &[crate::cwmp::ParamAttr]) {
        self.get_or_create(key, |dev| {
            for a in attrs {
                dev.attributes.insert(
                    a.name.clone(),
                    AttrEntry {
                        notification: a.notification.clone(),
                        access_list: a.access_list.clone(),
                    },
                );
            }
        });
    }

    pub fn set_rpc_methods(&self, key: &str, methods: Vec<String>) {
        let snapshot = {
            let mut g = self.inner.lock();
            match g.devices.get_mut(key) {
                Some(dev) => {
                    dev.rpc_methods = methods;
                    Some(dev.clone())
                }
                None => None,
            }
        };
        if let Some(dev) = snapshot {
            self.persist_device(&dev);
        }
    }

    // ---------- persistence ----------
    /// Snapshot ONE device into SQLite in a single transaction: UPSERT the
    /// device row + all its parameters + all its attributes, then replace its
    /// task rows (DELETE then re-INSERT the queue (queued=1) + history
    /// (queued=0)). Best-effort: any failure is logged and ignored.
    fn persist_device(&self, dev: &Device) {
        let mut conn = self.db.lock();
        let tx = match conn.transaction() {
            Ok(t) => t,
            Err(e) => {
                println!("[store] db: begin tx: {e}");
                return;
            }
        };
        let r = (|| -> rusqlite::Result<()> {
            let last_inform = serde_json::to_string(&dev.last_inform).unwrap_or_default();
            let rpc_methods = serde_json::to_string(&dev.rpc_methods).unwrap_or_default();
            tx.execute(
                "INSERT INTO devices
                   (key,oui,serial,product_class,manufacturer,model,software_version,
                    ip,cwmp_ns,root,connection_request_url,last_inform,last_seen,rpc_methods)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)
                 ON CONFLICT(key) DO UPDATE SET
                    oui=excluded.oui, serial=excluded.serial,
                    product_class=excluded.product_class, manufacturer=excluded.manufacturer,
                    model=excluded.model, software_version=excluded.software_version,
                    ip=excluded.ip, cwmp_ns=excluded.cwmp_ns, root=excluded.root,
                    connection_request_url=excluded.connection_request_url,
                    last_inform=excluded.last_inform, last_seen=excluded.last_seen,
                    rpc_methods=excluded.rpc_methods",
                rusqlite::params![
                    dev.key,
                    dev.oui,
                    dev.serial,
                    dev.product_class,
                    dev.manufacturer,
                    dev.model,
                    dev.software_version,
                    dev.ip,
                    dev.cwmp_ns,
                    dev.root,
                    dev.connection_request_url,
                    last_inform,
                    dev.last_seen,
                    rpc_methods,
                ],
            )?;
            // parameters: UPSERT each (don't delete others — params only grow).
            for (name, ent) in &dev.parameters {
                tx.execute(
                    "INSERT INTO parameters(device_key,name,value,type,writable,ts)
                     VALUES (?1,?2,?3,?4,?5,?6)
                     ON CONFLICT(device_key,name) DO UPDATE SET
                        value=excluded.value, type=excluded.type,
                        writable=excluded.writable, ts=excluded.ts",
                    rusqlite::params![dev.key, name, ent.value, ent.type_, ent.writable, ent.ts,],
                )?;
            }
            // attributes: UPSERT each.
            for (name, ent) in &dev.attributes {
                let access = serde_json::to_string(&ent.access_list).unwrap_or_default();
                tx.execute(
                    "INSERT INTO attributes(device_key,name,notification,access_list)
                     VALUES (?1,?2,?3,?4)
                     ON CONFLICT(device_key,name) DO UPDATE SET
                        notification=excluded.notification, access_list=excluded.access_list",
                    rusqlite::params![dev.key, name, ent.notification, access],
                )?;
            }
            // tasks: replace this device's set with its current queue + history.
            tx.execute(
                "DELETE FROM tasks WHERE device_key=?1",
                rusqlite::params![dev.key],
            )?;
            for t in &dev.queue {
                let data = serde_json::to_string(&t.to_persist()).unwrap_or_default();
                tx.execute(
                    "INSERT OR REPLACE INTO tasks(id,device_key,queued,data,created,updated)
                     VALUES (?1,?2,1,?3,?4,?5)",
                    rusqlite::params![t.id as i64, dev.key, data, t.created, t.updated],
                )?;
            }
            for t in &dev.history {
                let data = serde_json::to_string(&t.to_persist()).unwrap_or_default();
                tx.execute(
                    "INSERT OR REPLACE INTO tasks(id,device_key,queued,data,created,updated)
                     VALUES (?1,?2,0,?3,?4,?5)",
                    rusqlite::params![t.id as i64, dev.key, data, t.created, t.updated],
                )?;
            }
            Ok(())
        })();
        match r {
            Ok(()) => {
                if let Err(e) = tx.commit() {
                    println!("[store] db: commit: {e}");
                }
            }
            Err(e) => {
                println!("[store] db: persist_device {}: {e}", dev.key);
                // tx drops -> rollback
            }
        }
    }

    /// Persist EVERY in-memory device to SQLite (used by `save()` so existing
    /// callers that expect a full flush keep working; e.g. graceful shutdown).
    pub fn save(&self) {
        let devices: Vec<Device> = {
            let g = self.inner.lock();
            g.devices.values().cloned().collect()
        };
        for dev in &devices {
            self.persist_device(dev);
        }
    }

    /// Load ALL durable state from SQLite into the in-memory model: devices (+
    /// parameters, attributes, rpc_methods, queue/history tasks), captured
    /// credentials (global + per-device), the event log, the wire ring buffer,
    /// and settings. Also advances TASK_SEQ / wire_seq past the loaded maxima.
    fn load_from_db(&self) {
        // settings first (so seed is overridden by persisted values).
        self.load_settings_from_db();

        let mut max_task_id: u64 = 0;
        let mut max_wire_id: u64 = 0;
        let mut g = self.inner.lock();
        let conn = self.db.lock();

        // --- devices ---
        if let Ok(mut stmt) = conn.prepare(
            "SELECT key,oui,serial,product_class,manufacturer,model,software_version,
                    ip,cwmp_ns,root,connection_request_url,last_inform,last_seen,rpc_methods
             FROM devices",
        ) {
            let rows = stmt.query_map([], |row| {
                let mut dev = Device::new(&row.get::<_, String>(0)?);
                dev.oui = row.get(1)?;
                dev.serial = row.get(2)?;
                dev.product_class = row.get(3)?;
                dev.manufacturer = row.get(4)?;
                dev.model = row.get(5)?;
                dev.software_version = row.get(6)?;
                dev.ip = row.get(7)?;
                dev.cwmp_ns = row.get(8)?;
                dev.root = row.get(9)?;
                dev.connection_request_url = row.get(10)?;
                let li: String = row.get(11)?;
                dev.last_inform = serde_json::from_str(&li).unwrap_or(Value::Null);
                dev.last_seen = row.get(12)?;
                let rm: String = row.get(13)?;
                dev.rpc_methods = serde_json::from_str(&rm).unwrap_or_default();
                Ok(dev)
            });
            if let Ok(rows) = rows {
                for dev in rows.flatten() {
                    g.devices.insert(dev.key.clone(), dev);
                }
            }
        }

        // --- parameters ---
        if let Ok(mut stmt) =
            conn.prepare("SELECT device_key,name,value,type,writable,ts FROM parameters")
        {
            let rows = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    ParamEntry {
                        value: row.get(2)?,
                        type_: row.get(3)?,
                        writable: row.get(4)?,
                        ts: row.get(5)?,
                    },
                ))
            });
            if let Ok(rows) = rows {
                for (dk, name, ent) in rows.flatten() {
                    if let Some(dev) = g.devices.get_mut(&dk) {
                        dev.parameters.insert(name, ent);
                    }
                }
            }
        }

        // --- attributes ---
        if let Ok(mut stmt) =
            conn.prepare("SELECT device_key,name,notification,access_list FROM attributes")
        {
            let rows = stmt.query_map([], |row| {
                let access: String = row.get(3)?;
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    AttrEntry {
                        notification: row.get(2)?,
                        access_list: serde_json::from_str(&access).unwrap_or_default(),
                    },
                ))
            });
            if let Ok(rows) = rows {
                for (dk, name, ent) in rows.flatten() {
                    if let Some(dev) = g.devices.get_mut(&dk) {
                        dev.attributes.insert(name, ent);
                    }
                }
            }
        }

        // --- tasks (queue: queued=1, history: queued=0) ---
        if let Ok(mut stmt) =
            conn.prepare("SELECT device_key,queued,data FROM tasks ORDER BY id ASC")
        {
            let rows = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                ))
            });
            if let Ok(rows) = rows {
                for (dk, queued, data) in rows.flatten() {
                    if let Ok(v) = serde_json::from_str::<Value>(&data) {
                        let task = Task::from_persist(&v);
                        max_task_id = max_task_id.max(task.id);
                        if let Some(dev) = g.devices.get_mut(&dk) {
                            if queued == 1 {
                                dev.queue.push(task);
                            } else {
                                dev.history.push(task);
                            }
                        }
                    }
                }
            }
        }

        // --- captures (global '' list + per-device lists) ---
        if let Ok(mut stmt) = conn.prepare("SELECT device_key,data FROM captures") {
            let rows = stmt.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            });
            if let Ok(rows) = rows {
                for (dk, data) in rows.flatten() {
                    if let Ok(v) = serde_json::from_str::<Value>(&data) {
                        if dk.is_empty() {
                            g.captures.push(v);
                        } else if let Some(dev) = g.devices.get_mut(&dk) {
                            dev.captures.push(v);
                        }
                    }
                }
            }
        }

        // --- events (most recent EVENT_DB_CAP, oldest-first into the log) ---
        if let Ok(mut stmt) =
            conn.prepare("SELECT ts,device_key,level,message FROM events ORDER BY id DESC LIMIT ?1")
        {
            let rows = stmt.query_map(rusqlite::params![EVENT_DB_CAP], |row| {
                let dk: Option<String> = row.get(1)?;
                Ok(LogEntry {
                    ts: row.get(0)?,
                    key: dk,
                    level: row.get(2)?,
                    msg: row.get(3)?,
                })
            });
            if let Ok(rows) = rows {
                let mut entries: Vec<LogEntry> = rows.flatten().collect();
                entries.reverse(); // selected DESC (newest); restore oldest-first
                g.log.extend(entries);
            }
        }

        // --- wire ring (newest WIRE_CAP frames, oldest-first) ---
        if let Ok(mut stmt) = conn.prepare(
            "SELECT id,ts,dir,client_ip,session_key,summary,headers,body
             FROM wire ORDER BY id DESC LIMIT ?1",
        ) {
            let rows = stmt.query_map(rusqlite::params![WIRE_CAP as i64], |row| {
                let id: i64 = row.get(0)?;
                let headers: String = row.get(6)?;
                Ok(WireEntry {
                    id: id as u64,
                    ts: row.get(1)?,
                    dir: row.get(2)?,
                    client_ip: row.get(3)?,
                    session_key: row.get(4)?,
                    summary: row.get(5)?,
                    headers: serde_json::from_str(&headers).unwrap_or_default(),
                    body: row.get(7)?,
                })
            });
            if let Ok(rows) = rows {
                let mut frames: Vec<WireEntry> = rows.flatten().collect();
                frames.reverse(); // we selected DESC; restore oldest-first order
                let mut q = self.wire.lock();
                for f in frames {
                    max_wire_id = max_wire_id.max(f.id);
                    q.push_back(f);
                }
            }
        }
        // The LIMIT above caps the ring, but the true max wire id may be higher
        // (older rows beyond WIRE_CAP). Read it directly so ids never collide.
        if let Ok(m) = conn.query_row("SELECT COALESCE(MAX(id),0) FROM wire", [], |r| {
            r.get::<_, i64>(0)
        }) {
            max_wire_id = max_wire_id.max(m as u64);
        }

        drop(conn);
        drop(g);

        // Advance the id sequences past everything loaded.
        bump_task_seq(max_task_id);
        let want_wire = max_wire_id + 1;
        let cur = self.wire_seq.load(Ordering::SeqCst);
        if cur < want_wire {
            self.wire_seq.store(want_wire, Ordering::SeqCst);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trip: a device + param + queued task + event written by one Store
    /// must survive being dropped and reloaded by a fresh Store on the same dir.
    #[test]
    fn persistence_round_trip() {
        let dir = std::env::temp_dir().join(format!("acs_store_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let key = "00227F-ROUNDTRIP01";

        {
            let store = Store::new(
                dir.clone(),
                Settings::default(),
                "127.0.0.1".to_string(),
                false,
            );
            store.get_or_create(key, |dev| {
                dev.oui = "00227F".to_string();
                dev.serial = "ROUNDTRIP01".to_string();
                dev.model = "RV6699".to_string();
            });
            store.update_parameters(
                key,
                &[crate::cwmp::ParamValue {
                    name: "InternetGatewayDevice.DeviceInfo.UpTime".to_string(),
                    value: "12345".to_string(),
                    type_: "xsd:unsignedInt".to_string(),
                }],
            );
            let t = Task::new("get", json!({"names": ["X."]}), Some("probe"), None, 0);
            store.enqueue(key, t);
            store.event_info("round-trip event", Some(key));
            // store dropped here -> connection closed
        }

        let store2 = Store::new(
            dir.clone(),
            Settings::default(),
            "127.0.0.1".to_string(),
            false,
        );
        let detail = store2.device_detail(key).expect("device should reload");
        assert_eq!(detail.get("key").and_then(|v| v.as_str()), Some(key));
        assert_eq!(detail.get("model").and_then(|v| v.as_str()), Some("RV6699"));
        let params = detail.get("parameters").and_then(|v| v.as_array()).unwrap();
        assert!(
            params.iter().any(|p| p.get("name").and_then(|v| v.as_str())
                == Some("InternetGatewayDevice.DeviceInfo.UpTime")),
            "param should reload"
        );
        let queue = detail.get("queue").and_then(|v| v.as_array()).unwrap();
        assert_eq!(queue.len(), 1, "queued task should reload");
        assert_eq!(
            queue[0].get("label").and_then(|v| v.as_str()),
            Some("probe")
        );
        let log = store2.log_tail(50);
        assert!(
            log.iter()
                .any(|e| e.get("msg").and_then(|v| v.as_str()) == Some("round-trip event")),
            "event should reload"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
