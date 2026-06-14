//! store.rs — thread-safe device registry, parameter cache, and task queue
//! (port of store.py). Devices + discovered parameters persist to JSON.

use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::settings::Settings;

static TASK_SEQ: AtomicU64 = AtomicU64::new(1);

/// Max number of wire-log frames kept in the in-memory ring buffer (the
/// durable wire.log keeps everything appended until cleared).
const WIRE_CAP: usize = 300;

pub fn now_iso() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

fn next_task_id() -> u64 {
    TASK_SEQ.fetch_add(1, Ordering::SeqCst)
}

/// Render a wire frame as a human-readable block for the durable wire.log.
fn format_wire_block(e: &WireEntry) -> String {
    use std::fmt::Write as _;
    let arrow = if e.dir == "in" { "<<< IN " } else { ">>> OUT" };
    let mut s = String::new();
    let _ = writeln!(
        s,
        "{} #{} {} client={} session={} | {}",
        arrow,
        e.id,
        e.ts,
        e.client_ip,
        e.session_key.as_deref().unwrap_or("-"),
        e.summary,
    );
    for (k, v) in &e.headers {
        let _ = writeln!(s, "    {}: {}", k, v);
    }
    if e.body.is_empty() {
        let _ = writeln!(s, "    <empty body>");
    } else {
        let _ = writeln!(s, "    --- body ---\n{}", e.body);
    }
    s.push('\n');
    s
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

    pub fn from_persist(d: &Value) -> Device {
        let key = d
            .get("key")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let mut dev = Device::new(&key);
        let gs = |k: &str| d.get(k).and_then(|v| v.as_str()).map(|s| s.to_string());
        if let Some(v) = gs("oui") {
            dev.oui = v;
        }
        if let Some(v) = gs("serial") {
            dev.serial = v;
        }
        if let Some(v) = gs("product_class") {
            dev.product_class = v;
        }
        if let Some(v) = gs("manufacturer") {
            dev.manufacturer = v;
        }
        if let Some(v) = gs("model") {
            dev.model = v;
        }
        if let Some(v) = gs("software_version") {
            dev.software_version = v;
        }
        if let Some(v) = gs("ip") {
            dev.ip = v;
        }
        if let Some(v) = gs("cwmp_ns") {
            dev.cwmp_ns = v;
        }
        if let Some(v) = gs("root") {
            dev.root = v;
        }
        if let Some(v) = gs("connection_request_url") {
            dev.connection_request_url = v;
        }
        if let Some(v) = gs("last_seen") {
            dev.last_seen = v;
        }
        if let Some(v) = d.get("last_inform") {
            dev.last_inform = v.clone();
        }
        if let Some(obj) = d.get("parameters").and_then(|v| v.as_object()) {
            for (k, v) in obj {
                if let Ok(pe) = serde_json::from_value::<ParamEntry>(v.clone()) {
                    dev.parameters.insert(k.clone(), pe);
                }
            }
        }
        if let Some(obj) = d.get("attributes").and_then(|v| v.as_object()) {
            for (k, v) in obj {
                if let Ok(ae) = serde_json::from_value::<AttrEntry>(v.clone()) {
                    dev.attributes.insert(k.clone(), ae);
                }
            }
        }
        if let Some(arr) = d.get("rpc_methods").and_then(|v| v.as_array()) {
            dev.rpc_methods = arr
                .iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect();
        }
        dev
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
    path: std::path::PathBuf,
    captures_path: std::path::PathBuf,
    settings_path: std::path::PathBuf,
    wire_log_path: std::path::PathBuf,
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

impl Store {
    /// `seed` is the startup settings (from CLI/env). If settings.json exists at
    /// `settings_path` it overrides the seed (UI changes win and persist).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        path: std::path::PathBuf,
        captures_path: std::path::PathBuf,
        settings_path: std::path::PathBuf,
        seed: Settings,
        advertise_ip: String,
        advertise_ip_explicit: bool,
    ) -> Store {
        // wire.log lives in the data dir alongside settings.json (same parent).
        let wire_log_path = settings_path
            .parent()
            .map(|p| p.join("wire.log"))
            .unwrap_or_else(|| std::path::PathBuf::from("wire.log"));
        let store = Store {
            path,
            captures_path,
            settings_path,
            wire_log_path,
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
        store.load();
        store.load_settings();
        store
    }

    // ---------- diagnostic wire log ----------
    /// Next monotonic wire frame id.
    fn next_wire_id(&self) -> u64 {
        self.wire_seq.fetch_add(1, Ordering::SeqCst)
    }

    /// Path to the durable wire.log file (data_dir + "wire.log").
    pub fn wire_log_path(&self) -> &std::path::Path {
        &self.wire_log_path
    }

    /// Build + record a wire frame: assigns the id/ts, pushes into the capped
    /// ring buffer, and appends a human-readable block to wire.log. File I/O
    /// happens OUTSIDE the ring-buffer lock (short critical section only).
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
        // Format the durable block before taking any lock.
        let block = format_wire_block(&entry);
        {
            let mut q = self.wire.lock();
            q.push_back(entry);
            while q.len() > WIRE_CAP {
                q.pop_front();
            }
        }
        // Append outside the lock.
        let _ = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.wire_log_path)
            .and_then(|mut f| {
                use std::io::Write;
                f.write_all(block.as_bytes())
            });
    }

    /// Clone the ring buffer (oldest-first) for the API.
    pub fn wire_entries(&self) -> Vec<WireEntry> {
        let q = self.wire.lock();
        q.iter().cloned().collect()
    }

    /// Clear the in-memory ring buffer and truncate wire.log on disk.
    pub fn wire_clear(&self) {
        {
            let mut q = self.wire.lock();
            q.clear();
        }
        // Truncate (don't delete) so the file still exists for tailing.
        let _ = std::fs::write(&self.wire_log_path, b"");
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

    /// Mutate the settings under the write lock, then persist to settings.json.
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

    /// Resolve the host (no :port) that file/upload URLs should advertise.
    /// Precedence: settings.advertise_host (if non-empty) -> CPE-learned host ->
    /// explicit --advertise-ip (if it was set) -> auto-detected IP.
    ///
    /// `advertise_ip` already holds either the explicit --advertise-ip value or
    /// the auto-detected LAN IP, so it serves as the final fallback for both the
    /// "explicit" and "auto-detected" tiers; `advertise_ip_explicit` only
    /// documents which one it is.
    pub fn advertise_host(&self) -> String {
        let configured = self.with_settings(|s| s.advertise_host.trim().to_string());
        if !configured.is_empty() {
            return configured;
        }
        if let Some(h) = self.learned_host()
            && !h.is_empty()
        {
            return h;
        }
        self.advertise_ip.clone()
    }

    /// The resolved advertise host to *report* in the API, or "" when nothing
    /// has been configured/learned/explicitly set yet (the URL builder still
    /// falls back to the auto-detected IP, but we don't claim that guess as
    /// "effective" until a CPE Informs or the admin sets it). Precedence:
    /// settings.advertise_host -> CPE-learned host -> explicit --advertise-ip.
    pub fn advertise_effective(&self) -> String {
        let configured = self.with_settings(|s| s.advertise_host.trim().to_string());
        if !configured.is_empty() {
            return configured;
        }
        if let Some(h) = self.learned_host()
            && !h.is_empty()
        {
            return h;
        }
        if self.advertise_ip_explicit {
            return self.advertise_ip.clone();
        }
        String::new()
    }

    fn save_settings(&self) {
        let data = {
            let g = self.settings.read();
            serde_json::to_string_pretty(&*g).unwrap_or_default()
        };
        let tmp = self.settings_path.with_extension("json.tmp");
        match std::fs::write(&tmp, data) {
            Ok(_) => {
                if let Err(e) = std::fs::rename(&tmp, &self.settings_path) {
                    println!("[store] settings save failed: {}", e);
                }
            }
            Err(e) => println!("[store] settings save failed: {}", e),
        }
    }

    fn load_settings(&self) {
        if !self.settings_path.exists() {
            return;
        }
        let text = match std::fs::read_to_string(&self.settings_path) {
            Ok(t) => t,
            Err(e) => {
                println!("[store] settings load failed: {}", e);
                return;
            }
        };
        match serde_json::from_str::<Settings>(&text) {
            Ok(s) => {
                *self.settings.write() = s;
            }
            Err(e) => println!("[store] settings load failed: {}", e),
        }
    }

    // ---------- captured credentials ----------
    /// Record a captured credential, DEDUPED. Identity = (scheme, username,
    /// password for Basic | response for Digest). On a repeat we bump `count`
    /// and refresh `last`; we never append a duplicate row (in memory or to
    /// captures.jsonl). A genuinely new credential is pushed (count=1,
    /// first=last=now) and appended once to the durable log. The deduped
    /// in-memory list (global + per-device) is capped at ~200 distinct creds.
    pub fn add_capture(&self, key: &str, rec: Value) {
        let now = now_iso();
        let (scheme, username, identity) = capture_identity(&rec);
        // `is_new` decides whether we touch the durable log (only NEW creds).
        let mut new_record: Option<Value> = None;
        {
            let mut g = self.inner.lock();
            // Global list: dedup or insert.
            if let Some(existing) = g
                .captures
                .iter_mut()
                .find(|c| capture_matches(c, &scheme, &username, &identity))
            {
                bump_capture(existing, &now);
            } else {
                let mut fresh = rec.clone();
                {
                    let obj = fresh.as_object_mut().unwrap();
                    obj.remove("ts");
                    obj.insert("key".to_string(), json!(key));
                    obj.insert("first".to_string(), json!(now));
                    obj.insert("last".to_string(), json!(now));
                    obj.insert("count".to_string(), json!(1u64));
                }
                g.captures.push(fresh.clone());
                if g.captures.len() > 200 {
                    let start = g.captures.len() - 200;
                    g.captures.drain(0..start);
                }
                new_record = Some(fresh);
            }
            // Per-device list: same dedup against this device's captures.
            if let Some(dev) = g.devices.get_mut(key) {
                if let Some(existing) = dev
                    .captures
                    .iter_mut()
                    .find(|c| capture_matches(c, &scheme, &username, &identity))
                {
                    bump_capture(existing, &now);
                } else {
                    let mut fresh = rec.clone();
                    {
                        let obj = fresh.as_object_mut().unwrap();
                        obj.remove("ts");
                        obj.insert("key".to_string(), json!(key));
                        obj.insert("first".to_string(), json!(now));
                        obj.insert("last".to_string(), json!(now));
                        obj.insert("count".to_string(), json!(1u64));
                    }
                    dev.captures.push(fresh);
                    if dev.captures.len() > 200 {
                        let start = dev.captures.len() - 200;
                        dev.captures.drain(0..start);
                    }
                }
            }
        }
        // Append to the durable log ONLY for a genuinely new unique credential.
        if let Some(rec) = new_record {
            let line = format!("{}\n", serde_json::to_string(&rec).unwrap_or_default());
            let _ = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.captures_path)
                .and_then(|mut f| {
                    use std::io::Write;
                    f.write_all(line.as_bytes())
                });
        }
    }

    /// Clear all captured credentials: global list, every device's list, and
    /// truncate captures.jsonl on disk (kept as an empty file).
    pub fn captures_clear(&self) {
        {
            let mut g = self.inner.lock();
            g.captures.clear();
            for dev in g.devices.values_mut() {
                dev.captures.clear();
            }
        }
        let _ = std::fs::write(&self.captures_path, b"");
    }

    /// Clear the in-memory event log.
    pub fn log_clear(&self) {
        let mut g = self.inner.lock();
        g.log.clear();
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
        let mut g = self.inner.lock();
        let dev = g
            .devices
            .entry(key.to_string())
            .or_insert_with(|| Device::new(key));
        f(dev)
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
        {
            let mut g = self.inner.lock();
            let dev = g
                .devices
                .entry(key.to_string())
                .or_insert_with(|| Device::new(key));
            dev.queue.push(task);
        }
        self.event(&format!("queued task #{} {}", id, label), Some(key), "info");
        id
    }

    pub fn pop_next(&self, key: &str) -> Option<Task> {
        let mut g = self.inner.lock();
        let dev = g.devices.get_mut(key)?;
        if dev.queue.is_empty() {
            return None;
        }
        let mut t = dev.queue.remove(0);
        t.status = "inflight".to_string();
        t.updated = now_iso();
        Some(t)
    }

    pub fn finish_task(
        &self,
        key: &str,
        mut task: Task,
        status: &str,
        result: Value,
        fault: Value,
    ) {
        {
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
            }
        }
        self.save();
    }

    pub fn pending_count(&self, key: &str) -> usize {
        let g = self.inner.lock();
        g.devices.get(key).map(|d| d.queue.len()).unwrap_or(0)
    }

    // ---------- parameter cache ----------
    pub fn update_parameters(&self, key: &str, pairs: &[crate::cwmp::ParamValue]) {
        let mut g = self.inner.lock();
        let dev = g
            .devices
            .entry(key.to_string())
            .or_insert_with(|| Device::new(key));
        let ts = now_iso();
        for p in pairs {
            let ent = dev.parameters.entry(p.name.clone()).or_default();
            ent.value = p.value.clone();
            ent.type_ = p.type_.clone();
            ent.ts = ts.clone();
        }
    }

    pub fn update_names(&self, key: &str, names: &[crate::cwmp::ParamName]) {
        let mut g = self.inner.lock();
        let dev = g
            .devices
            .entry(key.to_string())
            .or_insert_with(|| Device::new(key));
        let ts = now_iso();
        for n in names {
            let ent = dev.parameters.entry(n.name.clone()).or_default();
            ent.writable = Some(n.writable.clone());
            ent.ts = ts.clone();
        }
    }

    pub fn update_attributes(&self, key: &str, attrs: &[crate::cwmp::ParamAttr]) {
        let mut g = self.inner.lock();
        let dev = g
            .devices
            .entry(key.to_string())
            .or_insert_with(|| Device::new(key));
        for a in attrs {
            dev.attributes.insert(
                a.name.clone(),
                AttrEntry {
                    notification: a.notification.clone(),
                    access_list: a.access_list.clone(),
                },
            );
        }
    }

    pub fn set_rpc_methods(&self, key: &str, methods: Vec<String>) {
        let mut g = self.inner.lock();
        if let Some(dev) = g.devices.get_mut(key) {
            dev.rpc_methods = methods;
        }
    }

    // ---------- persistence ----------
    pub fn save(&self) {
        let data = {
            let g = self.inner.lock();
            let devices: Vec<Value> = g.devices.values().map(|d| d.to_persist()).collect();
            json!({ "devices": devices })
        };
        let tmp = self.path.with_extension("json.tmp");
        let serialized = serde_json::to_string_pretty(&data).unwrap_or_default();
        match std::fs::write(&tmp, serialized) {
            Ok(_) => {
                if let Err(e) = std::fs::rename(&tmp, &self.path) {
                    println!("[store] save failed: {}", e);
                }
            }
            Err(e) => println!("[store] save failed: {}", e),
        }
    }

    fn load(&self) {
        if !self.path.exists() {
            return;
        }
        let text = match std::fs::read_to_string(&self.path) {
            Ok(t) => t,
            Err(e) => {
                println!("[store] load failed: {}", e);
                return;
            }
        };
        let data: Value = match serde_json::from_str(&text) {
            Ok(d) => d,
            Err(e) => {
                println!("[store] load failed: {}", e);
                return;
            }
        };
        let mut g = self.inner.lock();
        if let Some(arr) = data.get("devices").and_then(|v| v.as_array()) {
            for d in arr {
                let dev = Device::from_persist(d);
                g.devices.insert(dev.key.clone(), dev);
            }
        }
    }
}
