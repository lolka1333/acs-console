//! console.rs — control-plane HTTP server: REST API + file server + static UI
//! (port of console.py). Serves the built React frontend from cfg.web_dir.

use std::path::Path;
use std::sync::Arc;

use axum::{
    Json,
    body::Bytes,
    extract::{ConnectInfo, Path as AxPath, Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use std::net::SocketAddr;

use crate::config::Config;
use crate::connreq;
use crate::settings::{Settings, SettingsPatch};
use crate::store::{Store, Task};

pub struct ConsoleState {
    pub store: Arc<Store>,
    pub cfg: Arc<Config>,
}

impl ConsoleState {
    pub fn new(store: Arc<Store>, cfg: Arc<Config>) -> Arc<ConsoleState> {
        Arc::new(ConsoleState { store, cfg })
    }
}

/// HTTP Basic-auth gate for the whole console (UI + REST + files). When
/// `console_password` is empty the console is open (LAN use); set it to protect
/// a publicly-exposed console. Applied as an axum middleware layer.
pub async fn console_auth(
    State(state): State<Arc<ConsoleState>>,
    req: Request,
    next: Next,
) -> Response {
    let (user, pass) = state
        .store
        .with_settings(|s| (s.console_username.clone(), s.console_password.clone()));
    if pass.is_empty() {
        return next.run(req).await;
    }
    // The CPE (router) fetches Download files from /files and PUTs Uploads to
    // /upload with no credentials, so those stay open even when the console is
    // protected. Only the UI + REST API require auth.
    let path = req.uri().path();
    if path.starts_with("/files/") || path.starts_with("/upload/") {
        return next.run(req).await;
    }
    let authed = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(|h| check_basic(h, &user, &pass))
        .unwrap_or(false);
    if authed {
        next.run(req).await
    } else {
        (
            StatusCode::UNAUTHORIZED,
            [(
                header::WWW_AUTHENTICATE,
                "Basic realm=\"rv6699-acs console\"",
            )],
            "401 Unauthorized — console requires authentication",
        )
            .into_response()
    }
}

fn check_basic(hdr: &str, user: &str, pass: &str) -> bool {
    let rest = match hdr
        .strip_prefix("Basic ")
        .or_else(|| hdr.strip_prefix("basic "))
    {
        Some(r) => r.trim(),
        None => return false,
    };
    let decoded = match STANDARD.decode(rest) {
        Ok(d) => d,
        Err(_) => return false,
    };
    let s = String::from_utf8_lossy(&decoded);
    match s.split_once(':') {
        Some((u, p)) => u == user && p == pass,
        None => false,
    }
}

fn json_response(value: Value, code: StatusCode) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        header::HeaderValue::from_static("*"),
    );
    (code, headers, Json(value)).into_response()
}

// ---- GET /api/state ----
pub async fn api_state(State(state): State<Arc<ConsoleState>>) -> Response {
    let store = &state.store;
    let cfg = &state.cfg;
    let s = store.settings();
    let auth = if s.capture {
        format!("capture/{}", s.challenge)
    } else if !s.acs_password.is_empty() {
        "enforced".to_string()
    } else {
        "open".to_string()
    };
    let advertise_effective = store.advertise_effective();
    // The host shown in advertise_ip / acs_url tracks the effective advertise host
    // (configured -> CPE-learned -> explicit -> auto). Empty -> not learned yet.
    let shown_host = if advertise_effective.is_empty() {
        cfg.advertise_ip.clone()
    } else {
        advertise_effective.clone()
    };
    let body = json!({
        "devices": store.list_views(),
        "log": store.log_tail(200),
        "captures": store.captures_tail(50),
        "config": {
            "advertise_ip": shown_host,
            "cwmp_port": cfg.cwmp_port,
            "console_port": cfg.console_port,
            "acs_username": s.acs_username,
            "auth": auth,
            "cr_username": s.cr_username,
            "acs_url": format!("http://{}:{}/", shown_host, cfg.cwmp_port),
            "needs_setup": s.console_password_generated,
            "advertise_effective": advertise_effective,
            "console_auth": !s.console_password.is_empty(),
        },
    });
    json_response(body, StatusCode::OK)
}

/// Build the public GET /api/settings view (never exposes raw secrets).
fn settings_view(store: &Arc<Store>, cfg: &Config) -> Value {
    let s = store.settings();
    json!({
        "acs_username": s.acs_username,
        "acs_auth_enabled": !s.acs_password.is_empty(),
        "capture": s.capture,
        "challenge": s.challenge,
        "cr_username": s.cr_username,
        "cr_password_set": !s.cr_password.is_empty(),
        "console_username": s.console_username,
        "console_password_set": !s.console_password.is_empty(),
        "console_password_generated": s.console_password_generated,
        "advertise_host": s.advertise_host,
        "advertise_effective": store.advertise_effective(),
        "needs_setup": s.console_password_generated,
        "debug_wire": s.debug_wire,
        "ports": {
            "cwmp": cfg.cwmp_port,
            "console": cfg.console_port,
        },
    })
}

// ---- GET /api/settings ----
pub async fn api_get_settings(State(state): State<Arc<ConsoleState>>) -> Response {
    json_response(settings_view(&state.store, &state.cfg), StatusCode::OK)
}

// ---- PUT /api/settings ----
pub async fn api_put_settings(
    State(state): State<Arc<ConsoleState>>,
    body: Option<Json<SettingsPatch>>,
) -> Response {
    let patch = match body {
        Some(Json(p)) => p,
        None => SettingsPatch::default(),
    };
    // validate before mutating
    if let Some(ch) = &patch.challenge
        && !Settings::valid_challenge(ch)
    {
        return json_response(
            json!({"error": "challenge must be one of basic|digest|both"}),
            StatusCode::BAD_REQUEST,
        );
    }
    state.store.update_settings(|s| {
        if let Some(v) = patch.acs_username {
            s.acs_username = v;
        }
        if let Some(v) = patch.acs_password {
            s.acs_password = v;
        }
        if let Some(v) = patch.console_username {
            s.console_username = v;
        }
        if let Some(v) = patch.console_password {
            // Any deliberate console_password change (to a real password, or to ""
            // to intentionally open the console) is an admin choice, not a
            // machine-generated default — so clear the generated flag.
            s.console_password_generated = false;
            s.console_password = v;
        }
        if let Some(v) = patch.capture {
            s.capture = v;
        }
        if let Some(v) = patch.challenge {
            s.challenge = v;
        }
        if let Some(v) = patch.cr_username {
            s.cr_username = v;
        }
        if let Some(v) = patch.cr_password {
            s.cr_password = v;
        }
        if let Some(v) = patch.advertise_host {
            s.advertise_host = v;
        }
        if let Some(v) = patch.debug_wire {
            s.debug_wire = v;
        }
    });
    state.store.event_info("settings updated via console", None);
    json_response(settings_view(&state.store, &state.cfg), StatusCode::OK)
}

// ---- GET /api/wire ----
// Diagnostic CWMP wire log: { enabled, entries: [most-recent ~300, oldest-first] }.
// Behind the normal console_auth middleware (NOT exempted).
pub async fn api_get_wire(State(state): State<Arc<ConsoleState>>) -> Response {
    let enabled = state.store.with_settings(|s| s.debug_wire);
    let entries = state.store.wire_entries();
    json_response(
        json!({ "enabled": enabled, "entries": entries }),
        StatusCode::OK,
    )
}

// ---- DELETE /api/wire ----
// Clear the wire ring buffer and truncate data/wire.log.
pub async fn api_clear_wire(State(state): State<Arc<ConsoleState>>) -> Response {
    state.store.wire_clear();
    json_response(json!({ "ok": true }), StatusCode::OK)
}

// ---- DELETE /api/captures ----
// Clear the global + per-device captured credentials and truncate captures.jsonl.
pub async fn api_clear_captures(State(state): State<Arc<ConsoleState>>) -> Response {
    state.store.captures_clear();
    json_response(json!({ "ok": true }), StatusCode::OK)
}

// ---- DELETE /api/log ----
// Clear the in-memory event log.
pub async fn api_clear_log(State(state): State<Arc<ConsoleState>>) -> Response {
    state.store.log_clear();
    json_response(json!({ "ok": true }), StatusCode::OK)
}

// ---- GET /api/device/:key ----
pub async fn api_device(
    State(state): State<Arc<ConsoleState>>,
    AxPath(key): AxPath<String>,
) -> Response {
    match state.store.device_detail(&key) {
        Some(detail) => json_response(detail, StatusCode::OK),
        None => json_response(json!({"error": "no such device"}), StatusCode::NOT_FOUND),
    }
}

// ---- POST /api/device/:key/task ----
pub async fn api_task(
    State(state): State<Arc<ConsoleState>>,
    AxPath(key): AxPath<String>,
    body: Option<Json<Value>>,
) -> Response {
    let store = &state.store;
    let cfg = &state.cfg;
    let body = body.map(|j| j.0).unwrap_or_else(|| json!({}));

    let ttype = match body.get("type").and_then(|v| v.as_str()) {
        Some(t) if !t.is_empty() => t.to_string(),
        _ => return json_response(json!({"error": "missing type"}), StatusCode::BAD_REQUEST),
    };
    let mut args = body.get("args").cloned().unwrap_or_else(|| json!({}));
    if !args.is_object() {
        args = json!({});
    }
    let label = body
        .get("label")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| ttype.clone());

    // convenience: rewrite download/upload URLs to our file server, using the
    // effective advertise host (configured -> CPE-learned -> explicit -> auto).
    let host = store.advertise_host();
    if ttype == "download" {
        let has_file = args.get("file").and_then(|v| v.as_str()).is_some();
        let has_url = args.get("url").is_some();
        if has_file && !has_url {
            let file = args
                .get("file")
                .and_then(|v| v.as_str())
                .unwrap()
                .to_string();
            let obj = args.as_object_mut().unwrap();
            obj.insert("url".to_string(), json!(cfg.file_url(&host, &file)));
            let fp = Path::new(&cfg.files_dir).join(&file);
            if let Ok(meta) = std::fs::metadata(&fp) {
                obj.entry("file_size").or_insert_with(|| json!(meta.len()));
            }
        }
    }
    if ttype == "upload" {
        let has_file = args.get("file").and_then(|v| v.as_str()).is_some();
        let has_url = args.get("url").is_some();
        if has_file && !has_url {
            let file = args
                .get("file")
                .and_then(|v| v.as_str())
                .unwrap()
                .to_string();
            let obj = args.as_object_mut().unwrap();
            obj.insert("url".to_string(), json!(cfg.upload_url(&host, &file)));
        }
    }

    let task = Task::new(&ttype, args, Some(&label), None, 0);
    let id = store.enqueue(&key, task);
    json_response(
        json!({"queued": id, "pending": store.pending_count(&key)}),
        StatusCode::OK,
    )
}

// ---- POST /api/device/:key/connreq ----
pub async fn api_connreq(
    State(state): State<Arc<ConsoleState>>,
    AxPath(key): AxPath<String>,
) -> Response {
    let store = &state.store;
    let url = match store.device_field(&key, |d| d.connection_request_url.clone()) {
        Some(u) => u,
        None => {
            return json_response(json!({"error": "no such device"}), StatusCode::NOT_FOUND);
        }
    };
    let (cr_user, cr_pass) =
        store.with_settings(|s| (s.cr_username.clone(), s.cr_password.clone()));
    let (ok, detail) = connreq::trigger(&url, &cr_user, &cr_pass).await;
    store.event(
        &format!("connection request -> {}: {}", url, detail),
        Some(&key),
        if ok { "info" } else { "error" },
    );
    json_response(
        json!({"ok": ok, "detail": detail, "url": url}),
        StatusCode::OK,
    )
}

// ---- POST /api/device/:key/discover ----
pub async fn api_discover(
    State(state): State<Arc<ConsoleState>>,
    AxPath(key): AxPath<String>,
    body: Option<Json<Value>>,
) -> Response {
    let store = &state.store;
    let cfg = &state.cfg;
    let body = body.map(|j| j.0).unwrap_or_else(|| json!({}));

    let dev_root = store.device_field(&key, |d| d.root.clone());
    let root = body
        .get("path")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .unwrap_or_else(|| dev_root.unwrap_or_else(|| "InternetGatewayDevice.".to_string()));
    let max_depth = body
        .get("max_depth")
        .and_then(|v| v.as_u64())
        .map(|v| v as u32)
        .unwrap_or(cfg.walk_max_depth);
    let max_nodes = body
        .get("max_nodes")
        .and_then(|v| v.as_u64())
        .map(|v| v as u32)
        .unwrap_or(cfg.walk_max_nodes);

    let wid = store.register_walk(max_depth, max_nodes);
    let task = Task::new(
        "getnames",
        json!({"path": root, "next_level": true}),
        Some(&format!("discover {}", root)),
        Some(wid),
        0,
    );
    let qid = store.enqueue(&key, task);
    store.event_info(
        &format!(
            "started discovery walk #{} from {} (depth<={}, nodes<={})",
            wid, root, max_depth, max_nodes
        ),
        Some(&key),
    );
    json_response(json!({"walk_id": wid, "queued": qid}), StatusCode::OK)
}

// ---- GET /files/:name ----
pub async fn serve_file(
    State(state): State<Arc<ConsoleState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    AxPath(name): AxPath<String>,
) -> Response {
    let cfg = &state.cfg;
    let safe = Path::new(&name)
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| name.clone());
    let fp = Path::new(&cfg.files_dir).join(&safe);
    match std::fs::read(&fp) {
        Ok(data) => {
            let size = data.len();
            state.store.event_info(
                &format!("serving file {} ({} B) to {}", safe, size, peer.ip()),
                None,
            );
            let mut headers = HeaderMap::new();
            headers.insert(
                header::CONTENT_TYPE,
                header::HeaderValue::from_static("application/octet-stream"),
            );
            (StatusCode::OK, headers, data).into_response()
        }
        Err(_) => json_response(json!({"error": "no such file"}), StatusCode::NOT_FOUND),
    }
}

// ---- PUT|POST /upload/:name ----
pub async fn accept_upload(
    State(state): State<Arc<ConsoleState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    AxPath(name): AxPath<String>,
    body: Bytes,
) -> Response {
    let cfg = &state.cfg;
    let safe = {
        let base = Path::new(&name)
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default();
        if base.is_empty() {
            "upload.bin".to_string()
        } else {
            base
        }
    };
    let _ = std::fs::create_dir_all(&cfg.uploads_dir);
    let fp = Path::new(&cfg.uploads_dir).join(&safe);
    let n = body.len();
    match std::fs::write(&fp, &body) {
        Ok(_) => {
            state.store.event_info(
                &format!("received upload {} ({} B) from {}", safe, n, peer.ip()),
                None,
            );
            json_response(
                json!({"ok": true, "stored": fp.to_string_lossy(), "size": n}),
                StatusCode::OK,
            )
        }
        Err(e) => json_response(
            json!({"error": format!("write failed: {}", e)}),
            StatusCode::INTERNAL_SERVER_ERROR,
        ),
    }
}
