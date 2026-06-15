//! cpe_server.rs — the CPE-facing CWMP HTTP server (the ACS endpoint).
//!
//! Port of cpe_server.py. Implements the TR-069 session state machine. In the
//! Python version, per-connection state lives on the handler object (one TCP
//! connection per session). Here, axum invokes a handler per HTTP request, so
//! session state is keyed by the ACSSESSION cookie the ACS sets in the
//! InformResponse and the CPE echoes back (falling back to client IP).

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::{ConnectInfo, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode},
    response::{IntoResponse, Response},
};
use parking_lot::Mutex;
use rand::RngExt;
use serde_json::{Value, json};

use crate::config::Config;
use crate::cwmp;
use crate::digest;
use crate::settings::Settings;
use crate::store::{Store, Task};

/// Live per-session state, correlated by ACSSESSION cookie or client IP.
#[derive(Default)]
pub struct Session {
    pub session_key: Option<String>, // device key once we see the Inform
    pub session_ns: String,
    pub authenticated: bool,
    pub cookie: Option<String>,
    pub inflight: Option<Task>, // task awaiting a response
    pub acs_id_seq: u64,
    pub touched: i64, // unix seconds of last write (for pruning)
}

pub struct CpeState {
    pub store: Arc<Store>,
    pub cfg: Arc<Config>,
    pub sessions: Mutex<HashMap<String, Session>>,
}

impl CpeState {
    pub fn new(store: Arc<Store>, cfg: Arc<Config>) -> Arc<CpeState> {
        Arc::new(CpeState {
            store,
            cfg,
            sessions: Mutex::new(HashMap::new()),
        })
    }
}

fn token_hex(nbytes: usize) -> String {
    let mut rng = rand::rng();
    (0..nbytes)
        .map(|_| format!("{:02x}", rng.random::<u8>()))
        .collect()
}

fn new_acs_id(seq: &mut u64) -> String {
    *seq += 1;
    format!("ACS_{}_{}", seq, token_hex(2))
}

/// Extract the ACSSESSION cookie value from request headers.
fn extract_cookie(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get("cookie")?.to_str().ok()?;
    for part in raw.split(';') {
        let p = part.trim();
        if let Some(v) = p.strip_prefix("ACSSESSION=") {
            return Some(v.to_string());
        }
    }
    None
}

/// Extract the request Host header and strip any :port, returning the bare
/// host/domain the CPE used to reach us. IPv6 literals keep their brackets.
fn host_from_headers(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get("host")?.to_str().ok()?.trim();
    if raw.is_empty() {
        return None;
    }
    // [::1]:7547  /  [::1]
    if let Some(rest) = raw.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            return Some(format!("[{}]", &rest[..end]));
        }
        return Some(raw.to_string());
    }
    // host:port  ->  host  (only split when exactly one ':' = host:port, not IPv6)
    match raw.rsplit_once(':') {
        Some((h, p))
            if !h.contains(':') && p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty() =>
        {
            Some(h.to_string())
        }
        _ => Some(raw.to_string()),
    }
}

/// GET on the CWMP endpoint = health check.
pub async fn cwmp_get() -> Response {
    (
        StatusCode::OK,
        [("Content-Type", "text/plain")],
        "rv6699-acs CWMP endpoint. POST your Inform here.",
    )
        .into_response()
}

fn send_envelope(
    body_inner: &str,
    cwmp_id: &str,
    session_ns: &str,
    seq: &mut u64,
    cookie: Option<&str>,
) -> Response {
    let id = if cwmp_id.is_empty() {
        new_acs_id(seq)
    } else {
        cwmp_id.to_string()
    };
    let data = cwmp::envelope(body_inner, &id, session_ns);
    let mut headers = HeaderMap::new();
    headers.insert(
        "Content-Type",
        HeaderValue::from_static("text/xml; charset=\"utf-8\""),
    );
    headers.insert("SOAPAction", HeaderValue::from_static(""));
    if let Some(c) = cookie
        && let Ok(v) = HeaderValue::from_str(&format!("ACSSESSION={}; Path=/", c))
    {
        headers.insert("Set-Cookie", v);
    }
    (StatusCode::OK, headers, data).into_response()
}

fn send_end() -> Response {
    let mut headers = HeaderMap::new();
    headers.insert("Content-Length", HeaderValue::from_static("0"));
    (StatusCode::NO_CONTENT, headers).into_response()
}

fn send_401(cfg: &Config, settings: &Settings) -> Response {
    let body = b"<html><body>401 Unauthorized</body></html>".to_vec();
    let mut headers = HeaderMap::new();
    let challenge = settings.challenge.as_str();
    // Offer the operator-selected scheme(s) in BOTH capture and enforcement modes.
    // The МГТС cwmp authenticates with Basic by default, so a Digest-only challenge
    // would lock out a Basic CPE — honoring `challenge` (default "basic") lets the
    // router answer with the scheme it actually speaks. Both schemes may be sent.
    if challenge != "digest"
        && let Ok(v) = HeaderValue::from_str(&format!("Basic realm=\"{}\"", cfg.realm))
    {
        headers.append("WWW-Authenticate", v);
    }
    if challenge != "basic" {
        let ch = digest::challenge_header(&cfg.realm, &cfg.nonce_secret);
        if let Ok(v) = HeaderValue::from_str(&ch) {
            headers.append("WWW-Authenticate", v);
        }
    }
    headers.insert("Content-Type", HeaderValue::from_static("text/html"));
    (StatusCode::UNAUTHORIZED, headers, body).into_response()
}

/// Main CWMP POST handler.
pub async fn cwmp_post(
    State(state): State<Arc<CpeState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    method: Method,
    headers: HeaderMap,
    raw: Bytes,
) -> Response {
    let cfg = state.cfg.clone();
    let store = state.store.clone();
    let settings = store.settings();
    let client_ip = peer.ip().to_string();
    let debug_wire = settings.debug_wire;

    // The Host header (sans :port) is exactly the host/domain the router used to
    // reach us, so file/upload URLs built from it are reachable by the router.
    let host_header = host_from_headers(&headers);

    // session id: cookie if present, else client IP
    let cookie_id = extract_cookie(&headers);
    let session_id = cookie_id.clone().unwrap_or_else(|| client_ip.clone());

    // pull session state (clone-light: we operate on it then write back)
    let (mut sess_auth, mut sess_seq, mut sess_ns, mut sess_key, mut sess_cookie, mut inflight) = {
        let mut sessions = state.sessions.lock();
        let s = sessions
            .entry(session_id.clone())
            .or_insert_with(|| Session {
                session_ns: cwmp::CWMP_DEFAULT.to_string(),
                ..Default::default()
            });
        (
            s.authenticated,
            s.acs_id_seq,
            s.session_ns.clone(),
            s.session_key.clone(),
            s.cookie.clone(),
            s.inflight.take(),
        )
    };

    let msg = cwmp::parse(&raw);
    let kind = msg.kind.clone();

    // --- auth (only meaningful on the first message of the session) ---
    // The Python reference ties `authenticated` to the TCP connection: every new
    // session re-authenticates. We key sessions by the ACSSESSION cookie that the
    // ACS sets in the InformResponse and the CPE echoes on every continuation.
    // A request that carries the cookie is a proven continuation of an
    // authenticated session and rides it. A request WITHOUT the cookie is a
    // session start (Inform / fresh connection) and must (re)authenticate. This
    // satisfies the open-mode selftest (auth always passes) and a real enforced
    // CPE (Inform authenticates, cookie carries the rest), while never trusting a
    // stale IP-keyed session for a different credential.
    let is_continuation = cookie_id.is_some() && sess_auth;
    if !is_continuation {
        let auth_hdr = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        if !check_auth(
            &cfg,
            &settings,
            &store,
            auth_hdr.as_deref(),
            sess_key.as_deref(),
            &client_ip,
        ) {
            sess_auth = false;
            // write back nothing changed except keep inflight
            put_session(
                &state,
                &session_id,
                sess_auth,
                sess_seq,
                &sess_ns,
                &sess_key,
                &sess_cookie,
                inflight,
            );
            let resp = send_401(&cfg, &settings);
            if debug_wire {
                wire_log_in(
                    &store,
                    &method,
                    &headers,
                    &raw,
                    &client_ip,
                    sess_key.as_deref(),
                );
                return wire_log_out(store.clone(), resp, client_ip, sess_key).await;
            }
            return resp;
        }
        sess_auth = true;
    }
    if !msg.cwmp_ns.is_empty() {
        sess_ns = msg.cwmp_ns.clone();
    }

    let resp: Response = match kind.as_str() {
        "Inform" => handle_inform(
            &store,
            &msg,
            &client_ip,
            host_header.as_deref(),
            &mut sess_key,
            &sess_ns,
            &mut sess_cookie,
            &mut sess_seq,
        ),
        "empty" => send_next_or_end(
            &store,
            &cfg,
            sess_key.as_deref(),
            &sess_ns,
            &mut sess_seq,
            &mut inflight,
        ),
        "GetRPCMethods" => {
            let body = cwmp::get_rpc_methods_response(&cwmp::ACS_RPC_METHODS);
            send_envelope(
                &body,
                msg.id.as_deref().unwrap_or(""),
                &sess_ns,
                &mut sess_seq,
                None,
            )
        }
        "TransferComplete" => handle_transfer_complete(
            &store,
            &msg,
            false,
            sess_key.as_deref(),
            &sess_ns,
            &mut sess_seq,
        ),
        "AutonomousTransferComplete" => handle_transfer_complete(
            &store,
            &msg,
            true,
            sess_key.as_deref(),
            &sess_ns,
            &mut sess_seq,
        ),
        "parse_error" => {
            store.event(
                &format!("parse error: {}", msg.error.clone().unwrap_or_default()),
                sess_key.as_deref(),
                "error",
            );
            send_end()
        }
        k if k.ends_with("Response") || k == "Fault" => handle_rpc_response(
            &store,
            &cfg,
            &msg,
            sess_key.as_deref(),
            &sess_ns,
            &mut sess_seq,
            &mut inflight,
        ),
        _ => {
            store.event(
                &format!("unhandled inbound kind={}", kind),
                sess_key.as_deref(),
                "warn",
            );
            send_end()
        }
    };

    // Diagnostic wire log: record the inbound request (now that sess_key is
    // resolved, e.g. by handle_inform) and the outbound response. wire_log_out
    // buffers the response body so it can both log it and forward it intact.
    let resp = if debug_wire {
        wire_log_in(
            &store,
            &method,
            &headers,
            &raw,
            &client_ip,
            sess_key.as_deref(),
        );
        wire_log_out(store.clone(), resp, client_ip.clone(), sess_key.clone()).await
    } else {
        resp
    };

    put_session(
        &state,
        &session_id,
        sess_auth,
        sess_seq,
        &sess_ns,
        &sess_key,
        &sess_cookie,
        inflight,
    );
    resp
}

/// Lowercase header map with the Authorization value masked to "<scheme>
/// <redacted>" so credentials never reach disk. Used for inbound frames.
fn masked_request_headers(headers: &HeaderMap) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for (name, value) in headers.iter() {
        let n = name.as_str().to_string();
        let v = value.to_str().unwrap_or("<binary>").to_string();
        let v = if n.eq_ignore_ascii_case("authorization") {
            // Keep the scheme word (Basic/Digest/…) but redact the credential.
            let scheme = v.split_whitespace().next().unwrap_or("");
            if scheme.is_empty() {
                "<redacted>".to_string()
            } else {
                format!("{} <redacted>", scheme)
            }
        } else {
            v
        };
        out.insert(n, v);
    }
    out
}

/// Record the inbound CPE request as a wire frame (dir="in").
fn wire_log_in(
    store: &Store,
    method: &Method,
    headers: &HeaderMap,
    raw: &Bytes,
    client_ip: &str,
    session_key: Option<&str>,
) {
    let body = String::from_utf8_lossy(raw).to_string();
    let summary = format!("{} / (len={})", method.as_str(), raw.len());
    store.wire_push(
        "in",
        client_ip,
        session_key,
        &summary,
        masked_request_headers(headers),
        &body,
    );
}

/// Pick a short, telling local-name from a CWMP response body for the summary,
/// e.g. "InformResponse" / "GetParameterValues" / "Fault". Searches inside the
/// SOAP Body so the header's `cwmp:ID` element is never mistaken for the RPC.
fn first_cwmp_localname(body: &str) -> Option<String> {
    // Only look after the SOAP Body opening tag (any prefix, e.g. SOAP-ENV:Body).
    let scan = match body.find(":Body>").or_else(|| body.find("Body>")) {
        Some(i) => &body[i..],
        None => body,
    };
    for tag in scan.split('<') {
        // tag like "cwmp:InformResponse>" or "SOAP-ENV:Body>"
        let name = tag.split([' ', '>', '/']).next().unwrap_or("");
        if let Some(local) = name.strip_prefix("cwmp:")
            && !local.is_empty()
        {
            return Some(local.to_string());
        }
    }
    None
}

/// Buffer an outbound response so we can log it (dir="out") AND forward it
/// intact to the CPE. Decomposes the response, reads the body bytes, records a
/// wire frame, then rebuilds an identical response.
async fn wire_log_out(
    store: Arc<Store>,
    resp: Response,
    client_ip: String,
    session_key: Option<String>,
) -> Response {
    let (parts, body) = resp.into_parts();
    let bytes = match axum::body::to_bytes(body, usize::MAX).await {
        Ok(b) => b,
        Err(_) => {
            // Couldn't buffer; forward an empty-bodied response of same status.
            return Response::from_parts(parts, axum::body::Body::empty());
        }
    };
    let body_str = String::from_utf8_lossy(&bytes).to_string();

    // Response headers we set (Content-Type/Content-Length/SOAPAction/Set-Cookie).
    let mut hdrs = BTreeMap::new();
    for (name, value) in parts.headers.iter() {
        hdrs.insert(
            name.as_str().to_string(),
            value.to_str().unwrap_or("<binary>").to_string(),
        );
    }

    let status = parts.status;
    let summary = if status == StatusCode::NO_CONTENT {
        "204 (session end)".to_string()
    } else if status == StatusCode::UNAUTHORIZED {
        "401 challenge".to_string()
    } else if let Some(local) = first_cwmp_localname(&body_str) {
        format!("{} {}", status.as_u16(), local)
    } else {
        format!(
            "{} {}",
            status.as_u16(),
            status.canonical_reason().unwrap_or("")
        )
        .trim()
        .to_string()
    };

    store.wire_push(
        "out",
        &client_ip,
        session_key.as_deref(),
        &summary,
        hdrs,
        &body_str,
    );

    Response::from_parts(parts, axum::body::Body::from(bytes))
}

#[allow(clippy::too_many_arguments)]
fn put_session(
    state: &Arc<CpeState>,
    session_id: &str,
    authenticated: bool,
    acs_id_seq: u64,
    session_ns: &str,
    session_key: &Option<String>,
    cookie: &Option<String>,
    inflight: Option<Task>,
) {
    let now = chrono::Utc::now().timestamp();
    let mut sessions = state.sessions.lock();
    // Bound the map: drop sessions untouched for > 10 minutes.
    if sessions.len() > 64 {
        sessions.retain(|_, s| now - s.touched < 600);
    }
    // Write the session under the primary key (client IP for the cookie-less
    // Inform that starts the session) AND, once issued, the ACSSESSION cookie.
    // A real CPE (gSOAP cookie engine) echoes the cookie on every continuation,
    // so its empty-POST / RPC-response must resolve to the SAME session that the
    // Inform created — otherwise queued RPCs are never sent.
    let mut keys: Vec<&str> = vec![session_id];
    if let Some(c) = cookie
        && c != session_id
    {
        keys.push(c);
    }
    for key in keys {
        let s = sessions.entry(key.to_string()).or_default();
        s.authenticated = authenticated;
        s.acs_id_seq = acs_id_seq;
        s.session_ns = session_ns.to_string();
        s.session_key = session_key.clone();
        s.cookie = cookie.clone();
        s.inflight = inflight.clone();
        s.touched = now;
    }
}

// ---------------- auth ----------------
fn check_auth(
    cfg: &Config,
    settings: &Settings,
    store: &Store,
    auth_hdr: Option<&str>,
    session_key: Option<&str>,
    client_ip: &str,
) -> bool {
    // capture mode: make the CPE reveal its provisioned ACS credential
    if settings.capture {
        if let Some(hdr) = auth_hdr {
            capture_cred(store, hdr, session_key, client_ip);
            return true;
        }
        return false;
    }
    if settings.acs_password.is_empty() {
        return true; // open mode
    }
    let hdr = match auth_hdr {
        Some(h) => h,
        None => return false,
    };
    let ok = digest::verify(
        "POST",
        hdr,
        &settings.acs_username,
        &settings.acs_password,
        &cfg.realm,
        300.0,
    );
    if !ok {
        store.event("auth failed", session_key, "warn");
    }
    ok
}

fn capture_cred(store: &Store, hdr: &str, session_key: Option<&str>, client_ip: &str) {
    let a = digest::parse_auth_header(hdr);
    let scheme = a.scheme().to_string();
    let key = session_key.unwrap_or("");
    let rec: Value;
    if scheme == "basic" {
        let username = a.get("username").to_string();
        let password = a.get("_basic_password").to_string();
        rec = json!({
            "scheme": "basic",
            "username": username,
            "password": password,
            "raw": hdr,
        });
        store.event(
            &format!(
                "*** CAPTURED ACS credential (Basic, PLAINTEXT): username='{}' password='{}' from {}",
                username, password, client_ip
            ),
            session_key,
            "warn",
        );
    } else if scheme == "digest" {
        let username = a.get("username").to_string();
        let response = a.get("response").to_string();
        let algorithm = if a.get("algorithm").is_empty() {
            "MD5".to_string()
        } else {
            a.get("algorithm").to_string()
        };
        rec = json!({
            "scheme": "digest",
            "username": username,
            "realm": a.get("realm"),
            "nonce": a.get("nonce"),
            "nc": a.get("nc"),
            "cnonce": a.get("cnonce"),
            "qop": a.get("qop"),
            "uri": a.get("uri"),
            "response": response,
            "algorithm": algorithm,
            "method": "POST",
            "raw": hdr,
        });
        store.event(
            &format!(
                "*** CAPTURED ACS credential (Digest hash) username='{}' response={} — crack offline with crack_acs_digest.py",
                username, response
            ),
            session_key,
            "warn",
        );
    } else {
        let s = if scheme.is_empty() {
            "unknown"
        } else {
            &scheme
        };
        rec = json!({ "scheme": s, "raw": hdr });
        store.event(
            &format!("captured Authorization ({}) from {}", s, client_ip),
            session_key,
            "warn",
        );
    }
    store.add_capture(key, rec);
}

// ---------------- Inform ----------------
#[allow(clippy::too_many_arguments)]
fn handle_inform(
    store: &Store,
    msg: &cwmp::ParsedMessage,
    client_ip: &str,
    host_header: Option<&str>,
    sess_key: &mut Option<String>,
    session_ns: &str,
    sess_cookie: &mut Option<String>,
    seq: &mut u64,
) -> Response {
    // Learn the host/domain the router used to reach us (for file/upload URLs).
    if let Some(h) = host_header {
        store.set_learned_host(h);
    }
    let g = |k: &str| msg.device_id.get(k).cloned().unwrap_or_default();
    let oui = {
        let o = g("OUI");
        if o.is_empty() {
            "000000".to_string()
        } else {
            o
        }
    };
    let serial = {
        let s = g("SerialNumber");
        if s.is_empty() {
            "unknown".to_string()
        } else {
            s
        }
    };
    // Drop Informs whose OUI isn't a real 6-hex-digit IEEE OUI. Internet scanners
    // probing the public :7547 send garbage DeviceIds (e.g. "DISCOVERYSERVICE");
    // rejecting them keeps fake devices out of the list and off the session
    // machinery. A 6-hex OUI is mandatory in TR-069, so genuine CPEs (and the
    // selftest, which uses real OUIs) are unaffected.
    if oui.len() != 6 || !oui.chars().all(|c| c.is_ascii_hexdigit()) {
        store.event(
            &format!("dropped Inform from bogus OUI {oui:?} (serial {serial:?})"),
            None,
            "warn",
        );
        return send_end();
    }
    let key = format!("{}-{}", oui, serial);
    *sess_key = Some(key.clone());

    let ts = crate::store::now_iso();
    store.get_or_create(&key, |dev| {
        dev.oui = oui.clone();
        dev.serial = serial.clone();
        let pc = g("ProductClass");
        if !pc.is_empty() {
            dev.product_class = pc;
        }
        let mf = g("Manufacturer");
        if !mf.is_empty() {
            dev.manufacturer = mf;
        }
        dev.cwmp_ns = session_ns.to_string();
        dev.ip = client_ip.to_string();
        dev.last_seen = ts.clone();
        dev.online_hint = true;
        let events: Vec<Value> = msg
            .events
            .iter()
            .map(|e| json!({"code": e.code, "command_key": e.command_key}))
            .collect();
        dev.last_inform = json!({
            "ts": ts,
            "events": events,
            "source": client_ip,
        });
        // absorb the forced ParameterList carried in the Inform
        for p in &msg.parameters {
            let ent = dev.parameters.entry(p.name.clone()).or_default();
            ent.value = p.value.clone();
            ent.type_ = p.type_.clone();
            ent.ts = ts.clone();
            if p.name.ends_with("ManagementServer.ConnectionRequestURL") {
                dev.connection_request_url = p.value.clone();
            }
            if p.name.starts_with("Device.") {
                dev.root = "Device.".to_string();
            } else if p.name.starts_with("InternetGatewayDevice.") {
                dev.root = "InternetGatewayDevice.".to_string();
            }
        }
        if dev.model.is_empty() {
            dev.model = dev.product_class.clone();
        }
    });

    let ev_codes: Vec<String> = msg.events.iter().map(|e| e.code.clone()).collect();
    store.event_info(
        &format!("Inform from {} events=[{}]", client_ip, ev_codes.join(",")),
        Some(&key),
    );
    store.save();

    let cookie = token_hex(8);
    *sess_cookie = Some(cookie.clone());
    send_envelope(
        &cwmp::inform_response(),
        msg.id.as_deref().unwrap_or(""),
        session_ns,
        seq,
        Some(&cookie),
    )
}

// ---------------- transfer complete ----------------
fn handle_transfer_complete(
    store: &Store,
    msg: &cwmp::ParsedMessage,
    autonomous: bool,
    session_key: Option<&str>,
    session_ns: &str,
    seq: &mut u64,
) -> Response {
    let ck = &msg.command_key;
    let fc = if msg.fault_code.is_empty() {
        "0".to_string()
    } else {
        msg.fault_code.clone()
    };
    let ok = fc.is_empty() || fc == "0";
    let label = if autonomous {
        "AutonomousTransferComplete"
    } else {
        "TransferComplete"
    };
    store.event(
        &format!(
            "{} key={} fault={} {}",
            label,
            ck,
            fc,
            if ok { "OK" } else { &msg.fault_string }
        ),
        session_key,
        if ok { "info" } else { "error" },
    );
    let body = if autonomous {
        cwmp::autonomous_transfer_complete_response()
    } else {
        cwmp::transfer_complete_response()
    };
    send_envelope(
        &body,
        msg.id.as_deref().unwrap_or(""),
        session_ns,
        seq,
        None,
    )
}

// ---------------- RPC responses ----------------
#[allow(clippy::too_many_arguments)]
fn handle_rpc_response(
    store: &Store,
    cfg: &Config,
    msg: &cwmp::ParsedMessage,
    session_key: Option<&str>,
    session_ns: &str,
    seq: &mut u64,
    inflight: &mut Option<Task>,
) -> Response {
    let task = inflight.take();
    let kind = &msg.kind;
    let key = session_key.unwrap_or("");

    if kind == "Fault" {
        let code = &msg.cwmp_fault_code;
        store.event(
            &format!(
                "CPE Fault {} {} (task #{})",
                code,
                msg.cwmp_fault_string,
                task.as_ref()
                    .map(|t| t.id.to_string())
                    .unwrap_or_else(|| "?".to_string())
            ),
            session_key,
            "error",
        );
        if let Some(t) = task {
            let set_faults: Vec<Value> = msg
                .set_faults
                .iter()
                .map(|f| json!({"name": f.name, "code": f.code, "string": f.string}))
                .collect();
            let fault = json!({
                "code": code,
                "string": msg.cwmp_fault_string,
                "set_faults": set_faults,
            });
            store.finish_task(key, t, "fault", Value::Null, fault);
        }
        return send_next_or_end(store, cfg, session_key, session_ns, seq, inflight);
    }

    if let Some(t) = task {
        let result = absorb(store, key, msg);
        let walk_id = t.walk_id;
        let walk_depth = t.walk_depth;
        let path = t
            .args
            .get("path")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        store.finish_task(key, t, "done", result, Value::Null);
        // discovery walk expansion
        if let Some(wid) = walk_id
            && kind == "GetParameterNamesResponse"
        {
            expand_walk(store, key, wid, walk_depth, &path, msg);
        }
    }
    send_next_or_end(store, cfg, session_key, session_ns, seq, inflight)
}

fn absorb(store: &Store, key: &str, msg: &cwmp::ParsedMessage) -> Value {
    match msg.kind.as_str() {
        "GetParameterValuesResponse" => {
            store.update_parameters(key, &msg.parameters);
            let params: Vec<Value> = msg
                .parameters
                .iter()
                .map(|p| json!({"name": p.name, "value": p.value, "type": p.type_}))
                .collect();
            json!({ "parameters": params })
        }
        "GetParameterNamesResponse" => {
            store.update_names(key, &msg.names);
            let names: Vec<Value> = msg
                .names
                .iter()
                .map(|n| json!({"name": n.name, "writable": n.writable}))
                .collect();
            json!({ "names": names })
        }
        "GetParameterAttributesResponse" => {
            store.update_attributes(key, &msg.attributes);
            let attrs: Vec<Value> = msg
                .attributes
                .iter()
                .map(|a| json!({"name": a.name, "notification": a.notification, "access_list": a.access_list}))
                .collect();
            json!({ "attributes": attrs })
        }
        "SetParameterValuesResponse" | "DeleteObjectResponse" => json!({ "status": msg.status }),
        "AddObjectResponse" => {
            json!({ "instance_number": msg.instance_number, "status": msg.status })
        }
        "DownloadResponse" | "UploadResponse" => json!({
            "status": msg.status,
            "start_time": msg.start_time,
            "complete_time": msg.complete_time,
        }),
        "GetRPCMethodsResponse" => {
            store.set_rpc_methods(key, msg.methods.clone());
            json!({ "methods": msg.methods })
        }
        other => json!({ "raw_kind": other }),
    }
}

fn expand_walk(
    store: &Store,
    key: &str,
    walk_id: u64,
    walk_depth: u32,
    task_path: &str,
    msg: &cwmp::ParsedMessage,
) {
    let info = match store.walk_info(walk_id) {
        Some(i) => i,
        None => return,
    };
    let max_depth = info.max_depth;
    for n in &msg.names {
        let name = &n.name;
        if !name.ends_with('.') {
            continue; // leaf parameter, already recorded
        }
        if name == task_path {
            continue;
        }
        if walk_depth + 1 > max_depth {
            continue;
        }
        if !store.walk_expand(walk_id) {
            store.event(
                &format!("discovery walk #{} hit node cap", walk_id),
                Some(key),
                "warn",
            );
            break;
        }
        let child = Task::new(
            "getnames",
            json!({"path": name, "next_level": true}),
            Some(&format!("walk {}", name)),
            Some(walk_id),
            walk_depth + 1,
        );
        store.enqueue(key, child);
    }
}

// ---------------- queue driver ----------------
fn send_next_or_end(
    store: &Store,
    _cfg: &Config,
    session_key: Option<&str>,
    session_ns: &str,
    seq: &mut u64,
    inflight: &mut Option<Task>,
) -> Response {
    let key = match session_key {
        Some(k) => k,
        None => {
            *inflight = None;
            return send_end();
        }
    };
    loop {
        let task = store.pop_next(key);
        let mut task = match task {
            Some(t) => t,
            None => {
                *inflight = None;
                return send_end();
            }
        };
        let body = build_rpc(&task);
        let body = match body {
            Some(b) => b,
            None => {
                store.finish_task(
                    key,
                    task,
                    "error",
                    Value::Null,
                    json!({"string": "unknown task type"}),
                );
                continue;
            }
        };
        let id = new_acs_id(seq);
        task.cwmp_id = Some(id.clone());
        let label = task.label.clone();
        let tid = task.id;
        *inflight = Some(task);
        store.event_info(&format!("-> {} (task #{})", label, tid), Some(key));
        return send_envelope(&body, &id, session_ns, seq, None);
    }
}

fn arg_str(args: &Value, k: &str, default: &str) -> String {
    args.get(k)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| default.to_string())
}

fn arg_i64(args: &Value, k: &str, default: i64) -> i64 {
    match args.get(k) {
        Some(Value::Number(n)) => n.as_i64().unwrap_or(default),
        Some(Value::String(s)) => s.parse::<i64>().unwrap_or(default),
        _ => default,
    }
}

fn arg_bool(args: &Value, k: &str, default: bool) -> bool {
    match args.get(k) {
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => matches!(s.to_lowercase().as_str(), "1" | "true"),
        Some(Value::Number(n)) => n.as_i64().map(|i| i != 0).unwrap_or(default),
        _ => default,
    }
}

fn build_rpc(task: &Task) -> Option<String> {
    let a = &task.args;
    let t = task.type_.as_str();
    match t {
        "get" => {
            let names = string_list(a, "names");
            Some(cwmp::get_parameter_values(&names))
        }
        "set" => {
            let params = parse_set_params(a);
            let pk = arg_str(a, "parameter_key", "");
            Some(cwmp::set_parameter_values(&params, &pk))
        }
        "getnames" | "discover" => Some(cwmp::get_parameter_names(
            &arg_str(a, "path", ""),
            arg_bool(a, "next_level", true),
        )),
        "getattr" => {
            let names = string_list(a, "names");
            Some(cwmp::get_parameter_attributes(&names))
        }
        "setattr" => {
            let items = parse_attr_items(a);
            Some(cwmp::set_parameter_attributes(&items))
        }
        "addobject" => Some(cwmp::add_object(
            &arg_str(a, "object_name", ""),
            &arg_str(a, "parameter_key", ""),
        )),
        "deleteobject" => Some(cwmp::delete_object(
            &arg_str(a, "object_name", ""),
            &arg_str(a, "parameter_key", ""),
        )),
        "reboot" => Some(cwmp::reboot(&arg_str(a, "command_key", "acs-reboot"))),
        "factoryreset" => Some(cwmp::factory_reset()),
        "getrpcmethods" => Some(cwmp::get_rpc_methods()),
        "download" => {
            let url = arg_str(a, "url", "");
            Some(cwmp::download(
                &arg_str(a, "command_key", "dl"),
                &arg_str(a, "file_type", "1 Firmware Upgrade Image"),
                &url,
                &arg_str(a, "username", ""),
                &arg_str(a, "password", ""),
                arg_i64(a, "file_size", 0),
                &arg_str(a, "target_filename", ""),
                arg_i64(a, "delay_seconds", 0),
                &arg_str(a, "success_url", ""),
                &arg_str(a, "failure_url", ""),
            ))
        }
        "upload" => {
            let url = arg_str(a, "url", "");
            Some(cwmp::upload(
                &arg_str(a, "command_key", "ul"),
                &arg_str(a, "file_type", "1 Vendor Configuration File"),
                &url,
                &arg_str(a, "username", ""),
                &arg_str(a, "password", ""),
                arg_i64(a, "delay_seconds", 0),
            ))
        }
        _ => None,
    }
}

fn string_list(args: &Value, k: &str) -> Vec<String> {
    args.get(k)
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default()
}

/// params: [[name, value, type], ...]
fn parse_set_params(args: &Value) -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    if let Some(arr) = args.get("params").and_then(|v| v.as_array()) {
        for row in arr {
            if let Some(r) = row.as_array() {
                let name = r.first().and_then(|v| v.as_str()).unwrap_or("").to_string();
                let value = value_to_string(r.get(1));
                let xtype = r.get(2).and_then(|v| v.as_str()).unwrap_or("").to_string();
                out.push((name, value, xtype));
            }
        }
    }
    out
}

fn value_to_string(v: Option<&Value>) -> String {
    match v {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::Bool(b)) => b.to_string(),
        Some(Value::Null) | None => String::new(),
        Some(other) => other.to_string(),
    }
}

fn parse_attr_items(args: &Value) -> Vec<cwmp::AttrItem> {
    let mut out = Vec::new();
    if let Some(arr) = args.get("items").and_then(|v| v.as_array()) {
        for it in arr {
            let name = it
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let notification = match it.get("notification") {
                Some(Value::Number(n)) => n.as_i64().unwrap_or(0),
                Some(Value::String(s)) => s.parse::<i64>().unwrap_or(0),
                _ => 0,
            };
            let notification_change = it
                .get("notification_change")
                .and_then(|v| v.as_bool())
                .unwrap_or(true);
            let access_list = it.get("access_list").and_then(|v| v.as_array()).map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect::<Vec<_>>()
            });
            out.push(cwmp::AttrItem {
                name,
                notification,
                notification_change,
                access_list,
            });
        }
    }
    out
}
