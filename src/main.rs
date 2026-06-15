//! main.rs — start the rv6699 TR-069 ACS (port of run_acs.py).
//!
//!   CPE-facing CWMP endpoint :   http://<host>:7547/   (point the router here)
//!   Web console + REST + files:  http://<host>:7548/

mod config;
mod connreq;
mod console;
mod cpe_server;
mod cwmp;
mod digest;
mod settings;
mod store;

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use axum::response::IntoResponse;
use axum::{
    Router,
    routing::{delete, get, post, put},
};
use clap::Parser;
use tower_http::cors::CorsLayer;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::services::ServeDir;
use tower_http::timeout::TimeoutLayer;

use config::Config;
use console::ConsoleState;
use cpe_server::CpeState;
use settings::Settings;
use store::Store;

/// Every flag also reads an env var (clap `env`), so the Docker image is
/// configured purely through the environment — no shell entrypoint needed.
#[derive(Parser, Debug)]
#[command(name = "rv6699-acs", about = "rv6699 TR-069 ACS")]
struct Cli {
    /// bind address
    #[arg(long, env = "HOST", default_value = "0.0.0.0")]
    host: String,
    /// public/LAN IP or hostname the router + file URLs use (auto-detected if unset)
    #[arg(long, env = "ADVERTISE_IP")]
    advertise_ip: Option<String>,
    #[arg(long, env = "CWMP_PORT", default_value_t = 7547)]
    cwmp_port: u16,
    #[arg(long, env = "CONSOLE_PORT", default_value_t = 7548)]
    console_port: u16,
    #[arg(long, env = "ACS_USER", default_value = "ag")]
    acs_user: String,
    /// if set, the CPE must authenticate with this (Digest/Basic)
    #[arg(long, env = "ACS_PASS", default_value = "")]
    acs_pass: String,
    /// console (browser/REST) Basic-auth username
    #[arg(long, env = "CONSOLE_USER", default_value = "admin")]
    console_user: String,
    /// if set, the web console + REST API require this password (Basic auth).
    /// If omitted on first run, a random password is generated and printed in
    /// the startup banner (the console is never open-by-default).
    #[arg(long, env = "CONSOLE_PASS")]
    console_pass: Option<String>,
    #[arg(long, env = "CR_USER", default_value = "F7QOyhi33VFQ")]
    cr_user: String,
    /// Connection Request password (set this to wake the router)
    #[arg(long, env = "CR_PASS", default_value = "")]
    cr_pass: String,
    /// credential-capture mode: challenge the CPE so it reveals the ACS
    /// username/password it was provisioned with. Bare `--capture` enables it;
    /// the CAPTURE env var accepts 1/0/true/false/yes/no/on/off.
    #[arg(
        long,
        env = "CAPTURE",
        num_args = 0..=1,
        default_value = "false",
        default_missing_value = "true",
        value_parser = parse_truthy
    )]
    capture: bool,
    /// capture challenge scheme: basic=plaintext (best), digest=crackable hash,
    /// both=CPE picks (default basic)
    #[arg(long, env = "CHALLENGE", default_value = "basic", value_parser = ["basic", "digest", "both"])]
    challenge: String,
    /// diagnostic CWMP "wire log": record every inbound request + outbound
    /// response (Authorization header masked) to an in-memory ring buffer and
    /// the durable SQLite wire table. Bare `--debug-wire` enables it; the
    /// DEBUG_WIRE env var accepts 1/0/true/false/yes/no/on/off. Also toggleable
    /// live from the web Settings panel.
    #[arg(
        long,
        env = "DEBUG_WIRE",
        num_args = 0..=1,
        default_value = "false",
        default_missing_value = "true",
        value_parser = parse_truthy
    )]
    debug_wire: bool,
    #[arg(long, env = "DATA_DIR", default_value = "data")]
    data_dir: String,
    #[arg(long, env = "FILES_DIR", default_value = "files")]
    files_dir: String,
    #[arg(long, env = "UPLOADS_DIR", default_value = "uploads")]
    uploads_dir: String,
    /// serve the console from this dir instead of the binary-embedded copy
    /// (frontend-dev override; empty = use the embedded console)
    #[arg(long, env = "WEB_DIR", default_value = "")]
    web_dir: String,
}

/// The built React console, embedded into the binary at compile time so the ACS
/// ships as ONE self-contained file (no frontend/dist folder needed at runtime).
/// `--web-dir <dir>` overrides this with on-disk serving for frontend dev.
#[derive(rust_embed::RustEmbed)]
#[folder = "frontend/dist"]
struct WebAssets;

/// Serve the embedded console with SPA fallback (unknown client routes -> index.html).
async fn serve_embedded(uri: axum::http::Uri) -> axum::response::Response {
    use axum::http::{StatusCode, header::CONTENT_TYPE};
    let path = uri.path().trim_start_matches('/');
    let path = if path.is_empty() { "index.html" } else { path };
    if let Some(file) = WebAssets::get(path) {
        let mime = file.metadata.mimetype().to_string();
        return ([(CONTENT_TYPE, mime)], file.data.into_owned()).into_response();
    }
    // client-router route -> serve index.html with 200 so the SPA takes over
    match WebAssets::get("index.html") {
        Some(idx) => (
            StatusCode::OK,
            [(CONTENT_TYPE, "text/html; charset=utf-8")],
            idx.data.into_owned(),
        )
            .into_response(),
        None => (StatusCode::NOT_FOUND, "console UI not embedded").into_response(),
    }
}

/// Parse common boolean spellings (so the CAPTURE env var accepts 1/yes/on etc.).
fn parse_truthy(s: &str) -> Result<bool, String> {
    match s.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" | "" => Ok(false),
        other => Err(format!(
            "expected a boolean (1/0/true/false/yes/no/on/off), got '{other}'"
        )),
    }
}

fn detect_ip() -> String {
    // mirror Python: UDP connect to 192.168.1.1:80 and read local addr.
    match std::net::UdpSocket::bind("0.0.0.0:0") {
        Ok(sock) => match sock.connect("192.168.1.1:80") {
            Ok(_) => sock
                .local_addr()
                .map(|a| a.ip().to_string())
                .unwrap_or_else(|_| "127.0.0.1".to_string()),
            Err(_) => "127.0.0.1".to_string(),
        },
        Err(_) => "127.0.0.1".to_string(),
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let advertise_ip_explicit = cli.advertise_ip.is_some();
    let advertise_ip = cli.advertise_ip.clone().unwrap_or_else(detect_ip);
    let cfg = Config {
        host_ip: cli.host.clone(),
        advertise_ip,
        advertise_ip_explicit,
        cwmp_port: cli.cwmp_port,
        console_port: cli.console_port,
        data_dir: cli.data_dir.clone(),
        files_dir: cli.files_dir.clone(),
        uploads_dir: cli.uploads_dir.clone(),
        web_dir: cli.web_dir.clone(),
        ..Config::default()
    };
    cfg.ensure_dirs();

    // Seed the runtime-mutable settings from CLI/env. settings.json (if present)
    // overrides this inside Store::new, so prior UI changes win and persist.
    let seed = Settings {
        acs_username: cli.acs_user.clone(),
        acs_password: cli.acs_pass.clone(),
        console_username: cli.console_user.clone(),
        // resolved below: CLI value wins; else settings.json; else generated
        console_password: cli.console_pass.clone().unwrap_or_default(),
        console_password_generated: false,
        capture: cli.capture,
        challenge: cli.challenge.clone(),
        cr_username: cli.cr_user.clone(),
        cr_password: cli.cr_pass.clone(),
        advertise_host: String::new(),
        debug_wire: cli.debug_wire,
    };

    let store = Arc::new(Store::new(
        cfg.devices_path(),
        cfg.captures_path(),
        cfg.settings_path(),
        seed,
        cfg.advertise_ip.clone(),
        cfg.advertise_ip_explicit,
    ));
    let cfg = Arc::new(cfg);

    // --- secure first run: resolve the console password ---
    //   1. CONSOLE_PASS / --console-pass provided  -> use it,            generated=false
    //   2. else settings.json already had one       -> keep it + its flag
    //   3. else (nothing set)                        -> GENERATE one,    generated=true
    // Step 2 already happened in Store::new (settings.json overrode the seed).
    let mut generated_pass: Option<String> = None;
    if let Some(p) = cli.console_pass.clone() {
        // explicit override always wins and is never "generated"
        store.update_settings(|s| {
            s.console_password = p;
            s.console_password_generated = false;
        });
    } else {
        let cur =
            store.with_settings(|s| (s.console_password.clone(), s.console_password_generated));
        if cur.0.is_empty() && !cur.1 {
            let pw = gen_password();
            generated_pass = Some(pw.clone());
            store.update_settings(|s| {
                s.console_password = pw;
                s.console_password_generated = true;
            });
        } else if cur.1 {
            // a previously-generated password loaded from settings.json — surface
            // it again so the admin who missed the first log can still read it.
            generated_pass = Some(cur.0);
        }
    }

    // ---- CPE-facing CWMP server ----
    let cpe_state = CpeState::new(store.clone(), cfg.clone());
    let cpe_app = Router::new()
        .route("/", get(cpe_server::cwmp_get).post(cpe_server::cwmp_post))
        // any path is the CWMP endpoint for POST; GET = health
        .fallback(get(cpe_server::cwmp_get).post(cpe_server::cwmp_post))
        // Harden the internet-exposed :7547 against scanners/slow-loris: cap the
        // request body (real Informs are a few KB) and time out stuck requests so a
        // hostile/half-open connection can't pile up and wedge the listener.
        .layer(TimeoutLayer::with_status_code(
            axum::http::StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(30),
        ))
        .layer(RequestBodyLimitLayer::new(256 * 1024))
        .with_state(cpe_state);

    // ---- Console server (REST + files + static UI) ----
    let console_state = ConsoleState::new(store.clone(), cfg.clone());

    let mut console_app = Router::new()
        .route("/api/state", get(console::api_state))
        .route(
            "/api/settings",
            get(console::api_get_settings).put(console::api_put_settings),
        )
        .route(
            "/api/wire",
            get(console::api_get_wire).delete(console::api_clear_wire),
        )
        .route("/api/captures", delete(console::api_clear_captures))
        .route("/api/log", delete(console::api_clear_log))
        .route("/api/device/{key}", get(console::api_device))
        .route("/api/device/{key}/task", post(console::api_task))
        .route("/api/device/{key}/connreq", post(console::api_connreq))
        .route("/api/device/{key}/discover", post(console::api_discover))
        .route("/files/{name}", get(console::serve_file))
        .route(
            "/upload/{name}",
            put(console::accept_upload).post(console::accept_upload),
        )
        .with_state(console_state.clone());

    // Frontend serving. DEFAULT: serve the React console EMBEDDED in the binary
    // (single self-contained file). DEV OVERRIDE: if --web-dir points at an
    // existing dir, serve from disk instead (live frontend rebuilds). Both use a
    // SPA fallback (unknown client routes -> index.html with HTTP 200).
    let web_dir = cfg.web_dir.clone();
    if !web_dir.is_empty() && Path::new(&web_dir).is_dir() {
        let spa_index = Path::new(&web_dir).join("index.html");
        let serve = ServeDir::new(&web_dir).fallback(get(move || {
            let p = spa_index.clone();
            async move {
                match tokio::fs::read(&p).await {
                    Ok(bytes) => (
                        axum::http::StatusCode::OK,
                        [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
                        bytes,
                    )
                        .into_response(),
                    Err(_) => (
                        axum::http::StatusCode::NOT_FOUND,
                        "console UI missing in --web-dir",
                    )
                        .into_response(),
                }
            }
        }));
        console_app = console_app.fallback_service(serve);
    } else {
        // default: the console is baked into the binary
        console_app = console_app.fallback(get(serve_embedded));
    }

    // Basic-auth gate (no-op unless --console-pass / CONSOLE_PASS is set).
    let console_app = console_app
        .layer(axum::middleware::from_fn_with_state(
            console_state.clone(),
            console::console_auth,
        ))
        .layer(CorsLayer::permissive());

    // ---- banner ----
    print_banner(&cfg, &store.settings(), &store.advertise_effective());
    if let Some(pw) = &generated_pass {
        print_first_run_notice(&store.with_settings(|s| s.console_username.clone()), pw);
    }
    store.event_info("ACS started", None);

    let cpe_addr: SocketAddr = format!("{}:{}", cfg.host_ip, cfg.cwmp_port)
        .parse()
        .expect("invalid CWMP bind addr");
    let console_addr: SocketAddr = format!("{}:{}", cfg.host_ip, cfg.console_port)
        .parse()
        .expect("invalid console bind addr");

    let cpe_listener = tokio::net::TcpListener::bind(cpe_addr)
        .await
        .unwrap_or_else(|e| panic!("cannot bind CWMP {}: {}", cpe_addr, e));
    let console_listener = tokio::net::TcpListener::bind(console_addr)
        .await
        .unwrap_or_else(|e| panic!("cannot bind console {}: {}", console_addr, e));

    let cpe_server = axum::serve(
        cpe_listener,
        cpe_app.into_make_service_with_connect_info::<SocketAddr>(),
    );
    let console_server = axum::serve(
        console_listener,
        console_app.into_make_service_with_connect_info::<SocketAddr>(),
    );

    let store_for_shutdown = store.clone();
    tokio::select! {
        r = cpe_server => { if let Err(e) = r { eprintln!("cpe server error: {}", e); } }
        r = console_server => { if let Err(e) = r { eprintln!("console server error: {}", e); } }
        _ = shutdown_signal() => {
            println!("\nshutting down…");
            store_for_shutdown.save();
        }
    }
}

/// Resolve on Ctrl-C or (on Unix/containers) SIGTERM, so `docker stop` shuts
/// down cleanly and persists state.
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {}
        _ = term => {}
    }
}

/// Generate a random 12-hex-char console password for secure first run.
fn gen_password() -> String {
    use rand::RngExt;
    let mut rng = rand::rng();
    (0..6)
        .map(|_| format!("{:02x}", rng.random::<u8>()))
        .collect()
}

/// Boxed first-run notice printed when the console password was auto-generated.
/// The admin reads this from `docker compose logs`.
fn print_first_run_notice(user: &str, password: &str) {
    let line = format!(
        "  user={}  password={}  (change it in Settings)",
        user, password
    );
    let width = line.len().max(56);
    let bar = "=".repeat(width);
    println!(
        "\n  {bar}\n  FIRST-RUN ADMIN LOGIN\n{line}\n  {bar}\n",
        bar = bar,
        line = line,
    );
}

fn print_banner(cfg: &Config, s: &Settings, advertise_effective: &str) {
    let auth_line = if s.capture {
        format!(
            "CAPTURE mode (challenge={}) — logging the credentials the CPE presents",
            s.challenge
        )
    } else if !s.acs_password.is_empty() {
        format!("ENFORCED user={}", s.acs_username)
    } else {
        "OPEN (accepts any credentials)".to_string()
    };
    let cr_line = format!(
        "user={} pass={}",
        s.cr_username,
        if s.cr_password.is_empty() {
            "UNSET (cannot wake router)"
        } else {
            "set"
        }
    );
    let console_auth = if s.console_password.is_empty() {
        "OPEN  <-- set a console password in Settings before exposing publicly!".to_string()
    } else if s.console_password_generated {
        format!(
            "Basic auth, user={} (auto-generated — see notice below)",
            s.console_username
        )
    } else {
        format!("Basic auth, user={}", s.console_username)
    };
    // host shown for the CPE/console URLs: effective advertise host, else the
    // auto-detected IP (file URLs auto-derive from the CPE's Host header at runtime).
    let ip = if advertise_effective.is_empty() {
        cfg.advertise_ip.as_str()
    } else {
        advertise_effective
    };
    let adv_line = if s.advertise_host.is_empty() {
        "auto (learned from CPE Host header; override in Settings)".to_string()
    } else {
        format!("configured = {}", s.advertise_host)
    };
    let wire_line = if s.debug_wire {
        "ON  (toggle in Settings)".to_string()
    } else {
        "off (enable with --debug-wire or in Settings)".to_string()
    };
    let banner = format!(
        "
  rv6699 TR-069 ACS  —  running
  ------------------------------------------------------------
  CPE / CWMP endpoint :  http://{ip}:{cwmp}/
      -> set the router's  ACS URL  field to exactly this
  Web console         :  http://{ip}:{console}/
  ACS auth            :  {auth}
  Console auth        :  {console_auth}
  Conn-Request creds  :  {cr}
  Advertise host      :  {adv}
  Wire log            :  {wire}
  Data dir            :  {data}/   Files: {files}/   Uploads: {uploads}/
  ------------------------------------------------------------
  Waiting for Informs…  (Ctrl-C to stop)
",
        ip = ip,
        cwmp = cfg.cwmp_port,
        console = cfg.console_port,
        auth = auth_line,
        console_auth = console_auth,
        cr = cr_line,
        adv = adv_line,
        wire = wire_line,
        data = cfg.data_dir,
        files = cfg.files_dir,
        uploads = cfg.uploads_dir,
    );
    println!("{}", banner);
}
