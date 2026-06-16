//! settings.rs — runtime-mutable ACS settings, persisted in the SQLite store (acs.db).
//!
//! These fields are editable live from the web console (PUT /api/settings) and
//! survive restarts. The startup seed comes from the CLI/env (config.rs); a row
//! persisted in acs.db (if present) overrides the seed so UI changes win.

use serde::{Deserialize, Serialize};

/// The live, persisted, web-editable configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    /// ACS-session auth: the username the CPE must present. Empty password =>
    /// open mode (no CPE auth).
    #[serde(default = "default_acs_username")]
    pub acs_username: String,
    #[serde(default)]
    pub acs_password: String,

    /// Console (browser/REST) Basic-auth credentials.
    #[serde(default = "default_console_username")]
    pub console_username: String,
    #[serde(default)]
    pub console_password: String,
    /// True when console_password was machine-generated on first run (the admin
    /// has not chosen one yet). Drives the `needs_setup` UI hint.
    #[serde(default)]
    pub console_password_generated: bool,

    /// Credential-capture mode + challenge scheme ("basic"|"digest"|"both").
    #[serde(default)]
    pub capture: bool,
    #[serde(default = "default_challenge")]
    pub challenge: String,

    /// Connection Request creds (we authenticate to the CPE to wake it).
    #[serde(default)]
    pub cr_username: String,
    #[serde(default)]
    pub cr_password: String,

    /// The host/IP the router + file URLs should use. Empty => auto-derive
    /// (learned from the CPE's Host header, then explicit --advertise-ip, then
    /// auto-detected LAN IP).
    #[serde(default)]
    pub advertise_host: String,

    /// Diagnostic "wire log": when true, the CWMP endpoint records every
    /// inbound request and outbound response (headers masked for secrets, body
    /// verbatim) into an in-memory ring buffer and the durable SQLite wire
    /// table. Default false.
    #[serde(default)]
    pub debug_wire: bool,
}

fn default_acs_username() -> String {
    "ag".to_string()
}

fn default_console_username() -> String {
    "admin".to_string()
}

fn default_challenge() -> String {
    "basic".to_string()
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            acs_username: default_acs_username(),
            acs_password: String::new(),
            console_username: default_console_username(),
            console_password: String::new(),
            console_password_generated: false,
            capture: false,
            challenge: default_challenge(),
            cr_username: String::new(),
            cr_password: String::new(),
            advertise_host: String::new(),
            debug_wire: false,
        }
    }
}

impl Settings {
    /// Validate the challenge scheme name.
    pub fn valid_challenge(s: &str) -> bool {
        matches!(s, "basic" | "digest" | "both")
    }
}

/// Partial update body for PUT /api/settings. Absent field (None) => leave
/// unchanged; present field (Some, even Some("")) => set to that value.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct SettingsPatch {
    pub acs_username: Option<String>,
    pub acs_password: Option<String>,
    pub console_username: Option<String>,
    pub console_password: Option<String>,
    pub capture: Option<bool>,
    pub challenge: Option<String>,
    pub cr_username: Option<String>,
    pub cr_password: Option<String>,
    pub advertise_host: Option<String>,
    pub debug_wire: Option<bool>,
}
