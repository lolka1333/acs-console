//! config.rs — runtime configuration for the ACS.

use crate::util::token_hex;

/// Static, startup-only configuration. Runtime-mutable settings (ACS/console
/// creds, capture, challenge, CR creds, advertise host) now live in
/// `settings::Settings` behind a RwLock on the Store; the fields below seed
/// those at boot and never change after.
#[derive(Clone, Debug)]
pub struct Config {
    pub host_ip: String,      // bind address for the CPE-facing server
    pub advertise_ip: String, // our LAN IP the CPE/file URLs use (auto-detected)
    /// True if --advertise-ip / ADVERTISE_IP was explicitly provided. When false,
    /// `advertise_ip` is just the auto-detected fallback and ranks below the
    /// CPE-learned host in the file-URL host precedence.
    pub advertise_ip_explicit: bool,
    pub cwmp_port: u16,    // CPE-facing CWMP endpoint
    pub console_port: u16, // web console + REST + file server
    pub realm: String,
    // discovery walk caps
    pub walk_max_depth: u32,
    pub walk_max_nodes: u32,
    // data dirs
    pub data_dir: String,
    pub files_dir: String,
    pub uploads_dir: String,
    pub web_dir: String,
    pub nonce_secret: String,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            host_ip: "0.0.0.0".to_string(),
            advertise_ip: "192.168.1.68".to_string(),
            advertise_ip_explicit: false,
            cwmp_port: 7547,
            console_port: 7548,
            realm: "rv6699-acs".to_string(),
            walk_max_depth: 8,
            walk_max_nodes: 4000,
            data_dir: "data".to_string(),
            files_dir: "files".to_string(),
            uploads_dir: "uploads".to_string(),
            // Empty = serve the binary-embedded console (the real default; main.rs
            // overrides from --web-dir/WEB_DIR when an on-disk copy is requested).
            web_dir: String::new(),
            nonce_secret: token_hex(16),
        }
    }
}

impl Config {
    pub fn ensure_dirs(&self) {
        for d in [&self.data_dir, &self.files_dir, &self.uploads_dir] {
            let _ = std::fs::create_dir_all(d);
        }
    }

    /// Build a /files/<name> URL for the given advertise host (already :port-free).
    pub fn file_url(&self, host: &str, name: &str) -> String {
        format!("http://{}:{}/files/{}", host, self.console_port, name)
    }

    /// Build a /upload/<name> URL for the given advertise host.
    pub fn upload_url(&self, host: &str, name: &str) -> String {
        format!("http://{}:{}/upload/{}", host, self.console_port, name)
    }
}
