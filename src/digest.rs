//! digest.rs — HTTP Digest auth, both directions (port of digest.py).
//!
//! Server side: the ACS challenges the CPE on the CWMP session.
//! RFC 2617 Digest, qop="auth", algorithm=MD5. Basic also accepted.

use base64::Engine;
use md5::{Digest, Md5};
use rand::RngExt;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

fn md5_hex(s: &str) -> String {
    let mut h = Md5::new();
    h.update(s.as_bytes());
    hex::encode(h.finalize())
}

fn token_hex(nbytes: usize) -> String {
    let mut rng = rand::rng();
    (0..nbytes)
        .map(|_| format!("{:02x}", rng.random::<u8>()))
        .collect()
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn make_nonce(secret: &str) -> String {
    let ts = now_unix().to_string();
    let rnd = token_hex(8);
    let sig = md5_hex(&format!("{ts}:{rnd}:{secret}"));
    base64::engine::general_purpose::STANDARD.encode(format!("{ts}:{rnd}:{sig}"))
}

pub fn nonce_age(nonce: &str) -> f64 {
    match base64::engine::general_purpose::STANDARD.decode(nonce) {
        Ok(bytes) => {
            let decoded = String::from_utf8_lossy(&bytes);
            let ts_str = decoded.split(':').next().unwrap_or("");
            match ts_str.parse::<u64>() {
                Ok(ts) => (now_unix() as f64) - (ts as f64),
                Err(_) => 1e9,
            }
        }
        Err(_) => 1e9,
    }
}

/// Parsed Authorization header. `_scheme` holds "basic"/"digest"/other.
#[derive(Debug, Clone, Default)]
pub struct AuthHeader {
    pub map: HashMap<String, String>,
}

impl AuthHeader {
    pub fn get(&self, k: &str) -> &str {
        self.map.get(k).map(|s| s.as_str()).unwrap_or("")
    }
    pub fn scheme(&self) -> &str {
        self.get("_scheme")
    }
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

/// Parse an Authorization: Digest ... header into a map.
pub fn parse_auth_header(header: &str) -> AuthHeader {
    let mut out = AuthHeader::default();
    if header.is_empty() {
        return out;
    }
    let (scheme, rest) = match header.split_once(' ') {
        Some((s, r)) => (s, r),
        None => (header, ""),
    };
    let scheme_l = scheme.to_lowercase();
    out.map.insert("_scheme".to_string(), scheme_l.clone());
    if scheme_l == "basic" {
        if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(rest.trim()) {
            // latin-1 decode = each byte to char
            let decoded: String = bytes.iter().map(|&b| b as char).collect();
            let (user, pw) = match decoded.split_once(':') {
                Some((u, p)) => (u.to_string(), p.to_string()),
                None => (decoded.clone(), String::new()),
            };
            out.map.insert("username".to_string(), user);
            out.map.insert("_basic_password".to_string(), pw);
        }
        return out;
    }
    // Digest: comma-separated key=value (value optionally quoted)
    for part in split_commas(rest) {
        if !part.contains('=') {
            continue;
        }
        let trimmed = part.trim();
        if let Some((k, v)) = trimmed.split_once('=') {
            let k = k.trim().to_string();
            let v = v.trim().trim_matches('"').to_string();
            out.map.insert(k, v);
        }
    }
    out
}

/// Split on commas that are not inside quotes.
fn split_commas(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut buf = String::new();
    let mut inq = false;
    for ch in s.chars() {
        if ch == '"' {
            inq = !inq;
            buf.push(ch);
        } else if ch == ',' && !inq {
            out.push(buf.clone());
            buf.clear();
        } else {
            buf.push(ch);
        }
    }
    if !buf.is_empty() {
        out.push(buf);
    }
    out
}

pub fn challenge_header(realm: &str, secret: &str) -> String {
    let nonce = make_nonce(secret);
    let opaque = token_hex(8);
    format!(
        "Digest realm=\"{realm}\", qop=\"auth\", nonce=\"{nonce}\", \
opaque=\"{opaque}\", algorithm=MD5"
    )
}

/// Constant-time string comparison.
fn ct_eq(a: &str, b: &str) -> bool {
    let a = a.as_bytes();
    let b = b.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Validate a CPE Authorization header against the configured creds.
pub fn verify(
    method: &str,
    auth_header: &str,
    username: &str,
    password: &str,
    realm: &str,
    max_age: f64,
) -> bool {
    let a = parse_auth_header(auth_header);
    if a.is_empty() {
        return false;
    }
    if a.scheme() == "basic" {
        return a.get("username") == username && a.get("_basic_password") == password;
    }
    if a.scheme() != "digest" {
        return false;
    }
    if a.get("username") != username {
        return false;
    }
    let nonce = a.get("nonce");
    if nonce_age(nonce) > max_age {
        return false;
    }
    let uri = a.get("uri");
    let a_realm = if a.get("realm").is_empty() {
        realm
    } else {
        a.get("realm")
    };
    let ha1 = md5_hex(&format!("{username}:{a_realm}:{password}"));
    let ha2 = md5_hex(&format!("{method}:{uri}"));
    let qop = a.get("qop");
    let expect = if qop == "auth" {
        let nc = a.get("nc");
        let cnonce = a.get("cnonce");
        md5_hex(&format!("{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}"))
    } else {
        md5_hex(&format!("{ha1}:{nonce}:{ha2}"))
    };
    ct_eq(&expect, a.get("response"))
}
