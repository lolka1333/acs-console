//! digest.rs — HTTP Digest auth, both directions.
//!
//! Server side: the ACS challenges the CPE on the CWMP session.
//! RFC 2617 Digest, qop="auth", algorithm=MD5. Basic also accepted.

use base64::Engine;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::util::{md5_hex, token_hex};

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

/// Parsed Authorization header. The `"_scheme"` map key holds
/// "basic"/"digest"/other; credentials and digest fields are sibling keys.
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

/// Recompute and constant-time-compare a nonce's signature: detects a forged or
/// tampered nonce (minted without `secret`) before we even check its age.
fn verify_nonce(nonce: &str, secret: &str) -> bool {
    let decoded = match base64::engine::general_purpose::STANDARD.decode(nonce) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let decoded = String::from_utf8_lossy(&decoded);
    let mut parts = decoded.splitn(3, ':');
    match (parts.next(), parts.next(), parts.next()) {
        (Some(ts), Some(rnd), Some(sig)) => ct_eq(&md5_hex(&format!("{ts}:{rnd}:{secret}")), sig),
        _ => false,
    }
}

/// Validate a CPE Authorization header against the configured creds.
pub fn verify(
    method: &str,
    auth_header: &str,
    username: &str,
    password: &str,
    realm: &str,
    nonce_secret: &str,
    max_age: f64,
) -> bool {
    let a = parse_auth_header(auth_header);
    if a.is_empty() {
        return false;
    }
    if a.scheme() == "basic" {
        return a.get("username") == username && ct_eq(a.get("_basic_password"), password);
    }
    if a.scheme() != "digest" {
        return false;
    }
    if a.get("username") != username {
        return false;
    }
    let nonce = a.get("nonce");
    // Reject nonces we did not mint, then stale ones.
    if !verify_nonce(nonce, nonce_secret) || nonce_age(nonce) > max_age {
        return false;
    }
    let uri = a.get("uri");
    // HA1 must bind to the realm WE issued in the challenge, not a client-echoed
    // one. A conformant CPE echoes the same value, so this never breaks real auth.
    let ha1 = md5_hex(&format!("{username}:{realm}:{password}"));
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

#[cfg(test)]
mod tests {
    use super::*;

    fn b64(s: &str) -> String {
        base64::engine::general_purpose::STANDARD.encode(s)
    }

    // Build the Authorization header a CPE would send for qop=auth, given the
    // realm it used for HA1 (the server should bind HA1 to ITS realm, not this).
    fn client_digest(
        method: &str,
        uri: &str,
        user: &str,
        pass: &str,
        realm: &str,
        nonce: &str,
    ) -> String {
        let ha1 = md5_hex(&format!("{user}:{realm}:{pass}"));
        let ha2 = md5_hex(&format!("{method}:{uri}"));
        let (nc, cnonce) = ("00000001", "0a4f113b");
        let resp = md5_hex(&format!("{ha1}:{nonce}:{nc}:{cnonce}:auth:{ha2}"));
        format!(
            "Digest username=\"{user}\", realm=\"{realm}\", nonce=\"{nonce}\", uri=\"{uri}\", \
             qop=auth, nc={nc}, cnonce=\"{cnonce}\", response=\"{resp}\""
        )
    }

    #[test]
    fn digest_round_trip_and_tampering() {
        let (realm, secret, user, pass, uri) =
            ("rv6699-acs", "f00dcafe", "ag", "TheRealMgtsPass!", "/cwmp");

        // The ACS issues the challenge; pull the server-minted nonce back out.
        let nonce = parse_auth_header(&challenge_header(realm, secret))
            .get("nonce")
            .to_string();

        // 1) honest CPE response with the correct creds + server realm -> accept.
        let ok = client_digest("POST", uri, user, pass, realm, &nonce);
        assert!(verify("POST", &ok, user, pass, realm, secret, 300.0));

        // 2) wrong password -> reject.
        assert!(!verify("POST", &ok, user, "nope", realm, secret, 300.0));

        // 3) HA1 computed with a DIFFERENT realm -> reject (server binds its own).
        let wrong_realm = client_digest("POST", uri, user, pass, "evil-realm", &nonce);
        assert!(!verify(
            "POST",
            &wrong_realm,
            user,
            pass,
            realm,
            secret,
            300.0
        ));

        // 4) forged nonce: fresh timestamp (age ok) but a signature not minted
        //    with `secret` -> verify_nonce rejects even though the response is
        //    internally consistent for that nonce.
        let forged = b64(&format!("{}:aa:badsig", now_unix()));
        let forged_auth = client_digest("POST", uri, user, pass, realm, &forged);
        assert!(!verify(
            "POST",
            &forged_auth,
            user,
            pass,
            realm,
            secret,
            300.0
        ));

        // 5) stale (but correctly-signed) nonce -> reject on age.
        assert!(!verify("POST", &ok, user, pass, realm, secret, -1.0));
    }

    #[test]
    fn basic_auth_constant_time_compare() {
        let (realm, secret, user, pass) = ("rv6699-acs", "f00dcafe", "ag", "TheRealMgtsPass!");
        let good = format!("Basic {}", b64(&format!("{user}:{pass}")));
        assert!(verify("POST", &good, user, pass, realm, secret, 300.0));
        let bad = format!("Basic {}", b64(&format!("{user}:wrong")));
        assert!(!verify("POST", &bad, user, pass, realm, secret, 300.0));
    }
}
