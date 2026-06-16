//! connreq.rs — TR-069 Connection Request client.
//!
//! The ACS makes an HTTP GET to the CPE's ConnectionRequestURL. The CPE answers
//! with a Digest 401 challenge; we retry with the Connection Request creds.
//! Implemented over a raw tokio TcpStream (no reqwest).

use crate::digest;
use crate::util::{md5_hex, token_hex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

struct ParsedUrl {
    host: String,
    port: u16,
    path: String,
}

fn parse_url(url: &str) -> Option<ParsedUrl> {
    let rest = url.strip_prefix("http://")?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse::<u16>().unwrap_or(80)),
        None => (authority.to_string(), 80),
    };
    Some(ParsedUrl {
        host,
        port,
        path: path.to_string(),
    })
}

/// Send a raw HTTP GET, optionally with an Authorization header.
/// Returns (status_code, headers_block). The body is not needed by any caller
/// (we only inspect the status line and WWW-Authenticate), so it is discarded.
async fn http_get(
    u: &ParsedUrl,
    auth: Option<&str>,
    timeout_secs: f64,
) -> Result<(u16, String), String> {
    let addr = format!("{}:{}", u.host, u.port);
    let dur = Duration::from_secs_f64(timeout_secs);

    let connect = TcpStream::connect(&addr);
    let mut stream = match timeout(dur, connect).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(format!("unreachable: {}", e)),
        Err(_) => return Err("unreachable: connection timed out".to_string()),
    };

    let mut req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: rv6699-acs\r\nAccept: */*\r\nConnection: close\r\n",
        u.path,
        if u.port == 80 {
            u.host.clone()
        } else {
            format!("{}:{}", u.host, u.port)
        }
    );
    if let Some(a) = auth {
        req.push_str(&format!("Authorization: {}\r\n", a));
    }
    req.push_str("\r\n");

    if let Err(e) = timeout(dur, stream.write_all(req.as_bytes())).await {
        return Err(format!("error: write timed out ({e})"));
    }
    let _ = stream.flush().await;

    // read the whole response (Connection: close)
    let mut buf = Vec::new();
    loop {
        let mut tmp = [0u8; 4096];
        match timeout(dur, stream.read(&mut tmp)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => buf.extend_from_slice(&tmp[..n]),
            Ok(Err(e)) => return Err(format!("error: {}", e)),
            Err(_) => return Err("error: read timed out".to_string()),
        }
        // stop once we at least have headers and seem complete enough for our needs
        if buf.len() > 65536 {
            break;
        }
    }

    let head_str = match buf.windows(4).position(|w| w == b"\r\n\r\n") {
        Some(i) => String::from_utf8_lossy(&buf[..i + 4]).into_owned(),
        None => String::from_utf8_lossy(&buf).into_owned(),
    };
    let status = head_str
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| "error: malformed response".to_string())?;
    Ok((status, head_str))
}

fn header_value(head: &str, name: &str) -> Option<String> {
    let lname = name.to_lowercase();
    for line in head.lines() {
        if let Some((k, v)) = line.split_once(':')
            && k.trim().to_lowercase() == lname
        {
            return Some(v.trim().to_string());
        }
    }
    None
}

/// Build a Digest Authorization header in response to a WWW-Authenticate challenge.
fn build_digest_auth(
    challenge: &str,
    username: &str,
    password: &str,
    method: &str,
    uri: &str,
) -> Option<String> {
    let a = digest::parse_auth_header(challenge);
    if a.scheme() != "digest" {
        return None;
    }
    let realm = a.get("realm");
    let nonce = a.get("nonce");
    let qop_raw = a.get("qop");
    let opaque = a.get("opaque");
    let algorithm = a.get("algorithm");

    let ha1 = md5_hex(&format!("{username}:{realm}:{password}"));
    let ha2 = md5_hex(&format!("{method}:{uri}"));

    // qop may be a comma list; pick "auth" if present
    let use_qop = qop_raw.split(',').map(|s| s.trim()).any(|s| s == "auth");

    let mut header = format!(
        "Digest username=\"{username}\", realm=\"{realm}\", nonce=\"{nonce}\", uri=\"{uri}\""
    );
    let response;
    if use_qop {
        let nc = "00000001";
        let cnonce = token_hex(8);
        response = md5_hex(&format!("{ha1}:{nonce}:{nc}:{cnonce}:auth:{ha2}"));
        header.push_str(&format!(
            ", qop=auth, nc={nc}, cnonce=\"{cnonce}\", response=\"{response}\""
        ));
    } else {
        response = md5_hex(&format!("{ha1}:{nonce}:{ha2}"));
        header.push_str(&format!(", response=\"{response}\""));
    }
    // We only compute plain-MD5 HA1, so advertise MD5 — never echo back an
    // algorithm we don't implement (e.g. MD5-sess), which the CPE would reject.
    if !algorithm.is_empty() {
        header.push_str(", algorithm=MD5");
    }
    if !opaque.is_empty() {
        header.push_str(&format!(", opaque=\"{opaque}\""));
    }
    Some(header)
}

fn build_basic_auth(username: &str, password: &str) -> String {
    use base64::Engine;
    let enc = base64::engine::general_purpose::STANDARD.encode(format!("{username}:{password}"));
    format!("Basic {enc}")
}

/// Send a Connection Request. Returns (ok, detail).
pub async fn trigger(url: &str, username: &str, password: &str) -> (bool, String) {
    if url.is_empty() {
        return (
            false,
            "no ConnectionRequestURL known (wait for first Inform)".to_string(),
        );
    }
    let u = match parse_url(url) {
        Some(u) => u,
        None => return (false, format!("error: cannot parse URL {url}")),
    };
    let timeout_secs = 10.0;

    // first request (no auth)
    let (status, head) = match http_get(&u, None, timeout_secs).await {
        Ok(r) => r,
        Err(e) => return (false, e),
    };

    if status == 200 || status == 204 {
        return (true, format!("HTTP {status} — CPE will connect shortly"));
    }

    if status == 401 {
        // build an auth header from the challenge and retry
        let challenge = header_value(&head, "WWW-Authenticate").unwrap_or_default();
        let auth = if challenge.to_lowercase().starts_with("digest") {
            build_digest_auth(&challenge, username, password, "GET", &u.path)
                .unwrap_or_else(|| build_basic_auth(username, password))
        } else {
            build_basic_auth(username, password)
        };
        let (status2, _head2) = match http_get(&u, Some(&auth), timeout_secs).await {
            Ok(r) => r,
            Err(e) => return (false, e),
        };
        if status2 == 200 || status2 == 204 {
            return (true, format!("HTTP {status2} — CPE will connect shortly"));
        }
        return (
            false,
            format!("HTTP {status2} (check Connection Request username/password)"),
        );
    }

    (
        false,
        format!("HTTP {status} (check Connection Request username/password)"),
    )
}
