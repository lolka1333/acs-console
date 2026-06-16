//! util.rs — tiny shared helpers used across the ACS.

use md5::{Digest, Md5};
use rand::RngExt;

/// Lowercase hex MD5 digest of a string.
pub fn md5_hex(s: &str) -> String {
    let mut h = Md5::new();
    h.update(s.as_bytes());
    hex::encode(h.finalize())
}

/// `nbytes` random bytes rendered as lowercase hex (2·nbytes chars).
pub fn token_hex(nbytes: usize) -> String {
    let mut rng = rand::rng();
    (0..nbytes)
        .map(|_| format!("{:02x}", rng.random::<u8>()))
        .collect()
}
