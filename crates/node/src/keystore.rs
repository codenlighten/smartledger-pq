//! On-disk keystore. ML-DSA private keys can't re-derive their public half via
//! the `fips204` API, so we persist both. The file is JSON with hex fields.
//!
//! NOTE: this stores the secret key in plaintext. Production deployments must
//! encrypt it at rest (e.g. age/GPG) and lock down file permissions; `.gitignore`
//! already excludes `*.key` / `keystore/`.

use serde::{Deserialize, Serialize};
use slc_crypto::{SigningKey, VerifyingKey};
use std::io;
use std::path::Path;

#[derive(Serialize, Deserialize)]
struct KeyFile {
    secret_key: String,
    public_key: String,
}

/// Persist a keypair to `path`.
pub fn save(path: &Path, sk: &SigningKey, pk: &VerifyingKey) -> io::Result<()> {
    let kf = KeyFile {
        secret_key: hex::encode(sk.to_bytes()),
        public_key: pk.to_hex(),
    };
    let json = serde_json::to_string_pretty(&kf)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    std::fs::write(path, json)
}

/// Load a keypair from `path`.
pub fn load(path: &Path) -> io::Result<(SigningKey, VerifyingKey)> {
    let json = std::fs::read_to_string(path)?;
    let kf: KeyFile = serde_json::from_str(&json)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let sk_bytes = hex::decode(&kf.secret_key)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let sk = SigningKey::from_bytes(&sk_bytes)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let pk = VerifyingKey::from_hex(&kf.public_key)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    Ok((sk, pk))
}

/// Generate a new keypair and write it to `path`.
pub fn generate(path: &Path) -> io::Result<(SigningKey, VerifyingKey)> {
    let (sk, pk) = SigningKey::generate().map_err(io::Error::other)?;
    save(path, &sk, &pk)?;
    Ok((sk, pk))
}
