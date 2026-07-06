//! On-disk keystore for a license issuer (SmartLedger's SLH-DSA keypair).
//! Both halves are stored because SLH-DSA can't re-derive the public key from
//! the secret. Guard this file — it is the authority to mint licenses.

use crate::LicenseIssuer;
use serde::{Deserialize, Serialize};
use slc_crypto::{SlhSigningKey, SlhVerifyingKey};
use std::io;
use std::path::Path;

#[derive(Serialize, Deserialize)]
struct IssuerFile {
    secret_key: String,
    public_key: String,
}

/// Generate a new issuer keypair and write it to `path`.
pub fn generate(path: &Path) -> io::Result<LicenseIssuer> {
    let (sk, pk) = SlhSigningKey::generate().map_err(io::Error::other)?;
    let kf = IssuerFile {
        secret_key: hex::encode(sk.to_bytes()),
        public_key: pk.to_hex(),
    };
    std::fs::write(
        path,
        serde_json::to_string_pretty(&kf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?,
    )?;
    Ok(LicenseIssuer::from_keypair(sk, pk))
}

/// Load an issuer keypair from `path`.
pub fn load(path: &Path) -> io::Result<LicenseIssuer> {
    let kf: IssuerFile = serde_json::from_str(&std::fs::read_to_string(path)?)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let sk_bytes = hex::decode(&kf.secret_key)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let sk = SlhSigningKey::from_bytes(&sk_bytes)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let pk = SlhVerifyingKey::from_hex(&kf.public_key)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    Ok(LicenseIssuer::from_keypair(sk, pk))
}
