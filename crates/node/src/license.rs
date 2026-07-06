//! License enforcement: verify a SmartLedger-signed license on node startup.
//! Kept as a testable function separate from the binary.

use crate::config::NodeConfig;
use slc_crypto::SlhVerifyingKey;
use slc_license::{Entitlements, SignedLicense};

/// Verify the node's configured license against SmartLedger's issuer key at
/// time `now`, bound to `chain_id`.
///
/// * `Ok(None)` — no license configured (unlicensed / dev mode).
/// * `Ok(Some(entitlements))` — a valid license; the node may run.
/// * `Err(msg)` — a license was configured but is invalid/expired; refuse to run.
pub fn check(cfg: &NodeConfig, chain_id: &str, now: u64) -> Result<Option<Entitlements>, String> {
    let path = match &cfg.license_file {
        Some(p) => p,
        None => return Ok(None),
    };
    let issuer_hex = cfg
        .license_issuer_pubkey
        .as_ref()
        .ok_or("license_file is set but license_issuer_pubkey is missing")?;
    let issuer = SlhVerifyingKey::from_hex(issuer_hex)
        .map_err(|_| "invalid license_issuer_pubkey hex".to_string())?;

    let json = std::fs::read_to_string(path).map_err(|e| format!("read license {path}: {e}"))?;
    let signed = SignedLicense::from_json(&json).map_err(|e| format!("parse license: {e}"))?;

    signed
        .verify(&issuer, now, Some(chain_id))
        .map_err(|e| format!("license invalid: {e}"))?;
    Ok(Some(signed.license.entitlements))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::GenesisConfig;
    use slc_license::{License, LicenseIssuer};

    fn base_cfg() -> NodeConfig {
        NodeConfig {
            genesis: GenesisConfig { chain_id: "acme".into(), validators: vec![] },
            key_path: "k".into(),
            block_store_path: "b".into(),
            base_timeout_ms: 1000,
            listen: None,
            peers: None,
            anchor_interval: 0,
            anchor_backend: None,
            anchor_file: None,
            notaryhash_endpoint: None,
            notaryhash_api_key_env: None,
            anchor_key_path: None,
            rpc_addr: None,
            license_file: None,
            license_issuer_pubkey: None,
        }
    }

    fn license(now: u64) -> License {
        License {
            licensee: "Acme".into(),
            license_id: "L1".into(),
            product: "smartledger-chain".into(),
            tier: "enterprise".into(),
            entitlements: Entitlements {
                max_nodes: Some(5),
                max_notarizations_per_month: None,
                anchoring: true,
                features: vec![],
            },
            chain_id: Some("acme".into()),
            issued_at: now,
            expires_at: now + 1000,
        }
    }

    #[test]
    fn unlicensed_is_allowed() {
        assert!(check(&base_cfg(), "acme", 1000).unwrap().is_none());
    }

    #[test]
    fn valid_license_grants_entitlements_and_expiry_is_enforced() {
        let dir = std::env::temp_dir().join(format!("slc-lic-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("license.json");

        // Issue one license (slow SLH-DSA sign) and reuse it.
        let issuer = LicenseIssuer::generate().unwrap();
        let now = 1_751_000_000u64;
        let signed = issuer.issue(license(now)).unwrap();
        std::fs::write(&path, signed.to_json().unwrap()).unwrap();

        let mut cfg = base_cfg();
        cfg.license_file = Some(path.to_string_lossy().into_owned());
        cfg.license_issuer_pubkey = Some(issuer.public_key().to_hex());

        // Valid now → entitlements returned.
        let ent = check(&cfg, "acme", now + 10).unwrap().unwrap();
        assert_eq!(ent.max_nodes, Some(5));

        // Expired → refuse.
        assert!(check(&cfg, "acme", now + 5000).is_err());

        // Wrong chain → refuse.
        assert!(check(&cfg, "other", now + 10).is_err());

        // Missing issuer pubkey → refuse.
        cfg.license_issuer_pubkey = None;
        assert!(check(&cfg, "acme", now + 10).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
