//! Build an anchor backend from a [`NodeConfig`]. Kept out of the binary so the
//! selection logic — including the feature-gated BSV backend — is unit-testable.

use crate::config::NodeConfig;
use slc_anchor::{AnchorBackend, FileAnchor, MockAnchor};
use slc_crypto::{SigningKey, VerifyingKey};

/// Resolve the configured backend name, applying the defaulting rule.
pub fn backend_name(cfg: &NodeConfig) -> &str {
    cfg.anchor_backend.as_deref().unwrap_or({
        if cfg.anchor_file.is_some() {
            "file"
        } else {
            "mock"
        }
    })
}

/// Construct the anchor backend for `cfg`, or `Ok(None)` if anchoring is off.
///
/// `anchor_sk`/`anchor_pk` are the identity that signs BSV anchors (only used by
/// the `notaryhash` backend). Returns `Err` on misconfiguration.
#[cfg_attr(not(feature = "notaryhash"), allow(unused_variables))]
pub fn build_backend(
    cfg: &NodeConfig,
    anchor_sk: SigningKey,
    anchor_pk: VerifyingKey,
) -> Result<Option<Box<dyn AnchorBackend>>, String> {
    if cfg.anchor_interval == 0 {
        return Ok(None);
    }
    let backend: Box<dyn AnchorBackend> = match backend_name(cfg) {
        "mock" => Box::new(MockAnchor::new()),
        "file" => {
            let path = cfg
                .anchor_file
                .clone()
                .ok_or("anchor_file is required for the file backend")?;
            Box::new(FileAnchor::new(path))
        }
        "notaryhash" => {
            #[cfg(feature = "notaryhash")]
            {
                let endpoint = cfg
                    .notaryhash_endpoint
                    .clone()
                    .unwrap_or_else(|| "https://notaryhash.com".to_string());
                let env_name = cfg
                    .notaryhash_api_key_env
                    .clone()
                    .unwrap_or_else(|| "NOTARYHASH_API_KEY".to_string());
                let api_key = std::env::var(&env_name)
                    .map_err(|_| format!("set ${env_name} for the notaryhash backend"))?;
                Box::new(slc_anchor::NotaryHashAnchor::new(
                    endpoint, api_key, anchor_sk, anchor_pk,
                ))
            }
            #[cfg(not(feature = "notaryhash"))]
            {
                return Err(
                    "the notaryhash backend requires building with --features notaryhash".into(),
                );
            }
        }
        other => return Err(format!("unknown anchor_backend '{other}'")),
    };
    Ok(Some(backend))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::GenesisConfig;

    fn base_cfg() -> NodeConfig {
        NodeConfig {
            genesis: GenesisConfig {
                chain_id: "t".into(),
                validators: vec![],
            },
            key_path: "k".into(),
            block_store_path: "b".into(),
            base_timeout_ms: 1000,
            listen: None,
            peers: None,
            anchor_interval: 2,
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

    fn key() -> (SigningKey, VerifyingKey) {
        SigningKey::generate().unwrap()
    }

    #[test]
    fn disabled_when_interval_zero() {
        let mut cfg = base_cfg();
        cfg.anchor_interval = 0;
        let (sk, pk) = key();
        assert!(build_backend(&cfg, sk, pk).unwrap().is_none());
    }

    #[test]
    fn defaults_to_mock_then_file() {
        let mut cfg = base_cfg();
        assert_eq!(backend_name(&cfg), "mock");
        cfg.anchor_file = Some("/tmp/x".into());
        assert_eq!(backend_name(&cfg), "file");
    }

    #[test]
    fn builds_mock_backend() {
        let cfg = base_cfg();
        let (sk, pk) = key();
        let b = build_backend(&cfg, sk, pk).unwrap().unwrap();
        assert_eq!(b.name(), "mock");
    }

    #[test]
    fn unknown_backend_errors() {
        let mut cfg = base_cfg();
        cfg.anchor_backend = Some("dogecoin".into());
        let (sk, pk) = key();
        assert!(build_backend(&cfg, sk, pk).is_err());
    }

    #[cfg(feature = "notaryhash")]
    #[test]
    fn builds_notaryhash_backend_when_key_present() {
        let mut cfg = base_cfg();
        cfg.anchor_backend = Some("notaryhash".into());
        cfg.notaryhash_api_key_env = Some("SLC_TEST_NH_KEY".into());
        std::env::set_var("SLC_TEST_NH_KEY", "dummy-key-not-used-offline");
        let (sk, pk) = key();
        let b = build_backend(&cfg, sk, pk).unwrap().unwrap();
        assert_eq!(b.name(), "notaryhash-bsv");
    }
}
