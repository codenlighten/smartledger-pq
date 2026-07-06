//! Genesis and node configuration (JSON-serializable).

use serde::{Deserialize, Serialize};
use slc_crypto::VerifyingKey;

/// A validator's public identity and where to reach it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorInfo {
    /// The validator's ML-DSA public key (hex).
    pub pubkey: VerifyingKey,
    /// `host:port` this validator listens on.
    pub addr: String,
}

/// The shared, agreed-upon starting parameters. Every node must load an
/// identical genesis for the chain to be well-defined.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenesisConfig {
    /// Human-readable chain identifier, e.g. `"smartledger-mainnet"`.
    pub chain_id: String,
    /// The ordered roster of legally-known validators.
    pub validators: Vec<ValidatorInfo>,
}

impl GenesisConfig {
    /// The public keys, in roster order.
    pub fn validator_keys(&self) -> Vec<VerifyingKey> {
        self.validators.iter().map(|v| v.pubkey.clone()).collect()
    }

    /// The listen addresses of every validator except `me`.
    pub fn peer_addrs(&self, me: &VerifyingKey) -> Vec<String> {
        self.validators
            .iter()
            .filter(|v| &v.pubkey != me)
            .map(|v| v.addr.clone())
            .collect()
    }
}

/// Per-node runtime configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeConfig {
    pub genesis: GenesisConfig,
    /// Path to this node's keystore file.
    pub key_path: String,
    /// Where committed blocks are written (JSON-lines).
    pub block_store_path: String,
    /// Base consensus timeout in milliseconds (grows linearly with round).
    #[serde(default = "default_timeout_ms")]
    pub base_timeout_ms: u64,
}

fn default_timeout_ms() -> u64 {
    1000
}
