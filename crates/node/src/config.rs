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
    /// The socket to bind for p2p (e.g. `0.0.0.0:9000`). If unset, the node's
    /// advertised address from the genesis roster is used. Set this explicitly
    /// in containers/cloud, where the bind address differs from the public one.
    #[serde(default)]
    pub listen: Option<String>,
    /// Explicit peer addresses to gossip with. If unset, derived from the
    /// genesis roster (every validator but this one).
    #[serde(default)]
    pub peers: Option<Vec<String>>,
    /// Publish a public-chain checkpoint every N finalized blocks. `0` disables
    /// anchoring.
    #[serde(default)]
    pub anchor_interval: u64,
    /// Which anchor backend to use: `"mock"`, `"file"`, or `"notaryhash"`.
    /// If unset: `"file"` when `anchor_file` is set, else `"mock"`.
    #[serde(default)]
    pub anchor_backend: Option<String>,
    /// If set (and the file backend is used), append anchor records to this file
    /// (a local stand-in for a public chain).
    #[serde(default)]
    pub anchor_file: Option<String>,
    /// notaryhash base URL (defaults to `https://notaryhash.com`).
    #[serde(default)]
    pub notaryhash_endpoint: Option<String>,
    /// Name of the environment variable holding the notaryhash API key
    /// (defaults to `NOTARYHASH_API_KEY`). The key is never stored in config.
    #[serde(default)]
    pub notaryhash_api_key_env: Option<String>,
    /// Optional dedicated anchor keystore. If unset, the node signs anchors with
    /// its own validator key.
    #[serde(default)]
    pub anchor_key_path: Option<String>,
    /// Client-facing RPC listen address (e.g. `0.0.0.0:7000`). Disabled if unset.
    #[serde(default)]
    pub rpc_addr: Option<String>,
    /// Path to a SmartLedger-signed license file. If set, the node verifies it
    /// on startup and refuses to run if it is invalid or expired.
    #[serde(default)]
    pub license_file: Option<String>,
    /// SmartLedger's license issuer public key (SLH-DSA, hex). Required when
    /// `license_file` is set.
    #[serde(default)]
    pub license_issuer_pubkey: Option<String>,
}

fn default_timeout_ms() -> u64 {
    1000
}
