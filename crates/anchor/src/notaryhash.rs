//! [`NotaryHashAnchor`] — anchor checkpoints to **BSV mainnet** via the
//! notaryhash.com notarize API.
//!
//! notaryhash records *signed hashes* on-chain via `OP_RETURN`. We sign the
//! 32-byte checkpoint root with an ML-DSA-65 key (FIPS 204, empty context) and
//! POST `{ algorithm, hashAlgorithm, payloadHash, publicKey, signature }` to
//! `/v1/notarize`. Because our chain and notaryhash share FIPS 204, the very
//! same post-quantum key that secures SmartLedger-Chain signs its BSV anchor —
//! no translation layer (cross-verified against notaryhash's `@noble` stack).
//!
//! Enable with the `notaryhash` cargo feature.

use crate::backend::{AnchorBackend, AnchorError, Receipt};
use crate::checkpoint::Checkpoint;
use base64::Engine as _;
use slc_crypto::{Hash, SigningKey, VerifyingKey};

/// notaryhash's identifier for ML-DSA-65 (FIPS 204, NIST level 3).
const ALGORITHM: &str = "ML-DSA-65";

/// A live BSV anchor backend backed by notaryhash.com.
pub struct NotaryHashAnchor {
    endpoint: String,
    api_key: String,
    signing_key: SigningKey,
    public_key: VerifyingKey,
    mode: Option<&'static str>,
}

impl NotaryHashAnchor {
    /// `endpoint` is the service base URL (e.g. `https://notaryhash.com`).
    /// `signing_key`/`public_key` are the chain's ML-DSA-65 anchor identity.
    pub fn new(
        endpoint: impl Into<String>,
        api_key: impl Into<String>,
        signing_key: SigningKey,
        public_key: VerifyingKey,
    ) -> NotaryHashAnchor {
        NotaryHashAnchor {
            endpoint: endpoint.into(),
            api_key: api_key.into(),
            signing_key,
            public_key,
            mode: None,
        }
    }

    /// Pin the on-chain mode: `"full"` (whole proof on-chain) or `"hybrid"`
    /// (compact — SHA-256 of the large PQ blobs on-chain). Default: server auto.
    pub fn with_mode(mut self, mode: &'static str) -> NotaryHashAnchor {
        self.mode = Some(mode);
        self
    }

    /// Build the `/v1/notarize` request body for a checkpoint `root`.
    fn notarize_body(&self, root: Hash) -> Result<serde_json::Value, AnchorError> {
        let signature = self
            .signing_key
            .sign(root.as_bytes(), &[]) // empty context == pure ML-DSA
            .map_err(|e| AnchorError::Io(format!("anchor signing failed: {e}")))?;
        let b64 = base64::engine::general_purpose::STANDARD;
        let mut body = serde_json::json!({
            "algorithm": ALGORITHM,
            "hashAlgorithm": "SHA-256",
            "payloadHash": root.to_hex(),                       // hex, always
            "publicKey": b64.encode(self.public_key.to_bytes()), // base64 for ML-DSA
            "signature": b64.encode(signature.to_bytes()),
            "encoding": "base64",
        });
        if let Some(mode) = self.mode {
            body["mode"] = serde_json::Value::String(mode.to_string());
        }
        Ok(body)
    }
}

impl AnchorBackend for NotaryHashAnchor {
    fn name(&self) -> &str {
        "notaryhash-bsv"
    }

    fn anchor(&mut self, checkpoint: &Checkpoint) -> Result<Receipt, AnchorError> {
        let root = checkpoint.root();
        let body = self.notarize_body(root)?;
        let url = format!("{}/v1/notarize", self.endpoint.trim_end_matches('/'));

        let response = ureq::post(&url)
            .set("X-API-Key", &self.api_key)
            .send_json(body)
            .map_err(|e| AnchorError::Io(format!("notarize request failed: {e}")))?;
        let parsed: serde_json::Value = response
            .into_json()
            .map_err(|e| AnchorError::Io(format!("bad notarize response: {e}")))?;

        // A batched anchor may not have a txid yet; fall back to the cert id.
        let cert = &parsed["certificate"];
        let txid = cert["anchor"]["txid"].as_str().unwrap_or_default();
        let reference = if !txid.is_empty() {
            format!("bsv-mainnet:{txid}")
        } else if let Some(id) = parsed["id"].as_str() {
            format!("notaryhash:cert:{id}")
        } else {
            "notaryhash:pending".to_string()
        };
        Ok(Receipt {
            backend: self.name().to_string(),
            reference,
            checkpoint_root: root,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notarize_body_is_well_formed_and_self_verifying() {
        let (sk, pk) = SigningKey::generate().unwrap();
        let backend = NotaryHashAnchor::new("https://notaryhash.com", "test-key", sk, pk.clone());
        let root = Hash::digest(b"checkpoint-root");
        let body = backend.notarize_body(root).unwrap();

        assert_eq!(body["algorithm"], "ML-DSA-65");
        assert_eq!(body["hashAlgorithm"], "SHA-256");
        assert_eq!(body["payloadHash"], root.to_hex());
        assert_eq!(body["encoding"], "base64");

        let b64 = base64::engine::general_purpose::STANDARD;
        let pk_bytes = b64.decode(body["publicKey"].as_str().unwrap()).unwrap();
        let sig_bytes = b64.decode(body["signature"].as_str().unwrap()).unwrap();
        assert_eq!(pk_bytes.len(), slc_crypto::PUBKEY_LEN); // 1952
        assert_eq!(sig_bytes.len(), slc_crypto::SIG_LEN); //  3309

        // The submitted signature is a valid ML-DSA-65 signature over the root
        // under an empty context — exactly what notaryhash's @noble verifier
        // (cross-checked separately) re-derives.
        let sig = slc_crypto::Signature::from_bytes(&sig_bytes).unwrap();
        assert!(pk.verify(root.as_bytes(), &sig, &[]));
    }
}
