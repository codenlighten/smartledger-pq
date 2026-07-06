//! The atomic unit of the chain: a self-verifying notarization entry.
//!
//! An [`Attestation`] is exactly the triple you specified — `{ pubkey, hash,
//! signature }` — where a legally-known actor signs a commitment (document
//! hash) with their own ML-DSA key. Because the actor signs it themselves,
//! every entry is *self-verifying* and *conflict-free*: no two attestations can
//! ever contradict each other, which is what lets consensus stay single-round.

use crate::{merkle, LedgerError};
use serde::{Deserialize, Serialize};
use slc_crypto::{context, Hash, Signature, SigningKey, VerifyingKey, PUBKEY_LEN, SIG_LEN};

/// A notarization entry: an actor's post-quantum signature over a data hash.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attestation {
    /// The actor's ML-DSA public key — their durable on-chain identity.
    pub pubkey: VerifyingKey,
    /// SHA3-256 commitment to the notarized data. The data itself never leaves
    /// the actor's premises, so notarization is privacy-preserving by design.
    pub hash: Hash,
    /// ML-DSA-65 signature by `pubkey` over `hash`.
    pub signature: Signature,
}

impl Attestation {
    /// Build and sign a fresh attestation over `hash`.
    pub fn create(
        signing_key: &SigningKey,
        pubkey: &VerifyingKey,
        hash: Hash,
    ) -> Result<Attestation, LedgerError> {
        let signature = signing_key.sign(hash.as_bytes(), context::ATTESTATION)?;
        Ok(Attestation {
            pubkey: pubkey.clone(),
            hash,
            signature,
        })
    }

    /// Does this actor's signature genuinely cover this hash? Anyone can check
    /// this with no chain access — it depends only on the entry itself.
    pub fn verify(&self) -> bool {
        self.pubkey
            .verify(self.hash.as_bytes(), &self.signature, context::ATTESTATION)
    }

    /// Canonical byte encoding used as Merkle-leaf preimage. Fixed-width fields
    /// mean the encoding is unambiguous and length-prefix-free.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(PUBKEY_LEN + Hash::LEN + SIG_LEN);
        buf.extend_from_slice(&self.pubkey.to_bytes());
        buf.extend_from_slice(self.hash.as_bytes());
        buf.extend_from_slice(self.signature.to_bytes());
        buf
    }

    /// Domain-separated Merkle leaf digest for this attestation.
    pub fn leaf_hash(&self) -> Hash {
        merkle::hash_leaf(&self.encode())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_then_self_verify() {
        let (sk, pk) = SigningKey::generate().unwrap();
        let att = Attestation::create(&sk, &pk, Hash::digest(b"contract.pdf")).unwrap();
        assert!(att.verify());
    }

    #[test]
    fn forged_hash_is_rejected() {
        let (sk, pk) = SigningKey::generate().unwrap();
        let mut att = Attestation::create(&sk, &pk, Hash::digest(b"real")).unwrap();
        att.hash = Hash::digest(b"swapped"); // attacker swaps the notarized hash
        assert!(!att.verify());
    }

    #[test]
    fn substituted_identity_is_rejected() {
        let (sk, pk) = SigningKey::generate().unwrap();
        let (_sk2, pk2) = SigningKey::generate().unwrap();
        let mut att = Attestation::create(&sk, &pk, Hash::digest(b"doc")).unwrap();
        att.pubkey = pk2; // attacker claims someone else notarized it
        assert!(!att.verify());
    }
}
