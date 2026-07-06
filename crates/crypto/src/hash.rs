//! Quantum-resistant hashing primitive.
//!
//! We use SHA3-256 (Keccak). Grover's algorithm only offers a quadratic
//! speedup against preimage search, leaving SHA3-256 at ~128-bit security
//! even against a large quantum adversary — ample for notarization commitments.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha3::{Digest, Sha3_256};
use std::fmt;

/// A 32-byte SHA3-256 digest. Serializes as a lowercase hex string so that
/// notarization proofs are human-readable and JSON-portable.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Hash(pub [u8; 32]);

impl Hash {
    /// Length in bytes.
    pub const LEN: usize = 32;

    /// Compute the SHA3-256 digest of `data`.
    pub fn digest(data: &[u8]) -> Self {
        let mut hasher = Sha3_256::new();
        hasher.update(data);
        let out = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&out);
        Hash(bytes)
    }

    /// The all-zero hash. Used as the `prev_hash` of the genesis block.
    pub const fn zero() -> Self {
        Hash([0u8; 32])
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> Result<Self, crate::CryptoError> {
        let raw = hex::decode(s).map_err(|_| crate::CryptoError::Encoding)?;
        let bytes: [u8; 32] = raw.try_into().map_err(|_| crate::CryptoError::Encoding)?;
        Ok(Hash(bytes))
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash({})", self.to_hex())
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl Serialize for Hash {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Hash {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Hash::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_is_deterministic() {
        assert_eq!(Hash::digest(b"smartledger"), Hash::digest(b"smartledger"));
        assert_ne!(Hash::digest(b"a"), Hash::digest(b"b"));
    }

    #[test]
    fn hex_roundtrip() {
        let h = Hash::digest(b"notarize me");
        let back = Hash::from_hex(&h.to_hex()).unwrap();
        assert_eq!(h, back);
    }

    #[test]
    fn known_answer() {
        // SHA3-256("") known-answer test vector.
        assert_eq!(
            Hash::digest(b"").to_hex(),
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        );
    }
}
