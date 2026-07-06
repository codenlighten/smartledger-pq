//! Post-quantum identity & signatures via ML-DSA-65 (FIPS 204, "Dilithium").
//!
//! ML-DSA-65 targets NIST security category 3 — a balanced default: fast
//! verification, ~1952-byte public keys and ~3309-byte signatures. Every node
//! operator and every notarizing client is a *legally known actor* whose public
//! key IS their on-chain identity.

use crate::{CryptoError, Hash};
use fips204::ml_dsa_65;
use fips204::traits::{SerDes, Signer, Verifier};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

/// Length of a serialized ML-DSA-65 public key.
pub const PUBKEY_LEN: usize = ml_dsa_65::PK_LEN;
/// Length of a serialized ML-DSA-65 secret key.
pub const SECKEY_LEN: usize = ml_dsa_65::SK_LEN;
/// Length of an ML-DSA-65 signature.
pub const SIG_LEN: usize = ml_dsa_65::SIG_LEN;

/// A secret key. Never leaves the operator's machine; not serialized by default.
pub struct SigningKey {
    inner: ml_dsa_65::PrivateKey,
}

impl SigningKey {
    /// Generate a fresh keypair using the operating system CSPRNG.
    pub fn generate() -> Result<(SigningKey, VerifyingKey), CryptoError> {
        let (pk, sk) = ml_dsa_65::try_keygen().map_err(|_| CryptoError::KeyGen)?;
        Ok((SigningKey { inner: sk }, VerifyingKey { inner: pk }))
    }

    /// Restore a signing key from its serialized bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<SigningKey, CryptoError> {
        let arr: [u8; SECKEY_LEN] = bytes.try_into().map_err(|_| CryptoError::Encoding)?;
        let inner = ml_dsa_65::PrivateKey::try_from_bytes(arr).map_err(|_| CryptoError::Encoding)?;
        Ok(SigningKey { inner })
    }

    /// Serialize the secret key. Handle with care — persist encrypted at rest.
    pub fn to_bytes(&self) -> [u8; SECKEY_LEN] {
        self.inner.clone().into_bytes()
    }

    /// Sign `message` under a domain-separation `context` string.
    pub fn sign(&self, message: &[u8], context: &[u8]) -> Result<Signature, CryptoError> {
        let raw = self
            .inner
            .try_sign(message, context)
            .map_err(|_| CryptoError::Sign)?;
        Ok(Signature(raw))
    }
}

/// A public key — the durable, on-chain identity of an actor.
#[derive(Clone)]
pub struct VerifyingKey {
    inner: ml_dsa_65::PublicKey,
}

impl VerifyingKey {
    /// Verify that `signature` over `message` was produced by this key under `context`.
    pub fn verify(&self, message: &[u8], signature: &Signature, context: &[u8]) -> bool {
        self.inner.verify(message, &signature.0, context)
    }

    pub fn to_bytes(&self) -> [u8; PUBKEY_LEN] {
        self.inner.clone().into_bytes()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<VerifyingKey, CryptoError> {
        let arr: [u8; PUBKEY_LEN] = bytes.try_into().map_err(|_| CryptoError::Encoding)?;
        let inner = ml_dsa_65::PublicKey::try_from_bytes(arr).map_err(|_| CryptoError::Encoding)?;
        Ok(VerifyingKey { inner })
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    pub fn from_hex(s: &str) -> Result<VerifyingKey, CryptoError> {
        let raw = hex::decode(s).map_err(|_| CryptoError::Encoding)?;
        VerifyingKey::from_bytes(&raw)
    }

    /// A compact, stable identifier for this actor: SHA3-256 of the public key.
    /// Convenient for logs, allow-lists and human reference without shipping 2 KB.
    pub fn id(&self) -> Hash {
        Hash::digest(&self.to_bytes())
    }
}

impl PartialEq for VerifyingKey {
    fn eq(&self, other: &Self) -> bool {
        self.to_bytes() == other.to_bytes()
    }
}
impl Eq for VerifyingKey {}

impl fmt::Debug for VerifyingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VerifyingKey({})", self.id())
    }
}

impl Serialize for VerifyingKey {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}
impl<'de> Deserialize<'de> for VerifyingKey {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        VerifyingKey::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

/// An ML-DSA-65 signature. Serializes as hex so it can travel inside a proof.
#[derive(Clone)]
pub struct Signature(pub(crate) [u8; SIG_LEN]);

impl Signature {
    pub fn to_bytes(&self) -> &[u8; SIG_LEN] {
        &self.0
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Signature, CryptoError> {
        let arr: [u8; SIG_LEN] = bytes.try_into().map_err(|_| CryptoError::Encoding)?;
        Ok(Signature(arr))
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> Result<Signature, CryptoError> {
        let raw = hex::decode(s).map_err(|_| CryptoError::Encoding)?;
        Signature::from_bytes(&raw)
    }
}

impl PartialEq for Signature {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}
impl Eq for Signature {}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signature({}…)", &self.to_hex()[..16])
    }
}

impl Serialize for Signature {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}
impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Signature::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CTX: &[u8] = b"slc-test";

    #[test]
    fn sign_and_verify_roundtrip() {
        let (sk, pk) = SigningKey::generate().unwrap();
        let msg = b"the quantum fox jumps";
        let sig = sk.sign(msg, CTX).unwrap();
        assert!(pk.verify(msg, &sig, CTX));
    }

    #[test]
    fn tampered_message_fails() {
        let (sk, pk) = SigningKey::generate().unwrap();
        let sig = sk.sign(b"original", CTX).unwrap();
        assert!(!pk.verify(b"tampered", &sig, CTX));
    }

    #[test]
    fn wrong_context_fails() {
        let (sk, pk) = SigningKey::generate().unwrap();
        let sig = sk.sign(b"msg", b"ctx-a").unwrap();
        assert!(!pk.verify(b"msg", &sig, b"ctx-b"));
    }

    #[test]
    fn wrong_key_fails() {
        let (sk, _pk) = SigningKey::generate().unwrap();
        let (_sk2, pk2) = SigningKey::generate().unwrap();
        let sig = sk.sign(b"msg", CTX).unwrap();
        assert!(!pk2.verify(b"msg", &sig, CTX));
    }

    #[test]
    fn pubkey_hex_roundtrip() {
        let (_sk, pk) = SigningKey::generate().unwrap();
        let back = VerifyingKey::from_hex(&pk.to_hex()).unwrap();
        assert_eq!(pk, back);
    }

    #[test]
    fn signature_hex_roundtrip() {
        let (sk, pk) = SigningKey::generate().unwrap();
        let sig = sk.sign(b"msg", CTX).unwrap();
        let back = Signature::from_hex(&sig.to_hex()).unwrap();
        assert!(pk.verify(b"msg", &back, CTX));
    }

    #[test]
    fn signing_key_bytes_roundtrip() {
        let (sk, pk) = SigningKey::generate().unwrap();
        let restored = SigningKey::from_bytes(&sk.to_bytes()).unwrap();
        let sig = restored.sign(b"msg", CTX).unwrap();
        assert!(pk.verify(b"msg", &sig, CTX));
    }
}
