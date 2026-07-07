//! Hash-based post-quantum signatures via SLH-DSA-SHA2-128s (FIPS 205,
//! "SPHINCS+").
//!
//! SLH-DSA's security rests *only* on the strength of its hash function — no
//! lattice or number-theoretic assumptions — which makes it the most
//! conservative choice for signatures that must remain valid for a very long
//! time. We use it for software **licenses**: signed rarely, verified
//! occasionally, and expected to hold up for years. Signatures are large
//! (~7.8 KB) and slow, which is fine for that use.

use crate::CryptoError;
use fips205::slh_dsa_sha2_128s;
use fips205::traits::{SerDes, Signer, Verifier};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

pub const SLH_PUBKEY_LEN: usize = slh_dsa_sha2_128s::PK_LEN;
pub const SLH_SECKEY_LEN: usize = slh_dsa_sha2_128s::SK_LEN;
pub const SLH_SIG_LEN: usize = slh_dsa_sha2_128s::SIG_LEN;

/// An SLH-DSA secret key (e.g. SmartLedger's license-issuing key).
pub struct SlhSigningKey {
    inner: slh_dsa_sha2_128s::PrivateKey,
}

impl SlhSigningKey {
    pub fn generate() -> Result<(SlhSigningKey, SlhVerifyingKey), CryptoError> {
        let (pk, sk) = slh_dsa_sha2_128s::try_keygen().map_err(|_| CryptoError::KeyGen)?;
        Ok((SlhSigningKey { inner: sk }, SlhVerifyingKey { inner: pk }))
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<SlhSigningKey, CryptoError> {
        let arr: [u8; SLH_SECKEY_LEN] = bytes.try_into().map_err(|_| CryptoError::Encoding)?;
        let inner =
            slh_dsa_sha2_128s::PrivateKey::try_from_bytes(&arr).map_err(|_| CryptoError::Encoding)?;
        Ok(SlhSigningKey { inner })
    }

    pub fn to_bytes(&self) -> [u8; SLH_SECKEY_LEN] {
        self.inner.clone().into_bytes()
    }

    /// Sign `message` under a domain-separation `context` (hedged / randomized).
    pub fn sign(&self, message: &[u8], context: &[u8]) -> Result<SlhSignature, CryptoError> {
        let raw = self
            .inner
            .try_sign(message, context, true)
            .map_err(|_| CryptoError::Sign)?;
        Ok(SlhSignature(raw))
    }
}

/// An SLH-DSA public key — the durable identity of a license issuer.
#[derive(Clone)]
pub struct SlhVerifyingKey {
    inner: slh_dsa_sha2_128s::PublicKey,
}

impl SlhVerifyingKey {
    pub fn verify(&self, message: &[u8], signature: &SlhSignature, context: &[u8]) -> bool {
        self.inner.verify(message, &signature.0, context)
    }

    pub fn to_bytes(&self) -> [u8; SLH_PUBKEY_LEN] {
        self.inner.clone().into_bytes()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<SlhVerifyingKey, CryptoError> {
        let arr: [u8; SLH_PUBKEY_LEN] = bytes.try_into().map_err(|_| CryptoError::Encoding)?;
        let inner =
            slh_dsa_sha2_128s::PublicKey::try_from_bytes(&arr).map_err(|_| CryptoError::Encoding)?;
        Ok(SlhVerifyingKey { inner })
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    pub fn from_hex(s: &str) -> Result<SlhVerifyingKey, CryptoError> {
        let raw = hex::decode(s).map_err(|_| CryptoError::Encoding)?;
        SlhVerifyingKey::from_bytes(&raw)
    }
}

impl PartialEq for SlhVerifyingKey {
    fn eq(&self, other: &Self) -> bool {
        self.to_bytes() == other.to_bytes()
    }
}
impl Eq for SlhVerifyingKey {}

impl fmt::Debug for SlhVerifyingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SlhVerifyingKey({})", &self.to_hex()[..16])
    }
}

impl Serialize for SlhVerifyingKey {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}
impl<'de> Deserialize<'de> for SlhVerifyingKey {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        SlhVerifyingKey::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

/// An SLH-DSA signature. Serializes as hex.
#[derive(Clone)]
pub struct SlhSignature([u8; SLH_SIG_LEN]);

impl SlhSignature {
    pub fn to_bytes(&self) -> &[u8; SLH_SIG_LEN] {
        &self.0
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<SlhSignature, CryptoError> {
        let arr: [u8; SLH_SIG_LEN] = bytes.try_into().map_err(|_| CryptoError::Encoding)?;
        Ok(SlhSignature(arr))
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> Result<SlhSignature, CryptoError> {
        let raw = hex::decode(s).map_err(|_| CryptoError::Encoding)?;
        SlhSignature::from_bytes(&raw)
    }
}

impl PartialEq for SlhSignature {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}
impl Eq for SlhSignature {}

impl fmt::Debug for SlhSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SlhSignature({}…)", &self.to_hex()[..16])
    }
}

impl Serialize for SlhSignature {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}
impl<'de> Deserialize<'de> for SlhSignature {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        SlhSignature::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CTX: &[u8] = b"slc-license-test";

    /// SLH-DSA signing is CPU-heavy (~seconds). Serialize these tests across the
    /// whole workspace (via an OS-held port) so they peg at most one core and
    /// don't starve the I/O-timed multi-node TCP integration tests running in
    /// parallel. The OS releases the port if a test process dies (no stale lock).
    fn slh_serial() -> std::net::TcpListener {
        loop {
            if let Ok(l) = std::net::TcpListener::bind("127.0.0.1:59717") {
                return l;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let _serial = slh_serial();
        let (sk, pk) = SlhSigningKey::generate().unwrap();
        let sig = sk.sign(b"license bytes", CTX).unwrap();
        assert!(pk.verify(b"license bytes", &sig, CTX));
    }

    #[test]
    fn tampered_message_or_context_fails() {
        let _serial = slh_serial();
        let (sk, pk) = SlhSigningKey::generate().unwrap();
        let sig = sk.sign(b"original", CTX).unwrap();
        assert!(!pk.verify(b"tampered", &sig, CTX));
        assert!(!pk.verify(b"original", &sig, b"other-ctx"));
    }

    #[test]
    fn wrong_key_fails() {
        let _serial = slh_serial();
        let (sk, _pk) = SlhSigningKey::generate().unwrap();
        let (_sk2, pk2) = SlhSigningKey::generate().unwrap();
        let sig = sk.sign(b"m", CTX).unwrap();
        assert!(!pk2.verify(b"m", &sig, CTX));
    }

    #[test]
    fn hex_roundtrips() {
        let _serial = slh_serial();
        let (sk, pk) = SlhSigningKey::generate().unwrap();
        let sig = sk.sign(b"m", CTX).unwrap();
        assert_eq!(SLH_SIG_LEN, 7856);
        let pk2 = SlhVerifyingKey::from_hex(&pk.to_hex()).unwrap();
        let sig2 = SlhSignature::from_hex(&sig.to_hex()).unwrap();
        assert!(pk2.verify(b"m", &sig2, CTX));
    }
}
