//! `slc-license` — post-quantum software licenses for SmartLedger-Chain.
//!
//! A license is a small JSON document signed by SmartLedger's **SLH-DSA**
//! (FIPS 205, hash-based) issuing key. A node — or the `slc` CLI — verifies it
//! **offline** against SmartLedger's public key: no license server, no
//! phone-home, which suits on-prem and regulated deployments. Because the
//! signature is post-quantum and hash-based, the license itself is quantum-safe
//! and holds up for the long term.
//!
//! Verification checks four things: the issuer is the trusted SmartLedger key,
//! the signature covers the license, the license has not expired, and (if the
//! license is bound to a chain) it matches.

pub mod keystore;

use serde::{Deserialize, Serialize};
use slc_crypto::{context, SlhSignature, SlhSigningKey, SlhVerifyingKey};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum LicenseError {
    #[error("license was not issued by the trusted SmartLedger key")]
    WrongIssuer,
    #[error("license signature is invalid")]
    BadSignature,
    #[error("license expired at {expires_at}, now {now}")]
    Expired { expires_at: u64, now: u64 },
    #[error("license is not valid until {issued_at}, now {now}")]
    NotYetValid { issued_at: u64, now: u64 },
    #[error("license is bound to chain '{expected}', not '{actual}'")]
    WrongChain { expected: String, actual: String },
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("crypto error: {0}")]
    Crypto(#[from] slc_crypto::CryptoError),
}

/// What a license grants.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entitlements {
    /// Max validator nodes the licensee may operate (`None` = unlimited).
    #[serde(default)]
    pub max_nodes: Option<u32>,
    /// Included notarizations per month (`None` = unmetered).
    #[serde(default)]
    pub max_notarizations_per_month: Option<u64>,
    /// Whether BSV anchoring is licensed.
    #[serde(default)]
    pub anchoring: bool,
    /// Named premium features (e.g. `"governance"`, `"spv"`, `"support"`).
    #[serde(default)]
    pub features: Vec<String>,
}

/// The license body (everything that is signed).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct License {
    pub licensee: String,
    pub license_id: String,
    #[serde(default = "default_product")]
    pub product: String,
    pub tier: String,
    pub entitlements: Entitlements,
    /// If set, the license is valid only for this chain id.
    #[serde(default)]
    pub chain_id: Option<String>,
    /// Unix seconds.
    pub issued_at: u64,
    pub expires_at: u64,
}

fn default_product() -> String {
    "smartledger-chain".to_string()
}

impl License {
    /// Canonical bytes that are signed — deterministic JSON of the body.
    pub fn signing_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("license serializes")
    }
}

/// A license plus its issuer key and signature.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedLicense {
    pub license: License,
    pub issuer: SlhVerifyingKey,
    pub signature: SlhSignature,
}

impl SignedLicense {
    /// Verify the license offline against the `trusted` SmartLedger issuer key
    /// at time `now` (unix seconds), optionally requiring a matching `chain_id`.
    pub fn verify(
        &self,
        trusted: &SlhVerifyingKey,
        now: u64,
        chain_id: Option<&str>,
    ) -> Result<(), LicenseError> {
        if &self.issuer != trusted {
            return Err(LicenseError::WrongIssuer);
        }
        if !self
            .issuer
            .verify(&self.license.signing_bytes(), &self.signature, context::LICENSE)
        {
            return Err(LicenseError::BadSignature);
        }
        if now < self.license.issued_at {
            return Err(LicenseError::NotYetValid {
                issued_at: self.license.issued_at,
                now,
            });
        }
        if now >= self.license.expires_at {
            return Err(LicenseError::Expired {
                expires_at: self.license.expires_at,
                now,
            });
        }
        if let Some(bound) = &self.license.chain_id {
            match chain_id {
                Some(actual) if actual == bound => {}
                other => {
                    return Err(LicenseError::WrongChain {
                        expected: bound.clone(),
                        actual: other.unwrap_or("").to_string(),
                    })
                }
            }
        }
        Ok(())
    }

    pub fn to_json(&self) -> Result<String, LicenseError> {
        serde_json::to_string_pretty(self).map_err(|e| LicenseError::Serialization(e.to_string()))
    }

    pub fn from_json(s: &str) -> Result<SignedLicense, LicenseError> {
        serde_json::from_str(s).map_err(|e| LicenseError::Serialization(e.to_string()))
    }
}

/// SmartLedger's license-issuing authority (holds the SLH-DSA secret key).
pub struct LicenseIssuer {
    sk: SlhSigningKey,
    pk: SlhVerifyingKey,
}

impl LicenseIssuer {
    pub fn generate() -> Result<LicenseIssuer, LicenseError> {
        let (sk, pk) = SlhSigningKey::generate()?;
        Ok(LicenseIssuer { sk, pk })
    }

    /// Load an issuer from a persisted keypair (SLH-DSA can't re-derive the
    /// public key from the secret, so both are stored — see the keystore).
    pub fn from_keypair(sk: SlhSigningKey, pk: SlhVerifyingKey) -> LicenseIssuer {
        LicenseIssuer { sk, pk }
    }

    pub fn public_key(&self) -> &SlhVerifyingKey {
        &self.pk
    }

    pub fn secret_bytes(&self) -> [u8; slc_crypto::SLH_SECKEY_LEN] {
        self.sk.to_bytes()
    }

    /// Sign a license.
    pub fn issue(&self, license: License) -> Result<SignedLicense, LicenseError> {
        let signature = self.sk.sign(&license.signing_bytes(), context::LICENSE)?;
        Ok(SignedLicense {
            license,
            issuer: self.pk.clone(),
            signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a_license(now: u64) -> License {
        License {
            licensee: "Acme Corp".into(),
            license_id: "LIC-0001".into(),
            product: "smartledger-chain".into(),
            tier: "enterprise".into(),
            entitlements: Entitlements {
                max_nodes: Some(10),
                max_notarizations_per_month: Some(100_000),
                anchoring: true,
                features: vec!["governance".into(), "spv".into()],
            },
            chain_id: Some("acme-notary".into()),
            issued_at: now,
            expires_at: now + 365 * 24 * 3600,
        }
    }

    /// Serialize CPU-heavy SLH-DSA signing across the workspace (see the note in
    /// `slc-crypto`'s slh tests) so it doesn't starve parallel TCP tests.
    fn slh_serial() -> std::net::TcpListener {
        loop {
            if let Ok(l) = std::net::TcpListener::bind("127.0.0.1:59717") {
                return l;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }

    #[test]
    fn issue_verify_and_reject_all_the_ways() {
        let _serial = slh_serial();
        // One (slow) SLH-DSA signature, reused across every check.
        let issuer = LicenseIssuer::generate().unwrap();
        let now = 1_751_000_000;
        let signed = issuer.issue(a_license(now)).unwrap();
        let trusted = issuer.public_key();

        // Valid for the bound chain, within the window.
        signed.verify(trusted, now + 1000, Some("acme-notary")).unwrap();

        // Wrong chain.
        assert!(matches!(
            signed.verify(trusted, now + 1000, Some("other-chain")),
            Err(LicenseError::WrongChain { .. })
        ));

        // Expired.
        assert!(matches!(
            signed.verify(trusted, now + 400 * 24 * 3600, Some("acme-notary")),
            Err(LicenseError::Expired { .. })
        ));

        // Not yet valid.
        assert!(matches!(
            signed.verify(trusted, now - 10, Some("acme-notary")),
            Err(LicenseError::NotYetValid { .. })
        ));

        // Untrusted issuer key.
        let (_s2, other_pk) = SlhSigningKey::generate().unwrap();
        assert_eq!(
            signed.verify(&other_pk, now + 1000, Some("acme-notary")),
            Err(LicenseError::WrongIssuer)
        );

        // Tampered body (raise the node cap) → signature no longer matches.
        let mut tampered = signed.clone();
        tampered.license.entitlements.max_nodes = Some(1000);
        assert_eq!(
            tampered.verify(trusted, now + 1000, Some("acme-notary")),
            Err(LicenseError::BadSignature)
        );

        // JSON round-trip still verifies.
        let json = signed.to_json().unwrap();
        let back = SignedLicense::from_json(&json).unwrap();
        back.verify(trusted, now + 1000, Some("acme-notary")).unwrap();
    }
}
