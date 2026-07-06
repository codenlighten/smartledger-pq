//! `slc-crypto` — the post-quantum cryptographic core of SmartLedger-Chain.
//!
//! Two primitives, both chosen to survive a cryptographically-relevant quantum
//! computer:
//!
//! * [`Hash`] — SHA3-256, quantum-resistant commitment / Merkle hashing.
//! * [`SigningKey`] / [`VerifyingKey`] / [`Signature`] — ML-DSA-65 (FIPS 204).
//!
//! Everything here is deterministic and side-effect free except key/sig
//! generation, which draws from the OS CSPRNG.

mod hash;
mod keys;

pub use hash::Hash;
pub use keys::{Signature, SigningKey, VerifyingKey, PUBKEY_LEN, SECKEY_LEN, SIG_LEN};

use thiserror::Error;

/// Errors surfaced by the crypto layer. Deliberately coarse: we never reveal
/// *why* a signature failed, only that it did.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CryptoError {
    #[error("key generation failed")]
    KeyGen,
    #[error("signing failed")]
    Sign,
    #[error("invalid encoding or length")]
    Encoding,
}

/// Domain-separation contexts. Signatures made for one purpose can never be
/// replayed as another because the ML-DSA context string differs.
pub mod context {
    /// A client attesting to (notarizing) a document hash.
    pub const ATTESTATION: &[u8] = b"SLC-attestation-v1";
    /// A validator signing a block id. A non-nil *precommit* uses this context,
    /// so the very same signature doubles as a quorum-certificate share.
    pub const BLOCK: &[u8] = b"SLC-block-v1";
    /// A consensus proposer signing a proposal (binds height, round, value).
    pub const PROPOSAL: &[u8] = b"SLC-proposal-v1";
    /// A validator signing a prevote or a nil vote (never counts toward a QC).
    pub const VOTE: &[u8] = b"SLC-vote-v1";
}
