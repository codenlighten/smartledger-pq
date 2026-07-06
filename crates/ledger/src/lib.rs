//! `slc-ledger` — the notarization value chain for SmartLedger-Chain.
//!
//! The data model, bottom to top:
//!
//! * [`Attestation`] — a self-verifying `{ pubkey, hash, signature }` entry.
//! * [`merkle`] — batches attestations into a root with inclusion proofs.
//! * [`BlockHeader`] / [`Block`] — a chained, timestamped batch.
//! * [`QuorumCertificate`] — a quorum of [`ValidatorSet`] members finalizing a
//!   header (all of consensus finality, as a portable object).
//! * [`NotarizationProof`] — the offline-verifiable certificate a client keeps.
//!
//! This crate is pure and deterministic: no networking, no clock, no storage.
//! Consensus and the node daemon build on top of it.

pub mod merkle;

mod attestation;
mod block;
mod proof;
mod validators;

pub use attestation::Attestation;
pub use block::{Block, BlockHeader, QuorumCertificate, ValidatorSig};
pub use merkle::{MerklePath, MerkleStep, MerkleTree};
pub use proof::NotarizationProof;
pub use validators::ValidatorSet;

use thiserror::Error;

/// Errors surfaced by the ledger layer.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum LedgerError {
    #[error("crypto error: {0}")]
    Crypto(#[from] slc_crypto::CryptoError),
    #[error("attestation signature is invalid")]
    InvalidAttestation,
    #[error("attestation is not included under the block's merkle root")]
    NotIncluded,
    #[error("quorum certificate commits to a different block id than the header")]
    BlockIdMismatch,
    #[error("insufficient quorum: {got} valid signatures, need {need}")]
    InsufficientQuorum { got: usize, need: usize },
    #[error("serialization error: {0}")]
    Serialization(String),
}
