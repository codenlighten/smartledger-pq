//! `slc-anchor` — public-chain checkpoint anchoring for SmartLedger-Chain.
//!
//! Periodically the chain commits a run of finalized blocks into a single
//! [`Checkpoint`] and publishes its 32-byte root to an external, tamper-evident
//! ledger through an [`AnchorBackend`]. An [`AnchoredProof`] then binds a
//! notarized document all the way out to that public anchor — so history cannot
//! be rewritten even by a fully-colluding validator set.
//!
//! * [`Checkpoint`] / [`CheckpointInclusion`] — Merkle commitment over block ids.
//! * [`opreturn`] — Bitcoin/BSV `OP_RETURN` encoding of a checkpoint root.
//! * [`AnchorBackend`] ([`MockAnchor`], [`FileAnchor`]) — where roots get published.
//! * [`AnchorService`] — batches blocks, publishes, and reconstructs proofs.
//! * [`AnchoredProof`] — a notarization proof hardened with anchor evidence.

pub mod opreturn;

mod backend;
mod checkpoint;
mod proof;
mod service;

pub use backend::{AnchorBackend, AnchorError, FileAnchor, MockAnchor, Receipt};
pub use checkpoint::{Checkpoint, CheckpointInclusion};
pub use proof::{AnchorRecord, AnchoredProof};
pub use service::AnchorService;
