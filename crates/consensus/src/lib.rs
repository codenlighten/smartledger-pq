//! `slc-consensus` — Quorum-Certified Notary BFT.
//!
//! A Tendermint-style two-phase BFT (propose → prevote → precommit → commit)
//! with locking and view (round) change, specialized to SmartLedger-Chain's
//! conflict-free notary workload. See [`Engine`] for the state machine and
//! [`messages`] for the wire format.
//!
//! Finality is instant: a committed [`slc_ledger::Block`] carries a
//! [`slc_ledger::QuorumCertificate`] assembled from the precommit signatures,
//! so downstream notarization proofs need nothing but validator public keys.

mod engine;
pub mod messages;

pub use engine::{Effect, Engine, Step, TimeoutKind};
pub use messages::{ConsensusMsg, ProposalMsg, Proposed, VoteMsg, VoteType};
