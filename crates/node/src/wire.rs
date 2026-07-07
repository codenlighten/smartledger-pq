//! The peer-to-peer message type. Framing lives in [`crate::frame`]; JSON keeps
//! the protocol debuggable and the dominant cost is the ~3 KB ML-DSA signatures
//! either way.

use serde::{Deserialize, Serialize};
use slc_consensus::ConsensusMsg;
use slc_ledger::{Attestation, Block, SignedValidatorChange};

/// Everything that travels between nodes.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum WireMsg {
    /// A consensus protocol message (proposal or vote).
    Consensus(ConsensusMsg),
    /// A client attestation being gossiped toward whoever proposes next.
    Attestation(Attestation),
    /// A validator-set change being gossiped toward whoever proposes next.
    Governance(SignedValidatorChange),
    /// Catch-up: request finalized blocks starting at height `from`.
    GetBlocks { from: u64 },
    /// Catch-up: a batch of finalized blocks (in height order).
    Blocks(Vec<Block>),
}
