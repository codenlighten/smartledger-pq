//! The peer-to-peer message type. Framing lives in [`crate::frame`]; JSON keeps
//! the protocol debuggable and the dominant cost is the ~3 KB ML-DSA signatures
//! either way.

use serde::{Deserialize, Serialize};
use slc_consensus::ConsensusMsg;
use slc_ledger::{Attestation, SignedValidatorChange};

/// Everything that travels between nodes.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum WireMsg {
    /// A consensus protocol message (proposal or vote).
    Consensus(ConsensusMsg),
    /// A client attestation being gossiped toward whoever proposes next.
    Attestation(Attestation),
    /// A validator-set change being gossiped toward whoever proposes next.
    Governance(SignedValidatorChange),
}
