//! [`AnchoredProof`] — a notarization proof plus external immutability evidence.
//!
//! A plain [`NotarizationProof`] proves a document was notarized by a validator
//! quorum. An anchored proof adds a fourth guarantee: the block it lives in was
//! committed to a checkpoint whose root was **published to a public chain**. So
//! even if every validator later colluded to rewrite history, the anchored
//! record — timestamped in an external ledger they do not control — would expose
//! the fork.

use crate::backend::{AnchorError, Receipt};
use crate::checkpoint::CheckpointInclusion;
use serde::{Deserialize, Serialize};
use slc_ledger::{NotarizationProof, ValidatorSet};

/// A stored record of one published checkpoint.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorRecord {
    pub from_height: u64,
    pub to_height: u64,
    pub checkpoint_root: slc_crypto::Hash,
    pub receipt: Receipt,
}

/// A notarization proof hardened with a public-chain anchor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchoredProof {
    /// The underlying proof: attestation → Merkle inclusion → quorum certificate.
    pub notarization: NotarizationProof,
    /// The block's inclusion under the checkpoint root.
    pub checkpoint: CheckpointInclusion,
    /// The published-checkpoint record carrying the external reference.
    pub record: AnchorRecord,
}

impl AnchoredProof {
    /// Verify all four layers against a known `validator_set`:
    /// notarization, that the checkpoint covers exactly this block, that the
    /// block is included under the anchored root, and that the published receipt
    /// matches that root.
    pub fn verify(&self, validator_set: &ValidatorSet) -> Result<(), AnchorError> {
        // 1. The base notarization proof holds.
        self.notarization.verify(validator_set)?;
        // 2. The checkpoint inclusion is about this proof's block.
        if self.checkpoint.block_id != self.notarization.header.id() {
            return Err(AnchorError::BlockMismatch);
        }
        // 3. The block is included under the anchored checkpoint root.
        if !self.checkpoint.verify(self.record.checkpoint_root) {
            return Err(AnchorError::NotInCheckpoint);
        }
        // 4. The published receipt commits to that very root.
        if self.record.receipt.checkpoint_root != self.record.checkpoint_root {
            return Err(AnchorError::ReceiptMismatch);
        }
        Ok(())
    }

    pub fn to_json(&self) -> Result<String, AnchorError> {
        serde_json::to_string_pretty(self).map_err(|e| AnchorError::Io(e.to_string()))
    }

    pub fn from_json(s: &str) -> Result<AnchoredProof, AnchorError> {
        serde_json::from_str(s).map_err(|e| AnchorError::Io(e.to_string()))
    }
}
