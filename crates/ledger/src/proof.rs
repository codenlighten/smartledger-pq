//! The portable notarization proof — the product a client actually keeps.
//!
//! A [`NotarizationProof`] is a small, self-contained certificate. Given only
//! the validator set's public keys, *anyone* can verify — offline, with no
//! running chain, decades later — that:
//!
//! 1. a specific actor signed a specific data hash (the attestation),
//! 2. that attestation was sealed into a specific block (Merkle inclusion), and
//! 3. a quorum of named validators finalized that block at a vouched-for time.

use crate::{merkle::MerkleTree, Attestation, Block, BlockHeader, LedgerError, MerklePath, QuorumCertificate, ValidatorSet};
use serde::{Deserialize, Serialize};
use slc_crypto::Hash;

/// A complete, offline-verifiable proof of notarization for one attestation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotarizationProof {
    /// The self-verifying `{ pubkey, hash, signature }` entry.
    pub attestation: Attestation,
    /// Merkle authentication path from the attestation to `header.merkle_root`.
    pub path: MerklePath,
    /// The finalized block header (carries height and the notarized timestamp).
    pub header: BlockHeader,
    /// The quorum certificate proving validators ratified `header`.
    pub qc: QuorumCertificate,
}

impl NotarizationProof {
    /// Extract a proof for the attestation at `index` within `block`.
    pub fn from_block(block: &Block, index: usize) -> Option<NotarizationProof> {
        let leaves: Vec<Hash> = block.attestations.iter().map(|a| a.leaf_hash()).collect();
        let tree = MerkleTree::build(leaves);
        let path = tree.proof(index)?;
        let attestation = block.attestations.get(index)?.clone();
        Some(NotarizationProof {
            attestation,
            path,
            header: block.header.clone(),
            qc: block.qc.clone(),
        })
    }

    /// The notarized data commitment this proof is about.
    pub fn hash(&self) -> Hash {
        self.attestation.hash
    }

    /// The time the validator quorum vouched for (unix seconds).
    pub fn timestamp(&self) -> u64 {
        self.header.timestamp
    }

    /// Verify all three layers against a known `validator_set`. Returns `Ok` iff
    /// the proof is sound in every respect.
    pub fn verify(&self, validator_set: &ValidatorSet) -> Result<(), LedgerError> {
        // 1. The actor's own post-quantum signature covers the hash.
        if !self.attestation.verify() {
            return Err(LedgerError::InvalidAttestation);
        }
        // 2. The attestation is included under the block's Merkle root.
        let leaf = self.attestation.leaf_hash();
        if self.path.compute_root(leaf) != self.header.merkle_root {
            return Err(LedgerError::NotIncluded);
        }
        // 3. A quorum of named validators finalized this exact header.
        self.qc.verify(&self.header, validator_set)?;
        Ok(())
    }

    /// Serialize to pretty JSON — a proof is meant to be stored and emailed.
    pub fn to_json(&self) -> Result<String, LedgerError> {
        serde_json::to_string_pretty(self).map_err(|e| LedgerError::Serialization(e.to_string()))
    }

    pub fn from_json(s: &str) -> Result<NotarizationProof, LedgerError> {
        serde_json::from_str(s).map_err(|e| LedgerError::Serialization(e.to_string()))
    }
}
