//! Blocks, headers, and the quorum certificate that finalizes them.

use crate::{Attestation, LedgerError, ValidatorSet};
use serde::{Deserialize, Serialize};
use slc_crypto::{context, Hash, Signature, SigningKey, VerifyingKey};
use std::collections::HashSet;

/// The compact, signable summary of a block. Everything a proof needs about a
/// block lives here — the attestation bodies are not required to verify.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockHeader {
    /// Position in the chain; genesis is height 0.
    pub height: u64,
    /// SHA3-256 id of the previous block header ([`Hash::zero`] at genesis).
    pub prev_hash: Hash,
    /// Merkle root over this block's attestations.
    pub merkle_root: Hash,
    /// Number of attestations sealed in this block.
    pub tx_count: u32,
    /// Unix seconds. In consensus this is the median of validator clocks, so it
    /// is a value the quorum collectively vouches for — the notarized *time*.
    pub timestamp: u64,
    /// Commitment to this block's governance changes (see
    /// [`crate::governance::governance_root`]); binds validator-set changes into
    /// the quorum certificate. Empty-list root when there are none.
    pub gov_root: Hash,
}

impl BlockHeader {
    /// Deterministic, fixed-layout encoding. This is both the block id preimage
    /// and the message validators sign, so it must be canonical.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(8 + Hash::LEN * 3 + 4 + 8);
        buf.extend_from_slice(&self.height.to_be_bytes());
        buf.extend_from_slice(self.prev_hash.as_bytes());
        buf.extend_from_slice(self.merkle_root.as_bytes());
        buf.extend_from_slice(&self.tx_count.to_be_bytes());
        buf.extend_from_slice(&self.timestamp.to_be_bytes());
        buf.extend_from_slice(self.gov_root.as_bytes());
        buf
    }

    /// The block id: SHA3-256 of the canonical header encoding.
    pub fn id(&self) -> Hash {
        Hash::digest(&self.signing_bytes())
    }

    /// A validator's contribution to this header's quorum certificate.
    pub fn sign(&self, signing_key: &SigningKey) -> Result<Signature, LedgerError> {
        Ok(signing_key.sign(self.id().as_bytes(), context::BLOCK)?)
    }
}

/// A single validator's signature over a block id.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorSig {
    pub validator: VerifyingKey,
    pub signature: Signature,
}

/// Proof that a quorum of the validator set finalized a specific block. This is
/// the whole of consensus finality distilled into a portable object.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuorumCertificate {
    /// The block id every signature below commits to.
    pub block_id: Hash,
    pub signatures: Vec<ValidatorSig>,
}

impl QuorumCertificate {
    /// Assemble a certificate. Callers add signatures until [`Self::is_final`].
    pub fn new(block_id: Hash) -> QuorumCertificate {
        QuorumCertificate {
            block_id,
            signatures: Vec::new(),
        }
    }

    /// Add a validator's signature (no verification here — see [`Self::verify`]).
    pub fn add(&mut self, validator: VerifyingKey, signature: Signature) {
        self.signatures.push(ValidatorSig {
            validator,
            signature,
        });
    }

    /// Count the *distinct, in-set, valid* signatures over `block_id`. Junk,
    /// duplicates, and non-member signatures contribute nothing.
    fn count_valid(&self, set: &ValidatorSet) -> usize {
        let mut seen = HashSet::new();
        let mut valid = 0usize;
        for vs in &self.signatures {
            if !set.contains(&vs.validator) {
                continue;
            }
            if !seen.insert(vs.validator.id()) {
                continue; // one vote per validator
            }
            if vs
                .validator
                .verify(self.block_id.as_bytes(), &vs.signature, context::BLOCK)
            {
                valid += 1;
            }
        }
        valid
    }

    /// Does this certificate already carry a quorum against `set`?
    pub fn is_final(&self, set: &ValidatorSet) -> bool {
        self.count_valid(set) >= set.threshold()
    }

    /// Verify the certificate finalizes `header` under `set`: the committed
    /// block id must match, and a quorum of distinct members must have signed.
    pub fn verify(&self, header: &BlockHeader, set: &ValidatorSet) -> Result<(), LedgerError> {
        if self.block_id != header.id() {
            return Err(LedgerError::BlockIdMismatch);
        }
        let valid = self.count_valid(set);
        if valid < set.threshold() {
            return Err(LedgerError::InsufficientQuorum {
                got: valid,
                need: set.threshold(),
            });
        }
        Ok(())
    }
}

/// A finalized block: its header, the attestations it seals, any validator-set
/// changes it enacts, and the quorum certificate proving the set ratified it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub attestations: Vec<Attestation>,
    #[serde(default)]
    pub governance: Vec<crate::SignedValidatorChange>,
    pub qc: QuorumCertificate,
}
