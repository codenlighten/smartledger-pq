//! Wire messages for Quorum-Certified Notary BFT and their signing rules.
//!
//! Signature contexts are chosen so that a **non-nil precommit is itself a
//! quorum-certificate share**: it signs the block id under [`context::BLOCK`],
//! exactly what [`slc_ledger::QuorumCertificate`] expects. Prevotes and nil
//! votes sign under [`context::VOTE`] and never contribute to finality.

use serde::{Deserialize, Serialize};
use slc_crypto::{context, Hash, Signature, SigningKey, VerifyingKey};
use slc_ledger::{Attestation, BlockHeader, MerkleTree};

/// A candidate block value: a header plus the attestations it commits to. The
/// finalized [`slc_ledger::Block`] (header + attestations + QC) is assembled
/// only once a precommit quorum forms.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proposed {
    pub header: BlockHeader,
    pub attestations: Vec<Attestation>,
}

impl Proposed {
    /// The block id — the value everyone votes on.
    pub fn id(&self) -> Hash {
        self.header.id()
    }

    /// Is this a well-formed value to build on top of `tip` at `height`? Checks
    /// structural integrity only; each attestation must also self-verify.
    ///
    /// A valid block is **never empty**: blocks exist only to notarize, so an
    /// empty block is rejected here. This makes empty-block production not just
    /// discouraged but structurally impossible — no quorum will ratify one.
    pub fn is_valid(&self, tip: Hash, height: u64) -> bool {
        if self.attestations.is_empty() {
            return false;
        }
        if self.header.height != height || self.header.prev_hash != tip {
            return false;
        }
        if self.header.tx_count as usize != self.attestations.len() {
            return false;
        }
        if self.attestations.iter().any(|a| !a.verify()) {
            return false;
        }
        let leaves: Vec<Hash> = self.attestations.iter().map(|a| a.leaf_hash()).collect();
        MerkleTree::build(leaves).root() == self.header.merkle_root
    }
}

/// Prevote (phase 1) or precommit (phase 2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum VoteType {
    Prevote,
    Precommit,
}

/// A proposal for `(height, round)`. `valid_round` is `Some(vr)` when the
/// proposer is re-proposing a value that already earned a polka in round `vr`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposalMsg {
    pub height: u64,
    pub round: u64,
    pub valid_round: Option<u64>,
    pub value: Proposed,
    pub proposer: VerifyingKey,
    pub sig: Signature,
}

/// A prevote or precommit for a block id (or `None` = nil).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VoteMsg {
    pub height: u64,
    pub round: u64,
    pub vote_type: VoteType,
    pub block_id: Option<Hash>,
    pub voter: VerifyingKey,
    pub sig: Signature,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConsensusMsg {
    Proposal(ProposalMsg),
    Vote(VoteMsg),
}

/// Canonical bytes a proposer signs: binds height, round, value id, valid_round.
fn proposal_signing_bytes(height: u64, round: u64, block_id: Hash, valid_round: Option<u64>) -> Vec<u8> {
    let mut buf = Vec::with_capacity(8 + 8 + Hash::LEN + 9);
    buf.extend_from_slice(&height.to_be_bytes());
    buf.extend_from_slice(&round.to_be_bytes());
    buf.extend_from_slice(block_id.as_bytes());
    match valid_round {
        Some(vr) => {
            buf.push(1);
            buf.extend_from_slice(&vr.to_be_bytes());
        }
        None => buf.push(0),
    }
    buf
}

/// Canonical bytes for a prevote / nil vote (precommit-for-a-block signs the
/// bare block id under `context::BLOCK` instead — see [`sign_vote`]).
fn vote_signing_bytes(height: u64, round: u64, vote_type: VoteType, block_id: Option<Hash>) -> Vec<u8> {
    let mut buf = Vec::with_capacity(8 + 8 + 1 + 1 + Hash::LEN);
    buf.extend_from_slice(&height.to_be_bytes());
    buf.extend_from_slice(&round.to_be_bytes());
    buf.push(match vote_type {
        VoteType::Prevote => 0,
        VoteType::Precommit => 1,
    });
    match block_id {
        Some(id) => {
            buf.push(1);
            buf.extend_from_slice(id.as_bytes());
        }
        None => buf.push(0),
    }
    buf
}

impl ProposalMsg {
    pub fn create(
        sk: &SigningKey,
        proposer: VerifyingKey,
        height: u64,
        round: u64,
        valid_round: Option<u64>,
        value: Proposed,
    ) -> ProposalMsg {
        let bytes = proposal_signing_bytes(height, round, value.id(), valid_round);
        let sig = sk.sign(&bytes, context::PROPOSAL).expect("sign proposal");
        ProposalMsg {
            height,
            round,
            valid_round,
            value,
            proposer,
            sig,
        }
    }

    /// Authenticate the proposal and confirm the proposer is who it claims.
    pub fn verify_sig(&self) -> bool {
        let bytes = proposal_signing_bytes(self.height, self.round, self.value.id(), self.valid_round);
        self.proposer.verify(&bytes, &self.sig, context::PROPOSAL)
    }
}

impl VoteMsg {
    pub fn create(
        sk: &SigningKey,
        voter: VerifyingKey,
        height: u64,
        round: u64,
        vote_type: VoteType,
        block_id: Option<Hash>,
    ) -> VoteMsg {
        let sig = sign_vote(sk, height, round, vote_type, block_id);
        VoteMsg {
            height,
            round,
            vote_type,
            block_id,
            voter,
            sig,
        }
    }

    pub fn verify_sig(&self) -> bool {
        verify_vote(
            &self.voter,
            self.height,
            self.round,
            self.vote_type,
            self.block_id,
            &self.sig,
        )
    }
}

/// A non-nil precommit signs the bare block id under `context::BLOCK` so the
/// signature is reusable as a quorum-certificate share; everything else signs
/// the full canonical vote body under `context::VOTE`.
fn sign_vote(
    sk: &SigningKey,
    height: u64,
    round: u64,
    vote_type: VoteType,
    block_id: Option<Hash>,
) -> Signature {
    match (vote_type, block_id) {
        (VoteType::Precommit, Some(id)) => sk.sign(id.as_bytes(), context::BLOCK),
        _ => sk.sign(&vote_signing_bytes(height, round, vote_type, block_id), context::VOTE),
    }
    .expect("sign vote")
}

fn verify_vote(
    pk: &VerifyingKey,
    height: u64,
    round: u64,
    vote_type: VoteType,
    block_id: Option<Hash>,
    sig: &Signature,
) -> bool {
    match (vote_type, block_id) {
        (VoteType::Precommit, Some(id)) => pk.verify(id.as_bytes(), sig, context::BLOCK),
        _ => pk.verify(&vote_signing_bytes(height, round, vote_type, block_id), sig, context::VOTE),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use slc_crypto::SigningKey;
    use slc_ledger::BlockHeader;

    #[test]
    fn empty_block_is_invalid() {
        // A header claiming zero transactions can never be a valid value.
        let header = BlockHeader {
            height: 1,
            prev_hash: Hash::zero(),
            merkle_root: slc_ledger::merkle::empty_root(),
            tx_count: 0,
            timestamp: 0,
        };
        let value = Proposed {
            header,
            attestations: vec![],
        };
        assert!(!value.is_valid(Hash::zero(), 1), "empty blocks must be rejected");
    }

    #[test]
    fn well_formed_block_is_valid() {
        let (sk, pk) = SigningKey::generate().unwrap();
        let att = Attestation::create(&sk, &pk, Hash::digest(b"doc")).unwrap();
        let merkle_root = MerkleTree::build(vec![att.leaf_hash()]).root();
        let header = BlockHeader {
            height: 1,
            prev_hash: Hash::zero(),
            merkle_root,
            tx_count: 1,
            timestamp: 0,
        };
        let value = Proposed {
            header,
            attestations: vec![att],
        };
        assert!(value.is_valid(Hash::zero(), 1));
    }
}
