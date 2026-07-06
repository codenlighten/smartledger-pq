//! A checkpoint: a single Merkle commitment to a run of finalized blocks.
//!
//! Anchoring one 32-byte checkpoint root to a public chain commits to *every*
//! block in the window at once. Because our blocks are already hash-linked
//! (each header carries the previous block's id), and because the checkpoint
//! Merkle tree binds each block id, a published checkpoint makes it impossible
//! to later rewrite any block in the window without detection — even if the
//! entire validator set colludes.

use serde::{Deserialize, Serialize};
use slc_crypto::Hash;
use slc_ledger::{merkle, MerklePath, MerkleTree};

/// The checkpoint leaf for a block id — domain-separated via the ledger's own
/// leaf hashing so it can never be confused with an attestation leaf.
fn checkpoint_leaf(block_id: Hash) -> Hash {
    merkle::hash_leaf(block_id.as_bytes())
}

/// A checkpoint over blocks `[from_height, to_height]`.
pub struct Checkpoint {
    from_height: u64,
    to_height: u64,
    block_ids: Vec<Hash>,
    tree: MerkleTree,
    root: Hash,
}

impl Checkpoint {
    /// Build a checkpoint from block ids known to be contiguous in `[from, to]`.
    pub fn from_block_ids(block_ids: Vec<Hash>, from_height: u64, to_height: u64) -> Option<Checkpoint> {
        if block_ids.is_empty() {
            return None;
        }
        let leaves: Vec<Hash> = block_ids.iter().copied().map(checkpoint_leaf).collect();
        let tree = MerkleTree::build(leaves);
        let root = tree.root();
        Some(Checkpoint {
            from_height,
            to_height,
            block_ids,
            tree,
            root,
        })
    }

    pub fn root(&self) -> Hash {
        self.root
    }
    pub fn from_height(&self) -> u64 {
        self.from_height
    }
    pub fn to_height(&self) -> u64 {
        self.to_height
    }

    /// An inclusion proof that `block_id` is committed under this checkpoint.
    pub fn inclusion(&self, block_id: Hash) -> Option<CheckpointInclusion> {
        let idx = self.block_ids.iter().position(|&b| b == block_id)?;
        let path = self.tree.proof(idx)?;
        Some(CheckpointInclusion { block_id, path })
    }
}

/// A portable proof that a specific block id sits under a checkpoint root.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointInclusion {
    pub block_id: Hash,
    pub path: MerklePath,
}

impl CheckpointInclusion {
    /// Does this block id reconstruct the given checkpoint `root`?
    pub fn verify(&self, root: Hash) -> bool {
        self.path.compute_root(checkpoint_leaf(self.block_id)) == root
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(n: usize) -> Vec<Hash> {
        (0..n).map(|i| Hash::digest(format!("block-{i}").as_bytes())).collect()
    }

    #[test]
    fn every_block_is_included() {
        for n in 1..=9 {
            let block_ids = ids(n);
            let cp = Checkpoint::from_block_ids(block_ids.clone(), 1, n as u64).unwrap();
            for id in &block_ids {
                let inc = cp.inclusion(*id).expect("present");
                assert!(inc.verify(cp.root()), "n={n}");
            }
        }
    }

    #[test]
    fn outsider_block_not_included() {
        let block_ids = ids(5);
        let cp = Checkpoint::from_block_ids(block_ids, 1, 5).unwrap();
        assert!(cp.inclusion(Hash::digest(b"not-in-window")).is_none());
    }

    #[test]
    fn wrong_root_fails() {
        let block_ids = ids(5);
        let cp = Checkpoint::from_block_ids(block_ids.clone(), 1, 5).unwrap();
        let inc = cp.inclusion(block_ids[2]).unwrap();
        assert!(!inc.verify(Hash::digest(b"bogus-root")));
    }
}
