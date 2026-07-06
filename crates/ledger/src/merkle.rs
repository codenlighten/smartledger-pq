//! A binary Merkle tree with inclusion proofs, over SHA3-256.
//!
//! Two defensive choices:
//!
//! * **Domain separation** — leaves are hashed with a `0x00` prefix and
//!   internal nodes with `0x01`. This makes it impossible to present an
//!   internal node as if it were a leaf (the classic second-preimage attack).
//! * **Promote-odd** (RFC 6962 style) — when a level has an odd node count, the
//!   final node is carried up unchanged rather than duplicated. Duplicating the
//!   last leaf enables forgeries (CVE-2012-2459 in Bitcoin); promotion does not.

use serde::{Deserialize, Serialize};
use slc_crypto::Hash;

const LEAF_PREFIX: u8 = 0x00;
const NODE_PREFIX: u8 = 0x01;

/// Merkle root of a tree with zero leaves. A block should normally carry at
/// least one attestation, but genesis may be empty.
pub fn empty_root() -> Hash {
    Hash::digest(b"SLC-empty-merkle-v1")
}

/// Hash a leaf preimage with domain separation.
pub fn hash_leaf(data: &[u8]) -> Hash {
    let mut buf = Vec::with_capacity(1 + data.len());
    buf.push(LEAF_PREFIX);
    buf.extend_from_slice(data);
    Hash::digest(&buf)
}

/// Hash two child digests into their parent with domain separation.
fn hash_node(left: &Hash, right: &Hash) -> Hash {
    let mut buf = [0u8; 1 + 2 * Hash::LEN];
    buf[0] = NODE_PREFIX;
    buf[1..1 + Hash::LEN].copy_from_slice(left.as_bytes());
    buf[1 + Hash::LEN..].copy_from_slice(right.as_bytes());
    Hash::digest(&buf)
}

/// One hop of an authentication path.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleStep {
    /// The sibling digest to combine with the running accumulator.
    pub sibling: Hash,
    /// Whether the sibling sits on the *left* (so parent = H(sibling ‖ acc)).
    pub sibling_is_left: bool,
}

/// An inclusion proof: the sibling digests from a leaf up to the root.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerklePath {
    pub steps: Vec<MerkleStep>,
}

impl MerklePath {
    /// Recompute the root implied by `leaf_hash` walking this path. Compare the
    /// result against a trusted `merkle_root` to confirm inclusion.
    pub fn compute_root(&self, leaf_hash: Hash) -> Hash {
        let mut acc = leaf_hash;
        for step in &self.steps {
            acc = if step.sibling_is_left {
                hash_node(&step.sibling, &acc)
            } else {
                hash_node(&acc, &step.sibling)
            };
        }
        acc
    }
}

/// A fully materialized Merkle tree, retaining every level so it can emit an
/// inclusion proof for any leaf.
pub struct MerkleTree {
    /// `levels[0]` is the leaves; the last level is the root (or empty).
    levels: Vec<Vec<Hash>>,
}

impl MerkleTree {
    /// Build a tree from pre-hashed leaves (e.g. [`super::Attestation::leaf_hash`]).
    pub fn build(leaves: Vec<Hash>) -> MerkleTree {
        let mut levels = vec![leaves];
        while levels.last().unwrap().len() > 1 {
            let current = levels.last().unwrap();
            let mut next = Vec::with_capacity(current.len().div_ceil(2));
            let mut i = 0;
            while i < current.len() {
                if i + 1 < current.len() {
                    next.push(hash_node(&current[i], &current[i + 1]));
                    i += 2;
                } else {
                    next.push(current[i]); // promote lone node unchanged
                    i += 1;
                }
            }
            levels.push(next);
        }
        MerkleTree { levels }
    }

    /// The Merkle root. Equals [`empty_root`] when there are no leaves, and the
    /// single leaf's own hash when there is exactly one.
    pub fn root(&self) -> Hash {
        match self.levels.last() {
            Some(top) if top.len() == 1 => top[0],
            _ => empty_root(),
        }
    }

    /// Produce an inclusion proof for the leaf at `index`, or `None` if out of
    /// range.
    pub fn proof(&self, index: usize) -> Option<MerklePath> {
        if index >= self.levels[0].len() {
            return None;
        }
        let mut steps = Vec::new();
        let mut idx = index;
        for level in 0..self.levels.len() - 1 {
            let nodes = &self.levels[level];
            if idx.is_multiple_of(2) {
                // Left child. It has a right sibling unless it is a lone
                // promoted node, in which case there is no hop at this level.
                if idx + 1 < nodes.len() {
                    steps.push(MerkleStep {
                        sibling: nodes[idx + 1],
                        sibling_is_left: false,
                    });
                }
            } else {
                // Right child: sibling is on the left.
                steps.push(MerkleStep {
                    sibling: nodes[idx - 1],
                    sibling_is_left: true,
                });
            }
            idx /= 2;
        }
        Some(MerklePath { steps })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaves(n: usize) -> Vec<Hash> {
        (0..n)
            .map(|i| hash_leaf(format!("leaf-{i}").as_bytes()))
            .collect()
    }

    #[test]
    fn every_leaf_proves_for_various_sizes() {
        // Exercise odd and even counts, including the promote-odd path.
        for n in 1..=17 {
            let ls = leaves(n);
            let tree = MerkleTree::build(ls.clone());
            let root = tree.root();
            for (i, leaf) in ls.iter().enumerate() {
                let path = tree.proof(i).expect("in range");
                assert_eq!(path.compute_root(*leaf), root, "n={n} i={i}");
            }
        }
    }

    #[test]
    fn wrong_leaf_does_not_prove() {
        let ls = leaves(8);
        let tree = MerkleTree::build(ls.clone());
        let path = tree.proof(3).unwrap();
        let not_the_leaf = hash_leaf(b"outsider");
        assert_ne!(path.compute_root(not_the_leaf), tree.root());
    }

    #[test]
    fn single_leaf_root_is_leaf() {
        let ls = leaves(1);
        let tree = MerkleTree::build(ls.clone());
        assert_eq!(tree.root(), ls[0]);
        assert!(tree.proof(0).unwrap().steps.is_empty());
    }

    #[test]
    fn out_of_range_proof_is_none() {
        let tree = MerkleTree::build(leaves(4));
        assert!(tree.proof(4).is_none());
    }
}
