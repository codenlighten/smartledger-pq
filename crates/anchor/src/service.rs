//! The anchoring service: batch finalized blocks into fixed-size checkpoints,
//! publish each via a backend, and retain enough to reconstruct an
//! [`AnchoredProof`] for any block that has been anchored.

use crate::backend::AnchorBackend;
use crate::checkpoint::{Checkpoint, CheckpointInclusion};
use crate::proof::{AnchoredProof, AnchorRecord};
use slc_crypto::Hash;
use slc_ledger::NotarizationProof;

struct Window {
    block_ids: Vec<Hash>,
    from_height: u64,
    to_height: u64,
    record: AnchorRecord,
}

/// Accumulates block ids and anchors them every `interval` blocks.
pub struct AnchorService {
    backend: Box<dyn AnchorBackend>,
    interval: usize,
    pending_ids: Vec<Hash>,
    pending_from: Option<u64>,
    pending_to: u64,
    history: Vec<Window>,
}

impl AnchorService {
    /// Anchor once every `interval` finalized blocks (must be ≥ 1).
    pub fn new(backend: Box<dyn AnchorBackend>, interval: usize) -> AnchorService {
        assert!(interval >= 1, "anchor interval must be at least 1");
        AnchorService {
            backend,
            interval,
            pending_ids: Vec::new(),
            pending_from: None,
            pending_to: 0,
            history: Vec::new(),
        }
    }

    /// Note a newly finalized block. When a full window has accumulated, publish
    /// its checkpoint and return the resulting record.
    pub fn record_block(&mut self, block_id: Hash, height: u64) -> Option<AnchorRecord> {
        if self.pending_from.is_none() {
            self.pending_from = Some(height);
        }
        self.pending_to = height;
        self.pending_ids.push(block_id);
        if self.pending_ids.len() >= self.interval {
            self.flush()
        } else {
            None
        }
    }

    /// Publish the current pending window (if any). On backend failure the
    /// window is retained so a later block can retry.
    pub fn flush(&mut self) -> Option<AnchorRecord> {
        let from = self.pending_from?;
        let checkpoint =
            Checkpoint::from_block_ids(self.pending_ids.clone(), from, self.pending_to)?;
        let receipt = match self.backend.anchor(&checkpoint) {
            Ok(r) => r,
            Err(_) => return None, // keep pending; retry on the next block
        };
        let record = AnchorRecord {
            from_height: from,
            to_height: self.pending_to,
            checkpoint_root: checkpoint.root(),
            receipt,
        };
        self.history.push(Window {
            block_ids: std::mem::take(&mut self.pending_ids),
            from_height: from,
            to_height: self.pending_to,
            record: record.clone(),
        });
        self.pending_from = None;
        Some(record)
    }

    /// The name of the underlying backend.
    pub fn backend_name(&self) -> &str {
        self.backend.name()
    }

    /// Every checkpoint record published so far.
    pub fn records(&self) -> Vec<AnchorRecord> {
        self.history.iter().map(|w| w.record.clone()).collect()
    }

    /// Reconstruct the checkpoint inclusion for an anchored `block_id`.
    pub fn inclusion_for(&self, block_id: Hash) -> Option<(CheckpointInclusion, AnchorRecord)> {
        for w in &self.history {
            if w.block_ids.contains(&block_id) {
                let cp =
                    Checkpoint::from_block_ids(w.block_ids.clone(), w.from_height, w.to_height)?;
                let inclusion = cp.inclusion(block_id)?;
                return Some((inclusion, w.record.clone()));
            }
        }
        None
    }

    /// Wrap a notarization proof into an anchored proof, if its block has been
    /// anchored yet.
    pub fn anchor_proof(&self, notarization: NotarizationProof) -> Option<AnchoredProof> {
        let block_id = notarization.header.id();
        let (checkpoint, record) = self.inclusion_for(block_id)?;
        Some(AnchoredProof {
            notarization,
            checkpoint,
            record,
        })
    }
}
