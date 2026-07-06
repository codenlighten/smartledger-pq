//! Pluggable anchor backends. A backend takes a [`Checkpoint`] and publishes its
//! root to some external, tamper-evident medium, returning a [`Receipt`] that
//! points back to where it landed (a public-chain txid, a file offset, …).
//!
//! Real deployments implement this over a public blockchain (see
//! [`crate::opreturn`] for the on-chain encoding). Two reference backends are
//! provided: [`MockAnchor`] for tests and [`FileAnchor`] for local, auditable
//! runs.

use crate::checkpoint::Checkpoint;
use serde::{Deserialize, Serialize};
use slc_crypto::Hash;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AnchorError {
    #[error("anchor backend i/o error: {0}")]
    Io(String),
    #[error("base notarization proof is invalid: {0}")]
    Notarization(#[from] slc_ledger::LedgerError),
    #[error("proof's block is not the one covered by this checkpoint inclusion")]
    BlockMismatch,
    #[error("block is not included under the anchored checkpoint root")]
    NotInCheckpoint,
    #[error("anchor receipt does not match the checkpoint root it claims")]
    ReceiptMismatch,
}

/// External evidence that a checkpoint root was published.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receipt {
    /// Which backend published it, e.g. `"mock"`, `"file"`, `"bsv-opreturn"`.
    pub backend: String,
    /// Where to find it externally (txid, file offset, URL, …).
    pub reference: String,
    /// The value that was published — must equal the checkpoint root.
    pub checkpoint_root: Hash,
}

/// A backend that can publish a checkpoint root externally.
pub trait AnchorBackend: Send {
    fn name(&self) -> &str;
    fn anchor(&mut self, checkpoint: &Checkpoint) -> Result<Receipt, AnchorError>;
}

/// In-memory backend for tests: remembers every root it "published".
#[derive(Default)]
pub struct MockAnchor {
    published: Vec<Hash>,
}

impl MockAnchor {
    pub fn new() -> MockAnchor {
        MockAnchor::default()
    }
    pub fn published(&self) -> &[Hash] {
        &self.published
    }
}

impl AnchorBackend for MockAnchor {
    fn name(&self) -> &str {
        "mock"
    }
    fn anchor(&mut self, checkpoint: &Checkpoint) -> Result<Receipt, AnchorError> {
        let root = checkpoint.root();
        self.published.push(root);
        Ok(Receipt {
            backend: "mock".into(),
            reference: format!("mock:{}:{}", self.published.len() - 1, root),
            checkpoint_root: root,
        })
    }
}

/// Appends each anchored checkpoint to a JSON-lines file — a simple, auditable
/// external log standing in for a public chain during local runs.
pub struct FileAnchor {
    path: PathBuf,
    count: u64,
}

impl FileAnchor {
    pub fn new(path: impl Into<PathBuf>) -> FileAnchor {
        FileAnchor {
            path: path.into(),
            count: 0,
        }
    }
}

impl AnchorBackend for FileAnchor {
    fn name(&self) -> &str {
        "file"
    }
    fn anchor(&mut self, checkpoint: &Checkpoint) -> Result<Receipt, AnchorError> {
        let root = checkpoint.root();
        let line = serde_json::json!({
            "from_height": checkpoint.from_height(),
            "to_height": checkpoint.to_height(),
            "checkpoint_root": root.to_hex(),
            "op_return_script": hex::encode(crate::opreturn::script(root)),
        });
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| AnchorError::Io(e.to_string()))?;
        writeln!(f, "{line}").map_err(|e| AnchorError::Io(e.to_string()))?;
        let reference = format!("file:{}#{}", self.path.display(), self.count);
        self.count += 1;
        Ok(Receipt {
            backend: "file".into(),
            reference,
            checkpoint_root: root,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_backend_records_roots() {
        let mut mock = MockAnchor::new();
        let cp = Checkpoint::from_block_ids(vec![Hash::digest(b"b1")], 1, 1).unwrap();
        let receipt = mock.anchor(&cp).unwrap();
        assert_eq!(receipt.checkpoint_root, cp.root());
        assert_eq!(mock.published(), &[cp.root()]);
    }
}
