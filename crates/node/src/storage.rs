//! Append-only block storage: one JSON block per line, plus an in-memory mirror
//! that callers can observe (e.g. to serve proofs or, in tests, assert state).

use slc_crypto::Hash;
use slc_ledger::Block;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct BlockStore {
    path: Option<PathBuf>,
    blocks: Arc<Mutex<Vec<Block>>>,
}

impl BlockStore {
    /// Open (and, if present, load) a block store at `path`. Pass `None` for an
    /// ephemeral, memory-only store.
    pub fn open(path: Option<&Path>) -> BlockStore {
        let mut blocks = Vec::new();
        if let Some(p) = path {
            if let Ok(file) = File::open(p) {
                for line in BufReader::new(file).lines().map_while(Result::ok) {
                    if let Ok(block) = serde_json::from_str::<Block>(&line) {
                        blocks.push(block);
                    }
                }
            }
        }
        BlockStore {
            path: path.map(PathBuf::from),
            blocks: Arc::new(Mutex::new(blocks)),
        }
    }

    /// Append a freshly finalized block to memory and (if configured) disk.
    pub fn append(&self, block: &Block) {
        self.blocks.lock().unwrap().push(block.clone());
        if let Some(p) = &self.path {
            if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(p) {
                if let Ok(line) = serde_json::to_string(block) {
                    let _ = writeln!(f, "{line}");
                }
            }
        }
    }

    /// A shared handle to the committed-block list for observers.
    pub fn handle(&self) -> Arc<Mutex<Vec<Block>>> {
        self.blocks.clone()
    }

    /// The current chain tip `(block_id, height)`, or `(zero, 0)` if empty.
    pub fn tip(&self) -> (Hash, u64) {
        self.blocks
            .lock()
            .unwrap()
            .last()
            .map(|b| (b.header.id(), b.header.height))
            .unwrap_or((Hash::zero(), 0))
    }
}
