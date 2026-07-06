//! The peer-to-peer wire format: a length-prefixed frame carrying JSON.
//!
//! Frames are `u32` big-endian length followed by that many bytes of
//! `serde_json`-encoded [`WireMsg`]. JSON keeps the protocol debuggable; the
//! dominant cost is the ~3 KB ML-DSA signatures either way.

use serde::{Deserialize, Serialize};
use slc_consensus::ConsensusMsg;
use slc_ledger::Attestation;
use std::io::{self, Read, Write};

/// Reject absurd frames early (defensive against a hostile/garbled peer).
const MAX_FRAME: usize = 16 * 1024 * 1024;

/// Everything that travels between nodes.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum WireMsg {
    /// A consensus protocol message (proposal or vote).
    Consensus(ConsensusMsg),
    /// A client attestation being gossiped toward whoever proposes next.
    Attestation(Attestation),
}

/// Write one framed message.
pub fn write_frame<W: Write>(w: &mut W, msg: &WireMsg) -> io::Result<()> {
    let bytes = serde_json::to_vec(msg)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    w.write_all(&(bytes.len() as u32).to_be_bytes())?;
    w.write_all(&bytes)?;
    w.flush()
}

/// Read one framed message (blocking).
pub fn read_frame<R: Read>(r: &mut R) -> io::Result<WireMsg> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "frame too large"));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    serde_json::from_slice(&buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}
