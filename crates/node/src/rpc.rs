//! Client-facing RPC over TCP (framed JSON). External clients submit
//! attestations and fetch notarization proofs without speaking the consensus
//! protocol. Read requests are served straight from the committed-block view;
//! submissions are handed to the node's event loop (which gossips them).

use crate::event::Event;
use crate::frame::{read_frame, write_frame};
use serde::{Deserialize, Serialize};
use slc_crypto::Hash;
use slc_ledger::{Attestation, Block, NotarizationProof};
use std::io;
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::thread;

/// A request from a client.
///
/// `Submit` is far larger than the read variants because a post-quantum
/// attestation carries a ~2 KB ML-DSA public key and a ~3.3 KB signature; that
/// is intrinsic to the scheme, not an oversight.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum RpcRequest {
    /// Submit an attestation to be notarized.
    Submit(Attestation),
    /// Fetch a notarization proof for a notarized document hash, if it exists.
    GetProof(Hash),
    /// Chain status.
    Status,
}

/// A response to a client.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum RpcResponse {
    Submitted { accepted: bool },
    Proof(Box<Option<NotarizationProof>>),
    Status { height: u64, tip: Hash },
    Error(String),
}

/// Start the RPC accept loop on `listener` in a background thread.
pub fn serve(listener: TcpListener, ev_tx: Sender<Event>, committed: Arc<Mutex<Vec<Block>>>) {
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let ev_tx = ev_tx.clone();
            let committed = committed.clone();
            thread::spawn(move || handle_conn(stream, ev_tx, committed));
        }
    });
}

fn handle_conn(mut stream: TcpStream, ev_tx: Sender<Event>, committed: Arc<Mutex<Vec<Block>>>) {
    // One connection may carry many requests until the client hangs up.
    while let Ok(req) = read_frame::<_, RpcRequest>(&mut stream) {
        let resp = match req {
            RpcRequest::Submit(att) => {
                let accepted = att.verify() && ev_tx.send(Event::Submit(att)).is_ok();
                RpcResponse::Submitted { accepted }
            }
            RpcRequest::GetProof(hash) => RpcResponse::Proof(Box::new(find_proof(&committed, hash))),
            RpcRequest::Status => {
                let blocks = committed.lock().unwrap();
                let (height, tip) = blocks
                    .last()
                    .map(|b| (b.header.height, b.header.id()))
                    .unwrap_or((0, Hash::zero()));
                RpcResponse::Status { height, tip }
            }
        };
        if write_frame(&mut stream, &resp).is_err() {
            return;
        }
    }
}

/// Find and build a notarization proof for `hash` from the committed blocks.
fn find_proof(committed: &Arc<Mutex<Vec<Block>>>, hash: Hash) -> Option<NotarizationProof> {
    let blocks = committed.lock().unwrap();
    for block in blocks.iter() {
        if let Some(idx) = block.attestations.iter().position(|a| a.hash == hash) {
            return NotarizationProof::from_block(block, idx);
        }
    }
    None
}

/// A blocking client call: connect, send one request, read one response.
pub fn call(addr: &str, request: &RpcRequest) -> io::Result<RpcResponse> {
    let mut stream = TcpStream::connect(addr)?;
    write_frame(&mut stream, request)?;
    read_frame(&mut stream)
}
