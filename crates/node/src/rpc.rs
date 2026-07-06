//! Client-facing RPC over TCP (framed JSON). External clients submit
//! attestations and fetch notarization proofs without speaking the consensus
//! protocol. Read requests are served straight from the committed-block view;
//! submissions are handed to the node's event loop (which gossips them).

use crate::event::Event;
use crate::frame::{read_frame, write_frame};
use crate::meter::Meter;
use serde::{Deserialize, Serialize};
use slc_anchor::{AnchorService, AnchoredProof};
use slc_crypto::{Hash, VerifyingKey};
use slc_ledger::{Attestation, Block, NotarizationProof, SignedValidatorChange};
use std::io;
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

/// The optional shared anchoring service the RPC reads to build anchored proofs.
type SharedAnchor = Option<Arc<Mutex<AnchorService>>>;
/// The optional shared notarization meter enforcing the licensed volume.
type SharedMeter = Option<Arc<Mutex<Meter>>>;

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

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
    /// Submit a quorum-authorized validator-set change (operator action).
    SubmitGovernance(SignedValidatorChange),
    /// Add a peer address at runtime (operator action).
    AddPeer(String),
    /// Fetch a notarization proof for a notarized document hash, if it exists.
    GetProof(Hash),
    /// Fetch a BSV-hardened anchored proof, if the block has been anchored.
    GetAnchoredProof(Hash),
    /// Chain status.
    Status,
    /// This node's identity (chain id + public key) and chain tip.
    NodeInfo,
    /// Notarization usage against the licensed monthly volume.
    Usage,
}

/// A response to a client.
///
/// Variant sizes differ because post-quantum objects (public keys ~2 KB) are
/// large; that is intrinsic to the scheme.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum RpcResponse {
    Submitted { accepted: bool },
    Proof(Box<Option<NotarizationProof>>),
    AnchoredProof(Box<Option<AnchoredProof>>),
    Status { height: u64, tip: Hash },
    NodeInfo { chain_id: String, pubkey: VerifyingKey, height: u64, tip: Hash },
    Usage { count: u64, cap: Option<u64>, window_start: u64, window_secs: u64 },
    Error(String),
}

/// Start the RPC accept loop on `listener` in a background thread.
#[allow(clippy::too_many_arguments)]
pub fn serve(
    listener: TcpListener,
    ev_tx: Sender<Event>,
    committed: Arc<Mutex<Vec<Block>>>,
    anchor: SharedAnchor,
    chain_id: String,
    pubkey: VerifyingKey,
    meter: SharedMeter,
) {
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let ev_tx = ev_tx.clone();
            let committed = committed.clone();
            let anchor = anchor.clone();
            let chain_id = chain_id.clone();
            let pubkey = pubkey.clone();
            let meter = meter.clone();
            thread::spawn(move || {
                handle_conn(stream, ev_tx, committed, anchor, chain_id, pubkey, meter)
            });
        }
    });
}

#[allow(clippy::too_many_arguments)]
fn handle_conn(
    mut stream: TcpStream,
    ev_tx: Sender<Event>,
    committed: Arc<Mutex<Vec<Block>>>,
    anchor: SharedAnchor,
    chain_id: String,
    pubkey: VerifyingKey,
    meter: SharedMeter,
) {
    // One connection may carry many requests until the client hangs up.
    while let Ok(req) = read_frame::<_, RpcRequest>(&mut stream) {
        let resp = match req {
            RpcRequest::Submit(att) => {
                if !att.verify() {
                    RpcResponse::Submitted { accepted: false }
                } else if !record_usage(&meter) {
                    RpcResponse::Error("licensed notarization volume exceeded".into())
                } else {
                    let accepted = ev_tx.send(Event::Submit(att)).is_ok();
                    RpcResponse::Submitted { accepted }
                }
            }
            RpcRequest::SubmitGovernance(change) => {
                // Authorization is validated by the engine against the current
                // set; here we only forward it into the loop.
                let accepted = ev_tx.send(Event::SubmitGovernance(change)).is_ok();
                RpcResponse::Submitted { accepted }
            }
            RpcRequest::AddPeer(addr) => {
                let accepted = ev_tx.send(Event::AddPeer(addr)).is_ok();
                RpcResponse::Submitted { accepted }
            }
            RpcRequest::GetProof(hash) => RpcResponse::Proof(Box::new(find_proof(&committed, hash))),
            RpcRequest::GetAnchoredProof(hash) => {
                RpcResponse::AnchoredProof(Box::new(find_anchored_proof(&committed, &anchor, hash)))
            }
            RpcRequest::Status => {
                let blocks = committed.lock().unwrap();
                let (height, tip) = blocks
                    .last()
                    .map(|b| (b.header.height, b.header.id()))
                    .unwrap_or((0, Hash::zero()));
                RpcResponse::Status { height, tip }
            }
            RpcRequest::NodeInfo => {
                let blocks = committed.lock().unwrap();
                let (height, tip) = blocks
                    .last()
                    .map(|b| (b.header.height, b.header.id()))
                    .unwrap_or((0, Hash::zero()));
                RpcResponse::NodeInfo {
                    chain_id: chain_id.clone(),
                    pubkey: pubkey.clone(),
                    height,
                    tip,
                }
            }
            RpcRequest::Usage => match &meter {
                Some(m) => {
                    let (count, cap, window_start, window_secs) = m.lock().unwrap().status();
                    RpcResponse::Usage { count, cap, window_start, window_secs }
                }
                None => RpcResponse::Usage { count: 0, cap: None, window_start: 0, window_secs: 0 },
            },
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

/// Build a BSV-hardened anchored proof for `hash`: the notarization proof plus
/// the checkpoint inclusion and published receipt — but only once the block has
/// actually been anchored.
fn find_anchored_proof(
    committed: &Arc<Mutex<Vec<Block>>>,
    anchor: &SharedAnchor,
    hash: Hash,
) -> Option<AnchoredProof> {
    let proof = find_proof(committed, hash)?;
    let service = anchor.as_ref()?;
    service.lock().unwrap().anchor_proof(proof)
}

/// Record one notarization against the meter (if any). Returns whether it is
/// within the licensed volume; always `true` when unmetered.
fn record_usage(meter: &SharedMeter) -> bool {
    match meter {
        Some(m) => m.lock().unwrap().try_record(now_secs()),
        None => true,
    }
}

/// A blocking client call: connect, send one request, read one response.
pub fn call(addr: &str, request: &RpcRequest) -> io::Result<RpcResponse> {
    let mut stream = TcpStream::connect(addr)?;
    write_frame(&mut stream, request)?;
    read_frame(&mut stream)
}
