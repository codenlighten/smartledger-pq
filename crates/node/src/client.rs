//! Client-side helpers: hash a file, notarize it against a node's RPC, fetch a
//! proof, and verify a proof offline against a genesis. The `slc` binary is a
//! thin wrapper over these; keeping them here makes the client path testable.

use crate::config::GenesisConfig;
use crate::rpc::{call, RpcRequest, RpcResponse};
use slc_crypto::{Hash, SigningKey, VerifyingKey};
use slc_ledger::{Attestation, NotarizationProof, ValidatorSet};
use std::io;
use std::path::Path;

fn other(msg: impl Into<String>) -> io::Error {
    io::Error::other(msg.into())
}

/// The SHA3-256 commitment to a file's contents.
pub fn hash_file(path: &Path) -> io::Result<Hash> {
    let bytes = std::fs::read(path)?;
    Ok(Hash::digest(&bytes))
}

/// Sign `doc_hash` and submit it to `node_rpc` for notarization.
pub fn notarize(
    node_rpc: &str,
    signing_key: &SigningKey,
    public_key: &VerifyingKey,
    doc_hash: Hash,
) -> io::Result<bool> {
    let att = Attestation::create(signing_key, public_key, doc_hash)
        .map_err(|e| other(format!("attestation: {e}")))?;
    match call(node_rpc, &RpcRequest::Submit(att))? {
        RpcResponse::Submitted { accepted } => Ok(accepted),
        RpcResponse::Error(e) => Err(other(e)),
        _ => Err(other("unexpected response to submit")),
    }
}

/// Fetch a notarization proof for `doc_hash`, if the node has one.
pub fn get_proof(node_rpc: &str, doc_hash: Hash) -> io::Result<Option<NotarizationProof>> {
    match call(node_rpc, &RpcRequest::GetProof(doc_hash))? {
        RpcResponse::Proof(p) => Ok(*p),
        RpcResponse::Error(e) => Err(other(e)),
        _ => Err(other("unexpected response to get-proof")),
    }
}

/// The chain height and tip reported by a node.
pub fn status(node_rpc: &str) -> io::Result<(u64, Hash)> {
    match call(node_rpc, &RpcRequest::Status)? {
        RpcResponse::Status { height, tip } => Ok((height, tip)),
        RpcResponse::Error(e) => Err(other(e)),
        _ => Err(other("unexpected response to status")),
    }
}

/// Verify a proof offline against the validator set defined by `genesis`.
pub fn verify_proof(proof: &NotarizationProof, genesis: &GenesisConfig) -> bool {
    let set = ValidatorSet::bft(genesis.validator_keys());
    proof.verify(&set).is_ok()
}
