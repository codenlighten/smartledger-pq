//! Client-side helpers: hash a file, notarize it against a node's RPC, fetch a
//! proof, and verify a proof offline against a genesis. The `slc` binary is a
//! thin wrapper over these; keeping them here makes the client path testable.

use crate::config::GenesisConfig;
use crate::rpc::{call, RpcRequest, RpcResponse};
use slc_anchor::AnchoredProof;
use slc_crypto::{context, Hash, SigningKey, VerifyingKey};
use slc_ledger::{Attestation, NotarizationProof, SignedValidatorChange, ValidatorSet};
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

/// Fetch a BSV-hardened anchored proof for `doc_hash`, if the block has been
/// anchored yet.
pub fn get_anchored_proof(node_rpc: &str, doc_hash: Hash) -> io::Result<Option<AnchoredProof>> {
    match call(node_rpc, &RpcRequest::GetAnchoredProof(doc_hash))? {
        RpcResponse::AnchoredProof(p) => Ok(*p),
        RpcResponse::Error(e) => Err(other(e)),
        _ => Err(other("unexpected response to get-anchored-proof")),
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

/// A node's identity: chain id, public key, height, tip.
pub fn node_info(node_rpc: &str) -> io::Result<(String, VerifyingKey, u64, Hash)> {
    match call(node_rpc, &RpcRequest::NodeInfo)? {
        RpcResponse::NodeInfo { chain_id, pubkey, height, tip } => Ok((chain_id, pubkey, height, tip)),
        RpcResponse::Error(e) => Err(other(e)),
        _ => Err(other("unexpected response to node-info")),
    }
}

/// Verify a proof offline against the validator set defined by `genesis`.
pub fn verify_proof(proof: &NotarizationProof, genesis: &GenesisConfig) -> bool {
    let set = ValidatorSet::bft(genesis.validator_keys());
    proof.verify(&set).is_ok()
}

/// Verify an anchored proof offline against `genesis`: the notarization, the
/// checkpoint inclusion, and the published receipt.
pub fn verify_anchored_proof(proof: &AnchoredProof, genesis: &GenesisConfig) -> bool {
    let set = ValidatorSet::bft(genesis.validator_keys());
    proof.verify(&set).is_ok()
}

/// Add a validator's approval signature to a proposed change (in place).
pub fn approve_change(signed: &mut SignedValidatorChange, sk: &SigningKey, pk: &VerifyingKey) {
    let sig = sk
        .sign(&signed.change.signing_bytes(), context::GOVERNANCE)
        .expect("sign governance change");
    signed.approve(pk.clone(), sig);
}

/// Submit an authorized validator-set change to a node.
pub fn submit_governance(node_rpc: &str, signed: &SignedValidatorChange) -> io::Result<bool> {
    match call(node_rpc, &RpcRequest::SubmitGovernance(signed.clone()))? {
        RpcResponse::Submitted { accepted } => Ok(accepted),
        RpcResponse::Error(e) => Err(io::Error::other(e)),
        _ => Err(io::Error::other("unexpected response to submit-governance")),
    }
}
