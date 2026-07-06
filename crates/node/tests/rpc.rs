//! Client RPC over TCP: a client that speaks no consensus protocol submits an
//! attestation to one node and fetches a verifiable notarization proof back.

use slc_crypto::{Hash, SigningKey, VerifyingKey};
use slc_ledger::{Attestation, ValidatorSet};
use slc_node::config::{GenesisConfig, ValidatorInfo};
use slc_node::rpc::{call, RpcRequest, RpcResponse};
use slc_node::{Node, NodeHandle, Transport};
use std::net::TcpListener;
use std::time::{Duration, Instant};

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

#[test]
fn client_rpc_submit_then_fetch_proof() {
    // Four validators; node 0 also exposes a client RPC.
    let mut prep: Vec<(Transport, SigningKey, VerifyingKey)> = Vec::new();
    for _ in 0..4 {
        let (sk, pk) = SigningKey::generate().unwrap();
        prep.push((Transport::bind("127.0.0.1:0").unwrap(), sk, pk));
    }
    let genesis = GenesisConfig {
        chain_id: "smartledger-rpc".into(),
        validators: prep
            .iter()
            .map(|(t, _, pk)| ValidatorInfo {
                pubkey: pk.clone(),
                addr: t.local_addr().to_string(),
            })
            .collect(),
    };
    let set = ValidatorSet::bft(genesis.validator_keys());

    let rpc_addr = format!("127.0.0.1:{}", free_port());
    let mut nodes = Vec::new();
    for (i, (mut transport, sk, pk)) in prep.into_iter().enumerate() {
        transport.set_peers(genesis.peer_addrs(&pk));
        let mut node = Node::new(transport, &genesis, sk, pk, None, Duration::from_millis(1200));
        if i == 0 {
            node = node.with_rpc(rpc_addr.clone());
        }
        nodes.push(node);
    }
    let handles: Vec<NodeHandle> = nodes.into_iter().map(Node::spawn).collect();
    std::thread::sleep(Duration::from_millis(400)); // mesh connect + RPC bind

    // The client hashes and signs locally, then submits over RPC.
    let (c_sk, c_pk) = SigningKey::generate().unwrap();
    let doc_hash = Hash::digest(b"rpc-notarized-doc");
    let att = Attestation::create(&c_sk, &c_pk, doc_hash).unwrap();
    match call(&rpc_addr, &RpcRequest::Submit(att)).unwrap() {
        RpcResponse::Submitted { accepted } => assert!(accepted, "submit rejected"),
        other => panic!("unexpected submit response: {other:?}"),
    }

    // Poll GetProof until the document is notarized, then verify offline.
    let deadline = Instant::now() + Duration::from_secs(60);
    let proof = loop {
        if let RpcResponse::Proof(p) = call(&rpc_addr, &RpcRequest::GetProof(doc_hash)).unwrap() {
            if let Some(proof) = *p {
                break proof;
            }
        }
        assert!(Instant::now() < deadline, "timed out waiting for proof");
        std::thread::sleep(Duration::from_millis(100));
    };
    proof.verify(&set).expect("RPC-served proof must verify");
    assert_eq!(proof.hash(), doc_hash);

    // Status reflects a live chain.
    match call(&rpc_addr, &RpcRequest::Status).unwrap() {
        RpcResponse::Status { height, .. } => assert!(height >= 1),
        other => panic!("unexpected status response: {other:?}"),
    }

    for h in handles {
        h.shutdown();
    }
}
