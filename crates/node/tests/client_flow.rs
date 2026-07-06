//! The client path end to end (in-process): notarize via a node's RPC, fetch a
//! proof, and verify it offline against the genesis — plus a negative check that
//! it fails against a different validator set.

use slc_crypto::{Hash, SigningKey, VerifyingKey};
use slc_node::client;
use slc_node::config::{GenesisConfig, ValidatorInfo};
use slc_node::{Node, NodeHandle, Transport};
use std::net::TcpListener;
use std::time::{Duration, Instant};

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn genesis_from(prep: &[(Transport, SigningKey, VerifyingKey)]) -> GenesisConfig {
    GenesisConfig {
        chain_id: "smartledger-client".into(),
        validators: prep
            .iter()
            .map(|(t, _, pk)| ValidatorInfo {
                pubkey: pk.clone(),
                addr: t.local_addr().to_string(),
            })
            .collect(),
    }
}

#[test]
fn notarize_fetch_and_verify_via_client() {
    let mut prep: Vec<(Transport, SigningKey, VerifyingKey)> = Vec::new();
    for _ in 0..4 {
        let (sk, pk) = SigningKey::generate().unwrap();
        prep.push((Transport::bind("127.0.0.1:0").unwrap(), sk, pk));
    }
    let genesis = genesis_from(&prep);
    let rpc_addr = format!("127.0.0.1:{}", free_port());

    let mut nodes = Vec::new();
    for (i, (mut transport, sk, pk)) in prep.into_iter().enumerate() {
        transport.set_peers(genesis.peer_addrs(&pk));
        let mut node = Node::new(transport, &genesis, sk, pk, None, Duration::from_millis(300));
        if i == 0 {
            node = node.with_rpc(rpc_addr.clone());
        }
        nodes.push(node);
    }
    let handles: Vec<NodeHandle> = nodes.into_iter().map(Node::spawn).collect();
    std::thread::sleep(Duration::from_millis(400));

    // Client notarizes a "document" (any bytes hashed locally).
    let (c_sk, c_pk) = SigningKey::generate().unwrap();
    let doc_hash = Hash::digest(b"quarterly-report-Q2-2026.pdf");
    assert!(client::notarize(&rpc_addr, &c_sk, &c_pk, doc_hash).unwrap());

    // Fetch the proof.
    let deadline = Instant::now() + Duration::from_secs(30);
    let proof = loop {
        if let Some(p) = client::get_proof(&rpc_addr, doc_hash).unwrap() {
            break p;
        }
        assert!(Instant::now() < deadline, "timed out");
        std::thread::sleep(Duration::from_millis(100));
    };

    // Verifies against the real genesis...
    assert!(client::verify_proof(&proof, &genesis), "should verify against genesis");
    assert_eq!(proof.hash(), doc_hash);

    // ...and does NOT verify against a different validator set.
    let (_s, other_pk) = SigningKey::generate().unwrap();
    let wrong_genesis = GenesisConfig {
        chain_id: "impostor".into(),
        validators: vec![ValidatorInfo {
            pubkey: other_pk,
            addr: "127.0.0.1:1".into(),
        }],
    };
    assert!(!client::verify_proof(&proof, &wrong_genesis), "must reject wrong validators");

    let (height, _tip) = client::status(&rpc_addr).unwrap();
    assert!(height >= 1);

    for h in handles {
        h.shutdown();
    }
}
