//! The anchored-proof RPC: a client fetches a BSV-hardened proof (notarization +
//! checkpoint inclusion + published receipt) and verifies it offline. Also
//! checks the "notarized but not yet anchored" state before a checkpoint closes.

use slc_anchor::{AnchorService, MockAnchor};
use slc_crypto::{Hash, SigningKey, VerifyingKey};
use slc_node::client;
use slc_node::config::{GenesisConfig, ValidatorInfo};
use slc_node::{Node, NodeHandle, Transport};
use std::net::TcpListener;
use std::time::{Duration, Instant};

const INTERVAL: usize = 2;

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn wait_notarized(rpc: &str, hash: Hash) {
    let deadline = Instant::now() + Duration::from_secs(60);
    while client::get_proof(rpc, hash).unwrap().is_none() {
        assert!(Instant::now() < deadline, "timed out waiting for notarization");
        std::thread::sleep(Duration::from_millis(80));
    }
}

#[test]
fn anchored_proof_over_rpc() {
    let mut prep: Vec<(Transport, SigningKey, VerifyingKey)> = Vec::new();
    for _ in 0..4 {
        let (sk, pk) = SigningKey::generate().unwrap();
        prep.push((Transport::bind("127.0.0.1:0").unwrap(), sk, pk));
    }
    let genesis = GenesisConfig {
        chain_id: "smartledger-anchored-rpc".into(),
        validators: prep
            .iter()
            .map(|(t, _, pk)| ValidatorInfo {
                pubkey: pk.clone(),
                addr: t.local_addr().to_string(),
            })
            .collect(),
    };

    let rpc_addr = format!("127.0.0.1:{}", free_port());
    let mut nodes = Vec::new();
    for (i, (mut transport, sk, pk)) in prep.into_iter().enumerate() {
        transport.set_peers(genesis.peer_addrs(&pk));
        let mut node = Node::new(transport, &genesis, sk, pk, None, Duration::from_millis(1200));
        if i == 0 {
            node = node
                .with_anchor(AnchorService::new(Box::new(MockAnchor::new()), INTERVAL))
                .with_rpc(rpc_addr.clone());
        }
        nodes.push(node);
    }
    let handles: Vec<NodeHandle> = nodes.into_iter().map(Node::spawn).collect();
    std::thread::sleep(Duration::from_millis(400));

    let (c_sk, c_pk) = SigningKey::generate().unwrap();
    let doc0 = Hash::digest(b"anchored-rpc-doc-0");
    let doc1 = Hash::digest(b"anchored-rpc-doc-1");

    // Notarize the first document; it is notarized but NOT yet anchored
    // (checkpoint window of 2 has not closed).
    assert!(client::notarize(&rpc_addr, &c_sk, &c_pk, doc0).unwrap());
    wait_notarized(&rpc_addr, doc0);
    assert!(
        client::get_anchored_proof(&rpc_addr, doc0).unwrap().is_none(),
        "should not be anchored before the checkpoint closes"
    );

    // Notarize the second document → closes the checkpoint over blocks 1..=2.
    assert!(client::notarize(&rpc_addr, &c_sk, &c_pk, doc1).unwrap());
    wait_notarized(&rpc_addr, doc1);

    // Now both documents have BSV-hardened anchored proofs.
    let deadline = Instant::now() + Duration::from_secs(60);
    let anchored0 = loop {
        if let Some(p) = client::get_anchored_proof(&rpc_addr, doc0).unwrap() {
            break p;
        }
        assert!(Instant::now() < deadline, "timed out waiting for anchor");
        std::thread::sleep(Duration::from_millis(100));
    };

    assert!(client::verify_anchored_proof(&anchored0, &genesis), "anchored proof must verify");
    assert_eq!(anchored0.notarization.hash(), doc0);
    assert_eq!(anchored0.record.from_height, 1);
    assert_eq!(anchored0.record.to_height, INTERVAL as u64);
    assert_eq!(anchored0.record.receipt.backend, "mock");

    // The second document too.
    let anchored1 = client::get_anchored_proof(&rpc_addr, doc1).unwrap().unwrap();
    assert!(client::verify_anchored_proof(&anchored1, &genesis));
    assert_eq!(anchored1.notarization.hash(), doc1);

    // Tampering with the published root is rejected.
    let mut tampered = anchored0.clone();
    tampered.record.checkpoint_root = Hash::digest(b"forged");
    assert!(!client::verify_anchored_proof(&tampered, &genesis));

    for h in handles {
        h.shutdown();
    }
}
