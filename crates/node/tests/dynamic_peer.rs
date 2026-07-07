//! Runtime peer management: two isolated validators can't finalize; after an
//! operator adds them to each other at runtime (no restart), the network
//! converges and notarizes.

use slc_crypto::{Hash, SigningKey, VerifyingKey};
use slc_ledger::Attestation;
use slc_node::client;
use slc_node::config::{GenesisConfig, ValidatorInfo};
use slc_node::{Node, NodeHandle, Transport};
use std::net::TcpListener;
use std::time::{Duration, Instant};

mod common;

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

#[test]
fn add_peer_unsticks_a_disconnected_network() {
    let _serial = common::serial();
    // Two validators, each bound, each with its own RPC — but NO peers, so
    // nothing can flow between them.
    let mut prep: Vec<(Transport, SigningKey, VerifyingKey, String)> = Vec::new();
    for _ in 0..2 {
        let (sk, pk) = SigningKey::generate().unwrap();
        let t = Transport::bind("127.0.0.1:0").unwrap();
        let addr = t.local_addr().to_string();
        prep.push((t, sk, pk, addr));
    }
    let p2p_addrs: Vec<String> = prep.iter().map(|(_, _, _, a)| a.clone()).collect();
    let genesis = GenesisConfig {
        chain_id: "dynpeer".into(),
        validators: prep
            .iter()
            .map(|(_, _, pk, addr)| ValidatorInfo { pubkey: pk.clone(), addr: addr.clone() })
            .collect(),
    };

    let rpc_addrs: Vec<String> = (0..2).map(|_| format!("127.0.0.1:{}", free_port())).collect();
    let mut handles: Vec<NodeHandle> = Vec::new();
    for (i, (mut transport, sk, pk, _)) in prep.into_iter().enumerate() {
        transport.set_peers(vec![]); // deliberately isolated
        let node = Node::new(transport, &genesis, sk, pk, None, Duration::from_millis(500))
            .with_rpc(rpc_addrs[i].clone());
        handles.push(node.spawn());
    }
    std::thread::sleep(Duration::from_millis(400));

    // Submit a document to node 0. It cannot finalize (quorum is 2, and no
    // messages can reach node 1).
    let (c_sk, c_pk) = SigningKey::generate().unwrap();
    let target = Hash::digest(b"dynamic-peer-doc");
    handles[0].submit(Attestation::create(&c_sk, &c_pk, target).unwrap());

    let observers: Vec<_> = handles.iter().map(|h| h.committed()).collect();
    std::thread::sleep(Duration::from_secs(2));
    assert!(
        observers.iter().all(|o| o.lock().unwrap().is_empty()),
        "isolated validators must not finalize"
    );

    // Operator meshes them at runtime — no restart.
    assert!(client::add_peer(&rpc_addrs[0], &p2p_addrs[1]).unwrap());
    assert!(client::add_peer(&rpc_addrs[1], &p2p_addrs[0]).unwrap());

    // Now the network converges (re-gossip re-delivers the stuck round's
    // messages) and notarizes. Generous deadline: the full suite runs CPU-heavy
    // SLH-DSA tests in parallel that can starve this timing-sensitive scenario.
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        let done = observers
            .iter()
            .all(|o| o.lock().unwrap().iter().any(|b| b.attestations.iter().any(|a| a.hash == target)));
        if done {
            break;
        }
        assert!(Instant::now() < deadline, "network did not converge after add-peer");
        std::thread::sleep(Duration::from_millis(100));
    }

    for h in handles {
        h.shutdown();
    }
}
