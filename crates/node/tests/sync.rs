//! Block sync / catch-up: a network runs and finalizes several blocks, then a
//! fresh node joins late, is meshed in via `add-peer`, and catches up to the
//! live chain by fetching the finalized blocks it missed.

use slc_crypto::{Hash, SigningKey, VerifyingKey};
use slc_ledger::{Attestation, Block};
use slc_node::client;
use slc_node::config::{GenesisConfig, ValidatorInfo};
use slc_node::{Node, NodeHandle, Transport};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

mod common;

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn wait_len(committed: &Arc<Mutex<Vec<Block>>>, n: usize, within: Duration) -> Vec<Block> {
    let deadline = Instant::now() + within;
    loop {
        {
            let b = committed.lock().unwrap();
            if b.len() >= n {
                return b.clone();
            }
        }
        assert!(Instant::now() < deadline, "timed out waiting for {n} blocks");
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn a_late_node_catches_up_to_the_chain() {
    let _serial = common::serial();
    // Four validators, meshed, each with an RPC.
    let mut v_tp: Vec<Transport> = Vec::new();
    let mut v_sk: Vec<SigningKey> = Vec::new();
    let mut v_pk: Vec<VerifyingKey> = Vec::new();
    for _ in 0..4 {
        let (sk, pk) = SigningKey::generate().unwrap();
        v_tp.push(Transport::bind("127.0.0.1:0").unwrap());
        v_sk.push(sk);
        v_pk.push(pk);
    }
    let v_addrs: Vec<String> = v_tp.iter().map(|t| t.local_addr().to_string()).collect();
    let genesis = GenesisConfig {
        chain_id: "sync-test".into(),
        validators: v_pk
            .iter()
            .zip(&v_addrs)
            .map(|(pk, addr)| ValidatorInfo { pubkey: pk.clone(), addr: addr.clone() })
            .collect(),
    };
    let v_rpc: Vec<String> = (0..4).map(|_| format!("127.0.0.1:{}", free_port())).collect();

    let mut handles: Vec<NodeHandle> = Vec::new();
    for i in 0..4 {
        let mut transport = v_tp.remove(0);
        transport.set_peers(genesis.peer_addrs(&v_pk[i]));
        let sk = SigningKey::from_bytes(&v_sk[i].to_bytes()).unwrap();
        let node = Node::new(transport, &genesis, sk, v_pk[i].clone(), None, Duration::from_millis(500))
            .with_rpc(v_rpc[i].clone());
        handles.push(node.spawn());
    }
    std::thread::sleep(Duration::from_millis(400));

    // Notarize four documents → four finalized blocks.
    let (c_sk, c_pk) = SigningKey::generate().unwrap();
    let node0_committed = handles[0].committed();
    for i in 0..4 {
        handles[0].submit(Attestation::create(&c_sk, &c_pk, Hash::digest(format!("d{i}").as_bytes())).unwrap());
        wait_len(&node0_committed, i + 1, Duration::from_secs(30));
    }
    let chain = node0_committed.lock().unwrap().clone();
    assert_eq!(chain.len(), 4);

    // A fresh node joins late: same genesis (so it is a follower), peered to the
    // validators, starting from height 1 with no blocks.
    let mut follower_tp = Transport::bind("127.0.0.1:0").unwrap();
    let follower_p2p = follower_tp.local_addr().to_string();
    follower_tp.set_peers(v_addrs.clone());
    let (f_sk, f_pk) = SigningKey::generate().unwrap();
    let follower = Node::new(follower_tp, &genesis, f_sk, f_pk, None, Duration::from_millis(500));
    let follower_handle = follower.spawn();
    let follower_committed = follower_handle.committed();

    // Mesh the follower into each validator at runtime, so they can send to it.
    for rpc in &v_rpc {
        assert!(client::add_peer(rpc, &follower_p2p).unwrap());
    }

    // The follower catches up to all four finalized blocks purely by sync.
    let synced = wait_len(&follower_committed, 4, Duration::from_secs(90));
    assert_eq!(synced.len(), 4, "follower did not catch up");

    // It synced the *real* chain: identical block ids in order.
    for (a, b) in chain.iter().zip(synced.iter()) {
        assert_eq!(a.header.id(), b.header.id(), "synced block mismatch at height {}", a.header.height);
    }

    // And the follower reports the caught-up height over RPC-less committed view.
    assert_eq!(synced.last().unwrap().header.height, 4);

    follower_handle.shutdown();
    for h in handles {
        h.shutdown();
    }
}
