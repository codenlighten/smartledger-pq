//! Runtime peer management: a validator that existing nodes cannot reach is
//! unable to follow the chain; after an operator meshes it in with `add-peer`
//! (no restart), it catches up via block sync and then takes part in finalizing
//! the next block — all on a realistic 4-validator (quorum-3) set.

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

fn wait_len(c: &Arc<Mutex<Vec<Block>>>, n: usize, within: Duration) -> Vec<Block> {
    let deadline = Instant::now() + within;
    loop {
        {
            let b = c.lock().unwrap();
            if b.len() >= n {
                return b.clone();
            }
        }
        assert!(Instant::now() < deadline, "timed out waiting for {n} blocks");
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn add_peer_lets_an_unreachable_validator_rejoin() {
    let _serial = common::serial();

    // Four validators (quorum 3). All four are in genesis.
    let mut tp: Vec<Transport> = Vec::new();
    let mut sk: Vec<SigningKey> = Vec::new();
    let mut pk: Vec<VerifyingKey> = Vec::new();
    for _ in 0..4 {
        let (s, p) = SigningKey::generate().unwrap();
        tp.push(Transport::bind("127.0.0.1:0").unwrap());
        sk.push(s);
        pk.push(p);
    }
    let addrs: Vec<String> = tp.iter().map(|t| t.local_addr().to_string()).collect();
    let genesis = GenesisConfig {
        chain_id: "rejoin".into(),
        validators: pk
            .iter()
            .zip(&addrs)
            .map(|(p, a)| ValidatorInfo { pubkey: p.clone(), addr: a.clone() })
            .collect(),
    };
    let rpc: Vec<String> = (0..4).map(|_| format!("127.0.0.1:{}", free_port())).collect();

    // v0,v1,v2 are fully meshed and can finalize (quorum 3). v3 knows them and
    // can send, but they do NOT know v3 — so v3 receives nothing and can't follow.
    let mut handles: Vec<NodeHandle> = Vec::new();
    for i in 0..4 {
        let mut transport = tp.remove(0);
        let peers = if i < 3 {
            vec![addrs[(i + 1) % 3].clone(), addrs[(i + 2) % 3].clone()]
        } else {
            vec![addrs[0].clone(), addrs[1].clone(), addrs[2].clone()]
        };
        transport.set_peers(peers);
        let s = SigningKey::from_bytes(&sk[i].to_bytes()).unwrap();
        let node = Node::new(transport, &genesis, s, pk[i].clone(), None, Duration::from_millis(500))
            .with_rpc(rpc[i].clone());
        handles.push(node.spawn());
    }
    std::thread::sleep(Duration::from_millis(400));

    // Notarize two documents: v0,v1,v2 finalize; v3 stays at nothing.
    let (c_sk, c_pk) = SigningKey::generate().unwrap();
    let v0c = handles[0].committed();
    let v3c = handles[3].committed();
    for i in 0..2 {
        handles[0].submit(Attestation::create(&c_sk, &c_pk, Hash::digest(format!("d{i}").as_bytes())).unwrap());
        wait_len(&v0c, i + 1, Duration::from_secs(30));
    }
    let chain = v0c.lock().unwrap().clone();
    assert_eq!(chain.len(), 2);
    assert!(v3c.lock().unwrap().is_empty(), "unreachable validator can't follow");

    // Operator meshes v3 into the others at runtime — now they can reach it.
    for r in rpc.iter().take(3) {
        assert!(client::add_peer(r, &addrs[3]).unwrap());
    }

    // v3 catches up to both blocks via block sync...
    let synced = wait_len(&v3c, 2, Duration::from_secs(90));
    for (a, b) in chain.iter().zip(synced.iter()) {
        assert_eq!(a.header.id(), b.header.id());
    }

    // ...and now participates: a third notarization finalizes and v3 has it too.
    handles[0].submit(Attestation::create(&c_sk, &c_pk, Hash::digest(b"d2-after-rejoin")).unwrap());
    let v3_final = wait_len(&v3c, 3, Duration::from_secs(90));
    assert_eq!(v3_final.len(), 3);
    assert_eq!(v3_final[2].header.height, 3);
    // It agrees with the leaders on the new block.
    let leader_final = wait_len(&v0c, 3, Duration::from_secs(30));
    assert_eq!(v3_final[2].header.id(), leader_final[2].header.id());

    for h in handles {
        h.shutdown();
    }
}
