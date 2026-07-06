//! A real 4-node devnet over TCP loopback. Submit an attestation to one node
//! and assert every node independently finalizes, persists, and agrees on a
//! block containing it — with a valid quorum certificate and an extractable
//! notarization proof.

use slc_crypto::{Hash, SigningKey, VerifyingKey};
use slc_ledger::{Attestation, Block, NotarizationProof, ValidatorSet};
use slc_node::config::{GenesisConfig, ValidatorInfo};
use slc_node::{Node, NodeHandle, Transport};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

fn block_with_hash(blocks: &Arc<Mutex<Vec<Block>>>, target: Hash) -> Option<Block> {
    blocks
        .lock()
        .unwrap()
        .iter()
        .find(|b| b.attestations.iter().any(|a| a.hash == target))
        .cloned()
}

#[test]
fn four_node_devnet_notarizes_over_tcp() {
    // 1. Four validators, each with a bound loopback listener.
    let mut prep: Vec<(Transport, SigningKey, VerifyingKey)> = Vec::new();
    for _ in 0..4 {
        let (sk, pk) = SigningKey::generate().unwrap();
        let t = Transport::bind("127.0.0.1:0").expect("bind loopback");
        prep.push((t, sk, pk));
    }

    // 2. A shared genesis naming every validator and its address.
    let genesis = GenesisConfig {
        chain_id: "smartledger-devnet".into(),
        validators: prep
            .iter()
            .map(|(t, _, pk)| ValidatorInfo {
                pubkey: pk.clone(),
                addr: t.local_addr().to_string(),
            })
            .collect(),
    };
    let set = ValidatorSet::bft(genesis.validator_keys());

    // 3. Build every node (starts its accept loop) before spawning any run loop,
    //    so all listeners are up before the first proposal goes out.
    let mut nodes = Vec::new();
    for (mut transport, sk, pk) in prep {
        transport.set_peers(genesis.peer_addrs(&pk));
        nodes.push(Node::new(
            transport,
            &genesis,
            sk,
            pk,
            None,
            Duration::from_millis(300),
        ));
    }
    let handles: Vec<NodeHandle> = nodes.into_iter().map(Node::spawn).collect();

    // 4. A client notarizes a document by submitting to node 0.
    let (client_sk, client_pk) = SigningKey::generate().unwrap();
    let target = Hash::digest(b"devnet-notarized-document");
    let att = Attestation::create(&client_sk, &client_pk, target).unwrap();
    std::thread::sleep(Duration::from_millis(300)); // let the mesh connect
    handles[0].submit(att);

    // 5. Wait until every node has finalized a block containing it.
    let observers: Vec<_> = handles.iter().map(|h| h.committed()).collect();
    let deadline = Instant::now() + Duration::from_secs(30);
    let found: Vec<Block> = loop {
        let seen: Vec<Option<Block>> = observers
            .iter()
            .map(|o| block_with_hash(o, target))
            .collect();
        if seen.iter().all(Option::is_some) {
            break seen.into_iter().map(Option::unwrap).collect();
        }
        assert!(
            Instant::now() < deadline,
            "timed out before all nodes notarized the document"
        );
        std::thread::sleep(Duration::from_millis(50));
    };

    // 6. All nodes agree on the same block, its QC is valid, and a real
    //    notarization proof verifies against the validator set.
    let block0 = &found[0];
    for b in &found {
        assert_eq!(b.header.id(), block0.header.id(), "nodes disagree on the block");
    }
    block0
        .qc
        .verify(&block0.header, &set)
        .expect("finalized block carries a valid quorum certificate");

    let idx = block0
        .attestations
        .iter()
        .position(|a| a.hash == target)
        .unwrap();
    let proof = NotarizationProof::from_block(block0, idx).unwrap();
    proof.verify(&set).expect("notarization proof verifies");
    assert_eq!(proof.hash(), target);
    assert!(block0.header.height >= 1);

    // 7. The idle chain mints no empty blocks. Let it run a moment longer with
    //    nothing to notarize, then assert every committed block is non-empty and
    //    the chain has not ballooned — production is strictly attestation-driven.
    std::thread::sleep(Duration::from_millis(400));
    for o in &observers {
        let blocks = o.lock().unwrap();
        assert!(
            blocks.iter().all(|b| !b.attestations.is_empty()),
            "no block may be empty — blocks exist only to notarize"
        );
        assert!(
            blocks.len() <= 3,
            "an idle chain must not spew blocks (saw {})",
            blocks.len()
        );
    }

    for h in handles {
        h.shutdown();
    }
}
