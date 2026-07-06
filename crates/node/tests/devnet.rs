//! A real 4-node devnet over TCP loopback. Submit an attestation to one node
//! and assert every node independently finalizes, persists, and agrees on a
//! block containing it — with a valid quorum certificate and an extractable
//! notarization proof.

use slc_crypto::{Hash, SigningKey, VerifyingKey};
use slc_ledger::{Attestation, Block, NotarizationProof, ValidatorSet};
use slc_node::config::{GenesisConfig, ValidatorInfo};
use slc_node::{Node, NodeHandle, Transport};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

type Observer = Arc<Mutex<Vec<Block>>>;

fn block_with_hash(blocks: &Observer, target: Hash) -> Option<Block> {
    blocks
        .lock()
        .unwrap()
        .iter()
        .find(|b| b.attestations.iter().any(|a| a.hash == target))
        .cloned()
}

/// Poll every observer until each has finalized a block containing `target`,
/// returning node 0's copy. Panics on timeout.
fn wait_all(observers: &[Observer], target: Hash, within: Duration) -> Block {
    let deadline = Instant::now() + within;
    loop {
        if observers.iter().all(|o| block_with_hash(o, target).is_some()) {
            return block_with_hash(&observers[0], target).unwrap();
        }
        assert!(Instant::now() < deadline, "timed out waiting for all nodes");
        std::thread::sleep(Duration::from_millis(50));
    }
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
            Duration::from_millis(1200),
        ));
    }
    let handles: Vec<NodeHandle> = nodes.into_iter().map(Node::spawn).collect();

    // 4. A client notarizes a document by submitting to node 0.
    let (client_sk, client_pk) = SigningKey::generate().unwrap();
    let target = Hash::digest(b"devnet-notarized-document");
    let att = Attestation::create(&client_sk, &client_pk, target).unwrap();
    std::thread::sleep(Duration::from_millis(1200)); // let the mesh connect
    handles[0].submit(att);

    // 5. Wait until every node has finalized a block containing it.
    let observers: Vec<_> = handles.iter().map(|h| h.committed()).collect();
    let deadline = Instant::now() + Duration::from_secs(60);
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

/// Spawn a fresh 4-node network over new loopback ports, but with the given
/// persistent validator keys and per-node store paths (so a network can be torn
/// down and brought back up on the same on-disk chain).
fn spawn_net(
    dir: &Path,
    val_keys: &[(Vec<u8>, VerifyingKey)],
    timeout: Duration,
) -> (Vec<NodeHandle>, ValidatorSet) {
    let mut prep: Vec<(Transport, SigningKey, VerifyingKey)> = Vec::new();
    for (sk_bytes, pk) in val_keys {
        let sk = SigningKey::from_bytes(sk_bytes).unwrap();
        let t = Transport::bind("127.0.0.1:0").unwrap();
        prep.push((t, sk, pk.clone()));
    }
    let genesis = GenesisConfig {
        chain_id: "smartledger-resume".into(),
        validators: prep
            .iter()
            .map(|(t, _, pk)| ValidatorInfo {
                pubkey: pk.clone(),
                addr: t.local_addr().to_string(),
            })
            .collect(),
    };
    let set = ValidatorSet::bft(genesis.validator_keys());
    let mut nodes = Vec::new();
    for (i, (mut transport, sk, pk)) in prep.into_iter().enumerate() {
        transport.set_peers(genesis.peer_addrs(&pk));
        let path = dir.join(format!("node{i}.blocks"));
        nodes.push(Node::new(transport, &genesis, sk, pk, Some(&path), timeout));
    }
    let handles = nodes.into_iter().map(Node::spawn).collect();
    (handles, set)
}

#[test]
fn restart_resumes_and_chains_across_reboot() {
    // A private per-run scratch dir for the on-disk chain.
    let dir = std::env::temp_dir().join(format!("slc-resume-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    // Four validators whose keys persist across the reboot.
    let val_keys: Vec<(Vec<u8>, VerifyingKey)> = (0..4)
        .map(|_| {
            let (sk, pk) = SigningKey::generate().unwrap();
            (sk.to_bytes().to_vec(), pk)
        })
        .collect();

    let (client_sk, client_pk) = SigningKey::generate().unwrap();

    // --- Boot 1: notarize document A, then shut the whole network down. ---
    let (handles, _set) = spawn_net(&dir, &val_keys, Duration::from_millis(1200));
    let observers: Vec<Observer> = handles.iter().map(|h| h.committed()).collect();
    std::thread::sleep(Duration::from_millis(1200));
    let hash_a = Hash::digest(b"doc-A-before-reboot");
    handles[0].submit(Attestation::create(&client_sk, &client_pk, hash_a).unwrap());
    let block_a = wait_all(&observers, hash_a, Duration::from_secs(60));
    let height_a = block_a.header.height;
    let id_a = block_a.header.id();
    std::thread::sleep(Duration::from_millis(150)); // let every node flush to disk
    for h in handles {
        h.shutdown();
    }

    // --- Boot 2: same keys, same stores, new ports. Notarize document B. ---
    let (handles2, set2) = spawn_net(&dir, &val_keys, Duration::from_millis(1200));
    let observers2: Vec<Observer> = handles2.iter().map(|h| h.committed()).collect();

    // On resume, each node reloaded block A from disk.
    assert!(
        observers2
            .iter()
            .all(|o| block_with_hash(o, hash_a).is_some()),
        "rebooted nodes must reload the pre-reboot chain"
    );

    std::thread::sleep(Duration::from_millis(1200));
    let hash_b = Hash::digest(b"doc-B-after-reboot");
    handles2[0].submit(Attestation::create(&client_sk, &client_pk, hash_b).unwrap());
    let block_b = wait_all(&observers2, hash_b, Duration::from_secs(60));

    // Block B continues the chain directly on top of A — height advances by one
    // and its prev_hash is A's id. The reboot was seamless.
    assert_eq!(block_b.header.height, height_a + 1, "height must advance past reboot");
    assert_eq!(block_b.header.prev_hash, id_a, "B must chain onto A across reboot");
    block_b.qc.verify(&block_b.header, &set2).expect("post-reboot QC valid");

    for h in handles2 {
        h.shutdown();
    }
    let _ = std::fs::remove_dir_all(&dir);
}
