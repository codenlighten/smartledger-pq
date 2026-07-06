//! A live 4-node network with anchoring enabled: notarize enough documents to
//! close a checkpoint window, then confirm a node publishes the checkpoint and
//! that an anchored proof (notarization + checkpoint inclusion + published root)
//! verifies end to end.

use slc_anchor::{AnchoredProof, AnchorService, Checkpoint, MockAnchor};
use slc_crypto::{Hash, SigningKey, VerifyingKey};
use slc_ledger::{Attestation, Block, NotarizationProof, ValidatorSet};
use slc_node::{Node, NodeHandle, Transport};
use slc_node::config::{GenesisConfig, ValidatorInfo};
use slc_node::AnchorRecord;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const INTERVAL: usize = 2;

fn wait_until<T>(mut f: impl FnMut() -> Option<T>, within: Duration) -> T {
    let deadline = Instant::now() + within;
    loop {
        if let Some(v) = f() {
            return v;
        }
        assert!(Instant::now() < deadline, "timed out");
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn live_network_anchors_a_checkpoint_and_proof_verifies() {
    // Stand up four validators, each anchoring every INTERVAL blocks.
    let mut prep: Vec<(Transport, SigningKey, VerifyingKey)> = Vec::new();
    for _ in 0..4 {
        let (sk, pk) = SigningKey::generate().unwrap();
        prep.push((Transport::bind("127.0.0.1:0").unwrap(), sk, pk));
    }
    let genesis = GenesisConfig {
        chain_id: "smartledger-anchor".into(),
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
    for (mut transport, sk, pk) in prep {
        transport.set_peers(genesis.peer_addrs(&pk));
        let node = Node::new(transport, &genesis, sk, pk, None, Duration::from_millis(1200))
            .with_anchor(AnchorService::new(Box::new(MockAnchor::new()), INTERVAL));
        nodes.push(node);
    }
    let handles: Vec<NodeHandle> = nodes.into_iter().map(Node::spawn).collect();

    let committed: Vec<Arc<Mutex<Vec<Block>>>> = handles.iter().map(|h| h.committed()).collect();
    let records: Arc<Mutex<Vec<AnchorRecord>>> = handles[0].anchor_records();

    // Notarize INTERVAL documents so a full checkpoint window closes.
    let (c_sk, c_pk) = SigningKey::generate().unwrap();
    let targets: Vec<Hash> = (0..INTERVAL)
        .map(|i| Hash::digest(format!("anchor-doc-{i}").as_bytes()))
        .collect();
    std::thread::sleep(Duration::from_millis(1200));
    for t in &targets {
        handles[0].submit(Attestation::create(&c_sk, &c_pk, *t).unwrap());
        // brief spacing so each attestation triggers its own block
        std::thread::sleep(Duration::from_millis(120));
    }

    // Node 0 publishes a checkpoint covering the first INTERVAL blocks.
    let record = wait_until(|| records.lock().unwrap().first().cloned(), Duration::from_secs(60));
    assert_eq!(record.from_height, 1);
    assert_eq!(record.to_height, INTERVAL as u64);
    assert_eq!(record.receipt.backend, "mock");

    // Gather the finalized blocks in the checkpoint window (node 0's view).
    let window: Vec<Block> = wait_until(
        || {
            let blocks = committed[0].lock().unwrap();
            let win: Vec<Block> = blocks
                .iter()
                .filter(|b| b.header.height >= record.from_height && b.header.height <= record.to_height)
                .cloned()
                .collect();
            (win.len() == INTERVAL).then_some(win)
        },
        Duration::from_secs(10),
    );

    // Independently rebuild the checkpoint and confirm the node published the
    // correct root.
    let block_ids: Vec<Hash> = window.iter().map(|b| b.header.id()).collect();
    let checkpoint = Checkpoint::from_block_ids(block_ids, record.from_height, record.to_height).unwrap();
    assert_eq!(checkpoint.root(), record.checkpoint_root, "node anchored the wrong root");

    // Build an anchored proof for the first notarized document and verify all
    // four layers.
    let doc0_block = window
        .iter()
        .find(|b| b.attestations.iter().any(|a| a.hash == targets[0]))
        .expect("doc 0 is in the window");
    let idx = doc0_block
        .attestations
        .iter()
        .position(|a| a.hash == targets[0])
        .unwrap();
    let notarization = NotarizationProof::from_block(doc0_block, idx).unwrap();
    let inclusion = checkpoint.inclusion(doc0_block.header.id()).unwrap();
    let anchored = AnchoredProof {
        notarization,
        checkpoint: inclusion,
        record: record.clone(),
    };
    anchored.verify(&set).expect("anchored proof must verify");
    assert_eq!(anchored.notarization.hash(), targets[0]);

    for h in handles {
        h.shutdown();
    }
}
