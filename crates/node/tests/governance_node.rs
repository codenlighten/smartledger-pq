//! On-chain governance through a live network: an operator collects a quorum of
//! validator approvals and submits a validator-set change over RPC. It lands in
//! a block, and a 5th validator — meshed but not originally a validator — joins
//! at the activation height and starts signing blocks. Everything is derived
//! from the chain.

use slc_crypto::{context, Hash, SigningKey};
use slc_ledger::{
    Attestation, Block, SignedValidatorChange, ValidatorChange, ValidatorRegistry,
};
use slc_node::config::{GenesisConfig, ValidatorInfo};
use slc_node::rpc::{call, RpcRequest, RpcResponse};
use slc_node::{Node, NodeHandle, Transport};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const JOIN_HEIGHT: u64 = 3;

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn wait_height(committed: &Arc<Mutex<Vec<Block>>>, h: u64, within: Duration) -> Vec<Block> {
    let deadline = Instant::now() + within;
    loop {
        let blocks = committed.lock().unwrap();
        if blocks.iter().any(|b| b.header.height >= h) {
            return blocks.clone();
        }
        drop(blocks);
        assert!(Instant::now() < deadline, "timed out waiting for height {h}");
        std::thread::sleep(Duration::from_millis(80));
    }
}

#[test]
fn a_validator_joins_a_live_network_via_rpc_governance() {
    // Five keypairs and transports; the first four are the genesis validators.
    let mut sks = Vec::new();
    let mut pks = Vec::new();
    let mut transports = Vec::new();
    for _ in 0..5 {
        let (sk, pk) = SigningKey::generate().unwrap();
        sks.push(sk);
        pks.push(pk);
        transports.push(Transport::bind("127.0.0.1:0").unwrap());
    }
    let addrs: Vec<String> = transports.iter().map(|t| t.local_addr().to_string()).collect();
    let genesis = GenesisConfig {
        chain_id: "smartledger-gov-net".into(),
        validators: pks[0..4]
            .iter()
            .zip(&addrs[0..4])
            .map(|(pk, addr)| ValidatorInfo {
                pubkey: pk.clone(),
                addr: addr.clone(),
            })
            .collect(),
    };
    let newcomer = pks[4].clone();

    // Build five nodes, ALL meshed together (so the newcomer can follow and
    // later participate). Node 0 exposes the RPC.
    let rpc_addr = format!("127.0.0.1:{}", free_port());
    let mut nodes = Vec::new();
    for i in 0..5 {
        let mut transport = transports.remove(0);
        let peers: Vec<String> = addrs
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, a)| a.clone())
            .collect();
        transport.set_peers(peers);
        let sk = SigningKey::from_bytes(&sks[i].to_bytes()).unwrap();
        let mut node = Node::new(transport, &genesis, sk, pks[i].clone(), None, Duration::from_millis(300));
        if i == 0 {
            node = node.with_rpc(rpc_addr.clone());
        }
        nodes.push(node);
    }
    let handles: Vec<NodeHandle> = nodes.into_iter().map(Node::spawn).collect();
    std::thread::sleep(Duration::from_millis(500));

    // The operator builds the change and collects a quorum (3 of 4) of validator
    // approvals — exactly what `slc gov propose/approve` produce.
    let change = ValidatorChange {
        adds: vec![newcomer.clone()],
        removes: vec![],
        activation_height: JOIN_HEIGHT,
    };
    let mut signed = SignedValidatorChange::new(change.clone());
    for i in 0..3 {
        let sig = sks[i].sign(&change.signing_bytes(), context::GOVERNANCE).unwrap();
        signed.approve(pks[i].clone(), sig);
    }

    // Submit it over RPC. It rides into a block; then drive the chain to the
    // activation height with ordinary notarizations.
    match call(&rpc_addr, &RpcRequest::SubmitGovernance(signed)).unwrap() {
        RpcResponse::Submitted { accepted } => assert!(accepted),
        other => panic!("unexpected: {other:?}"),
    }
    let (c_sk, c_pk) = SigningKey::generate().unwrap();
    for h in 2..=JOIN_HEIGHT + 1 {
        handles[0].submit(Attestation::create(&c_sk, &c_pk, Hash::digest(format!("d{h}").as_bytes())).unwrap());
        std::thread::sleep(Duration::from_millis(150));
    }

    // Wait until we are past the activation height.
    let committed = handles[0].committed();
    let blocks = wait_height(&committed, JOIN_HEIGHT, Duration::from_secs(30));

    // A block carried the governance change...
    assert!(blocks.iter().any(|b| !b.governance.is_empty()), "a block must carry the change");

    // ...and blocks at/after the join height are finalized by the 5-validator
    // set, with the newcomer among the signers.
    let expected = {
        let mut r = ValidatorRegistry::new(genesis.validator_keys());
        r.record(change.clone());
        r.active_set(JOIN_HEIGHT)
    };
    assert_eq!(expected.len(), 5);
    assert_eq!(expected.threshold(), 4);

    let joined_block = blocks.iter().find(|b| b.header.height == JOIN_HEIGHT).expect("join-height block");
    joined_block.qc.verify(&joined_block.header, &expected).expect("finalized by 5-set");
    let signers: Vec<Hash> = joined_block.qc.signatures.iter().map(|s| s.validator.id()).collect();
    assert!(signers.contains(&newcomer.id()), "the newcomer signed a finalized block");
    // The finalized block genuinely carries a 4-of-5 quorum from the new set.
    let in_new_set: usize = joined_block
        .qc
        .signatures
        .iter()
        .filter(|s| expected.contains(&s.validator))
        .count();
    assert!(in_new_set >= 4, "must be finalized by a 4-of-5 quorum");

    for h in handles {
        h.shutdown();
    }
}
