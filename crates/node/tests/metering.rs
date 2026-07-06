//! Notarization metering over RPC: a node with a licensed cap of 2 accepts two
//! notarizations and rejects the third, and reports usage.

use slc_crypto::{Hash, SigningKey, VerifyingKey};
use slc_ledger::Attestation;
use slc_node::config::{GenesisConfig, ValidatorInfo};
use slc_node::rpc::{call, RpcRequest, RpcResponse};
use slc_node::{Node, Transport};
use std::net::TcpListener;
use std::time::Duration;

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

#[test]
fn metering_enforces_the_licensed_cap() {
    // A single-validator chain is enough to exercise the RPC meter.
    let (sk, pk): (SigningKey, VerifyingKey) = SigningKey::generate().unwrap();
    let mut transport = Transport::bind("127.0.0.1:0").unwrap();
    let genesis = GenesisConfig {
        chain_id: "metered".into(),
        validators: vec![ValidatorInfo { pubkey: pk.clone(), addr: transport.local_addr().to_string() }],
    };
    transport.set_peers(vec![]);
    let rpc_addr = format!("127.0.0.1:{}", free_port());
    let node = Node::new(transport, &genesis, sk, pk, None, Duration::from_millis(200))
        .with_rpc(rpc_addr.clone())
        .with_metering(Some(2), None);
    let handle = node.spawn();
    std::thread::sleep(Duration::from_millis(300));

    let (c_sk, c_pk) = SigningKey::generate().unwrap();
    let submit = |i: u32| {
        let att = Attestation::create(&c_sk, &c_pk, Hash::digest(format!("doc-{i}").as_bytes())).unwrap();
        call(&rpc_addr, &RpcRequest::Submit(att)).unwrap()
    };

    // First two within the licensed volume.
    assert!(matches!(submit(1), RpcResponse::Submitted { accepted: true }));
    assert!(matches!(submit(2), RpcResponse::Submitted { accepted: true }));

    // Third exceeds the cap → rejected with an error.
    match submit(3) {
        RpcResponse::Error(msg) => assert!(msg.contains("volume exceeded"), "got: {msg}"),
        other => panic!("expected quota error, got {other:?}"),
    }

    // Usage reflects the metered count.
    match call(&rpc_addr, &RpcRequest::Usage).unwrap() {
        RpcResponse::Usage { count, cap, .. } => {
            assert_eq!(count, 2);
            assert_eq!(cap, Some(2));
        }
        other => panic!("unexpected usage response: {other:?}"),
    }

    handle.shutdown();
}
