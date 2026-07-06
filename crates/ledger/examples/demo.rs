//! End-to-end demo: notarize a document and print its portable proof.
//!
//! Run with:  cargo run -p slc-ledger --example demo

use slc_crypto::{Hash, SigningKey, VerifyingKey};
use slc_ledger::{
    Attestation, Block, BlockHeader, MerkleTree, NotarizationProof, QuorumCertificate, ValidatorSet,
};

fn main() {
    // 1. Stand up a 4-node network of legally-known validators (quorum = 3).
    let mut v_sks: Vec<SigningKey> = Vec::new();
    let mut v_pks: Vec<VerifyingKey> = Vec::new();
    for _ in 0..4 {
        let (sk, pk) = SigningKey::generate().unwrap();
        v_sks.push(sk);
        v_pks.push(pk);
    }
    let set = ValidatorSet::bft(v_pks.clone());
    println!(
        "network: {} validators, Byzantine quorum = {}\n",
        set.len(),
        set.threshold()
    );

    // 2. A client notarizes a document (only its hash ever leaves the premises).
    let (client_sk, client_pk) = SigningKey::generate().unwrap();
    let document = b"Merger Agreement, executed 2026-07-05, v3-FINAL";
    let att = Attestation::create(&client_sk, &client_pk, Hash::digest(document)).unwrap();
    println!("client id   : {}", client_pk.id());
    println!("doc hash    : {}", att.hash);

    // 3. Validators seal it into block #1 and finalize with a 3-of-4 quorum.
    let merkle_root = MerkleTree::build(vec![att.leaf_hash()]).root();
    let header = BlockHeader {
        height: 1,
        prev_hash: Hash::zero(),
        merkle_root,
        tx_count: 1,
        timestamp: 1_751_731_200, // 2026-07-05T16:00:00Z
        gov_root: slc_ledger::governance::governance_root(&[]),
    };
    let mut qc = QuorumCertificate::new(header.id());
    for i in 0..set.threshold() {
        qc.add(v_pks[i].clone(), header.sign(&v_sks[i]).unwrap());
    }
    let block = Block {
        header,
        attestations: vec![att],
        governance: vec![],
        qc,
    };
    println!("block id    : {}", block.header.id());
    println!("finalized   : {}\n", block.qc.is_final(&set));

    // 4. The client extracts a portable proof and verifies it offline.
    let proof = NotarizationProof::from_block(&block, 0).unwrap();
    match proof.verify(&set) {
        Ok(()) => println!("PROOF VERIFIES against validator public keys \u{2714}\n"),
        Err(e) => println!("proof failed: {e}"),
    }

    println!("--- portable notarization proof (JSON, abridged) ---");
    let json = proof.to_json().unwrap();
    // Print the head so the terminal isn't flooded by the ~3 KB signatures.
    for line in json.lines().take(8) {
        println!("{line}");
    }
    println!(
        "  \u{2026} (Merkle path, header, and {} validator signatures)",
        set.threshold()
    );
}
