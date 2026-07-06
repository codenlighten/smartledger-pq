//! End-to-end: build a real chain of finalized blocks, anchor checkpoints via a
//! backend, and verify an anchored proof binds a notarized document all the way
//! out to the published checkpoint root.

use slc_anchor::{AnchorService, AnchoredProof, MockAnchor};
use slc_crypto::{Hash, SigningKey, VerifyingKey};
use slc_ledger::{
    Attestation, Block, BlockHeader, MerkleTree, NotarizationProof, QuorumCertificate, ValidatorSet,
};

fn validators(n: usize) -> (Vec<SigningKey>, Vec<VerifyingKey>) {
    let mut sks = Vec::new();
    let mut pks = Vec::new();
    for _ in 0..n {
        let (sk, pk) = SigningKey::generate().unwrap();
        sks.push(sk);
        pks.push(pk);
    }
    (sks, pks)
}

/// Seal one finalized block with a full quorum over the given attestations.
fn seal(
    height: u64,
    prev_hash: Hash,
    atts: Vec<Attestation>,
    sks: &[SigningKey],
    pks: &[VerifyingKey],
    quorum: usize,
) -> Block {
    let leaves: Vec<Hash> = atts.iter().map(|a| a.leaf_hash()).collect();
    let header = BlockHeader {
        height,
        prev_hash,
        merkle_root: MerkleTree::build(leaves).root(),
        tx_count: atts.len() as u32,
        timestamp: 1_751_000_000 + height,
        gov_root: slc_ledger::governance::governance_root(&[]),
    };
    let mut qc = QuorumCertificate::new(header.id());
    for i in 0..quorum {
        qc.add(pks[i].clone(), header.sign(&sks[i]).unwrap());
    }
    Block { header, attestations: atts, governance: vec![], qc }
}

#[test]
fn anchored_proof_verifies_end_to_end() {
    let (v_sks, v_pks) = validators(4);
    let set = ValidatorSet::bft(v_pks.clone());
    let quorum = set.threshold();

    // A client notarizes a document; it lands in block 2 of a short chain.
    let (c_sk, c_pk) = SigningKey::generate().unwrap();
    let target = Hash::digest(b"anchored-document");
    let att = Attestation::create(&c_sk, &c_pk, target).unwrap();

    let b1 = seal(1, Hash::zero(), vec![Attestation::create(&c_sk, &c_pk, Hash::digest(b"d1")).unwrap()], &v_sks, &v_pks, quorum);
    let b2 = seal(2, b1.header.id(), vec![att], &v_sks, &v_pks, quorum);
    let b3 = seal(3, b2.header.id(), vec![Attestation::create(&c_sk, &c_pk, Hash::digest(b"d3")).unwrap()], &v_sks, &v_pks, quorum);

    // Anchor every 3 blocks with the mock backend.
    let mut service = AnchorService::new(Box::new(MockAnchor::new()), 3);
    assert!(service.record_block(b1.header.id(), 1).is_none());
    assert!(service.record_block(b2.header.id(), 2).is_none());
    let record = service.record_block(b3.header.id(), 3).expect("checkpoint published at block 3");
    assert_eq!(record.from_height, 1);
    assert_eq!(record.to_height, 3);

    // Build the anchored proof for the document in block 2.
    let notarization = NotarizationProof::from_block(&b2, 0).unwrap();
    let anchored: AnchoredProof = service.anchor_proof(notarization).expect("block 2 is anchored");

    // Full four-layer verification passes.
    anchored.verify(&set).expect("anchored proof must verify");
    assert_eq!(anchored.notarization.hash(), target);

    // Survives a JSON round-trip (store it, email it, verify decades later).
    let json = anchored.to_json().unwrap();
    let restored = AnchoredProof::from_json(&json).unwrap();
    assert_eq!(restored, anchored);
    restored.verify(&set).expect("restored anchored proof verifies");
}

#[test]
fn tampering_with_the_anchor_is_caught() {
    let (v_sks, v_pks) = validators(4);
    let set = ValidatorSet::bft(v_pks.clone());
    let quorum = set.threshold();
    let (c_sk, c_pk) = SigningKey::generate().unwrap();
    let att = Attestation::create(&c_sk, &c_pk, Hash::digest(b"doc")).unwrap();
    let b1 = seal(1, Hash::zero(), vec![att], &v_sks, &v_pks, quorum);

    let mut service = AnchorService::new(Box::new(MockAnchor::new()), 1);
    service.record_block(b1.header.id(), 1).unwrap();
    let notarization = NotarizationProof::from_block(&b1, 0).unwrap();
    let mut anchored = service.anchor_proof(notarization).unwrap();
    anchored.verify(&set).unwrap();

    // Rewrite the published root: inclusion no longer reconstructs it.
    anchored.record.checkpoint_root = Hash::digest(b"forged-root");
    assert!(matches!(
        anchored.verify(&set),
        Err(slc_anchor::AnchorError::ReceiptMismatch | slc_anchor::AnchorError::NotInCheckpoint)
    ));
}

#[test]
fn unanchored_block_has_no_proof_yet() {
    let (v_sks, v_pks) = validators(4);
    let set = ValidatorSet::bft(v_pks.clone());
    let quorum = set.threshold();
    let (c_sk, c_pk) = SigningKey::generate().unwrap();
    let att = Attestation::create(&c_sk, &c_pk, Hash::digest(b"doc")).unwrap();
    let b1 = seal(1, Hash::zero(), vec![att], &v_sks, &v_pks, quorum);

    // Interval 5, only one block recorded → nothing anchored yet.
    let mut service = AnchorService::new(Box::new(MockAnchor::new()), 5);
    assert!(service.record_block(b1.header.id(), 1).is_none());
    let notarization = NotarizationProof::from_block(&b1, 0).unwrap();
    assert!(service.anchor_proof(notarization).is_none());
}
