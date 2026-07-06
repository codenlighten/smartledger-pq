//! Full value-chain test: a client notarizes documents, four validators seal
//! and finalize a block, the client extracts a portable proof and verifies it
//! offline — exactly the flow a real deployment performs.

use slc_crypto::{Hash, SigningKey, VerifyingKey};
use slc_ledger::{
    Attestation, Block, BlockHeader, NotarizationProof, QuorumCertificate, ValidatorSet,
};

/// Spin up `n` validator keypairs.
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

/// Seal attestations into a finalized block signed by `signers` of the set.
fn seal_block(
    height: u64,
    prev_hash: Hash,
    timestamp: u64,
    attestations: Vec<Attestation>,
    validator_sks: &[SigningKey],
    validator_pks: &[VerifyingKey],
    signers: usize,
) -> Block {
    let leaves: Vec<Hash> = attestations.iter().map(|a| a.leaf_hash()).collect();
    let merkle_root = slc_ledger::MerkleTree::build(leaves).root();
    let header = BlockHeader {
        height,
        prev_hash,
        merkle_root,
        tx_count: attestations.len() as u32,
        timestamp,
        gov_root: slc_ledger::governance::governance_root(&[]),
    };

    let mut qc = QuorumCertificate::new(header.id());
    for i in 0..signers {
        let sig = header.sign(&validator_sks[i]).unwrap();
        qc.add(validator_pks[i].clone(), sig);
    }

    Block {
        header,
        attestations,
        governance: vec![],
        qc,
    }
}

#[test]
fn notarize_seal_prove_and_verify_offline() {
    // A four-validator network → Byzantine quorum is 3.
    let (v_sks, v_pks) = validators(4);
    let set = ValidatorSet::bft(v_pks.clone());
    assert_eq!(set.threshold(), 3);

    // A client (a legally-known actor) notarizes three documents.
    let (client_sk, client_pk) = SigningKey::generate().unwrap();
    let docs = [b"invoice-001".as_slice(), b"contract.pdf", b"audit-log.json"];
    let attestations: Vec<Attestation> = docs
        .iter()
        .map(|d| Attestation::create(&client_sk, &client_pk, Hash::digest(d)).unwrap())
        .collect();

    // Validators seal them into block #1 with a 3-of-4 quorum.
    let block = seal_block(
        1,
        Hash::zero(),
        1_751_000_000,
        attestations,
        &v_sks,
        &v_pks,
        3,
    );
    assert!(block.qc.is_final(&set));

    // The client extracts a portable proof for the contract (index 1)...
    let proof = NotarizationProof::from_block(&block, 1).unwrap();
    assert_eq!(proof.hash(), Hash::digest(b"contract.pdf"));
    assert_eq!(proof.timestamp(), 1_751_000_000);

    // ...and it verifies against nothing but the validator public keys.
    proof.verify(&set).expect("proof must verify");

    // It survives a JSON round-trip (store it, email it, verify in 30 years).
    let json = proof.to_json().unwrap();
    let restored = NotarizationProof::from_json(&json).unwrap();
    assert_eq!(restored, proof);
    restored.verify(&set).expect("restored proof must verify");
}

#[test]
fn insufficient_quorum_is_rejected() {
    let (v_sks, v_pks) = validators(4);
    let set = ValidatorSet::bft(v_pks.clone()); // needs 3
    let (client_sk, client_pk) = SigningKey::generate().unwrap();
    let att = Attestation::create(&client_sk, &client_pk, Hash::digest(b"doc")).unwrap();

    // Only 2 validators sign — below the quorum of 3.
    let block = seal_block(1, Hash::zero(), 1_751_000_000, vec![att], &v_sks, &v_pks, 2);
    assert!(!block.qc.is_final(&set));

    let proof = NotarizationProof::from_block(&block, 0).unwrap();
    assert!(matches!(
        proof.verify(&set),
        Err(slc_ledger::LedgerError::InsufficientQuorum { got: 2, need: 3 })
    ));
}

#[test]
fn outsider_validator_signature_does_not_count() {
    let (v_sks, v_pks) = validators(4);
    let set = ValidatorSet::bft(v_pks.clone()); // needs 3
    let (client_sk, client_pk) = SigningKey::generate().unwrap();
    let att = Attestation::create(&client_sk, &client_pk, Hash::digest(b"doc")).unwrap();

    // Two real validators sign; then an outsider (not in the set) also signs.
    let leaves = vec![att.leaf_hash()];
    let merkle_root = slc_ledger::MerkleTree::build(leaves).root();
    let header = BlockHeader {
        height: 1,
        prev_hash: Hash::zero(),
        merkle_root,
        tx_count: 1,
        timestamp: 1_751_000_000,
        gov_root: slc_ledger::governance::governance_root(&[]),
    };
    let mut qc = QuorumCertificate::new(header.id());
    qc.add(v_pks[0].clone(), header.sign(&v_sks[0]).unwrap());
    qc.add(v_pks[1].clone(), header.sign(&v_sks[1]).unwrap());
    let (outsider_sk, outsider_pk) = SigningKey::generate().unwrap();
    qc.add(outsider_pk, header.sign(&outsider_sk).unwrap());

    let block = Block {
        header,
        attestations: vec![att],
        governance: vec![],
        qc,
    };
    let proof = NotarizationProof::from_block(&block, 0).unwrap();
    // The outsider's signature must not push us over the quorum.
    assert!(matches!(
        proof.verify(&set),
        Err(slc_ledger::LedgerError::InsufficientQuorum { got: 2, need: 3 })
    ));
}

#[test]
fn tampered_hash_breaks_inclusion() {
    let (v_sks, v_pks) = validators(4);
    let set = ValidatorSet::bft(v_pks.clone());
    let (client_sk, client_pk) = SigningKey::generate().unwrap();
    let att = Attestation::create(&client_sk, &client_pk, Hash::digest(b"genuine")).unwrap();
    let block = seal_block(1, Hash::zero(), 1_751_000_000, vec![att], &v_sks, &v_pks, 3);

    let mut proof = NotarizationProof::from_block(&block, 0).unwrap();
    // Attacker rewrites the notarized hash after the fact.
    proof.attestation.hash = Hash::digest(b"forged");
    // The client's own signature no longer covers it → InvalidAttestation.
    assert_eq!(proof.verify(&set), Err(slc_ledger::LedgerError::InvalidAttestation));
}
