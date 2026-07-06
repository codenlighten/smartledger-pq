//! Validator-set governance at the consensus level: a 5th validator, authorized
//! by a quorum of the original four, joins at a set activation height — and the
//! network keeps finalizing, switching from a 4-validator quorum (3) to a
//! 5-validator quorum (4) exactly at that height.

use slc_consensus::{ConsensusMsg, Effect, Engine, TimeoutKind};
use slc_crypto::{context, Hash, SigningKey, VerifyingKey};
use slc_ledger::{
    Attestation, Block, SignedValidatorChange, ValidatorChange, ValidatorRegistry, ValidatorSet,
};
use std::collections::VecDeque;

const JOIN_HEIGHT: u64 = 3;

struct Net {
    engines: Vec<Engine>,
    registry: ValidatorRegistry,
    msgq: VecDeque<ConsensusMsg>,
    timerq: VecDeque<(usize, u64, u64, TimeoutKind)>,
    commits: Vec<Vec<Block>>,
}

impl Net {
    fn apply(&mut self, i: usize, effects: Vec<Effect>) {
        for eff in effects {
            match eff {
                Effect::Broadcast(m) => self.msgq.push_back(m),
                Effect::ScheduleTimeout { height, round, kind } => {
                    self.timerq.push_back((i, height, round, kind))
                }
                Effect::Committed(b) => self.commits[i].push(*b),
            }
        }
    }

    fn submit_to_all(&mut self, att: &Attestation) {
        for i in 0..self.engines.len() {
            let eff = self.engines[i].add_attestation(att.clone());
            self.apply(i, eff);
        }
    }

    fn submit_gov_to_all(&mut self, signed: &SignedValidatorChange) {
        for i in 0..self.engines.len() {
            let (_ok, eff) = self.engines[i].add_governance(signed.clone());
            self.apply(i, eff);
        }
    }

    fn run(&mut self) {
        let mut steps = 0;
        while steps < 50_000 {
            steps += 1;
            if let Some(msg) = self.msgq.pop_front() {
                for i in 0..self.engines.len() {
                    let eff = self.engines[i].on_message(msg.clone());
                    self.apply(i, eff);
                }
            } else if let Some((i, h, r, kind)) = self.timerq.pop_front() {
                let eff = self.engines[i].on_timeout(h, r, kind);
                self.apply(i, eff);
            } else {
                return; // quiescent
            }
        }
        panic!("step budget exhausted");
    }
}

#[test]
fn a_fifth_validator_joins_by_quorum_and_consensus_continues() {
    // Five keypairs; the first four are the genesis validators.
    let mut sks = Vec::new();
    let mut pks = Vec::new();
    for _ in 0..5 {
        let (sk, pk) = SigningKey::generate().unwrap();
        sks.push(sk);
        pks.push(pk);
    }
    let genesis: Vec<VerifyingKey> = pks[0..4].to_vec();
    let newcomer = pks[4].clone();
    let genesis_set = ValidatorSet::bft(genesis.clone());

    // A change adding the newcomer, effective at JOIN_HEIGHT.
    let change = ValidatorChange {
        adds: vec![newcomer.clone()],
        removes: vec![],
        activation_height: JOIN_HEIGHT,
    };
    // Authorize it with a quorum (3 of 4) of the current validators.
    let mut signed = SignedValidatorChange::new(change.clone());
    for i in 0..3 {
        let sig = sks[i].sign(&change.signing_bytes(), context::GOVERNANCE).unwrap();
        signed.approve(pks[i].clone(), sig);
    }
    assert!(signed.is_authorized(&genesis_set), "change must be quorum-authorized");

    // Every node records the authorized change in its registry.
    let mut registry = ValidatorRegistry::new(genesis.clone());
    registry.record(signed.change.clone());
    assert_eq!(registry.active_set(2).threshold(), 3); // 4 validators
    assert_eq!(registry.active_set(JOIN_HEIGHT).threshold(), 4); // 5 validators

    // Build all five engines on the shared registry.
    let mut engines = Vec::new();
    for i in 0..5 {
        let sk = SigningKey::from_bytes(&sks[i].to_bytes()).unwrap();
        let mut e = Engine::with_registry(registry.clone(), sk, pks[i].clone(), Hash::zero(), 1);
        e.set_time(1_751_731_200);
        engines.push(e);
    }
    let mut net = Net {
        commits: vec![Vec::new(); 5],
        engines,
        registry,
        msgq: VecDeque::new(),
        timerq: VecDeque::new(),
    };

    // Start (all park — nothing to notarize yet).
    for i in 0..5 {
        let eff = net.engines[i].start();
        net.apply(i, eff);
    }
    net.run();

    // Notarize one document per height until past the join height.
    let (c_sk, c_pk) = SigningKey::generate().unwrap();
    for h in 1..=JOIN_HEIGHT {
        let att = Attestation::create(&c_sk, &c_pk, Hash::digest(format!("doc-{h}").as_bytes())).unwrap();
        net.submit_to_all(&att);
        net.run();
    }

    // All five nodes agree on every block, and each block is finalized by the
    // validator set in force at its height.
    for h in 1..=JOIN_HEIGHT {
        let idx = (h - 1) as usize;
        let block = &net.commits[0][idx];
        for node in 0..5 {
            assert_eq!(net.commits[node][idx].header.id(), block.header.id(), "node {node} height {h}");
        }
        let set = net.registry.active_set(block.header.height);
        block.qc.verify(&block.header, &set).unwrap_or_else(|e| panic!("height {h} QC: {e:?}"));
    }

    // Before the join: 4 validators, quorum 3. At/after: 5 validators, quorum 4.
    let pre = &net.commits[0][0];
    assert_eq!(net.registry.active_set(pre.header.height).len(), 4);

    let post = &net.commits[0][(JOIN_HEIGHT - 1) as usize];
    assert_eq!(post.header.height, JOIN_HEIGHT);
    let post_set = net.registry.active_set(post.header.height);
    assert_eq!(post_set.len(), 5, "newcomer is now a validator");
    assert_eq!(post_set.threshold(), 4);
    // The block genuinely carries a 4-of-5 quorum from the new set.
    assert!(post.qc.signatures.len() >= 4);
    assert!(post_set.contains(&newcomer));
}

#[test]
fn on_chain_governance_derives_the_set_from_blocks() {
    // No node is pre-configured with the change: they all learn it from a block.
    let mut sks = Vec::new();
    let mut pks = Vec::new();
    for _ in 0..5 {
        let (sk, pk) = SigningKey::generate().unwrap();
        sks.push(sk);
        pks.push(pk);
    }
    let genesis: Vec<VerifyingKey> = pks[0..4].to_vec();
    let newcomer = pks[4].clone();
    let genesis_set = ValidatorSet::bft(genesis.clone());

    // Every engine starts with the genesis roster ONLY (no recorded change).
    let genesis_registry = ValidatorRegistry::new(genesis.clone());
    let mut engines = Vec::new();
    for i in 0..5 {
        let sk = SigningKey::from_bytes(&sks[i].to_bytes()).unwrap();
        let mut e =
            Engine::with_registry(genesis_registry.clone(), sk, pks[i].clone(), Hash::zero(), 1);
        e.set_time(1_751_731_200);
        engines.push(e);
    }
    let mut net = Net {
        commits: vec![Vec::new(); 5],
        engines,
        registry: genesis_registry,
        msgq: VecDeque::new(),
        timerq: VecDeque::new(),
    };
    for i in 0..5 {
        let eff = net.engines[i].start();
        net.apply(i, eff);
    }
    net.run();

    // A quorum-authorized change adding the newcomer, activating at height 3.
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
    assert!(signed.is_authorized(&genesis_set));

    // Submit the change (as an operator would, gossiped to validators). It rides
    // in a GOVERNANCE-ONLY block 1 — no attestations needed.
    net.submit_gov_to_all(&signed);
    net.run();

    let block1 = &net.commits[0][0];
    assert!(block1.attestations.is_empty(), "block 1 is governance-only");
    assert_eq!(block1.governance.len(), 1, "block 1 carries the change");
    assert_eq!(block1.header.height, 1);

    // Advance to the activation height with ordinary notarizations.
    let (c_sk, c_pk) = SigningKey::generate().unwrap();
    for h in 2..=JOIN_HEIGHT {
        let att = Attestation::create(&c_sk, &c_pk, Hash::digest(format!("d{h}").as_bytes())).unwrap();
        net.submit_to_all(&att);
        net.run();
    }

    // Every node — including the newcomer — derived the 5-validator set purely
    // from the on-chain block, with no configuration.
    for i in 0..5 {
        assert_eq!(net.engines[i].validator_set().len(), 5, "node {i} derived set from chain");
    }

    // Block 3 is finalized by the new 4-of-5 quorum, and the newcomer is a member.
    let expected = {
        let mut r = ValidatorRegistry::new(genesis.clone());
        r.record(change.clone());
        r.active_set(JOIN_HEIGHT)
    };
    let block3 = &net.commits[0][(JOIN_HEIGHT - 1) as usize];
    assert_eq!(block3.header.height, JOIN_HEIGHT);
    block3.qc.verify(&block3.header, &expected).unwrap();
    assert_eq!(expected.len(), 5);
    assert!(expected.contains(&newcomer));
    for node in 0..5 {
        assert_eq!(net.commits[node][2].header.id(), block3.header.id());
    }
}
