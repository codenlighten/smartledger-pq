//! In-memory network simulation: run N independent [`Engine`]s, relay their
//! broadcasts, fire their timers, and assert they reach identical, valid,
//! quorum-certified blocks.
//!
//! With attestation-triggered production, an idle network is *silent* — engines
//! park with nothing to notarize. A client "submits" by gossiping an attestation
//! to every validator (mirroring the real node), which wakes them for exactly
//! one block. Quiescence is therefore the expected resting state, not a bug.

use slc_consensus::{ConsensusMsg, Effect, Engine, TimeoutKind};
use slc_crypto::{Hash, SigningKey, VerifyingKey};
use slc_ledger::{Attestation, Block, NotarizationProof, ValidatorSet};
use std::collections::VecDeque;

struct Sim {
    engines: Vec<Engine>,
    crashed: Vec<bool>,
    set: ValidatorSet,
    msgq: VecDeque<ConsensusMsg>,
    timerq: VecDeque<(usize, u64, u64, TimeoutKind)>,
    commits: Vec<Vec<Block>>,
}

impl Sim {
    fn new(n: usize) -> Sim {
        let mut sks = Vec::new();
        let mut pks = Vec::new();
        for _ in 0..n {
            let (sk, pk) = SigningKey::generate().unwrap();
            sks.push(sk);
            pks.push(pk);
        }
        let set = ValidatorSet::bft(pks.clone());

        let mut engines = Vec::new();
        for (sk, pk) in sks.into_iter().zip(pks.iter().cloned()) {
            let mut e = Engine::new(set.clone(), sk, pk, Hash::zero(), 1);
            e.set_time(1_751_731_200);
            engines.push(e);
        }
        Sim {
            crashed: vec![false; n],
            commits: vec![Vec::new(); n],
            engines,
            set,
            msgq: VecDeque::new(),
            timerq: VecDeque::new(),
        }
    }

    /// Crash the validator that would propose `height`/round 0, forcing a view
    /// change. Engine `i` owns `set.validators()[i]` (same key order in `new`).
    fn crash_round0_proposer(&mut self, height: u64) -> VerifyingKey {
        let mut sorted: Vec<VerifyingKey> = self.set.validators().to_vec();
        sorted.sort_by_key(|v| v.id());
        let idx = (height % sorted.len() as u64) as usize;
        let target = sorted[idx].clone();
        for i in 0..self.engines.len() {
            if self.set.validators()[i] == target {
                self.crashed[i] = true;
            }
        }
        target
    }

    fn apply(&mut self, i: usize, effects: Vec<Effect>) {
        for eff in effects {
            match eff {
                Effect::Broadcast(msg) => self.msgq.push_back(msg),
                Effect::ScheduleTimeout { height, round, kind } => {
                    self.timerq.push_back((i, height, round, kind))
                }
                Effect::Committed(block) => self.commits[i].push(*block),
            }
        }
    }

    fn start(&mut self) {
        for i in 0..self.engines.len() {
            if self.crashed[i] {
                continue;
            }
            let eff = self.engines[i].start();
            self.apply(i, eff);
        }
    }

    /// A client notarizes `att` by gossiping it to every (honest) validator.
    fn submit_to_all(&mut self, att: &Attestation) {
        for i in 0..self.engines.len() {
            if self.crashed[i] {
                continue;
            }
            let eff = self.engines[i].add_attestation(att.clone());
            self.apply(i, eff);
        }
    }

    /// Deliver all pending messages and fire all pending timers until the
    /// network goes quiescent (messages first, so the happy path never waits on
    /// a timer).
    fn run(&mut self) {
        let mut steps = 0;
        while steps < 20_000 {
            steps += 1;
            if let Some(msg) = self.msgq.pop_front() {
                for i in 0..self.engines.len() {
                    if self.crashed[i] {
                        continue;
                    }
                    let eff = self.engines[i].on_message(msg.clone());
                    self.apply(i, eff);
                }
            } else if let Some((i, h, r, kind)) = self.timerq.pop_front() {
                if !self.crashed[i] {
                    let eff = self.engines[i].on_timeout(h, r, kind);
                    self.apply(i, eff);
                }
            } else {
                return; // quiescent — the expected idle state
            }
        }
        panic!("step budget exhausted");
    }

    fn honest(&self) -> Vec<usize> {
        (0..self.engines.len()).filter(|&i| !self.crashed[i]).collect()
    }

    fn all_honest_parked(&self) -> bool {
        self.honest().iter().all(|&i| self.engines[i].is_parked())
    }
}

fn client_attestation(tag: &[u8]) -> Attestation {
    let (sk, pk) = SigningKey::generate().unwrap();
    Attestation::create(&sk, &pk, Hash::digest(tag)).unwrap()
}

#[test]
fn idle_until_attestation_then_exactly_one_block() {
    let mut sim = Sim::new(4);
    sim.start();
    sim.run();

    // Nothing to notarize → no blocks, everyone idle. This is the key property:
    // an idle chain mints no empty blocks.
    assert!(sim.honest().iter().all(|&i| sim.commits[i].is_empty()));
    assert!(sim.all_honest_parked());

    // A client notarizes one document.
    let att = client_attestation(b"one-and-only");
    sim.submit_to_all(&att);
    sim.run();

    let honest = sim.honest();
    for &i in &honest {
        assert_eq!(sim.commits[i].len(), 1, "expected exactly one block");
    }
    let block = &sim.commits[honest[0]][0];
    for &i in &honest {
        assert_eq!(sim.commits[i][0].header.id(), block.header.id());
    }
    block.qc.verify(&block.header, &sim.set).expect("valid QC");
    assert_eq!(block.header.height, 1);

    let proof = NotarizationProof::from_block(block, 0).unwrap();
    proof.verify(&sim.set).expect("proof verifies");
    assert_eq!(proof.hash(), Hash::digest(b"one-and-only"));

    // Draining again produces nothing more — no empty blocks, back to idle.
    sim.run();
    for &i in &honest {
        assert_eq!(sim.commits[i].len(), 1, "no empty blocks after going idle");
    }
    assert!(sim.all_honest_parked());
}

#[test]
fn each_attestation_triggers_its_own_block() {
    let mut sim = Sim::new(4);
    sim.start();
    sim.run();

    for (n, tag) in [(1u64, b"doc-a".as_slice()), (2, b"doc-b"), (3, b"doc-c")] {
        let att = client_attestation(tag);
        sim.submit_to_all(&att);
        sim.run();
        for &i in &sim.honest() {
            assert_eq!(sim.commits[i].len() as u64, n, "one block per attestation");
            assert_eq!(sim.commits[i][(n - 1) as usize].header.height, n);
        }
    }

    // Blocks are properly chained: each references the previous block's id.
    let chain = &sim.commits[sim.honest()[0]];
    for w in chain.windows(2) {
        assert_eq!(w[1].header.prev_hash, w[0].header.id(), "blocks must chain");
    }
}

#[test]
fn view_change_recovers_from_crashed_proposer() {
    let mut sim = Sim::new(4);
    let crashed = sim.crash_round0_proposer(1);
    sim.start();

    let att = client_attestation(b"view-change");
    sim.submit_to_all(&att);
    sim.run();

    let honest = sim.honest();
    assert_eq!(honest.len(), 3);
    let block = &sim.commits[honest[0]][0];
    block.qc.verify(&block.header, &sim.set).expect("QC valid despite crash");

    let signers: Vec<Hash> = block.qc.signatures.iter().map(|s| s.validator.id()).collect();
    assert!(!signers.contains(&crashed.id()), "crashed node must not have signed");
    for &i in &honest {
        assert_eq!(sim.commits[i][0].header.id(), block.header.id());
    }
}

#[test]
fn seven_validators_tolerate_two_faults() {
    let mut sim = Sim::new(7);
    assert_eq!(sim.set.threshold(), 5);
    sim.crash_round0_proposer(1);
    let extra = sim.crashed.iter().position(|&c| !c).unwrap();
    sim.crashed[extra] = true;
    assert_eq!(sim.honest().len(), 5);

    sim.start();
    let att = client_attestation(b"n7-f2");
    sim.submit_to_all(&att);
    sim.run();

    let honest = sim.honest();
    let block = &sim.commits[honest[0]][0];
    block.qc.verify(&block.header, &sim.set).expect("QC valid with 2 faults");
    for &i in &honest {
        assert_eq!(sim.commits[i][0].header.id(), block.header.id());
    }
}
