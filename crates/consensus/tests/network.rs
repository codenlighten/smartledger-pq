//! In-memory network simulation: run N independent [`Engine`]s, relay their
//! broadcasts, fire their timers, and assert they reach identical, valid,
//! quorum-certified blocks — including under a crashed proposer (view change).

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
    fn new(n: usize, seed_att: &Attestation) -> Sim {
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
            e.add_attestation(seed_att.clone());
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

    /// Crash the validator that would propose `height`/round 0, so the network
    /// must change view to make progress. Engine `i` owns `set.validators()[i]`
    /// (both built from the same key order in `Sim::new`).
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
                Effect::ScheduleTimeout {
                    height,
                    round,
                    kind,
                } => self.timerq.push_back((i, height, round, kind)),
                Effect::Committed(block) => self.commits[i].push(block),
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

    fn run_until_height(&mut self, target: u64) {
        let mut steps = 0;
        while steps < 200_000 {
            steps += 1;
            if self.min_honest_height() > target {
                return;
            }
            if let Some(msg) = self.msgq.pop_front() {
                for i in 0..self.engines.len() {
                    if self.crashed[i] {
                        continue;
                    }
                    let eff = self.engines[i].on_message(msg.clone());
                    self.apply(i, eff);
                }
            } else if let Some((i, h, r, kind)) = self.timerq.pop_front() {
                if self.crashed[i] {
                    continue;
                }
                let eff = self.engines[i].on_timeout(h, r, kind);
                self.apply(i, eff);
            } else {
                panic!("network went quiescent before reaching height {target}");
            }
        }
        panic!("step budget exhausted before reaching height {target}");
    }

    fn min_honest_height(&self) -> u64 {
        (0..self.engines.len())
            .filter(|&i| !self.crashed[i])
            .map(|i| self.engines[i].height())
            .min()
            .unwrap()
    }

    fn honest_indices(&self) -> Vec<usize> {
        (0..self.engines.len()).filter(|&i| !self.crashed[i]).collect()
    }
}

fn client_attestation(tag: &[u8]) -> Attestation {
    let (sk, pk) = SigningKey::generate().unwrap();
    Attestation::create(&sk, &pk, Hash::digest(tag)).unwrap()
}

#[test]
fn all_honest_commit_identical_blocks() {
    let att = client_attestation(b"honest-path");
    let mut sim = Sim::new(4, &att);
    sim.start();
    sim.run_until_height(2); // commit heights 1 and 2

    let honest = sim.honest_indices();
    // Every honest node committed the same first block id.
    let first_ids: Vec<Hash> = honest
        .iter()
        .map(|&i| sim.commits[i][0].header.id())
        .collect();
    assert!(first_ids.windows(2).all(|w| w[0] == w[1]), "block ids diverged");

    // The committed block's quorum certificate verifies against the set.
    let block = &sim.commits[honest[0]][0];
    block
        .qc
        .verify(&block.header, &sim.set)
        .expect("committed block must carry a valid quorum certificate");
    assert_eq!(block.header.height, 1);

    // And a real notarization proof extracts and verifies from it.
    let proof = NotarizationProof::from_block(block, 0).unwrap();
    proof.verify(&sim.set).expect("proof from committed block verifies");
    assert_eq!(proof.hash(), Hash::digest(b"honest-path"));
}

#[test]
fn view_change_recovers_from_crashed_proposer() {
    let att = client_attestation(b"view-change");
    let mut sim = Sim::new(4, &att);
    // Crash whoever proposes height 1 at round 0 → forces a round change.
    let crashed_key = sim.crash_round0_proposer(1);

    sim.start();
    sim.run_until_height(1);

    let honest = sim.honest_indices();
    assert_eq!(honest.len(), 3, "one node crashed");
    let block = &sim.commits[honest[0]][0];

    // Still finalized, with a valid 3-of-4 quorum certificate...
    block.qc.verify(&block.header, &sim.set).expect("QC valid despite crash");
    // ...and the crashed validator did not sign it.
    let signers: Vec<Hash> = block.qc.signatures.iter().map(|s| s.validator.id()).collect();
    assert!(!signers.contains(&crashed_key.id()), "crashed node should not have signed");

    // All honest nodes agree on the same block.
    for &i in &honest {
        assert_eq!(sim.commits[i][0].header.id(), block.header.id());
    }
}

#[test]
fn seven_validators_tolerate_two_faults() {
    // n = 7 tolerates f = 2 faults; quorum = 5. Crash two validators and still
    // finalize — proving the Byzantine threshold generalizes.
    let att = client_attestation(b"n7-f2");
    let mut sim = Sim::new(7, &att);
    assert_eq!(sim.set.threshold(), 5);

    // Crash the round-0 proposer for height 1, plus one more distinct node.
    sim.crash_round0_proposer(1);
    let extra = sim.crashed.iter().position(|&c| !c).unwrap();
    sim.crashed[extra] = true;
    assert_eq!(sim.honest_indices().len(), 5);

    sim.start();
    sim.run_until_height(1);

    let honest = sim.honest_indices();
    let block = &sim.commits[honest[0]][0];
    block.qc.verify(&block.header, &sim.set).expect("QC valid with 2 faults");
    for &i in &honest {
        assert_eq!(sim.commits[i][0].header.id(), block.header.id());
    }
}
