//! The Quorum-Certified Notary BFT state machine — one instance per validator.
//!
//! This is a faithful, compact implementation of the Tendermint consensus
//! algorithm (Buchman–Kwon–Milosevic, "The latest gossip on BFT consensus"),
//! specialized to a conflict-free notary workload: values are candidate blocks,
//! `valid(v)` is pure structural + signature checking (no transaction
//! execution), and a committed decision yields a [`Block`] whose
//! [`QuorumCertificate`] is assembled directly from the precommit signatures.
//!
//! The engine is deterministic and **I/O-free**: it consumes events
//! ([`Engine::on_message`], [`Engine::on_timeout`]) and emits [`Effect`]s
//! (broadcast, schedule-timeout, committed). A network/clock driver lives above
//! it. This is what makes consensus exhaustively testable in-process.

use crate::messages::{ConsensusMsg, Proposed, ProposalMsg, VoteMsg, VoteType};
use slc_crypto::{Hash, SigningKey, VerifyingKey};
use slc_ledger::{
    Attestation, Block, BlockHeader, MerkleTree, QuorumCertificate, ValidatorChange,
    ValidatorRegistry, ValidatorSet,
};
use std::collections::{HashMap, HashSet};

/// Maximum attestations packed into one block.
const MAX_TXS: usize = 10_000;

/// The phase within a round.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Step {
    Propose,
    Prevote,
    Precommit,
}

/// Which timeout a driver scheduled and is now firing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimeoutKind {
    Propose,
    Prevote,
    Precommit,
}

/// A side effect the driver must carry out.
///
/// Variants differ a lot in size because post-quantum objects are large (an
/// ML-DSA signature alone is ~3.3 KB); that is intrinsic, not an oversight.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug)]
pub enum Effect {
    /// Send this message to every other validator (and, conceptually, self).
    Broadcast(ConsensusMsg),
    /// Arm a timer; fire it back via [`Engine::on_timeout`] when it elapses.
    ScheduleTimeout {
        height: u64,
        round: u64,
        kind: TimeoutKind,
    },
    /// A block was finalized. Persist it and serve proofs from it. Boxed
    /// because a `Block` is far larger than the other effect variants.
    Committed(Box<Block>),
}

/// What a vote count should match.
#[derive(Clone, Copy)]
enum Match {
    Id(Hash),
    Nil,
    Any,
}

fn matches(block_id: Option<Hash>, want: Match) -> bool {
    match want {
        Match::Any => true,
        Match::Nil => block_id.is_none(),
        Match::Id(h) => block_id == Some(h),
    }
}

/// A single validator's consensus state machine.
pub struct Engine {
    /// The evolving roster; the active set is a function of height.
    registry: ValidatorRegistry,
    /// The validator set in force at the current height (cached).
    current_set: ValidatorSet,
    /// `current_set`'s members sorted by id, for deterministic proposer choice.
    validators_sorted: Vec<VerifyingKey>,
    me_sk: SigningKey,
    me_pk: VerifyingKey,

    height: u64,
    round: u64,
    step: Step,
    tip: Hash,
    now: u64,

    locked_value: Option<Proposed>,
    locked_round: Option<u64>,
    valid_value: Option<Proposed>,
    valid_round: Option<u64>,

    mempool: Vec<Attestation>,

    // Message stores for the current height, keyed by round.
    proposals: HashMap<u64, ProposalMsg>,
    prevotes: HashMap<u64, HashMap<Hash, VoteMsg>>,
    precommits: HashMap<u64, HashMap<Hash, VoteMsg>>,

    // One-shot guards (per round).
    prevote_timeout_started: HashSet<u64>,
    precommit_timeout_started: HashSet<u64>,
    polka_applied: HashSet<u64>,

    /// True when we have entered a fresh height (round 0) with nothing to
    /// notarize and are idling. A local attestation or any consensus activity
    /// un-parks us. This is what keeps an idle chain from minting empty blocks.
    parked: bool,
}

impl Engine {
    /// Create an engine for validator `me`, producing `start_height` on top of
    /// `tip` (use `Hash::zero()` and height `1` for a fresh chain after an
    /// implicit genesis at height 0).
    pub fn new(
        set: ValidatorSet,
        me_sk: SigningKey,
        me_pk: VerifyingKey,
        tip: Hash,
        start_height: u64,
    ) -> Engine {
        let registry = ValidatorRegistry::new(set.validators().to_vec());
        Engine::with_registry(registry, me_sk, me_pk, tip, start_height)
    }

    /// Create an engine backed by a [`ValidatorRegistry`], so the validator set
    /// can change by height via governance.
    pub fn with_registry(
        registry: ValidatorRegistry,
        me_sk: SigningKey,
        me_pk: VerifyingKey,
        tip: Hash,
        start_height: u64,
    ) -> Engine {
        let current_set = registry.active_set(start_height);
        let mut validators_sorted = current_set.validators().to_vec();
        validators_sorted.sort_by_key(|v| v.id());
        Engine {
            registry,
            current_set,
            validators_sorted,
            me_sk,
            me_pk,
            height: start_height,
            round: 0,
            step: Step::Propose,
            tip,
            now: 0,
            locked_value: None,
            locked_round: None,
            valid_value: None,
            valid_round: None,
            mempool: Vec::new(),
            proposals: HashMap::new(),
            prevotes: HashMap::new(),
            precommits: HashMap::new(),
            prevote_timeout_started: HashSet::new(),
            precommit_timeout_started: HashSet::new(),
            polka_applied: HashSet::new(),
            parked: false,
        }
    }

    // ---- driver-facing API ------------------------------------------------

    pub fn height(&self) -> u64 {
        self.height
    }
    pub fn round(&self) -> u64 {
        self.round
    }
    /// The validator set currently in force (at the engine's height).
    pub fn validator_set(&self) -> &ValidatorSet {
        &self.current_set
    }

    /// Record a finalized, authorized validator-set change. It applies at its
    /// `activation_height`; every node that records the identical change stays
    /// in agreement on who the validators are at each height.
    pub fn record_validator_change(&mut self, change: ValidatorChange) {
        self.registry.record(change);
        self.reload_set();
    }

    pub fn tip(&self) -> Hash {
        self.tip
    }

    /// Set the engine's notion of wall-clock time (unix seconds) used as the
    /// timestamp of blocks this node proposes.
    pub fn set_time(&mut self, now: u64) {
        self.now = now;
    }

    /// Queue an attestation for inclusion in a future block. If we were idling
    /// (parked) with nothing to notarize, this wakes us up and — if we are the
    /// proposer — kicks off a block. Returns any resulting effects.
    pub fn add_attestation(&mut self, att: Attestation) -> Vec<Effect> {
        self.mempool.push(att);
        let mut out = Vec::new();
        if self.parked {
            self.unpark(&mut out);
            self.advance(&mut out);
        }
        out
    }

    /// Whether the engine is currently idling with nothing to notarize.
    pub fn is_parked(&self) -> bool {
        self.parked
    }

    /// Begin consensus at the starting height (round 0).
    pub fn start(&mut self) -> Vec<Effect> {
        let mut out = Vec::new();
        self.start_round(0, &mut out);
        self.advance(&mut out);
        out
    }

    /// Handle an inbound consensus message.
    pub fn on_message(&mut self, msg: ConsensusMsg) -> Vec<Effect> {
        let mut out = Vec::new();
        // Always ingest (so votes are recorded even while we are parked), but
        // only *wake up* for something real to do: a proposal for our current
        // height means there is an actual block to vote on. We deliberately do
        // NOT un-park on votes or on stale/other-height messages — otherwise an
        // idle node would churn empty rounds forever, since an empty block can
        // never be finalized.
        let wake = matches!(&msg, ConsensusMsg::Proposal(pm) if pm.height == self.height);
        match msg {
            ConsensusMsg::Proposal(pm) => self.ingest_proposal(pm),
            ConsensusMsg::Vote(vm) => self.ingest_vote(vm),
        }
        if self.parked && wake && self.proposals.contains_key(&self.round) {
            self.unpark(&mut out);
        }
        self.advance(&mut out);
        out
    }

    /// Handle a timer that the driver previously scheduled.
    pub fn on_timeout(&mut self, height: u64, round: u64, kind: TimeoutKind) -> Vec<Effect> {
        let mut out = Vec::new();
        if height == self.height && round == self.round {
            match kind {
                TimeoutKind::Propose if self.step == Step::Propose => {
                    self.emit_prevote(None, &mut out);
                    self.step = Step::Prevote;
                }
                TimeoutKind::Prevote if self.step == Step::Prevote => {
                    self.emit_precommit(None, &mut out);
                    self.step = Step::Precommit;
                }
                TimeoutKind::Precommit => {
                    self.start_round(self.round + 1, &mut out);
                }
                _ => {}
            }
        }
        self.advance(&mut out);
        out
    }

    // ---- helpers ----------------------------------------------------------

    fn n(&self) -> usize {
        self.validators_sorted.len()
    }
    fn quorum(&self) -> usize {
        self.current_set.threshold()
    }

    /// Recompute the active validator set for the current height. Called when
    /// the height advances, so governance changes take effect at their
    /// activation height on every node identically.
    fn reload_set(&mut self) {
        self.current_set = self.registry.active_set(self.height);
        self.validators_sorted = self.current_set.validators().to_vec();
        self.validators_sorted.sort_by_key(|v| v.id());
    }
    fn f(&self) -> usize {
        self.n() - self.quorum()
    }

    fn proposer(&self, round: u64) -> &VerifyingKey {
        let idx = ((self.height + round) % self.n() as u64) as usize;
        &self.validators_sorted[idx]
    }
    fn is_proposer(&self, round: u64) -> bool {
        *self.proposer(round) == self.me_pk
    }

    fn get_value(&self) -> Proposed {
        let attestations: Vec<Attestation> =
            self.mempool.iter().take(MAX_TXS).cloned().collect();
        let leaves: Vec<Hash> = attestations.iter().map(|a| a.leaf_hash()).collect();
        let merkle_root = MerkleTree::build(leaves).root();
        let header = BlockHeader {
            height: self.height,
            prev_hash: self.tip,
            merkle_root,
            tx_count: attestations.len() as u32,
            timestamp: self.now,
        };
        Proposed {
            header,
            attestations,
        }
    }

    fn count_prevotes(&self, round: u64, want: Match) -> usize {
        self.prevotes
            .get(&round)
            .map_or(0, |m| m.values().filter(|v| matches(v.block_id, want)).count())
    }
    fn count_precommits(&self, round: u64, want: Match) -> usize {
        self.precommits
            .get(&round)
            .map_or(0, |m| m.values().filter(|v| matches(v.block_id, want)).count())
    }

    fn locked_id(&self) -> Option<Hash> {
        self.locked_value.as_ref().map(|v| v.id())
    }

    // ---- emitting our own messages ---------------------------------------

    fn start_round(&mut self, round: u64, out: &mut Vec<Effect>) {
        self.round = round;
        self.step = Step::Propose;
        // At the start of a fresh height with nothing pending, idle instead of
        // proposing. We only reach round 0 with `valid_value == None` (it is
        // reset on commit), so an empty mempool here means truly nothing to do.
        if round == 0 && self.valid_value.is_none() && self.mempool.is_empty() {
            self.parked = true;
            return;
        }
        self.parked = false;
        self.enter_propose(round, out);
    }

    /// Enter the propose step for `round`: propose if we can, otherwise arm the
    /// propose timeout so the round still advances.
    fn enter_propose(&mut self, round: u64, out: &mut Vec<Effect>) {
        if self.is_proposer(round) {
            let (value, vr) = match &self.valid_value {
                Some(v) => (v.clone(), self.valid_round),
                None => (self.get_value(), None),
            };
            // Never propose an empty block — no quorum would ratify it anyway.
            // With an empty mempool we instead let the round time out.
            if !value.attestations.is_empty() {
                let pm =
                    ProposalMsg::create(&self.me_sk, self.me_pk.clone(), self.height, round, vr, value);
                self.proposals.entry(round).or_insert_with(|| pm.clone());
                out.push(Effect::Broadcast(ConsensusMsg::Proposal(pm)));
                return;
            }
        }
        out.push(Effect::ScheduleTimeout {
            height: self.height,
            round,
            kind: TimeoutKind::Propose,
        });
    }

    /// Leave the idle state and actually enter the current round.
    fn unpark(&mut self, out: &mut Vec<Effect>) {
        if self.parked {
            self.parked = false;
            self.enter_propose(self.round, out);
        }
    }

    fn emit_prevote(&mut self, id: Option<Hash>, out: &mut Vec<Effect>) {
        let vm = VoteMsg::create(
            &self.me_sk,
            self.me_pk.clone(),
            self.height,
            self.round,
            VoteType::Prevote,
            id,
        );
        self.prevotes
            .entry(self.round)
            .or_default()
            .insert(self.me_pk.id(), vm.clone());
        out.push(Effect::Broadcast(ConsensusMsg::Vote(vm)));
    }

    fn emit_precommit(&mut self, id: Option<Hash>, out: &mut Vec<Effect>) {
        let vm = VoteMsg::create(
            &self.me_sk,
            self.me_pk.clone(),
            self.height,
            self.round,
            VoteType::Precommit,
            id,
        );
        self.precommits
            .entry(self.round)
            .or_default()
            .insert(self.me_pk.id(), vm.clone());
        out.push(Effect::Broadcast(ConsensusMsg::Vote(vm)));
    }

    // ---- ingesting others' messages --------------------------------------

    fn ingest_proposal(&mut self, pm: ProposalMsg) {
        if pm.height != self.height {
            return;
        }
        // Only the round's designated proposer may propose, and it must sign.
        if *self.proposer(pm.round) != pm.proposer || !pm.verify_sig() {
            return;
        }
        // First proposal for a round wins; ignore equivocating re-proposals.
        self.proposals.entry(pm.round).or_insert(pm);
    }

    fn ingest_vote(&mut self, vm: VoteMsg) {
        if vm.height != self.height || !self.current_set.contains(&vm.voter) || !vm.verify_sig() {
            return;
        }
        let store = match vm.vote_type {
            VoteType::Prevote => &mut self.prevotes,
            VoteType::Precommit => &mut self.precommits,
        };
        // First vote per (round, voter) wins; ignore equivocation.
        store.entry(vm.round).or_default().entry(vm.voter.id()).or_insert(vm);
    }

    // ---- the transition rules --------------------------------------------

    /// Apply every enabled rule until the state stops changing.
    fn advance(&mut self, out: &mut Vec<Effect>) {
        loop {
            let changed = self.try_commit(out)
                || self.try_skip(out)
                || self.try_prevote_on_proposal(out)
                || self.try_prevote_on_reproposal(out)
                || self.try_schedule_prevote_timeout(out)
                || self.try_precommit_on_polka(out)
                || self.try_precommit_nil(out)
                || self.try_schedule_precommit_timeout(out);
            if !changed {
                break;
            }
        }
    }

    /// Commit rule: a proposal for round `r` plus a precommit quorum for its id.
    fn try_commit(&mut self, out: &mut Vec<Effect>) -> bool {
        let candidates: Vec<(u64, Hash)> =
            self.proposals.iter().map(|(&r, pm)| (r, pm.value.id())).collect();
        for (r, id) in candidates {
            if self.count_precommits(r, Match::Id(id)) >= self.quorum() {
                let pm = self.proposals.get(&r).expect("present").clone();
                if pm.value.is_valid(self.tip, self.height) {
                    self.commit(r, id, pm.value, out);
                    return true;
                }
            }
        }
        false
    }

    /// Skip rule: on f+1 messages from a round beyond the current one, jump.
    fn try_skip(&mut self, out: &mut Vec<Effect>) -> bool {
        let mut rounds: Vec<u64> = self
            .prevotes
            .keys()
            .chain(self.precommits.keys())
            .copied()
            .filter(|&r| r > self.round)
            .collect();
        rounds.sort_unstable();
        rounds.dedup();
        for r in rounds {
            let mut voters: HashSet<Hash> = HashSet::new();
            if let Some(m) = self.prevotes.get(&r) {
                voters.extend(m.keys().copied());
            }
            if let Some(m) = self.precommits.get(&r) {
                voters.extend(m.keys().copied());
            }
            if voters.len() > self.f() {
                self.start_round(r, out);
                return true;
            }
        }
        false
    }

    /// Prevote on a fresh proposal (valid_round == None) while in Propose.
    fn try_prevote_on_proposal(&mut self, out: &mut Vec<Effect>) -> bool {
        if self.step != Step::Propose {
            return false;
        }
        let pm = match self.proposals.get(&self.round) {
            Some(p) if p.valid_round.is_none() => p.clone(),
            _ => return false,
        };
        let v = &pm.value;
        let acceptable =
            self.locked_round.is_none() || self.locked_id() == Some(v.id());
        let id = if v.is_valid(self.tip, self.height) && acceptable {
            Some(v.id())
        } else {
            None
        };
        self.emit_prevote(id, out);
        self.step = Step::Prevote;
        true
    }

    /// Prevote on a re-proposal justified by a polka in round `vr < round`.
    fn try_prevote_on_reproposal(&mut self, out: &mut Vec<Effect>) -> bool {
        if self.step != Step::Propose {
            return false;
        }
        let pm = match self.proposals.get(&self.round) {
            Some(p) if p.valid_round.is_some_and(|vr| vr < self.round) => p.clone(),
            _ => return false,
        };
        let vr = pm.valid_round.expect("checked");
        if self.count_prevotes(vr, Match::Id(pm.value.id())) < self.quorum() {
            return false;
        }
        let v = &pm.value;
        let acceptable =
            self.locked_round.is_none_or(|lr| lr <= vr) || self.locked_id() == Some(v.id());
        let id = if v.is_valid(self.tip, self.height) && acceptable {
            Some(v.id())
        } else {
            None
        };
        self.emit_prevote(id, out);
        self.step = Step::Prevote;
        true
    }

    /// Once we have any prevote quorum for the current round, arm the prevote
    /// timeout so a split vote cannot hang us.
    fn try_schedule_prevote_timeout(&mut self, out: &mut Vec<Effect>) -> bool {
        if self.step == Step::Prevote
            && !self.prevote_timeout_started.contains(&self.round)
            && self.count_prevotes(self.round, Match::Any) >= self.quorum()
        {
            self.prevote_timeout_started.insert(self.round);
            out.push(Effect::ScheduleTimeout {
                height: self.height,
                round: self.round,
                kind: TimeoutKind::Prevote,
            });
            return true;
        }
        false
    }

    /// Polka for a value: lock it, precommit it, and record it as valid.
    fn try_precommit_on_polka(&mut self, out: &mut Vec<Effect>) -> bool {
        if self.step < Step::Prevote || self.polka_applied.contains(&self.round) {
            return false;
        }
        let pm = match self.proposals.get(&self.round) {
            Some(p) => p.clone(),
            None => return false,
        };
        let v = &pm.value;
        if self.count_prevotes(self.round, Match::Id(v.id())) < self.quorum()
            || !v.is_valid(self.tip, self.height)
        {
            return false;
        }
        self.polka_applied.insert(self.round);
        if self.step == Step::Prevote {
            self.locked_value = Some(v.clone());
            self.locked_round = Some(self.round);
            self.emit_precommit(Some(v.id()), out);
            self.step = Step::Precommit;
        }
        self.valid_value = Some(v.clone());
        self.valid_round = Some(self.round);
        true
    }

    /// Polka for nil: precommit nil and move on.
    fn try_precommit_nil(&mut self, out: &mut Vec<Effect>) -> bool {
        if self.step == Step::Prevote && self.count_prevotes(self.round, Match::Nil) >= self.quorum() {
            self.emit_precommit(None, out);
            self.step = Step::Precommit;
            return true;
        }
        false
    }

    /// Once we have any precommit quorum for the current round, arm the
    /// precommit timeout so an inconclusive round eventually advances.
    fn try_schedule_precommit_timeout(&mut self, out: &mut Vec<Effect>) -> bool {
        if !self.precommit_timeout_started.contains(&self.round)
            && self.count_precommits(self.round, Match::Any) >= self.quorum()
        {
            self.precommit_timeout_started.insert(self.round);
            out.push(Effect::ScheduleTimeout {
                height: self.height,
                round: self.round,
                kind: TimeoutKind::Precommit,
            });
            return true;
        }
        false
    }

    /// Finalize `value` at round `r`, assemble its quorum certificate from the
    /// precommit signatures, emit it, and roll forward to the next height.
    fn commit(&mut self, r: u64, id: Hash, value: Proposed, out: &mut Vec<Effect>) {
        let mut qc = QuorumCertificate::new(id);
        if let Some(votes) = self.precommits.get(&r) {
            for vm in votes.values() {
                if vm.block_id == Some(id) {
                    qc.add(vm.voter.clone(), vm.sig.clone());
                }
            }
        }
        let block = Block {
            header: value.header.clone(),
            attestations: value.attestations.clone(),
            qc,
        };

        // Drop the now-sealed attestations from the mempool.
        let sealed: HashSet<Hash> = block.attestations.iter().map(|a| a.leaf_hash()).collect();
        self.mempool.retain(|a| !sealed.contains(&a.leaf_hash()));

        out.push(Effect::Committed(Box::new(block)));

        // Roll forward to the next height with fully reset per-height state.
        self.height += 1;
        self.tip = id;
        // The validator set may change at this new height (governance activation).
        self.reload_set();
        self.round = 0;
        self.step = Step::Propose;
        self.locked_value = None;
        self.locked_round = None;
        self.valid_value = None;
        self.valid_round = None;
        self.proposals.clear();
        self.prevotes.clear();
        self.precommits.clear();
        self.prevote_timeout_started.clear();
        self.precommit_timeout_started.clear();
        self.polka_applied.clear();

        self.start_round(0, out);
    }
}
