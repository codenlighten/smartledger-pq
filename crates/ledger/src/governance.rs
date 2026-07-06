//! Validator-set governance: how the roster of legally-known validators changes
//! over time — safely, deterministically, and without a privileged admin key.
//!
//! Authorization is by the validators themselves: a [`ValidatorChange`] takes
//! effect only if a **quorum of the current validators** signs it (a
//! [`SignedValidatorChange`]). Changes carry an `activation_height` so every
//! node switches to the new set at the same, agreed height — the set in force at
//! any height is a pure function of the genesis roster plus the activated
//! changes ([`ValidatorRegistry::active_set`]).

use crate::{ValidatorSet, ValidatorSig};
use serde::{Deserialize, Serialize};
use slc_crypto::{context, Hash, VerifyingKey};
use std::collections::HashSet;

/// A proposed change to the validator set, effective at `activation_height`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorChange {
    /// Validators to add (legally-known actors joining).
    pub adds: Vec<VerifyingKey>,
    /// Validators to remove.
    pub removes: Vec<VerifyingKey>,
    /// The height at which this change becomes effective. Must be strictly
    /// greater than the height of the block that finalizes it, so every node
    /// has the change before it applies.
    pub activation_height: u64,
}

impl ValidatorChange {
    /// Canonical bytes that approving validators sign. Order-independent within
    /// `adds`/`removes` via sorting, so independently-built encodings match.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut adds: Vec<[u8; slc_crypto::PUBKEY_LEN]> =
            self.adds.iter().map(|k| k.to_bytes()).collect();
        let mut removes: Vec<[u8; slc_crypto::PUBKEY_LEN]> =
            self.removes.iter().map(|k| k.to_bytes()).collect();
        adds.sort_unstable();
        removes.sort_unstable();

        let mut buf = Vec::new();
        buf.extend_from_slice(b"SLCGOV");
        buf.extend_from_slice(&self.activation_height.to_be_bytes());
        buf.extend_from_slice(&(adds.len() as u32).to_be_bytes());
        for k in &adds {
            buf.extend_from_slice(k);
        }
        buf.extend_from_slice(&(removes.len() as u32).to_be_bytes());
        for k in &removes {
            buf.extend_from_slice(k);
        }
        buf
    }

    /// A stable id for this change.
    pub fn id(&self) -> Hash {
        Hash::digest(&self.signing_bytes())
    }

    fn is_empty(&self) -> bool {
        self.adds.is_empty() && self.removes.is_empty()
    }
}

/// A [`ValidatorChange`] plus the approvals that authorize it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedValidatorChange {
    pub change: ValidatorChange,
    /// Signatures from current validators over `change.signing_bytes()`.
    pub approvals: Vec<ValidatorSig>,
}

impl SignedValidatorChange {
    pub fn new(change: ValidatorChange) -> SignedValidatorChange {
        SignedValidatorChange {
            change,
            approvals: Vec::new(),
        }
    }

    /// Add an approval (validity is checked in [`Self::is_authorized`]).
    pub fn approve(&mut self, validator: VerifyingKey, signature: slc_crypto::Signature) {
        self.approvals.push(ValidatorSig {
            validator,
            signature,
        });
    }

    /// Is this change authorized by a quorum of `current` validators? Junk,
    /// duplicate, and non-member approvals contribute nothing. An empty change
    /// is never authorized.
    pub fn is_authorized(&self, current: &ValidatorSet) -> bool {
        if self.change.is_empty() {
            return false;
        }
        let msg = self.change.signing_bytes();
        let mut seen = HashSet::new();
        let mut valid = 0usize;
        for approval in &self.approvals {
            if !current.contains(&approval.validator) {
                continue;
            }
            if !seen.insert(approval.validator.id()) {
                continue;
            }
            if approval
                .validator
                .verify(&msg, &approval.signature, context::GOVERNANCE)
            {
                valid += 1;
            }
        }
        valid >= current.threshold()
    }
}

/// The evolving validator roster: genesis plus every activated change.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorRegistry {
    genesis: Vec<VerifyingKey>,
    /// Changes that have been finalized on-chain, each with the height of the
    /// block that recorded it (for auditing) and its own activation height.
    changes: Vec<ValidatorChange>,
}

impl ValidatorRegistry {
    pub fn new(genesis: Vec<VerifyingKey>) -> ValidatorRegistry {
        ValidatorRegistry {
            genesis,
            changes: Vec::new(),
        }
    }

    /// Record a finalized, authorized change. Idempotent per distinct change.
    pub fn record(&mut self, change: ValidatorChange) {
        self.changes.push(change);
    }

    /// The validator public keys in force at `height`: genesis, with every
    /// change whose `activation_height <= height` applied in order.
    pub fn active_keys(&self, height: u64) -> Vec<VerifyingKey> {
        let mut keys = self.genesis.clone();
        let mut active: Vec<&ValidatorChange> = self
            .changes
            .iter()
            .filter(|c| c.activation_height <= height)
            .collect();
        active.sort_by_key(|c| c.activation_height);
        for change in active {
            for r in &change.removes {
                keys.retain(|k| k != r);
            }
            for a in &change.adds {
                if !keys.contains(a) {
                    keys.push(a.clone());
                }
            }
        }
        keys
    }

    /// The Byzantine validator set in force at `height`.
    pub fn active_set(&self, height: u64) -> ValidatorSet {
        ValidatorSet::bft(self.active_keys(height))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use slc_crypto::SigningKey;

    fn keys(n: usize) -> (Vec<SigningKey>, Vec<VerifyingKey>) {
        let mut sks = Vec::new();
        let mut pks = Vec::new();
        for _ in 0..n {
            let (sk, pk) = SigningKey::generate().unwrap();
            sks.push(sk);
            pks.push(pk);
        }
        (sks, pks)
    }

    fn sign_change(sk: &SigningKey, change: &ValidatorChange) -> slc_crypto::Signature {
        sk.sign(&change.signing_bytes(), context::GOVERNANCE).unwrap()
    }

    #[test]
    fn registry_applies_changes_at_activation_height() {
        let (_sks, pks) = keys(4);
        let (_nsk, newcomer) = SigningKey::generate().unwrap();
        let mut reg = ValidatorRegistry::new(pks.clone());

        reg.record(ValidatorChange {
            adds: vec![newcomer.clone()],
            removes: vec![],
            activation_height: 10,
        });

        // Before activation: genesis roster.
        assert_eq!(reg.active_keys(9).len(), 4);
        assert!(!reg.active_keys(9).contains(&newcomer));
        // At/after activation: newcomer included, quorum recomputed.
        assert_eq!(reg.active_keys(10).len(), 5);
        assert!(reg.active_keys(10).contains(&newcomer));
        assert_eq!(reg.active_set(9).threshold(), 3); // n=4 -> quorum 3
        assert_eq!(reg.active_set(10).threshold(), 4); // n=5 -> quorum 4
    }

    #[test]
    fn removal_and_readd_are_idempotent() {
        let (_sks, pks) = keys(5);
        let mut reg = ValidatorRegistry::new(pks.clone());
        reg.record(ValidatorChange {
            adds: vec![],
            removes: vec![pks[4].clone()],
            activation_height: 3,
        });
        assert_eq!(reg.active_keys(3).len(), 4);
        // Removing an absent key and adding a present key are no-ops.
        reg.record(ValidatorChange {
            adds: vec![pks[0].clone()],
            removes: vec![pks[4].clone()],
            activation_height: 5,
        });
        assert_eq!(reg.active_keys(5).len(), 4);
    }

    #[test]
    fn quorum_of_current_validators_authorizes() {
        let (sks, pks) = keys(4);
        let set = ValidatorSet::bft(pks.clone()); // quorum 3
        let (_nsk, newcomer) = SigningKey::generate().unwrap();
        let change = ValidatorChange {
            adds: vec![newcomer],
            removes: vec![],
            activation_height: 2,
        };

        // Two approvals: not enough.
        let mut svc = SignedValidatorChange::new(change.clone());
        svc.approve(pks[0].clone(), sign_change(&sks[0], &change));
        svc.approve(pks[1].clone(), sign_change(&sks[1], &change));
        assert!(!svc.is_authorized(&set));

        // Three distinct current validators: authorized.
        svc.approve(pks[2].clone(), sign_change(&sks[2], &change));
        assert!(svc.is_authorized(&set));
    }

    #[test]
    fn outsider_and_duplicate_approvals_do_not_count() {
        let (sks, pks) = keys(4);
        let set = ValidatorSet::bft(pks.clone()); // quorum 3
        let (out_sk, out_pk) = SigningKey::generate().unwrap();
        let change = ValidatorChange {
            adds: vec![out_pk.clone()],
            removes: vec![],
            activation_height: 2,
        };
        let mut svc = SignedValidatorChange::new(change.clone());
        svc.approve(pks[0].clone(), sign_change(&sks[0], &change));
        // Duplicate of validator 0.
        svc.approve(pks[0].clone(), sign_change(&sks[0], &change));
        // An outsider (not in the current set).
        svc.approve(out_pk, sign_change(&out_sk, &change));
        assert!(!svc.is_authorized(&set), "only 1 distinct in-set approval");
    }

    #[test]
    fn empty_change_is_never_authorized() {
        let (sks, pks) = keys(4);
        let set = ValidatorSet::bft(pks.clone());
        let change = ValidatorChange {
            adds: vec![],
            removes: vec![],
            activation_height: 2,
        };
        let mut svc = SignedValidatorChange::new(change.clone());
        for i in 0..3 {
            svc.approve(pks[i].clone(), sign_change(&sks[i], &change));
        }
        assert!(!svc.is_authorized(&set));
    }
}
