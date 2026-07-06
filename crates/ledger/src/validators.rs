//! The validator set — the roster of legally-known node operators whose
//! collective signatures finalize history.
//!
//! Security scales with membership: forging or rewriting a finalized block
//! requires a *quorum* of these named legal entities to each sign a fork — a
//! coordinated act of fraud that is legally attributable and (given public
//! anchoring) externally detectable.

use serde::{Deserialize, Serialize};
use slc_crypto::VerifyingKey;

/// An immutable snapshot of the validator roster and its quorum threshold.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorSet {
    validators: Vec<VerifyingKey>,
    threshold: usize,
}

impl ValidatorSet {
    /// Build a set with an explicit quorum threshold. Panics only on the
    /// nonsensical `threshold == 0` or `threshold > n`.
    pub fn new(validators: Vec<VerifyingKey>, threshold: usize) -> ValidatorSet {
        assert!(threshold >= 1, "quorum threshold must be at least 1");
        assert!(
            threshold <= validators.len(),
            "quorum threshold cannot exceed validator count"
        );
        ValidatorSet {
            validators,
            threshold,
        }
    }

    /// Build a set with the standard Byzantine quorum `n - f`, where `f` is the
    /// largest number of faults tolerable under `n >= 3f + 1`. For n = 4 the
    /// quorum is 3; for n = 7 it is 5; for n = 10 it is 7.
    pub fn bft(validators: Vec<VerifyingKey>) -> ValidatorSet {
        let n = validators.len();
        let f = n.saturating_sub(1) / 3;
        ValidatorSet::new(validators, n - f)
    }

    pub fn threshold(&self) -> usize {
        self.threshold
    }

    pub fn len(&self) -> usize {
        self.validators.len()
    }

    pub fn is_empty(&self) -> bool {
        self.validators.is_empty()
    }

    pub fn validators(&self) -> &[VerifyingKey] {
        &self.validators
    }

    /// Is `key` a member of this validator set?
    pub fn contains(&self, key: &VerifyingKey) -> bool {
        self.validators.iter().any(|v| v == key)
    }
}
