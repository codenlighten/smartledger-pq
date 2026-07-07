//! The single event type that funnels into a node's run loop from every
//! source: the network, the timer service, and local client submissions.

use crate::wire::WireMsg;
use slc_consensus::TimeoutKind;
use slc_ledger::{Attestation, SignedValidatorChange};

/// An input to [`crate::Node`]'s serialized event loop.
pub enum Event {
    /// A framed message arrived from a peer.
    Wire(WireMsg),
    /// A previously scheduled timer fired for `(height, round, kind)`.
    Timeout(u64, u64, TimeoutKind),
    /// A local client submitted an attestation to notarize.
    Submit(Attestation),
    /// A local operator submitted an authorized validator-set change.
    SubmitGovernance(SignedValidatorChange),
    /// A local operator added a peer at runtime.
    AddPeer(String),
    /// Periodic tick to re-gossip current-round messages (partition recovery).
    Regossip,
    /// Periodic tick to poll peers for missing blocks (catch-up).
    SyncPoll,
    /// Stop the loop.
    Shutdown,
}
