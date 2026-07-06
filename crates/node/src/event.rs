//! The single event type that funnels into a node's run loop from every
//! source: the network, the timer service, and local client submissions.

use crate::wire::WireMsg;
use slc_consensus::TimeoutKind;
use slc_ledger::Attestation;

/// An input to [`crate::Node`]'s serialized event loop.
pub enum Event {
    /// A framed message arrived from a peer.
    Wire(WireMsg),
    /// A previously scheduled timer fired for `(height, round, kind)`.
    Timeout(u64, u64, TimeoutKind),
    /// A local client submitted an attestation to notarize.
    Submit(Attestation),
    /// Stop the loop.
    Shutdown,
}
