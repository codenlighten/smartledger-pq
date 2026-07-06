//! `slc-node` — the runnable SmartLedger-Chain node.
//!
//! It binds a [`Transport`], drives the [`slc_consensus::Engine`] with real
//! network messages and timers, and persists finalized blocks. Everything funnels
//! through one [`Event`] loop, so the node has no shared-state races: the engine
//! is only ever touched from its own thread.
//!
//! ```no_run
//! use slc_node::{Node, Transport};
//! # use slc_node::config::GenesisConfig;
//! # fn go(genesis: GenesisConfig, sk: slc_crypto::SigningKey, pk: slc_crypto::VerifyingKey) {
//! let mut transport = Transport::bind("0.0.0.0:9000").unwrap();
//! transport.set_peers(genesis.peer_addrs(&pk));
//! let node = Node::new(transport, &genesis, sk, pk, None, std::time::Duration::from_millis(1000));
//! let handle = node.spawn();
//! # let _ = handle;
//! # }
//! ```

pub mod config;
pub mod keystore;
pub mod storage;

mod event;
mod node;
mod timers;
mod transport;
mod wire;

pub use event::Event;
pub use node::{Node, NodeHandle};
pub use transport::Transport;
pub use wire::WireMsg;

// Re-export the anchoring surface for convenience.
pub use slc_anchor::{AnchorRecord, AnchorService};
