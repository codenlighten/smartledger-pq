//! The node: it wires the consensus [`Engine`] to a real network, real timers,
//! and disk, then serializes every input through one event loop.

use crate::config::GenesisConfig;
use crate::event::Event;
use crate::storage::BlockStore;
use crate::timers::TimerService;
use crate::transport::Transport;
use crate::wire::WireMsg;
use slc_anchor::{AnchorRecord, AnchorService};
use slc_consensus::{Effect, Engine};
use slc_crypto::{SigningKey, VerifyingKey};
use slc_ledger::{Attestation, Block, ValidatorRegistry};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A running node. Build with [`Node::new`], then [`Node::spawn`].
pub struct Node {
    engine: Engine,
    transport: Transport,
    timers: TimerService,
    store: BlockStore,
    ev_rx: Receiver<Event>,
    ev_tx: Sender<Event>,
    base_timeout: Duration,
    /// Publishes periodic checkpoints to a public chain, when configured. Shared
    /// so the RPC can reconstruct anchored proofs from its checkpoint history.
    anchor: Option<Arc<Mutex<AnchorService>>>,
    /// Observable log of every checkpoint this node has anchored.
    anchor_records: Arc<Mutex<Vec<AnchorRecord>>>,
    /// Client-facing RPC listen address, when enabled.
    rpc_addr: Option<String>,
    /// This node's chain id and public identity, for the NodeInfo RPC.
    chain_id: String,
    node_pubkey: VerifyingKey,
}

/// A handle to a spawned node: submit attestations, observe commits, shut down.
pub struct NodeHandle {
    ev_tx: Sender<Event>,
    committed: Arc<Mutex<Vec<Block>>>,
    anchor_records: Arc<Mutex<Vec<AnchorRecord>>>,
    local_addr: SocketAddr,
    join: JoinHandle<()>,
}

impl NodeHandle {
    /// Submit an attestation for notarization (gossiped to all validators).
    pub fn submit(&self, att: Attestation) {
        let _ = self.ev_tx.send(Event::Submit(att));
    }

    /// Shared view of every block this node has finalized.
    pub fn committed(&self) -> Arc<Mutex<Vec<Block>>> {
        self.committed.clone()
    }

    /// Shared view of every checkpoint this node has anchored.
    pub fn anchor_records(&self) -> Arc<Mutex<Vec<AnchorRecord>>> {
        self.anchor_records.clone()
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Ask the loop to stop and wait for it.
    pub fn shutdown(self) {
        let _ = self.ev_tx.send(Event::Shutdown);
        let _ = self.join.join();
    }
}

impl Node {
    /// Assemble a node from a bound `transport`, the genesis config, and this
    /// node's own keypair. `store_path` may be `None` for an in-memory store.
    pub fn new(
        transport: Transport,
        genesis: &GenesisConfig,
        me_sk: SigningKey,
        me_pk: VerifyingKey,
        store_path: Option<&Path>,
        base_timeout: Duration,
    ) -> Node {
        // Resume from disk: if we have finalized blocks, continue the chain from
        // the stored tip rather than restarting at genesis. A fresh store yields
        // (zero, 0) → start at height 1 on top of the implicit genesis.
        let store = BlockStore::open(store_path);
        let (tip, last_height) = store.tip();
        // Rebuild the validator registry from genesis plus every governance
        // change recorded on-chain, so a rebooted node derives the current
        // validator set straight from its stored blocks — no config drift.
        let mut registry = ValidatorRegistry::new(genesis.validator_keys());
        for block in store.snapshot() {
            for change in &block.governance {
                registry.record(change.change.clone());
            }
        }
        let chain_id = genesis.chain_id.clone();
        let node_pubkey = me_pk.clone();
        let engine = Engine::with_registry(registry, me_sk, me_pk, tip, last_height + 1);
        let (ev_tx, ev_rx) = channel();
        transport
            .start_accept(ev_tx.clone())
            .expect("start accept loop");
        let timers = TimerService::start(ev_tx.clone());
        Node {
            engine,
            transport,
            timers,
            store,
            ev_rx,
            ev_tx,
            base_timeout,
            anchor: None,
            anchor_records: Arc::new(Mutex::new(Vec::new())),
            rpc_addr: None,
            chain_id,
            node_pubkey,
        }
    }

    /// Enable periodic public-chain anchoring with the given service.
    pub fn with_anchor(mut self, service: AnchorService) -> Node {
        self.anchor = Some(Arc::new(Mutex::new(service)));
        self
    }

    /// Enable the client-facing RPC on `addr` (e.g. `0.0.0.0:7000`).
    pub fn with_rpc(mut self, addr: impl Into<String>) -> Node {
        self.rpc_addr = Some(addr.into());
        self
    }

    /// Run the node on its own thread, returning a handle.
    pub fn spawn(self) -> NodeHandle {
        let ev_tx = self.ev_tx.clone();
        let committed = self.store.handle();
        let anchor_records = self.anchor_records.clone();
        let local_addr = self.transport.local_addr();

        // Start the client RPC before the loop moves onto its thread.
        if let Some(addr) = &self.rpc_addr {
            match std::net::TcpListener::bind(addr) {
                Ok(listener) => crate::rpc::serve(
                    listener,
                    ev_tx.clone(),
                    committed.clone(),
                    self.anchor.clone(),
                    self.chain_id.clone(),
                    self.node_pubkey.clone(),
                ),
                Err(e) => eprintln!("could not bind RPC on {addr}: {e}"),
            }
        }

        let join = thread::spawn(move || self.run());
        NodeHandle {
            ev_tx,
            committed,
            anchor_records,
            local_addr,
            join,
        }
    }

    fn run(mut self) {
        // Kick off consensus at the starting height.
        self.engine.set_time(now_unix());
        let effects = self.engine.start();
        self.handle_effects(effects);

        while let Ok(event) = self.ev_rx.recv() {
            self.engine.set_time(now_unix());
            let effects = match event {
                Event::Wire(WireMsg::Consensus(msg)) => self.engine.on_message(msg),
                Event::Wire(WireMsg::Attestation(att)) => self.engine.add_attestation(att),
                Event::Wire(WireMsg::Governance(change)) => self.engine.add_governance(change).1,
                Event::Timeout(h, r, kind) => self.engine.on_timeout(h, r, kind),
                Event::Submit(att) => {
                    // Gossip to peers so the next proposer can include it, then
                    // queue it locally (which may wake an idle proposer).
                    self.transport.broadcast(&WireMsg::Attestation(att.clone()));
                    self.engine.add_attestation(att)
                }
                Event::SubmitGovernance(change) => {
                    self.transport.broadcast(&WireMsg::Governance(change.clone()));
                    self.engine.add_governance(change).1
                }
                Event::Shutdown => {
                    self.timers.stop();
                    break;
                }
            };
            self.handle_effects(effects);
        }
    }

    fn handle_effects(&mut self, effects: Vec<Effect>) {
        for effect in effects {
            match effect {
                Effect::Broadcast(msg) => {
                    self.transport.broadcast(&WireMsg::Consensus(msg));
                }
                Effect::ScheduleTimeout {
                    height,
                    round,
                    kind,
                } => {
                    self.timers
                        .schedule(height, round, kind, self.timeout_for(round));
                }
                Effect::Committed(block) => {
                    self.store.append(&block);
                    // Feed the finalized block to the anchoring service; when a
                    // full checkpoint window closes, its root is published.
                    if let Some(anchor) = &self.anchor {
                        let record = anchor
                            .lock()
                            .unwrap()
                            .record_block(block.header.id(), block.header.height);
                        if let Some(record) = record {
                            println!(
                                "anchored checkpoint heights {}..={} via {} -> {}",
                                record.from_height,
                                record.to_height,
                                record.receipt.backend,
                                record.receipt.reference
                            );
                            self.anchor_records.lock().unwrap().push(record);
                        }
                    }
                }
            }
        }
    }

    /// Timeouts grow linearly with the round so a congested view eventually
    /// gives everyone enough time to converge.
    fn timeout_for(&self, round: u64) -> Duration {
        self.base_timeout * (round as u32 + 1)
    }
}
