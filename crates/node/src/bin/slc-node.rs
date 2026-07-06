//! `slc-node` — run a SmartLedger-Chain validator, or generate its keys.
//!
//! Usage:
//!   slc-node keygen <keystore.json>       Generate a validator keypair.
//!   slc-node run <config.json>            Run a validator from a node config.

use slc_anchor::{AnchorService, FileAnchor, MockAnchor};
use slc_node::config::NodeConfig;
use slc_node::{keystore, Node, Transport};
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("keygen") => match args.get(2) {
            Some(path) => keygen(path),
            None => usage(),
        },
        Some("run") => match args.get(2) {
            Some(path) => run(path),
            None => usage(),
        },
        _ => usage(),
    }
}

fn usage() -> ExitCode {
    eprintln!("usage:");
    eprintln!("  slc-node keygen <keystore.json>");
    eprintln!("  slc-node run <config.json>");
    ExitCode::FAILURE
}

fn keygen(path: &str) -> ExitCode {
    match keystore::generate(Path::new(path)) {
        Ok((_, pk)) => {
            println!("generated validator key");
            println!("public key (hex): {}", pk.to_hex());
            println!("identity (id)   : {}", pk.id());
            println!("wrote keystore  : {path}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("keygen failed: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(config_path: &str) -> ExitCode {
    let cfg: NodeConfig = match std::fs::read_to_string(config_path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
    {
        Some(c) => c,
        None => {
            eprintln!("could not read/parse config: {config_path}");
            return ExitCode::FAILURE;
        }
    };

    let (sk, pk) = match keystore::load(Path::new(&cfg.key_path)) {
        Ok(kp) => kp,
        Err(e) => {
            eprintln!("could not load keystore {}: {e}", cfg.key_path);
            return ExitCode::FAILURE;
        }
    };

    // Find our own listen address in the genesis roster.
    let my_addr = match cfg.genesis.validators.iter().find(|v| v.pubkey == pk) {
        Some(v) => v.addr.clone(),
        None => {
            eprintln!("this node's public key is not in the genesis validator set");
            return ExitCode::FAILURE;
        }
    };

    let mut transport = match Transport::bind(&my_addr) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("could not bind {my_addr}: {e}");
            return ExitCode::FAILURE;
        }
    };
    transport.set_peers(cfg.genesis.peer_addrs(&pk));

    println!("chain     : {}", cfg.genesis.chain_id);
    println!("identity  : {}", pk.id());
    println!("listening : {my_addr}");
    println!("validators: {}", cfg.genesis.validators.len());

    let mut node = Node::new(
        transport,
        &cfg.genesis,
        sk,
        pk,
        Some(Path::new(&cfg.block_store_path)),
        Duration::from_millis(cfg.base_timeout_ms),
    );

    // Optional public-chain anchoring.
    if cfg.anchor_interval > 0 {
        let backend: Box<dyn slc_anchor::AnchorBackend> = match &cfg.anchor_file {
            Some(path) => Box::new(FileAnchor::new(path.clone())),
            None => Box::new(MockAnchor::new()),
        };
        let service = AnchorService::new(backend, cfg.anchor_interval as usize);
        println!(
            "anchoring : every {} blocks via {}",
            cfg.anchor_interval,
            service.backend_name()
        );
        node = node.with_anchor(service);
    }

    let handle = node.spawn();

    // Run until Ctrl-C (the thread lives inside the handle).
    handle_wait(handle);
    ExitCode::SUCCESS
}

fn handle_wait(handle: slc_node::NodeHandle) {
    println!("node listening on {}. press Ctrl-C to stop.", handle.local_addr());
    // Park the main thread, keeping `handle` alive; the node runs on its own
    // thread. Ctrl-C terminates the process.
    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
}
