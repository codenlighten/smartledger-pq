//! `slc-node` — run a SmartLedger-Chain validator, or generate its keys.
//!
//! Usage:
//!   slc-node keygen <keystore.json>       Generate a validator keypair.
//!   slc-node run <config.json>            Run a validator from a node config.

use slc_anchor::{AnchorService, FileAnchor, MockAnchor};
use slc_node::config::{GenesisConfig, NodeConfig, ValidatorInfo};
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
        Some("init-devnet") => match args.get(2) {
            Some(dir) => init_devnet(dir, args.get(3).and_then(|s| s.parse().ok()).unwrap_or(4)),
            None => usage(),
        },
        _ => usage(),
    }
}

fn usage() -> ExitCode {
    eprintln!("usage:");
    eprintln!("  slc-node keygen <keystore.json>");
    eprintln!("  slc-node run <config.json>");
    eprintln!("  slc-node init-devnet <dir> [num_nodes=4]");
    ExitCode::FAILURE
}

/// Generate keystores, a shared genesis, and per-node configs for a local
/// N-validator devnet under `dir`.
fn init_devnet(dir: &str, n: usize) -> ExitCode {
    let dir = Path::new(dir);
    if let Err(e) = std::fs::create_dir_all(dir) {
        eprintln!("could not create {}: {e}", dir.display());
        return ExitCode::FAILURE;
    }

    // Generate keys and assign addresses.
    let mut validators = Vec::new();
    let mut keys = Vec::new();
    for i in 0..n {
        let key_path = dir.join(format!("node{i}.key"));
        let pk = match keystore::generate(&key_path) {
            Ok((_, pk)) => pk,
            Err(e) => {
                eprintln!("keygen failed: {e}");
                return ExitCode::FAILURE;
            }
        };
        validators.push(ValidatorInfo {
            pubkey: pk,
            addr: format!("127.0.0.1:{}", 9000 + i),
        });
        keys.push(key_path);
    }

    let genesis = GenesisConfig {
        chain_id: "smartledger-devnet".into(),
        validators,
    };

    // Write the genesis (for `slc verify`) and one config per node.
    let write = |path: std::path::PathBuf, value: &serde_json::Value| -> std::io::Result<()> {
        std::fs::write(path, serde_json::to_string_pretty(value).unwrap())
    };
    if let Err(e) = write(
        dir.join("genesis.json"),
        &serde_json::to_value(&genesis).unwrap(),
    ) {
        eprintln!("write genesis failed: {e}");
        return ExitCode::FAILURE;
    }

    for (i, key) in keys.iter().enumerate() {
        let cfg = NodeConfig {
            genesis: genesis.clone(),
            key_path: key.to_string_lossy().into_owned(),
            block_store_path: dir.join(format!("node{i}.blocks")).to_string_lossy().into_owned(),
            base_timeout_ms: 1000,
            anchor_interval: 0,
            anchor_file: None,
            rpc_addr: Some(format!("127.0.0.1:{}", 7000 + i)),
        };
        if let Err(e) = write(dir.join(format!("node{i}.config.json")), &serde_json::to_value(&cfg).unwrap()) {
            eprintln!("write config failed: {e}");
            return ExitCode::FAILURE;
        }
    }

    println!("initialized {n}-node devnet in {}", dir.display());
    println!("\nlaunch each node in its own terminal:");
    for i in 0..n {
        println!("  slc-node run {}/node{i}.config.json", dir.display());
    }
    println!("\nthen notarize a document (RPC on 127.0.0.1:7000):");
    println!("  slc keygen {}/client.key", dir.display());
    println!("  slc notarize <file> {}/client.key 127.0.0.1:7000", dir.display());
    ExitCode::SUCCESS
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

    // Optional client-facing RPC.
    if let Some(rpc) = &cfg.rpc_addr {
        println!("rpc       : {rpc}");
        node = node.with_rpc(rpc.clone());
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
