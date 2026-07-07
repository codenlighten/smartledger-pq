//! `slc-node` — run a SmartLedger-Chain validator, or generate its keys.
//!
//! Usage:
//!   slc-node keygen <keystore.json>       Generate a validator keypair.
//!   slc-node run <config.json>            Run a validator from a node config.

use slc_anchor::AnchorService;
use slc_crypto::SigningKey;
use slc_node::config::{GenesisConfig, NodeConfig, ValidatorInfo};
use slc_node::{anchoring, keystore, Node, Transport};
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
            Some(dir) => {
                let n = args.iter().skip(3).find_map(|a| a.parse::<usize>().ok()).unwrap_or(4);
                let docker = args.iter().any(|a| a == "--docker");
                init_devnet(dir, n, docker)
            }
            None => usage(),
        },
        Some("render-config") => match args.get(2) {
            Some(out) => render_config(out),
            None => usage(),
        },
        // Container entrypoint: keygen-if-absent, resolve genesis, render config,
        // and run — all in-process, so the image needs no shell or curl.
        Some("bootstrap") => bootstrap(),
        _ => usage(),
    }
}

/// Read a non-empty environment variable.
fn env(k: &str) -> Option<String> {
    std::env::var(k).ok().filter(|v| !v.is_empty())
}

/// HTTP GET for fetching a genesis over the network. Uses the same rustls-backed
/// `ureq` the anchor backend uses; available when built with `notaryhash`.
#[cfg(feature = "notaryhash")]
fn http_get(url: &str) -> Result<String, String> {
    ureq::get(url)
        .call()
        .map_err(|e| e.to_string())?
        .into_string()
        .map_err(|e| e.to_string())
}
#[cfg(not(feature = "notaryhash"))]
fn http_get(_url: &str) -> Result<String, String> {
    Err("genesis URL fetch needs the `notaryhash` feature; use SLC_GENESIS_JSON or mount a genesis file".into())
}

/// One-shot container bootstrap. Mirrors the old shell entrypoint in Rust:
/// generate a keystore on first boot, resolve a genesis (inline JSON, a URL, a
/// mounted file, or bootstrap a single-validator chain), render a config from
/// `SLC_*` env, and run. A node whose key isn't in the set runs as a follower.
fn bootstrap() -> ExitCode {
    let data = env("SLC_DATA").unwrap_or_else(|| "/data".into());
    let keystore_path = env("SLC_KEYSTORE").unwrap_or_else(|| format!("{data}/node.key"));
    let store_path = env("SLC_STORE").unwrap_or_else(|| format!("{data}/blocks"));
    let genesis_file = env("SLC_GENESIS_FILE").unwrap_or_else(|| format!("{data}/genesis.json"));
    // Export the resolved paths so `render_config` reads the same locations.
    std::env::set_var("SLC_KEYSTORE", &keystore_path);
    std::env::set_var("SLC_STORE", &store_path);
    std::env::set_var("SLC_GENESIS_FILE", &genesis_file);

    if let Err(e) = std::fs::create_dir_all(&data) {
        eprintln!("[bootstrap] cannot create {data}: {e}");
        return ExitCode::FAILURE;
    }

    // 1. Keystore (persisted on the data volume) — generate once.
    let pk = if Path::new(&keystore_path).exists() {
        match keystore::load(Path::new(&keystore_path)) {
            Ok((_, pk)) => pk,
            Err(e) => {
                eprintln!("[bootstrap] cannot load keystore {keystore_path}: {e}");
                return ExitCode::FAILURE;
            }
        }
    } else {
        eprintln!("[bootstrap] generating validator keystore at {keystore_path}");
        match keystore::generate(Path::new(&keystore_path)) {
            Ok((_, pk)) => pk,
            Err(e) => {
                eprintln!("[bootstrap] keygen failed: {e}");
                return ExitCode::FAILURE;
            }
        }
    };
    println!("[bootstrap] node public key: {}", pk.to_hex());

    // 2. Genesis: inline JSON, a URL, a pre-mounted file, or bootstrap.
    if !Path::new(&genesis_file).exists() {
        if let Some(json) = env("SLC_GENESIS_JSON") {
            if let Err(e) = std::fs::write(&genesis_file, json) {
                eprintln!("[bootstrap] cannot write genesis: {e}");
                return ExitCode::FAILURE;
            }
        } else if let Some(url) = env("SLC_GENESIS_URL") {
            eprintln!("[bootstrap] fetching genesis from {url}");
            match http_get(&url) {
                Ok(body) => {
                    if let Err(e) = std::fs::write(&genesis_file, body) {
                        eprintln!("[bootstrap] cannot write genesis: {e}");
                        return ExitCode::FAILURE;
                    }
                }
                Err(e) => {
                    eprintln!("[bootstrap] genesis fetch failed: {e}");
                    return ExitCode::FAILURE;
                }
            }
        }
    }
    if !Path::new(&genesis_file).exists() {
        let addr = env("SLC_PUBLIC_ADDR").unwrap_or_else(|| "127.0.0.1:9000".into());
        let chain = env("SLC_CHAIN_ID").unwrap_or_else(|| "smartledger".into());
        eprintln!("[bootstrap] no genesis provided; bootstrapping single-validator chain ({addr})");
        let g = format!(
            r#"{{"chain_id":"{chain}","validators":[{{"pubkey":"{}","addr":"{addr}"}}]}}"#,
            pk.to_hex()
        );
        if let Err(e) = std::fs::write(&genesis_file, g) {
            eprintln!("[bootstrap] cannot write genesis: {e}");
            return ExitCode::FAILURE;
        }
    }

    // 3. Render the node config from env + genesis.
    let config = format!("{data}/config.json");
    if let Err(e) = write_config(&config) {
        eprintln!("[bootstrap] {e}");
        return ExitCode::FAILURE;
    }

    // 4. Run.
    run(&config)
}

/// Build a node config JSON from environment variables (for containers/cloud).
/// Reads a genesis file at $SLC_GENESIS_FILE and emits a config to `out`.
fn render_config(out: &str) -> ExitCode {
    match write_config(out) {
        Ok(()) => {
            println!("wrote config: {out}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}

/// Core of `render-config`: emit a `NodeConfig` from `SLC_*` env + genesis file.
fn write_config(out: &str) -> Result<(), String> {
    let genesis_file = env("SLC_GENESIS_FILE").ok_or("SLC_GENESIS_FILE is required")?;
    let genesis: GenesisConfig = std::fs::read_to_string(&genesis_file)
        .map_err(|e| format!("could not read genesis at {genesis_file}: {e}"))
        .and_then(|s| serde_json::from_str(&s).map_err(|e| format!("could not parse genesis: {e}")))?;

    let cfg = NodeConfig {
        genesis,
        key_path: env("SLC_KEYSTORE").unwrap_or_else(|| "/data/node.key".into()),
        block_store_path: env("SLC_STORE").unwrap_or_else(|| "/data/blocks".into()),
        base_timeout_ms: env("SLC_BASE_TIMEOUT_MS").and_then(|v| v.parse().ok()).unwrap_or(1000),
        listen: env("SLC_LISTEN").or_else(|| Some("0.0.0.0:9000".into())),
        peers: env("SLC_PEERS").map(|s| s.split(',').map(|p| p.trim().to_string()).collect()),
        anchor_interval: env("SLC_ANCHOR_INTERVAL").and_then(|v| v.parse().ok()).unwrap_or(0),
        anchor_backend: env("SLC_ANCHOR_BACKEND"),
        anchor_file: env("SLC_ANCHOR_FILE"),
        notaryhash_endpoint: env("SLC_NOTARYHASH_ENDPOINT"),
        notaryhash_api_key_env: env("SLC_NOTARYHASH_API_KEY_ENV"),
        anchor_key_path: env("SLC_ANCHOR_KEY_PATH"),
        rpc_addr: env("SLC_RPC").or_else(|| Some("0.0.0.0:7000".into())),
        license_file: env("SLC_LICENSE_FILE"),
        license_issuer_pubkey: env("SLC_LICENSE_ISSUER_PUBKEY"),
    };

    let json = serde_json::to_string_pretty(&cfg).map_err(|e| format!("serialize failed: {e}"))?;
    std::fs::write(out, json).map_err(|e| format!("write failed: {e}"))
}

fn usage() -> ExitCode {
    eprintln!("usage:");
    eprintln!("  slc-node keygen <keystore.json>");
    eprintln!("  slc-node run <config.json>");
    eprintln!("  slc-node init-devnet <dir> [num_nodes=4]");
    eprintln!("  slc-node render-config <out.json>   (from SLC_* env vars)");
    eprintln!("  slc-node bootstrap                  (container entrypoint: keygen+genesis+run)");
    ExitCode::FAILURE
}

/// Generate keystores, a shared genesis, and per-node configs for a local
/// N-validator devnet under `dir`. With `docker`, use container-friendly
/// service-name addressing and `/data` paths for docker-compose.
fn init_devnet(dir: &str, n: usize, docker: bool) -> ExitCode {
    let dir = Path::new(dir);
    if let Err(e) = std::fs::create_dir_all(dir) {
        eprintln!("could not create {}: {e}", dir.display());
        return ExitCode::FAILURE;
    }

    // Generate keys and assign addresses. In docker mode each node advertises a
    // service-name address (resolved on the compose network) and binds 0.0.0.0.
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
        let addr = if docker {
            format!("node{i}:9000")
        } else {
            format!("127.0.0.1:{}", 9000 + i)
        };
        validators.push(ValidatorInfo { pubkey: pk, addr });
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
        let (key_path, store_path, listen, rpc) = if docker {
            (
                format!("/data/node{i}.key"),
                format!("/data/node{i}.blocks"),
                Some("0.0.0.0:9000".to_string()),
                Some("0.0.0.0:7000".to_string()),
            )
        } else {
            (
                key.to_string_lossy().into_owned(),
                dir.join(format!("node{i}.blocks")).to_string_lossy().into_owned(),
                None,
                Some(format!("127.0.0.1:{}", 7000 + i)),
            )
        };
        let cfg = NodeConfig {
            genesis: genesis.clone(),
            key_path,
            block_store_path: store_path,
            base_timeout_ms: 1000,
            listen,
            peers: None,
            anchor_interval: 0,
            anchor_backend: None,
            anchor_file: None,
            notaryhash_endpoint: None,
            notaryhash_api_key_env: None,
            anchor_key_path: None,
            rpc_addr: rpc,
            license_file: None,
            license_issuer_pubkey: None,
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

    // License gate: if a license is configured, it must verify or the node
    // refuses to start.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let notarization_cap = match slc_node::license::check(&cfg, &cfg.genesis.chain_id, now) {
        Ok(None) => None,
        Ok(Some(ent)) => {
            println!(
                "license   : valid (max_nodes={:?}, notarizations/mo={:?}, anchoring={}, features={:?})",
                ent.max_nodes, ent.max_notarizations_per_month, ent.anchoring, ent.features
            );
            ent.max_notarizations_per_month
        }
        Err(e) => {
            eprintln!("license check failed: {e}");
            return ExitCode::FAILURE;
        }
    };

    let is_validator = cfg.genesis.validators.iter().any(|v| v.pubkey == pk);

    // Bind address: explicit `listen`, else our advertised address from genesis.
    let my_addr = match cfg
        .listen
        .clone()
        .or_else(|| cfg.genesis.validators.iter().find(|v| v.pubkey == pk).map(|v| v.addr.clone()))
    {
        Some(a) => a,
        None => {
            eprintln!(
                "no listen address: set `listen` in config, or include this node in genesis"
            );
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
    // Peers: explicit list, else every other validator in genesis.
    let peers = cfg.peers.clone().unwrap_or_else(|| cfg.genesis.peer_addrs(&pk));
    transport.set_peers(peers);

    println!("chain     : {}", cfg.genesis.chain_id);
    println!("identity  : {}", pk.id());
    println!("listening : {my_addr}");
    println!("validators: {}", cfg.genesis.validators.len());
    println!(
        "role      : {}",
        if is_validator {
            "validator"
        } else {
            "follower (awaiting governance to become a validator)"
        }
    );

    // Resolve the anchor identity before the validator key moves into the node:
    // a dedicated anchor keystore if configured, otherwise the validator key.
    let anchor_identity = if cfg.anchor_interval > 0 {
        match &cfg.anchor_key_path {
            Some(p) => match keystore::load(Path::new(p)) {
                Ok(kp) => Some(kp),
                Err(e) => {
                    eprintln!("could not load anchor keystore {p}: {e}");
                    return ExitCode::FAILURE;
                }
            },
            // Reuse the validator key (reconstructed so `sk` can still move on).
            None => Some((
                SigningKey::from_bytes(&sk.to_bytes()).expect("clone key"),
                pk.clone(),
            )),
        }
    } else {
        None
    };

    let mut node = Node::new(
        transport,
        &cfg.genesis,
        sk,
        pk,
        Some(Path::new(&cfg.block_store_path)),
        Duration::from_millis(cfg.base_timeout_ms),
    );

    // Optional public-chain anchoring.
    if let Some((anchor_sk, anchor_pk)) = anchor_identity {
        match anchoring::build_backend(&cfg, anchor_sk, anchor_pk) {
            Ok(Some(backend)) => {
                let service = AnchorService::new(backend, cfg.anchor_interval as usize);
                println!(
                    "anchoring : every {} blocks via {}",
                    cfg.anchor_interval,
                    service.backend_name()
                );
                node = node.with_anchor(service);
            }
            Ok(None) => {}
            Err(e) => {
                eprintln!("anchor configuration error: {e}");
                return ExitCode::FAILURE;
            }
        }
    }

    // Optional client-facing RPC.
    if let Some(rpc) = &cfg.rpc_addr {
        println!("rpc       : {rpc}");
        node = node.with_rpc(rpc.clone());
    }

    // Notarization metering (persist usage next to the block store).
    let meter_path = std::path::PathBuf::from(format!("{}.meter", cfg.block_store_path));
    node = node.with_metering(notarization_cap, Some(meter_path));

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
