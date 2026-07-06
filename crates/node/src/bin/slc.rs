//! `slc` — the SmartLedger-Chain client.
//!
//!   slc keygen <keystore.json>                       Generate a client key.
//!   slc hash   <file>                                Print a file's SHA3-256 hash.
//!   slc notarize <file> <keystore.json> <node_rpc>   Notarize a file via a node.
//!   slc get-proof <hash> <node_rpc> [out.json]       Fetch a notarization proof.
//!   slc verify <proof.json> <genesis.json>           Verify a proof offline.
//!   slc status <node_rpc>                            Show chain height/tip.

use slc_anchor::AnchoredProof;
use slc_crypto::{Hash, SlhVerifyingKey, VerifyingKey};
use slc_ledger::{NotarizationProof, SignedValidatorChange, ValidatorChange};
use slc_license::{keystore as licstore, Entitlements, License, SignedLicense};
use slc_node::client;
use slc_node::config::GenesisConfig;
use slc_node::keystore;
use std::path::Path;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(String::as_str);
    let rest = &args[2.min(args.len())..];
    let result = match cmd {
        Some("keygen") => keygen(rest),
        Some("pubkey") => pubkey(rest),
        Some("hash") => hash(rest),
        Some("gov") => gov(rest),
        Some("license") => license(rest),
        Some("notarize") => notarize(rest),
        Some("get-proof") => get_proof(rest),
        Some("get-anchored-proof") => get_anchored_proof(rest),
        Some("verify") => verify(rest),
        Some("verify-anchored") => verify_anchored(rest),
        Some("status") => status(rest),
        Some("node-info") => node_info(rest),
        _ => return usage(),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn usage() -> ExitCode {
    eprintln!("usage:");
    eprintln!("  slc keygen <keystore.json>");
    eprintln!("  slc pubkey <keystore.json>");
    eprintln!("  slc hash <file>");
    eprintln!("  slc notarize <file> <keystore.json> <node_rpc>");
    eprintln!("  slc get-proof <hash> <node_rpc> [out.json]");
    eprintln!("  slc get-anchored-proof <hash> <node_rpc> [out.json]");
    eprintln!("  slc verify <proof.json> <genesis.json>");
    eprintln!("  slc verify-anchored <proof.json> <genesis.json>");
    eprintln!("  slc status <node_rpc>");
    eprintln!("  slc node-info <node_rpc>");
    eprintln!("  slc gov propose --add <pk> [--remove <pk>] --activation <h> [--out f.json]");
    eprintln!("  slc gov approve <change.json> <validator-keystore.json>");
    eprintln!("  slc gov submit <change.json> <node_rpc>");
    eprintln!("  slc gov show <change.json>");
    eprintln!("  slc license keygen <issuer.key>            (SmartLedger)");
    eprintln!("  slc license issuer-pubkey <issuer.key>");
    eprintln!("  slc license issue --issuer <issuer.key> --licensee <name> --tier <t> \\");
    eprintln!("        --expires-days <n> [--chain <id>] [--max-nodes <n>] [--anchoring] \\");
    eprintln!("        [--features a,b] [--out license.json]");
    eprintln!("  slc license verify <license.json> --issuer <pubkey-hex> [--chain <id>]");
    eprintln!("  slc license show <license.json>");
    ExitCode::FAILURE
}

type R = Result<(), String>;

fn keygen(a: &[String]) -> R {
    let path = a.first().ok_or("keygen <keystore.json>")?;
    let (_, pk) = keystore::generate(Path::new(path)).map_err(|e| e.to_string())?;
    println!("wrote keystore : {path}");
    println!("identity (id)  : {}", pk.id());
    Ok(())
}

fn pubkey(a: &[String]) -> R {
    let path = a.first().ok_or("pubkey <keystore.json>")?;
    let (_, pk) = keystore::load(Path::new(path)).map_err(|e| e.to_string())?;
    println!("{}", pk.to_hex());
    Ok(())
}

fn hash(a: &[String]) -> R {
    let path = a.first().ok_or("hash <file>")?;
    let h = client::hash_file(Path::new(path)).map_err(|e| e.to_string())?;
    println!("{h}");
    Ok(())
}

// ---- governance -----------------------------------------------------------

fn gov(a: &[String]) -> R {
    match a.first().map(String::as_str) {
        Some("propose") => gov_propose(&a[1..]),
        Some("approve") => gov_approve(&a[1..]),
        Some("submit") => gov_submit(&a[1..]),
        Some("show") => gov_show(&a[1..]),
        _ => Err("gov <propose|approve|submit|show> ...".into()),
    }
}

fn read_signed(path: &str) -> Result<SignedValidatorChange, String> {
    let json = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    serde_json::from_str(&json).map_err(|e| e.to_string())
}

fn write_signed(path: &str, signed: &SignedValidatorChange) -> R {
    let json = serde_json::to_string_pretty(signed).map_err(|e| e.to_string())?;
    std::fs::write(path, json).map_err(|e| e.to_string())
}

fn gov_propose(a: &[String]) -> R {
    let mut adds = Vec::new();
    let mut removes = Vec::new();
    let mut activation: Option<u64> = None;
    let mut out: Option<String> = None;
    let mut i = 0;
    while i < a.len() {
        match a[i].as_str() {
            "--add" => {
                let hex = a.get(i + 1).ok_or("--add needs a public key")?;
                adds.push(VerifyingKey::from_hex(hex).map_err(|_| "invalid --add public key")?);
                i += 2;
            }
            "--remove" => {
                let hex = a.get(i + 1).ok_or("--remove needs a public key")?;
                removes.push(VerifyingKey::from_hex(hex).map_err(|_| "invalid --remove public key")?);
                i += 2;
            }
            "--activation" => {
                activation = Some(a.get(i + 1).ok_or("--activation needs a height")?.parse().map_err(|_| "bad height")?);
                i += 2;
            }
            "--out" => {
                out = Some(a.get(i + 1).ok_or("--out needs a path")?.clone());
                i += 2;
            }
            other => return Err(format!("unknown flag {other}")),
        }
    }
    let activation_height = activation.ok_or("--activation <height> is required")?;
    if adds.is_empty() && removes.is_empty() {
        return Err("propose at least one --add or --remove".into());
    }
    let change = ValidatorChange {
        adds,
        removes,
        activation_height,
    };
    let signed = SignedValidatorChange::new(change);
    match out {
        Some(path) => {
            write_signed(&path, &signed)?;
            println!("wrote change: {path} (activation height {activation_height})");
            println!("each validator now runs: slc gov approve {path} <their-keystore>");
        }
        None => println!("{}", serde_json::to_string_pretty(&signed).unwrap()),
    }
    Ok(())
}

fn gov_approve(a: &[String]) -> R {
    let change_path = a.first().ok_or("approve <change.json> <keystore.json>")?;
    let ks = a.get(1).ok_or("missing <keystore.json>")?;
    let mut signed = read_signed(change_path)?;
    let (sk, pk) = keystore::load(Path::new(ks)).map_err(|e| e.to_string())?;
    client::approve_change(&mut signed, &sk, &pk);
    write_signed(change_path, &signed)?;
    println!("approved by {} ({} approval(s) now)", pk.id(), signed.approvals.len());
    Ok(())
}

fn gov_submit(a: &[String]) -> R {
    let change_path = a.first().ok_or("submit <change.json> <node_rpc>")?;
    let node = a.get(1).ok_or("missing <node_rpc>")?;
    let signed = read_signed(change_path)?;
    if client::submit_governance(node, &signed).map_err(|e| e.to_string())? {
        println!("submitted {} approval(s) to {node}", signed.approvals.len());
        println!("(the change lands in a block once a quorum has approved it)");
        Ok(())
    } else {
        Err("node did not accept the submission".into())
    }
}

fn gov_show(a: &[String]) -> R {
    let signed = read_signed(a.first().ok_or("show <change.json>")?)?;
    println!("activation height: {}", signed.change.activation_height);
    println!("adds   : {}", signed.change.adds.len());
    for k in &signed.change.adds {
        println!("  + {}", k.id());
    }
    println!("removes: {}", signed.change.removes.len());
    for k in &signed.change.removes {
        println!("  - {}", k.id());
    }
    println!("approvals: {}", signed.approvals.len());
    for ap in &signed.approvals {
        println!("  \u{2713} {}", ap.validator.id());
    }
    Ok(())
}

fn notarize(a: &[String]) -> R {
    let (file, ks, node) = (
        a.first().ok_or("notarize <file> <keystore.json> <node_rpc>")?,
        a.get(1).ok_or("missing <keystore.json>")?,
        a.get(2).ok_or("missing <node_rpc>")?,
    );
    let doc_hash = client::hash_file(Path::new(file)).map_err(|e| e.to_string())?;
    let (sk, pk) = keystore::load(Path::new(ks)).map_err(|e| e.to_string())?;
    let accepted = client::notarize(node, &sk, &pk, doc_hash).map_err(|e| e.to_string())?;
    if !accepted {
        return Err("node rejected the attestation".into());
    }
    println!("submitted for notarization");
    println!("document hash : {doc_hash}");
    println!("fetch proof   : slc get-proof {doc_hash} {node}");
    Ok(())
}

fn get_proof(a: &[String]) -> R {
    let hash_hex = a.first().ok_or("get-proof <hash> <node_rpc> [out.json]")?;
    let node = a.get(1).ok_or("missing <node_rpc>")?;
    let doc_hash = Hash::from_hex(hash_hex).map_err(|_| "invalid hash hex")?;
    match client::get_proof(node, doc_hash).map_err(|e| e.to_string())? {
        None => Err("not notarized yet (no proof available)".into()),
        Some(proof) => {
            let json = proof.to_json().map_err(|e| e.to_string())?;
            match a.get(2) {
                Some(out) => {
                    std::fs::write(out, &json).map_err(|e| e.to_string())?;
                    println!("wrote proof: {out}");
                }
                None => println!("{json}"),
            }
            Ok(())
        }
    }
}

fn get_anchored_proof(a: &[String]) -> R {
    let hash_hex = a.first().ok_or("get-anchored-proof <hash> <node_rpc> [out.json]")?;
    let node = a.get(1).ok_or("missing <node_rpc>")?;
    let doc_hash = Hash::from_hex(hash_hex).map_err(|_| "invalid hash hex")?;
    match client::get_anchored_proof(node, doc_hash).map_err(|e| e.to_string())? {
        None => Err("not anchored yet (notarized but no checkpoint published)".into()),
        Some(proof) => {
            let json = proof.to_json().map_err(|e| e.to_string())?;
            match a.get(2) {
                Some(out) => {
                    std::fs::write(out, &json).map_err(|e| e.to_string())?;
                    println!("wrote anchored proof: {out}");
                }
                None => println!("{json}"),
            }
            Ok(())
        }
    }
}

fn verify(a: &[String]) -> R {
    let proof_path = a.first().ok_or("verify <proof.json> <genesis.json>")?;
    let genesis_path = a.get(1).ok_or("missing <genesis.json>")?;
    let proof_json = std::fs::read_to_string(proof_path).map_err(|e| e.to_string())?;
    let proof = NotarizationProof::from_json(&proof_json).map_err(|e| e.to_string())?;
    let genesis_json = std::fs::read_to_string(genesis_path).map_err(|e| e.to_string())?;
    let genesis: GenesisConfig = serde_json::from_str(&genesis_json).map_err(|e| e.to_string())?;
    if client::verify_proof(&proof, &genesis) {
        println!("VALID ✔");
        println!("  document : {}", proof.hash());
        println!("  height   : {}", proof.header.height);
        println!("  timestamp: {}", proof.timestamp());
        Ok(())
    } else {
        Err("INVALID — proof did not verify against this genesis".into())
    }
}

fn verify_anchored(a: &[String]) -> R {
    let proof_path = a.first().ok_or("verify-anchored <proof.json> <genesis.json>")?;
    let genesis_path = a.get(1).ok_or("missing <genesis.json>")?;
    let proof_json = std::fs::read_to_string(proof_path).map_err(|e| e.to_string())?;
    let proof = AnchoredProof::from_json(&proof_json).map_err(|e| e.to_string())?;
    let genesis_json = std::fs::read_to_string(genesis_path).map_err(|e| e.to_string())?;
    let genesis: GenesisConfig = serde_json::from_str(&genesis_json).map_err(|e| e.to_string())?;
    if client::verify_anchored_proof(&proof, &genesis) {
        println!("VALID ✔ (notarized + anchored)");
        println!("  document      : {}", proof.notarization.hash());
        println!("  height        : {}", proof.notarization.header.height);
        println!("  checkpoint    : {}", proof.record.checkpoint_root);
        println!("  anchor backend: {}", proof.record.receipt.backend);
        println!("  anchor ref    : {}", proof.record.receipt.reference);
        Ok(())
    } else {
        Err("INVALID — anchored proof did not verify".into())
    }
}

fn status(a: &[String]) -> R {
    let node = a.first().ok_or("status <node_rpc>")?;
    let (height, tip) = client::status(node).map_err(|e| e.to_string())?;
    println!("height: {height}");
    println!("tip   : {tip}");
    Ok(())
}

// ---- licensing ------------------------------------------------------------

fn license(a: &[String]) -> R {
    match a.first().map(String::as_str) {
        Some("keygen") => lic_keygen(&a[1..]),
        Some("issuer-pubkey") => lic_issuer_pubkey(&a[1..]),
        Some("issue") => lic_issue(&a[1..]),
        Some("verify") => lic_verify(&a[1..]),
        Some("show") => lic_show(&a[1..]),
        _ => Err("license <keygen|issuer-pubkey|issue|verify|show> ...".into()),
    }
}

fn lic_keygen(a: &[String]) -> R {
    let path = a.first().ok_or("license keygen <issuer.key>")?;
    let issuer = licstore::generate(Path::new(path)).map_err(|e| e.to_string())?;
    println!("wrote issuer keystore: {path}");
    println!("issuer public key    : {}", issuer.public_key().to_hex());
    Ok(())
}

fn lic_issuer_pubkey(a: &[String]) -> R {
    let path = a.first().ok_or("license issuer-pubkey <issuer.key>")?;
    let issuer = licstore::load(Path::new(path)).map_err(|e| e.to_string())?;
    println!("{}", issuer.public_key().to_hex());
    Ok(())
}

/// Tiny flag reader: `--k v` (repeatable via caller), `--flag` booleans.
fn flag<'b>(a: &'b [String], name: &str) -> Option<&'b str> {
    a.iter().position(|x| x == name).and_then(|i| a.get(i + 1)).map(String::as_str)
}
fn has(a: &[String], name: &str) -> bool {
    a.iter().any(|x| x == name)
}

fn lic_issue(a: &[String]) -> R {
    let issuer_path = flag(a, "--issuer").ok_or("--issuer <issuer.key> is required")?;
    let licensee = flag(a, "--licensee").ok_or("--licensee <name> is required")?;
    let tier = flag(a, "--tier").unwrap_or("standard");
    let expires_days: u64 = flag(a, "--expires-days")
        .ok_or("--expires-days <n> is required")?
        .parse()
        .map_err(|_| "bad --expires-days")?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);

    let entitlements = Entitlements {
        max_nodes: flag(a, "--max-nodes").and_then(|v| v.parse().ok()),
        max_notarizations_per_month: flag(a, "--max-notarizations").and_then(|v| v.parse().ok()),
        anchoring: has(a, "--anchoring"),
        features: flag(a, "--features")
            .map(|s| s.split(',').map(|x| x.trim().to_string()).collect())
            .unwrap_or_default(),
    };
    let lic = License {
        licensee: licensee.to_string(),
        license_id: flag(a, "--id").map(str::to_string).unwrap_or_else(|| format!("LIC-{now}")),
        product: "smartledger-chain".into(),
        tier: tier.to_string(),
        entitlements,
        chain_id: flag(a, "--chain").map(str::to_string),
        issued_at: now,
        expires_at: now + expires_days * 24 * 3600,
    };

    let issuer = licstore::load(Path::new(issuer_path)).map_err(|e| e.to_string())?;
    eprintln!("signing license (SLH-DSA, a few seconds)...");
    let signed = issuer.issue(lic).map_err(|e| e.to_string())?;
    let json = signed.to_json().map_err(|e| e.to_string())?;
    match flag(a, "--out") {
        Some(out) => {
            std::fs::write(out, &json).map_err(|e| e.to_string())?;
            println!("wrote license: {out}");
        }
        None => println!("{json}"),
    }
    Ok(())
}

fn lic_verify(a: &[String]) -> R {
    let path = a.first().ok_or("license verify <license.json> --issuer <pubkey-hex>")?;
    let issuer_hex = flag(a, "--issuer").ok_or("--issuer <pubkey-hex> is required")?;
    let issuer = SlhVerifyingKey::from_hex(issuer_hex).map_err(|_| "invalid issuer pubkey hex")?;
    let signed = SignedLicense::from_json(&std::fs::read_to_string(path).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    match signed.verify(&issuer, now, flag(a, "--chain")) {
        Ok(()) => {
            println!("VALID ✔");
            println!("  licensee : {}", signed.license.licensee);
            println!("  tier     : {}", signed.license.tier);
            println!("  expires  : {} (unix)", signed.license.expires_at);
            Ok(())
        }
        Err(e) => Err(format!("INVALID — {e}")),
    }
}

fn lic_show(a: &[String]) -> R {
    let path = a.first().ok_or("license show <license.json>")?;
    let signed = SignedLicense::from_json(&std::fs::read_to_string(path).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    let l = &signed.license;
    println!("licensee   : {}", l.licensee);
    println!("license_id : {}", l.license_id);
    println!("product    : {}", l.product);
    println!("tier       : {}", l.tier);
    println!("chain_id   : {:?}", l.chain_id);
    println!("issued_at  : {}", l.issued_at);
    println!("expires_at : {}", l.expires_at);
    println!("entitlements:");
    println!("  max_nodes             : {:?}", l.entitlements.max_nodes);
    println!("  max_notarizations/mo  : {:?}", l.entitlements.max_notarizations_per_month);
    println!("  anchoring             : {}", l.entitlements.anchoring);
    println!("  features              : {:?}", l.entitlements.features);
    println!("issuer     : {}", signed.issuer.to_hex());
    Ok(())
}

fn node_info(a: &[String]) -> R {
    let node = a.first().ok_or("node-info <node_rpc>")?;
    let (chain_id, pubkey, height, tip) = client::node_info(node).map_err(|e| e.to_string())?;
    println!("chain_id : {chain_id}");
    println!("identity : {}", pubkey.id());
    println!("pubkey   : {}", pubkey.to_hex());
    println!("height   : {height}");
    println!("tip      : {tip}");
    Ok(())
}
