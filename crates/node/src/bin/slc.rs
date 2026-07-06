//! `slc` — the SmartLedger-Chain client.
//!
//!   slc keygen <keystore.json>                       Generate a client key.
//!   slc hash   <file>                                Print a file's SHA3-256 hash.
//!   slc notarize <file> <keystore.json> <node_rpc>   Notarize a file via a node.
//!   slc get-proof <hash> <node_rpc> [out.json]       Fetch a notarization proof.
//!   slc verify <proof.json> <genesis.json>           Verify a proof offline.
//!   slc status <node_rpc>                            Show chain height/tip.

use slc_anchor::AnchoredProof;
use slc_crypto::Hash;
use slc_ledger::NotarizationProof;
use slc_node::client;
use slc_node::config::GenesisConfig;
use slc_node::keystore;
use std::path::Path;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(String::as_str);
    let rest = &args[2.min(args.len())..];
    let result = match cmd {
        Some("keygen") => keygen(rest),
        Some("hash") => hash(rest),
        Some("notarize") => notarize(rest),
        Some("get-proof") => get_proof(rest),
        Some("get-anchored-proof") => get_anchored_proof(rest),
        Some("verify") => verify(rest),
        Some("verify-anchored") => verify_anchored(rest),
        Some("status") => status(rest),
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
    eprintln!("  slc hash <file>");
    eprintln!("  slc notarize <file> <keystore.json> <node_rpc>");
    eprintln!("  slc get-proof <hash> <node_rpc> [out.json]");
    eprintln!("  slc get-anchored-proof <hash> <node_rpc> [out.json]");
    eprintln!("  slc verify <proof.json> <genesis.json>");
    eprintln!("  slc verify-anchored <proof.json> <genesis.json>");
    eprintln!("  slc status <node_rpc>");
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

fn hash(a: &[String]) -> R {
    let path = a.first().ok_or("hash <file>")?;
    let h = client::hash_file(Path::new(path)).map_err(|e| e.to_string())?;
    println!("{h}");
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
