//! Live anchor: sign a checkpoint root with ML-DSA-65 and anchor it to BSV via
//! notaryhash.com.  Endpoint as arg 1, API key from `NOTARYHASH_API_KEY`.
//!
//!   NOTARYHASH_API_KEY=... cargo run -p slc-anchor --features notaryhash \
//!     --example notaryhash_anchor -- https://notaryhash.com

use slc_anchor::{AnchorBackend, Checkpoint, NotaryHashAnchor};
use slc_crypto::{Hash, SigningKey};

fn main() {
    let endpoint = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "https://notaryhash.com".to_string());
    let api_key = std::env::var("NOTARYHASH_API_KEY")
        .expect("set NOTARYHASH_API_KEY");

    // The chain's anchor identity (a fresh key here; a real deployment persists it).
    let (sk, pk) = SigningKey::generate().unwrap();
    println!("anchor identity (ML-DSA-65 id): {}", pk.id());

    // A checkpoint over a couple of block ids.
    let block_ids = vec![
        Hash::digest(b"slc-live-anchor-block-1"),
        Hash::digest(b"slc-live-anchor-block-2"),
    ];
    let checkpoint = Checkpoint::from_block_ids(block_ids, 1, 2).unwrap();
    println!("checkpoint root: {}", checkpoint.root());
    println!("endpoint       : {endpoint}");

    let mut backend = NotaryHashAnchor::new(endpoint, api_key, sk, pk);
    match backend.anchor(&checkpoint) {
        Ok(r) => {
            println!("\nANCHORED ✔");
            println!("  backend  : {}", r.backend);
            println!("  reference: {}", r.reference);
            println!("  root     : {}", r.checkpoint_root);
        }
        Err(e) => {
            eprintln!("\nanchor FAILED: {e}");
            std::process::exit(1);
        }
    }
}
