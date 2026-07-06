//! Emit a Rust-produced ML-DSA-65 (pubkey, message, signature) triple as hex,
//! so it can be cross-verified by an independent FIPS 204 implementation.
//! Signs with an EMPTY context — the "pure" ML-DSA a notaryhash-style verifier
//! (`@noble/post-quantum`, no context arg) expects.

use slc_crypto::{Hash, SigningKey};

fn main() {
    let (sk, pk) = SigningKey::generate().unwrap();
    let message = Hash::digest(b"slc-notaryhash-cross-verify").0; // a 32-byte payload hash
    let sig = sk.sign(&message, &[]).unwrap(); // empty context
    println!("{}", hex::encode(pk.to_bytes()));
    println!("{}", hex::encode(message));
    println!("{}", hex::encode(sig.to_bytes()));
}
