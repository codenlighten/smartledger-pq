//! Bitcoin/BSV `OP_RETURN` encoding for a checkpoint root.
//!
//! An `OP_RETURN` output carries arbitrary bytes in a provably-unspendable
//! script, which is the standard way to timestamp data on a UTXO chain. We emit
//! `OP_FALSE OP_RETURN <push(payload)>` where the payload is a magic tag, a
//! version byte, and the 32-byte checkpoint root. Broadcasting the transaction
//! is a wallet's job; this module builds and parses the committing script so the
//! rest of the system stays chain-agnostic.

use slc_crypto::Hash;

const OP_FALSE: u8 = 0x00;
const OP_RETURN: u8 = 0x6a;

/// Identifies a SmartLedger-Chain checkpoint in the sea of `OP_RETURN` data.
pub const MAGIC: [u8; 4] = *b"SLC1";
/// Payload format version.
pub const VERSION: u8 = 1;

/// The raw payload embedded after `OP_RETURN`: `MAGIC ‖ VERSION ‖ root`.
pub fn payload(root: Hash) -> Vec<u8> {
    let mut v = Vec::with_capacity(MAGIC.len() + 1 + Hash::LEN);
    v.extend_from_slice(&MAGIC);
    v.push(VERSION);
    v.extend_from_slice(root.as_bytes());
    v
}

/// The full committing script: `OP_FALSE OP_RETURN <pushdata payload>`.
/// The payload is 37 bytes, well under the 75-byte single-push limit.
pub fn script(root: Hash) -> Vec<u8> {
    let data = payload(root);
    let mut s = Vec::with_capacity(2 + 1 + data.len());
    s.push(OP_FALSE);
    s.push(OP_RETURN);
    s.push(data.len() as u8); // direct push opcode for lengths 1..=75
    s.extend_from_slice(&data);
    s
}

/// Recover a checkpoint root from a committing script, if it is a well-formed
/// SmartLedger `OP_RETURN`.
pub fn parse_root(script: &[u8]) -> Option<Hash> {
    // OP_FALSE OP_RETURN <len> <payload>
    let rest = script.strip_prefix(&[OP_FALSE, OP_RETURN])?;
    let (&len, rest) = rest.split_first()?;
    let data = rest.get(..len as usize)?;
    let data = data.strip_prefix(&MAGIC)?;
    let (&version, data) = data.split_first()?;
    if version != VERSION || data.len() != Hash::LEN {
        return None;
    }
    let mut bytes = [0u8; Hash::LEN];
    bytes.copy_from_slice(data);
    Some(Hash(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn script_roundtrips_the_root() {
        let root = Hash::digest(b"checkpoint");
        let s = script(root);
        assert_eq!(s[0], OP_FALSE);
        assert_eq!(s[1], OP_RETURN);
        assert_eq!(parse_root(&s), Some(root));
    }

    #[test]
    fn rejects_foreign_or_corrupt_scripts() {
        assert_eq!(parse_root(b"not a script"), None);
        let mut s = script(Hash::digest(b"x"));
        let n = s.len();
        s[n - 1] ^= 0xff; // corrupt the last root byte -> still parses, different root
        assert_ne!(parse_root(&s), Some(Hash::digest(b"x")));
        // Truncated payload fails to parse entirely.
        assert_eq!(parse_root(&s[..5]), None);
    }
}
