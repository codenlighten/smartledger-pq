# SmartLedger-Chain

A **post-quantum, permissioned notary chain**. Legally-known actors run the
nodes; the more of them there are, the harder history is to forge. Its single
job is done elegantly: **prove a piece of data existed in an exact form at an
exact time — forever, without revealing the data.**

## Why this design

- **Privacy by construction.** Clients submit only a SHA3-256 *hash* of their
  data. The content never leaves their premises.
- **Self-verifying entries.** Every entry is the triple `{ pubkey, hash,
  signature }` — a legally-known actor signs their own data hash with their
  own post-quantum key. No two entries can ever contradict each other.
- **Post-quantum where it matters.** Hashing (SHA3-256) and Merkle proofs are
  already quantum-safe. The quantum-vulnerable part is *signatures*, so those
  use **ML-DSA-65 (FIPS 204, "Dilithium")** for every actor and validator.
- **Identity-bound Byzantine security.** Forging or rewriting finalized history
  requires a *quorum* of named legal entities to each sign a fork — legally
  attributable fraud, and (with public anchoring) externally detectable.
- **Portable proofs.** A client keeps a small JSON certificate that anyone can
  verify **offline, decades later**, using only the validators' public keys.

## Consensus — Quorum-Certified Notary BFT

A Tendermint-style two-phase BFT (**propose → prevote → precommit → commit**)
with locking and timeout-driven round change. Instant finality: a committed
block carries a **Quorum Certificate** of **≥ 2f+1 of 3f+1** validator
signatures, which is exactly finality made portable.

The two phases (with locking) are what keep the protocol *live* even when a
Byzantine proposer shows its proposal to only some validators — a pure
single-round scheme is safe but can be stalled there. Conflict-freedom still
buys real simplification: no transaction execution, no state-conflict logic, no
ordering constraints, and — elegantly — **every non-nil precommit signature is
itself a quorum-certificate share** (it signs the block id under the same
context the certificate verifies), so consensus and proof share one signature.

The engine is a deterministic, I/O-free state machine (no clock, no sockets
inside), so the whole protocol — happy path, view change, N-validator/F-fault
thresholds — is exercised in-process by an in-memory network harness.

## Layout

```
crates/
  crypto/   ML-DSA-65 keys/signatures + SHA3-256 hashing   ✅ implemented
  ledger/   attestations, Merkle proofs, blocks, quorum     ✅ implemented
            certificates, portable notarization proofs
  consensus/ Quorum-Certified Notary BFT + view change,     ✅ implemented
            attestation-triggered (no empty blocks)
  anchor/    checkpoint anchoring; BSV mainnet via           ✅ implemented
            notaryhash.com (feature `notaryhash`) — verified live
  node/      TCP gossip, timers, storage, crash-recovery,    ✅ implemented
            client RPC, daemon + `slc`/`slc-node` CLIs
```

An idle chain is **silent** — blocks exist only to notarize, so empty blocks are
structurally impossible (a valid block always has ≥1 attestation, and the engine
idles until there is something to notarize).

## Try it

```sh
cargo test                                   # full suite (42 tests, incl. real-TCP devnet)
cargo run -p slc-ledger --example demo       # notarize a doc, print a proof

# Stand up a local 4-node network and notarize a file end to end:
cargo build --release
./target/release/slc-node init-devnet ./devnet 4
# launch each node (own terminal): ./target/release/slc-node run ./devnet/nodeN.config.json
./target/release/slc keygen   ./devnet/client.key
./target/release/slc notarize ./contract.pdf ./devnet/client.key 127.0.0.1:7000
./target/release/slc get-proof <hash> 127.0.0.1:7000 proof.json
./target/release/slc verify   proof.json ./devnet/genesis.json      # VALID ✔ — offline
```

### Anchoring to BSV
The `slc-anchor` crate anchors periodic checkpoints. With the `notaryhash`
feature, `NotaryHashAnchor` signs a checkpoint root with the chain's ML-DSA-65
key and publishes it to **BSV mainnet** via notaryhash.com's OP_RETURN notarize
API — the same post-quantum key that secures the chain signs its public anchor
(cross-verified against notaryhash's FIPS 204 stack; confirmed live on-chain).

## Status

**End to end and tested** (42 tests, clippy clean): attest → Merkle batch →
block → quorum certificate → portable proof → verify; a full BFT engine that
finalizes blocks, survives view changes, and generalizes across
N-validator/F-fault thresholds; attestation-triggered production (no empty
blocks); real 4-node TCP networks that notarize, agree, persist, and **recover
from reboot**; a client RPC + `slc` CLI for notarize/fetch/verify; and BSV
mainnet anchoring verified live on-chain. Adversarial coverage includes forged
hashes, substituted identities, insufficient quorums, outsider signatures,
crashed proposers, wrong validator sets, and anchor tampering.

## Cryptography

| Purpose            | Primitive        | Standard   | Quantum posture                    |
|--------------------|------------------|------------|------------------------------------|
| Commitments/Merkle | SHA3-256         | FIPS 202   | ~128-bit vs Grover — safe          |
| Identities/signing | ML-DSA-65        | FIPS 204   | Lattice-based — Shor-resistant     |

## License

MIT OR Apache-2.0
