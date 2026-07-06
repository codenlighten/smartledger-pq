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
            deterministic engine + in-memory network tests
  anchor/    periodic checkpoint anchoring to a public chain ⏳ planned
  node/      p2p networking, mempool, storage, daemon, CLI   ⏳ planned
```

## Try it

```sh
cargo test                                   # full suite (crypto + ledger + e2e)
cargo run -p slc-ledger --example demo       # notarize a doc, print a proof
```

## Status

The **value chain and consensus are complete and tested** (24 tests): attest →
Merkle batch → block → quorum certificate → portable proof → verify, plus a full
BFT engine that finalizes blocks, survives view changes, and generalizes across
N-validator/F-fault thresholds. Adversarial coverage includes forged hashes,
substituted identities, insufficient quorums, outsider signatures, and crashed
proposers. Networking transport, public anchoring, and the node daemon/CLI are
the next milestones.

## Cryptography

| Purpose            | Primitive        | Standard   | Quantum posture                    |
|--------------------|------------------|------------|------------------------------------|
| Commitments/Merkle | SHA3-256         | FIPS 202   | ~128-bit vs Grover — safe          |
| Identities/signing | ML-DSA-65        | FIPS 204   | Lattice-based — Shor-resistant     |

## License

MIT OR Apache-2.0
