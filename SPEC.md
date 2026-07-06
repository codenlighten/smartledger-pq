# SmartLedger-Chain — Protocol Specification

Version 1. This document specifies the wire formats, cryptography, consensus, and
verification rules of SmartLedger-Chain precisely enough for an independent
implementation and for third-party proof verification.

Conventions: byte strings are big-endian; `‖` is concatenation; `H(x)` is
SHA3-256; hashes/keys/signatures are lowercase hex in JSON.

---

## 1. Overview

SmartLedger-Chain is a **post-quantum, permissioned notary chain**. Its single
purpose: prove that a piece of data existed in an exact form at an exact time,
forever, without revealing the data. Validators are legally-known actors; the
security thesis is that forging finalized history requires a quorum of named
entities to collude — legally attributable, and (via public anchoring)
externally detectable.

Design principles:

- **Privacy by construction** — only hashes are submitted, never content.
- **Self-verifying entries** — every entry is signed by its own author.
- **Conflict-free ledger** — entries never contradict; the state is a growing set.
- **Post-quantum** where it matters — signatures use ML-DSA; hashing is SHA3.
- **Offline-verifiable proofs** — a proof verifies with only validator public keys.

---

## 2. Cryptography

| Purpose                    | Primitive            | Standard  | Sizes (bytes)            |
|----------------------------|----------------------|-----------|--------------------------|
| Hashing, Merkle, commitments | SHA3-256           | FIPS 202  | 32 (digest)              |
| Actor/validator signatures | ML-DSA-65 (Dilithium)| FIPS 204  | pk 1952, sig 3309        |
| License signatures         | SLH-DSA-SHA2-128s    | FIPS 205  | pk 32, sig 7856          |

All signatures use a **domain-separation context** (an ML-DSA/SLH-DSA context
string) so a signature made for one purpose can never be replayed as another:

| Context bytes            | Used for                                             |
|--------------------------|------------------------------------------------------|
| `SLC-attestation-v1`     | a client attesting to (notarizing) a data hash       |
| `SLC-block-v1`           | a validator signing a block id (a precommit / QC share) |
| `SLC-proposal-v1`        | a proposer signing a proposal                        |
| `SLC-vote-v1`            | a validator signing a prevote or a nil vote          |
| `SLC-governance-v1`      | a validator approving a validator-set change         |
| `SLC-license-v1`         | SmartLedger signing a software license               |

ML-DSA signatures are produced with an **empty** application context except for
the domain-separation context above; the checkpoint-anchor signature (§8) signs
the bare root with `SLC-block-v1`.

---

## 3. Data model

### 3.1 Attestation (the entry)

```
Attestation { pubkey: MlDsaPk, hash: H, signature: MlDsaSig }
```

`signature = Sign_ML-DSA(sk, hash, ctx = SLC-attestation-v1)`. An attestation is
**valid** iff `Verify(pubkey, hash, signature, SLC-attestation-v1)`. It is
self-verifying: anyone can check it with no chain access.

Leaf encoding for the Merkle tree: `encode(a) = pubkey ‖ hash ‖ signature`
(fixed-width). Leaf digest: `leaf(a) = H(0x00 ‖ encode(a))`.

### 3.2 Merkle tree

Binary tree over leaf digests with **domain separation** and **promote-odd**:

- Leaf: `H(0x00 ‖ data)`.
- Node: `H(0x01 ‖ left ‖ right)`.
- Odd level: the last node is promoted up unchanged (never duplicated).
- Empty tree: root = `H("SLC-empty-merkle-v1")`.

An inclusion proof is a list of `{ sibling: H, sibling_is_left: bool }` from leaf
to root; the root is recomputed by folding siblings.

### 3.3 Block header

```
BlockHeader { height: u64, prev_hash: H, merkle_root: H,
              tx_count: u32, timestamp: u64, gov_root: H }
```

- `merkle_root` — root over the block's attestation leaves.
- `gov_root` — commitment to governance changes (§6), `governance_root([])` if none.
- `timestamp` — unix seconds vouched for by the quorum.

Canonical signing bytes (the block-id preimage):
```
height(8) ‖ prev_hash(32) ‖ merkle_root(32) ‖ tx_count(4) ‖ timestamp(8) ‖ gov_root(32)
```
Block id: `id = H(signing_bytes)`.

### 3.4 Quorum certificate

```
ValidatorSig     { validator: MlDsaPk, signature: MlDsaSig }
QuorumCertificate { block_id: H, signatures: [ValidatorSig] }
```

A QC **finalizes** header `hdr` under validator set `S` iff `block_id = hdr.id`
and the number of *distinct, in-set* validators whose signature verifies over
`block_id` under `SLC-block-v1` is ≥ `quorum(S)`.

### 3.5 Block

```
Block { header, attestations: [Attestation], governance: [SignedValidatorChange], qc }
```

A block is **valid** iff: it has ≥1 attestation or ≥1 governance change (never
empty); every attestation self-verifies; `merkle_root` matches; `gov_root`
matches; every governance change is quorum-authorized and future-activating
(§6); and `qc` finalizes `header` under the set in force at `header.height`.

---

## 4. Validator set

```
quorum(S) = |S| − f,  where  f = ⌊(|S|−1)/3⌋   (the BFT 2f+1-of-3f+1 rule)
```

e.g. |S|=4→quorum 3, |S|=7→quorum 5. Proposer for `(height, round)` is
`sorted_by_id(S)[(height + round) mod |S|]`.

---

## 5. Consensus — Quorum-Certified Notary BFT

A Tendermint-style two-phase BFT (propose → prevote → precommit → commit) with
locking (`lockedValue/lockedRound`, `validValue/validRound`) and timeout-driven
round (view) change. Specialized to the conflict-free workload: `valid(v)` is
pure structural + signature checking (no transaction execution).

Key points:

- **Precommit == QC share.** A non-nil precommit signs the bare block id under
  `SLC-block-v1`; the commit assembles the QC directly from the precommits.
- **Instant finality.** A block with a precommit quorum is final; the QC is its
  portable proof of finality.
- **Attestation-triggered.** A block must notarize or govern, so **empty blocks
  are impossible**. A node with an empty mempool idles ("parks") and wakes on a
  local submission or a proposal for its current height (never on votes/stale
  messages, which would cause idle churn).
- **Re-gossip.** Each node periodically re-broadcasts its current-round proposal
  and votes, so a healed partition or a newly-added peer catches up and progress
  resumes. Safety rests on: *an honest validator signs at most one block per
  height*, plus quorum intersection.

Timeouts grow linearly with the round (`base × (round+1)`).

---

## 6. Governance (validator-set changes)

```
ValidatorChange       { adds: [MlDsaPk], removes: [MlDsaPk], activation_height: u64 }
SignedValidatorChange { change, approvals: [ValidatorSig] }
```

Authorization: `change` is authorized under set `S` iff ≥ `quorum(S)` distinct
in-set validators sign `change.signing_bytes()` under `SLC-governance-v1`. There
is **no admin key** — the validators themselves govern.

Change canonical bytes: `"SLCGOV" ‖ activation_height(8) ‖ len(adds)(4) ‖
sorted(adds) ‖ len(removes)(4) ‖ sorted(removes)`.

Application: a change is included in a block (bound by `gov_root`) only if
authorized and `activation_height > block.height`. On commit, every node records
it. The **validator set at height h** is a pure function:

```
active_set(h) = genesis, then apply every recorded change with
                activation_height ≤ h  (removes, then adds; deduplicated)
```

Because the set is chain-derived, a rebooted node reconstructs it by replaying
its stored blocks' governance. `gov_root = H("SLC-govroot-v1" ‖ len ‖
commitment(c)…)`, where `commitment(c) = H(change.id ‖ len ‖ sorted approver ids)`.

---

## 7. Notarization proof (offline-verifiable)

```
NotarizationProof { attestation, path: MerklePath, header: BlockHeader, qc }
```

Verification against a known validator set `S`:

1. `attestation.verify()` — the actor's PQ signature covers the hash.
2. `path.compute_root(attestation.leaf()) == header.merkle_root` — inclusion.
3. `qc.verify(header, S)` — a quorum of named validators finalized the header.

The proof is a self-contained JSON artifact; step 3 uses the set in force at
`header.height` (from genesis + governance, if any).

---

## 8. Public-chain anchoring

Every N finalized blocks, a **checkpoint** commits their ids into a Merkle root:
`checkpoint_leaf(id) = H(0x00 ‖ id)`. The 32-byte root is published to a public
chain (BSV) and its receipt retained.

On-chain encoding (`OP_RETURN`): `OP_FALSE OP_RETURN push( MAGIC ‖ VERSION ‖ root )`
where `MAGIC = "SLC1"`, `VERSION = 0x01`. (The reference deployment anchors via
notaryhash.com, which signs the root with the chain's own ML-DSA-65 key and
records it on BSV mainnet via its own `OP_RETURN` protocol.)

```
AnchoredProof { notarization: NotarizationProof, checkpoint: CheckpointInclusion, record: AnchorRecord }
```

Verification: the notarization proof holds; the checkpoint inclusion is for this
proof's block id; the block is included under `record.checkpoint_root`; and the
published receipt commits to that root. This binds a notarized document out to an
external, tamper-evident anchor that no validator collusion can rewrite.

---

## 9. Licensing

A license is signed by SmartLedger's **SLH-DSA** key and verified offline.

```
Entitlements { max_nodes?, max_notarizations_per_month?, anchoring, features[] }
License       { licensee, license_id, product, tier, entitlements, chain_id?, issued_at, expires_at }
SignedLicense { license, issuer: SlhPk, signature }
```

`signature = Sign_SLH-DSA(sk, serde_json(license), SLC-license-v1)`. A node
verifies: issuer == trusted key; signature valid; `issued_at ≤ now < expires_at`;
and (if bound) `chain_id` matches — else it refuses to run.

**Metering.** A node counts local client notarizations in a 30-day window
(persisted) and rejects submissions beyond `max_notarizations_per_month`.

---

## 10. Wire & RPC

**Framing.** Both p2p and RPC use length-prefixed JSON: `u32` big-endian length ‖
`serde_json` bytes (max 32 MiB).

**p2p (`WireMsg`).** `Consensus(ConsensusMsg)` | `Attestation` | `Governance` —
each node connects outbound to peers to send and accepts inbound to receive.

**client RPC (`RpcRequest`/`RpcResponse`).** `Submit`, `SubmitGovernance`,
`AddPeer`, `GetProof`, `GetAnchoredProof`, `Status`, `NodeInfo`, `Usage`.

---

## 11. Node lifecycle

1. Load keystore (ML-DSA validator key); optional license → verify or refuse.
2. Open the block store; **resume** from the stored tip and rebuild the validator
   registry by replaying stored blocks' governance.
3. Bind p2p listen address; connect to peers. A node whose key is not in the
   active set runs as a **follower** (syncs, serves proofs) until governance
   admits it.
4. Run one event loop: network, timers, re-gossip, client submissions — the
   consensus engine is touched only from this thread.

Limitation (v1): there is no block-sync/catch-up protocol, so a node must be
connected from genesis to hold full history; joining nodes run as followers from
the start.

---

## 12. Crate map

`slc-crypto` (primitives) · `slc-ledger` (attestations, Merkle, blocks, QC,
governance, proofs) · `slc-consensus` (the BFT engine) · `slc-anchor`
(checkpoints, BSV) · `slc-license` (licenses) · `slc-node` (transport, storage,
RPC, daemon, `slc`/`slc-node` CLIs).
