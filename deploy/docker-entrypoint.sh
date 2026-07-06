#!/usr/bin/env bash
# Container entrypoint for a SmartLedger-Chain node.
#
# On first boot it generates a validator keystore, resolves a genesis (from an
# inline env var, a URL, a mounted file, or by bootstrapping a single-validator
# chain), renders a config from SLC_* env vars, and runs the node. A node whose
# key is not yet in the validator set runs as a follower until governance adds
# it.
set -euo pipefail

DATA="${SLC_DATA:-/data}"
export SLC_KEYSTORE="${SLC_KEYSTORE:-$DATA/node.key}"
export SLC_STORE="${SLC_STORE:-$DATA/blocks}"
export SLC_GENESIS_FILE="${SLC_GENESIS_FILE:-$DATA/genesis.json}"
CONFIG="$DATA/config.json"
mkdir -p "$DATA"

# If not asked to run, just exec (e.g. `docker run <img> slc gov ...`).
if [ "${1:-run}" != "run" ]; then
  exec "$@"
fi

# 1. Keystore (persisted on the /data volume) — generate once.
if [ ! -f "$SLC_KEYSTORE" ]; then
  echo "[entrypoint] generating validator keystore at $SLC_KEYSTORE"
  slc-node keygen "$SLC_KEYSTORE" >/dev/null
fi
PUBKEY="$(slc pubkey "$SLC_KEYSTORE")"
echo "[entrypoint] node public key: $PUBKEY"

# 2. Genesis: inline JSON, a URL, a pre-mounted file, or bootstrap.
if [ -n "${SLC_GENESIS_JSON:-}" ]; then
  printf '%s' "$SLC_GENESIS_JSON" > "$SLC_GENESIS_FILE"
elif [ -n "${SLC_GENESIS_URL:-}" ]; then
  echo "[entrypoint] fetching genesis from $SLC_GENESIS_URL"
  curl -fsSL "$SLC_GENESIS_URL" -o "$SLC_GENESIS_FILE"
fi
if [ ! -f "$SLC_GENESIS_FILE" ]; then
  ADDR="${SLC_PUBLIC_ADDR:-127.0.0.1:9000}"
  echo "[entrypoint] no genesis provided; bootstrapping single-validator chain ($ADDR)"
  printf '{"chain_id":"%s","validators":[{"pubkey":"%s","addr":"%s"}]}' \
    "${SLC_CHAIN_ID:-smartledger}" "$PUBKEY" "$ADDR" > "$SLC_GENESIS_FILE"
fi

# 3. Render the node config from env + genesis.
slc-node render-config "$CONFIG" >/dev/null
echo "[entrypoint] config written to $CONFIG"

# 4. Run.
exec slc-node run "$CONFIG"
