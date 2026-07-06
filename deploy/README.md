# Deploying SmartLedger-Chain

Four ways to run a node, smallest to largest. A node whose key is **not yet in
the validator set** runs as a *follower* (it syncs and serves proofs) until the
consortium admits it via governance — see [Admitting a validator](#admitting-a-validator).

## 1. Local (from source)

```sh
cargo build --release
./target/release/slc-node init-devnet ./devnet 4      # keys + genesis + configs
# launch each node (own terminal): ./target/release/slc-node run ./devnet/nodeN.config.json
```

## 2. Single node in Docker

```sh
docker build -t smartledger-chain:latest .

# Bootstrap a brand-new single-validator chain:
docker run -d --name slc -p 9000:9000 -p 7000:7000 -v slc-data:/data \
  -e SLC_PUBLIC_ADDR=<public-ip>:9000 smartledger-chain:latest

# ...or join an existing chain by pointing at its genesis:
docker run -d --name slc -p 9000:9000 -p 7000:7000 -v slc-data:/data \
  -e SLC_GENESIS_URL=https://example.com/genesis.json \
  -e SLC_PUBLIC_ADDR=<public-ip>:9000 smartledger-chain:latest

docker logs slc | grep 'public key'      # this node's PQ identity
```

Anchoring to BSV: add `-e SLC_ANCHOR_INTERVAL=100 -e SLC_ANCHOR_BACKEND=notaryhash
-e NOTARYHASH_API_KEY=<key>`.

Key `SLC_*` env vars: `SLC_GENESIS_URL` / `SLC_GENESIS_JSON`, `SLC_PUBLIC_ADDR`
(advertised host:port), `SLC_LISTEN` (bind, default `0.0.0.0:9000`), `SLC_RPC`
(default `0.0.0.0:7000`), `SLC_PEERS` (comma-separated), `SLC_ANCHOR_*`.

## 3. Local multi-node devnet (docker-compose)

```sh
cargo run -p slc-node --bin slc-node -- init-devnet ./deploy/devnet 4 --docker
docker compose -f deploy/docker-compose.yml up
slc notarize <file> <client.key> 127.0.0.1:7000     # node0 RPC on the host
```

## 4. AWS one-click (CloudFormation)

`deploy/aws/cloudformation.yaml` launches an EC2 instance running the node in
Docker. Deploy via the console (**CloudFormation → Create stack → upload the
template**) or the CLI:

```sh
aws cloudformation deploy \
  --template-file deploy/aws/cloudformation.yaml \
  --stack-name smartledger-node \
  --parameter-overrides KeyName=<your-keypair> \
      GenesisUrl=https://example.com/genesis.json \
      RpcCidr=<your-office-cidr> SshCidr=<your-office-cidr> \
  --capabilities CAPABILITY_IAM
```

Leave `GenesisUrl` blank to bootstrap a new chain. Stack **Outputs** give the
p2p/RPC endpoints, the SSH command, and how to read the node's public key
(`slc node-info <ip>:7000`). Publish the node image to a registry and set
`DockerImage` accordingly. For a "Launch Stack" button, host the template on S3
and link `https://console.aws.amazon.com/cloudformation/home#/stacks/create/review?templateURL=<s3-url>`.

## Admitting a validator

Deploying a node makes it a *follower*. To promote it to a validator, the
consortium (existing validators) runs governance — no admin key, just a quorum:

```sh
# newcomer shares its public key:
slc node-info <newcomer-ip>:7000            # or: docker logs slc | grep 'public key'

# an operator proposes; each validator approves; then submit to any node:
slc gov propose --add <newcomer-pubkey> --activation <future-height> --out change.json
slc gov approve change.json <validator-keystore>     # repeated by ≥ quorum validators
slc gov submit  change.json <any-node-rpc>
```

Existing validators also need to reach the newcomer over p2p. Add its address to
each running node **without a restart**:

```sh
slc add-peer <newcomer-ip>:9000 <existing-node-rpc>   # repeat per validator
```

Then the change rides into a block; at `activation_height` every node — derived
from the chain, not config — switches to the new set, and the newcomer starts
signing blocks. Nodes periodically **re-gossip** their current-round messages, so
a newly-added peer (or a healed network partition) catches up and consensus
resumes on its own.

> Note: a node must be connected from genesis to have the full block history
> (there is no block-sync/catch-up protocol yet), so run joining nodes as
> followers from the start and admit them later via governance.
