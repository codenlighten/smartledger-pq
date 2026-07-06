# SmartLedger-Chain node — multi-stage build.
#
# Build stage: compile the release binaries (with BSV anchoring). rustls is pure
# Rust, so the runtime needs no OpenSSL — only CA certs for HTTPS to notaryhash.
FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release -p slc-node --bins --features notaryhash

# Runtime stage: slim, just the two binaries + entrypoint.
FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/slc-node /usr/local/bin/slc-node
COPY --from=build /src/target/release/slc /usr/local/bin/slc
COPY deploy/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Persist keys + blocks across restarts.
VOLUME /data
# p2p and client RPC.
EXPOSE 9000 7000

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["run"]
