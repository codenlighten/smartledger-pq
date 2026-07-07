# SmartLedger-Chain node — statically-linked, distroless image.
#
# The node is pure Rust with rustls (no OpenSSL), so it links fully static
# against musl and ships on `scratch`: no shell, no libc, no package manager —
# nothing for a vulnerability scanner to flag and no shell to pivot into. The
# old bash entrypoint now lives inside the binary (`slc-node bootstrap`).
FROM rust:1-bookworm AS build
RUN rustup target add x86_64-unknown-linux-musl \
    && apt-get update \
    && apt-get install -y --no-install-recommends musl-tools ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN cargo build --release --target x86_64-unknown-linux-musl -p slc-node --bins --features notaryhash \
    && strip target/x86_64-unknown-linux-musl/release/slc-node \
             target/x86_64-unknown-linux-musl/release/slc

# Runtime: an empty base. Only the two static binaries and a CA bundle (for
# HTTPS to notaryhash / a genesis URL) are copied in.
FROM scratch
LABEL org.opencontainers.image.source="https://github.com/codenlighten/smartledger-pq"
LABEL org.opencontainers.image.description="SmartLedger-Chain — post-quantum permissioned notary chain node"
LABEL org.opencontainers.image.licenses="MIT OR Apache-2.0"
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /src/target/x86_64-unknown-linux-musl/release/slc-node /usr/local/bin/slc-node
COPY --from=build /src/target/x86_64-unknown-linux-musl/release/slc /usr/local/bin/slc

# Persist keys + blocks across restarts.
VOLUME /data
# p2p and client RPC.
EXPOSE 9000 7000

# Default: bootstrap (keygen/genesis/config) then run. Other subcommands still
# work — `docker run <img> run /data/config.json`, `--entrypoint slc <img> ...`.
ENTRYPOINT ["/usr/local/bin/slc-node"]
CMD ["bootstrap"]
