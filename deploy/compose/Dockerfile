# AEGIS operator pilot — multi-node relay + client binaries.
# Build context: repository root (docker compose sets context: ../..).

FROM rust:1-bookworm AS builder
WORKDIR /build
COPY crates ./crates
RUN cd crates \
    && cargo build --release -p aegis-node -p aegis-client -p aegis-topology --bin aegis-pilot-gen

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/crates/target/release/aegis-node /usr/local/bin/aegis-node
COPY --from=builder /build/crates/target/release/aegis-client /usr/local/bin/aegis-client
WORKDIR /config
ENTRYPOINT ["aegis-node"]
CMD ["--config", "/config/node0.toml"]
