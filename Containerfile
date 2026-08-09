# Builds the acme-proxy server for the e2e lab (tests/e2e/).
# Not used by CI — the lab is a manual check, same as the rest of tests/e2e/.
#
# Every stage here (and in every other tests/e2e/*.Containerfile) is FROM
# debian:trixie-slim — no upstream language images. Debian trixie's own rustc/cargo
# (1.85 main / 1.94 backports) predate this crate's MSRV (rust-version = "1.97"), so
# the toolchain is installed via rustup instead of apt.
#
# Split into cargo-chef stages so the (large, LTO-release) dependency build is its
# own layer, cached by the content of Cargo.toml/Cargo.lock alone — a source-only
# change no longer forces every dependency crate to recompile.

FROM debian:trixie-slim AS chef
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl build-essential \
    && rm -rf /var/lib/apt/lists/*
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --profile minimal --default-toolchain stable
ENV PATH="/root/.cargo/bin:${PATH}"
RUN cargo install cargo-chef --locked
WORKDIR /app

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
RUN apt-get update \
    && apt-get install -y --no-install-recommends pkg-config libsqlite3-dev \
    && rm -rf /var/lib/apt/lists/*
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --locked --recipe-path recipe.json
COPY . .
RUN cargo build --release --locked

FROM debian:trixie-slim
# openssl is here only for tests/e2e/custom_signer/signer_script.sh, a lab
# scenario for signer.backend = "custom" that runs a real toy CA *inside* this
# container (the script is a subprocess of acme-proxy itself, so it needs
# tools available in this image, not the client image's). Harmless for every
# other scenario, which never invokes it.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates openssl \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/acme-proxy /usr/local/bin/acme-proxy
WORKDIR /data
ENTRYPOINT ["acme-proxy"]
CMD ["serve"]
