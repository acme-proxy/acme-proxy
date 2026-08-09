# Every stage is FROM debian:trixie-slim (see root Containerfile's header comment
# for why: Debian trixie's rustc/cargo predate this workspace's MSRV, so the
# toolchain comes from rustup, not apt). cargo-chef caches the dependency build as
# its own layer, keyed on Cargo.toml/Cargo.lock content rather than the whole tree.

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
COPY netbox-mock .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --locked --recipe-path recipe.json
COPY netbox-mock .
RUN cargo build --release --locked

FROM debian:trixie-slim
COPY --from=builder /app/target/release/netbox-mock /usr/local/bin/netbox-mock
CMD ["netbox-mock"]
