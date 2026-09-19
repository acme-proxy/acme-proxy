# Builds the acme-proxy server image, used two ways: by the e2e lab (tests/e2e/)
# and as the published deployment image (.github/workflows/release.yml, pushed to
# ghcr.io on a release tag; see doc/src/getting_started/deployment.md). Not used
# by CI's `test` job — the lab is a manual check, plus the nightly `e2e` job in
# .github/workflows/ci.yml.
#
# Every stage here (and in every other tests/e2e/*.Containerfile) is FROM
# debian:trixie-slim — no upstream language images. Debian trixie's own rustc/cargo
# (1.85 main / 1.94 backports) predate this crate's MSRV (rust-version = "1.97"), so
# the toolchain is installed via rustup instead of apt.
#
# The compile is kept cheap two ways, because a lab image rebuilt on every source
# change is squarely on a developer's inner loop:
#
#  1. `--mount=type=cache` keeps the cargo registry and `target/` across builds.
#     `COPY . .` invalidates its layer on any source change, so anything living
#     *in* a layer starts from nothing every time; a cache mount does not, which
#     makes the rebuild incremental rather than total. This replaced a four-stage
#     cargo-chef arrangement — chef froze the *dependency* build into a layer and
#     nothing did the same for the crate itself, which was the expensive half
#     (~2m15s of relink per source change, measured). A persistent `target/`
#     subsumes what chef was buying and drops the `cargo install cargo-chef
#     --locked` from-source build from every cold start.
#
#  2. The cargo profile is a build argument, `CARGO_PROFILE`, and the lab asks
#     for `e2e` (`--build-arg CARGO_PROFILE=e2e` in tests/e2e/common.rs): release
#     without fat LTO and with 16 codegen units (see Cargo.toml). The lab needs a
#     binary that *behaves* like the release one, not one optimised for
#     distribution.
#
#     The default is `release`, the distribution build, which is what
#     release.yml publishes. A default of `e2e` would make a hand-run
#     `podman build .` a near miss of the published image that nothing can tell
#     apart from outside; this way it reproduces it, at the cost of a fat-LTO
#     build of tens of minutes.
#
# The final stage is unnamed and last on purpose: tests/e2e/common.rs builds with
# no `--target`, so a stage appended after it would silently become the lab's
# image.
#
# Cache mounts need BuildKit when the harness is pointed at docker with the legacy
# builder (`DOCKER_BUILDKIT=0` fails here); modern docker defaults to BuildKit and
# podman/buildah support them natively.

FROM debian:trixie-slim AS builder
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       ca-certificates curl build-essential pkg-config libsqlite3-dev \
    && rm -rf /var/lib/apt/lists/*
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --profile minimal --default-toolchain stable
ENV PATH="/root/.cargo/bin:${PATH}"
WORKDIR /app
COPY . .
# Only `registry` and `git` are mounted, never `/root/.cargo` itself — that also
# holds rustup's toolchain binaries, and mounting over it hides `cargo`. The
# binary is copied out inside the same `RUN` because a cache mount is not
# committed to the layer, so a later `COPY --from=builder /app/target/...` would
# find an empty directory. `sharing=locked` because two cargo processes in one
# `target/` corrupt it: the lab's own builds are serialised by the `flock` in
# `ensure_images_built`, but a hand-run `podman build` alongside one is not.
#
# The `ARG` sits inside this stage (one declared before the first `FROM` reaches
# only `FROM` lines) and after `COPY . .`, so changing it invalidates only the
# build below. Both expansions are quoted because `RUN` is shell form: an empty
# value would otherwise turn the copy into `cp target//acme-proxy`. Each profile
# builds into its own `target/<profile>/`, so the two share one cache mount.
ARG CARGO_PROFILE=release
RUN --mount=type=cache,target=/root/.cargo/registry,sharing=locked \
    --mount=type=cache,target=/root/.cargo/git,sharing=locked \
    --mount=type=cache,target=/app/target,sharing=locked \
    cargo build --profile "${CARGO_PROFILE}" --locked --package acme-proxy \
    && cp "target/${CARGO_PROFILE}/acme-proxy" /app/acme-proxy

FROM debian:trixie-slim
# openssl is here only for tests/e2e/custom_signer/signer_script.sh, a lab
# scenario for signer.backend = "custom" that runs a real toy CA *inside* this
# container (the script is a subprocess of acme-proxy itself, so it needs
# tools available in this image, not the client image's). Harmless for every
# other scenario, which never invokes it.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates openssl \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/acme-proxy /usr/local/bin/acme-proxy
# Run as a non-root account that owns only its data directory (ASVS V13.2.2).
# Everything the server writes — sqlite.db and its WAL siblings, the CA key
# material, the CRL and its JSON ledger, a generated TLS cert, a mounted
# config.toml — lands in WORKDIR, so that is the one path this user needs. The
# uid/gid is fixed at 1000 (unused in debian:trixie-slim) so a bind-mounted host
# directory can be chowned to a predictable owner — see
# doc/src/getting_started/deployment.md.
RUN groupadd --gid 1000 acme-proxy \
    && useradd --uid 1000 --gid 1000 --no-create-home --home-dir /data \
       --shell /usr/sbin/nologin acme-proxy \
    && mkdir -p /data \
    && chown acme-proxy:acme-proxy /data
WORKDIR /data
USER acme-proxy
ENTRYPOINT ["acme-proxy"]
CMD ["serve"]
