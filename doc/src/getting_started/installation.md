# Installation

`acme-proxy` is a Rust application, published on
[crates.io](https://crates.io/crates/acme-proxy). There are three ways to get
it — `cargo install`, a source build, or a container image you build yourself —
and all three compile it locally. No prebuilt binaries are published.

The result is a single binary carrying both the server and the
[admin CLI](../operations/cli.md), so a deployment never needs a second tool.

## Prerequisites

- **Rust toolchain**: the crate is edition 2024 and declares a `rust-version` in
  `Cargo.toml` (currently **1.97**). That file is the source of truth; `cargo`
  refuses to build with anything older.
- **Cargo**: the Rust package manager.

SQLite is *not* a prerequisite: the driver is bundled with `sqlx`, the database
file is created automatically, and `DATABASE_URL` is not needed to compile. A
`sqlite3` binary is only useful if you want to inspect the database by hand.

You can install Rust via [rustup](https://rustup.rs/):
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

## From crates.io

```bash
cargo install acme-proxy
```

This fetches the published crate, compiles it, and puts the binary in
`~/.cargo/bin` — which needs to be on your `PATH`. Confirm it with:

```bash
acme-proxy --version
```

Tab completion and a man page come out of the binary itself, so there is nothing
extra to download:

```bash
acme-proxy completions zsh > ~/.zfunc/_acme-proxy
acme-proxy man | sudo tee /usr/share/man/man1/acme-proxy.1 > /dev/null
```

Both are generated from the command tree, so regenerate them when you upgrade.
The per-shell paths are in the
[admin CLI](../operations/cli.md#shell-completions) chapter.

To pin a version, or to move to a specific one later, name it:

```bash
cargo install acme-proxy --version 0.2.0
```

Upgrading is `cargo install acme-proxy --force`. Before doing so across a minor
version, read the `### Breaking` section of the
[changelog](https://github.com/acme-proxy/acme-proxy/blob/main/CHANGELOG.md#compatibility).
Before 1.0.0 the database schema is the only compatibility guarantee, so the
data survives an upgrade but a configuration key may have been renamed.

## Building from source

Prefer this if you intend to change anything, or want the test suite and the
book sources alongside the binary.

1. Clone the repository:
   ```bash
   git clone https://github.com/acme-proxy/acme-proxy.git
   cd acme-proxy
   ```

2. Build the project in release mode for production use:
   ```bash
   cargo build --release
   ```
The binary will be located at `target/release/acme-proxy`.

### Optional features

The default build has no optional features. One is available:

| Feature | What it adds |
|---|---|
| `hsm` | PKCS#11 support for the Local CA's issuing key, so it can live in a YubiKey or an HSM instead of a file — see [Hardware Keys](../signers/local_ca_hsm.md). |

```bash
cargo install acme-proxy --features hsm    # or, from a clone:
cargo build --release --features hsm
```

It is off by default because it pulls in `cryptoki` and its bindings, which a
deployment signing with an on-disk key does not need. The PKCS#11 module itself
is loaded at runtime, so enabling this adds no build-time C toolchain
requirement. Configuring `signer.local_ca.key_source = "pkcs11"` on a binary
built without it is a startup error naming the feature, never a silent fallback
to the file key.

## Container (Docker / Podman)

A `Containerfile` is provided in the repository to build an image.

```bash
podman build -t acme-proxy:latest .
```

The image's working directory is `/data` and its entrypoint is the `acme-proxy`
binary, so mount a volume there for the SQLite database, the configuration and
the CA key material — all of which default to paths relative to the working
directory.

```bash
podman run -d \
  -p 3000:3000 \
  -v ./data:/data \
  acme-proxy:latest
```

Drop a `config.toml` into `./data` (it must define at least one profile — see
the [Quick Start](quick_start.md)), or configure the container entirely through
`ACME_PROXY_*` environment variables:

```bash
podman run -d \
  -p 3000:3000 \
  -v ./data:/data \
  -e ACME_PROXY_PROFILES__DEFAULT__ENABLED=true \
  -e ACME_PROXY_SERVER__BASE_URL=https://acme.example.com \
  acme-proxy:latest
```

> No image is published to a public registry yet; build it yourself as above.
