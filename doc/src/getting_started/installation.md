# Installation

`acme-proxy` is a Rust application, published on
[crates.io](https://crates.io/crates/acme-proxy). There are four ways to get
it: `cargo install`, a source build, the published container image, or a
container image you build yourself. Only the published image comes prebuilt; no
standalone prebuilt binaries are published.

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
cargo install acme-proxy --version 0.5.0
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

The published [container image](#container-docker--podman) is the default
build, without `hsm`. A deployment that needs it builds its own binary.

## Container (Docker / Podman)

Every release is published to the GitHub Container Registry as a
multi-architecture image, for `linux/amd64` and `linux/arm64`:

```bash
podman pull ghcr.io/acme-proxy/acme-proxy:0.6.0
```

| Tag      | Points at                                                   |
|----------|-------------------------------------------------------------|
| `0.6.0`  | That release. It never moves.                               |
| `0.6`    | The newest `0.6.x` release: its fixes, never a new minor.   |
| `latest` | The highest release, whatever its minor.                    |
| `edge`   | The head of `main`, rebuilt on every merge. Not a release.  |
| `sha-…`  | One commit of `main`, as `edge` was when it was built.      |

Run a version tag, or `0.6` to take patch releases without a change on your
side. Avoid `latest` for an unattended deployment. Before 1.0.0 a minor
release may rename a configuration key, so a pull of `latest` can stop a server
from starting; the `### Breaking` sections of the
[changelog](https://github.com/acme-proxy/acme-proxy/blob/main/CHANGELOG.md#compatibility)
list every such change. `edge` is for trying what the next release will hold,
never for a certificate authority anyone depends on.

Every image holds the release build with the default features: the binary
`cargo install acme-proxy` produces.

To build the image yourself instead, use the `Containerfile` in a clone of the
repository:

```bash
podman build -t acme-proxy .
```

That is the same release build as the published image, fat LTO included, so it
takes tens of minutes.

The image's working directory is `/data` and its entrypoint is the `acme-proxy`
binary, so mount a volume there for the SQLite database, the configuration and
the CA key material — all of which default to paths relative to the working
directory. The image runs as a non-root user, so the mounted directory must be
writable by it — the `:U` flag below is the rootless-Podman way; see
[Deployment](deployment.md#container-deployments-docker--podman) for Docker.

```bash
podman run -d \
  -p 3000:3000 \
  -v ./data:/data:U \
  ghcr.io/acme-proxy/acme-proxy:0.6.0
```

Drop a `config.toml` into `./data` (it must define at least one profile — see
the [Quick Start](quick_start.md)), or configure the container entirely through
`ACME_PROXY_*` environment variables:

```bash
podman run -d \
  -p 3000:3000 \
  -v ./data:/data:U \
  -e ACME_PROXY_PROFILES__DEFAULT__ENABLED=true \
  -e ACME_PROXY_SERVER__BASE_URL=https://acme.example.com \
  ghcr.io/acme-proxy/acme-proxy:0.6.0
```

### Verifying the image

Each published image carries a signed build provenance attestation. It records
the repository, the commit and the workflow run that built the image. Check it
with the [GitHub CLI](https://cli.github.com/) before you run the image:

```bash
gh attestation verify oci://ghcr.io/acme-proxy/acme-proxy:0.6.0 \
  --repo acme-proxy/acme-proxy
```

The attestation is on the multi-architecture index, the object a tag resolves
to. The digest of one architecture's image, on its own, has no attestation to
find.
