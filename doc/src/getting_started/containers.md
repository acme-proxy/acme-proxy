# Containers

One container running every role, from the published image, under Docker
Compose or Podman. To run the roles in containers of their own, see [Docker
Compose, Roles Split](compose_roles.md).

Each release is published as `ghcr.io/acme-proxy/acme-proxy:<version>`, for
`linux/amd64` and `linux/arm64`, and the examples below pin one.
[Installation](installation.md#container-docker--podman) covers why to pin,
building the image yourself from the `Containerfile`, and verifying its
provenance:

```bash
podman pull ghcr.io/acme-proxy/acme-proxy:0.6.0
```

The image's working directory is `/data` and its entrypoint is the binary
itself, so `/data` is where the database, the CA key material and the CRL land
unless you override their paths.

The image runs as a non-root user (`acme-proxy`, uid/gid `1000`), so **the
directory you mount at `/data` must be writable by that uid**. How you arrange
that depends on the runtime:

- **Rootless Podman** — add `U` to the mount flags (`-v ./data:/data:U`, or
  `:Z,U` on SELinux systems). Podman then chowns the volume's contents to the
  user the container runs as. Alternatives: `podman unshare chown -R 1000:1000
  ./data` beforehand, or use a named volume (`-v acme-proxy-data:/data`), which
  Podman initializes with the right owner.
- **Docker / Docker Compose** — create the directory owned by uid `1000` before
  the first run: `mkdir -p ./data && sudo chown 1000:1000 ./data`. Or override
  the uid to your own (`--user "$(id -u):$(id -g)"`, or a Compose `user:` line)
  and own `./data` yourself — the server only needs to read and write that one
  directory.

## Docker Compose

Create a `docker-compose.yml` file:

```yaml
services:
  acme-proxy:
    image: ghcr.io/acme-proxy/acme-proxy:0.6.0
    container_name: acme-proxy
    restart: unless-stopped
    ports:
      - "3000:3000"
    volumes:
      - ./data:/data
    environment:
      - ACME_PROXY_PROFILES__DEFAULT__ENABLED=true
      - ACME_PROXY_DATABASE__URL=sqlite:///data/acme.db
      - RUST_LOG=acme_proxy=info
```

Create the data directory with the right owner before the first run:
```bash
mkdir -p ./data && sudo chown 1000:1000 ./data
```

Run the stack using:
```bash
docker compose up -d
```

`ACME_PROXY_PROFILES__DEFAULT__ENABLED=true` is what defines the profile when
there is no configuration file — the server serves nothing without at least one.
For anything beyond a single default profile, mount a `config.toml` into `/data`
instead.

## Podman (rootless)

Under rootless Podman you can run the container directly. The `U` flag chowns
the mounted directory to the non-root user the container runs as; add `Z` as
well on SELinux-enabled systems (RHEL/Fedora) for the mount label.

```bash
podman run -d --name acme-proxy \
  -p 3000:3000 \
  -v ./data:/data:U \
  -e ACME_PROXY_PROFILES__DEFAULT__ENABLED=true \
  -e ACME_PROXY_DATABASE__URL=sqlite:///data/acme.db \
  ghcr.io/acme-proxy/acme-proxy:0.6.0
```
