# Quick Start

Get `acme-proxy` running in a couple of minutes with an auto-generated Local CA.

## Step 1 — Write a configuration file

`acme-proxy` serves ACME only through **profiles**, so at least one enabled
profile is required — the server refuses to start without one. Everything else
has a working default.

By default the server also performs real domain-control validation (HTTP-01). To
test a client against the proxy locally without routing port 80 or configuring
DNS, this quick start turns validation off with `challenge.bypass`.

Create `config.toml` in your current directory:

```toml
[challenge]
# Testing only. See "Moving to production" below.
bypass = true

[profiles.default]
```

> `[profiles.default]` is not empty by accident — a profile's `enabled` key
> defaults to `true`, so naming the profile is all that is required. The profile
> name becomes part of the URL, and of every `kid` a client stores.

## Step 2 — Run the server

```bash
acme-proxy serve
```

`serve` is also the default, so a bare `acme-proxy` does the same thing.

There is **no `--config` flag**. The server reads `config.toml` from the current
working directory; point it elsewhere with `ACME_PROXY_CONFIG`:

```bash
ACME_PROXY_CONFIG=/etc/acme-proxy/config.toml acme-proxy serve
```

(The extension may be omitted — the format is then inferred.) A missing
configuration file is not an error: the server falls back to defaults, which is
why an environment-only deployment works.

Individual keys can also be overridden with `ACME_PROXY_*` environment
variables; see the [Configuration Reference](../configuration/reference.md).

The server binds `[::]:3000` and serves the ACME directory at
`http://localhost:3000/profile/default/directory`. On first run it creates
`sqlite.db`, `ca.pem` and `ca.key` in the working directory.

## Step 3 — Request a certificate

Point any standard ACME client at the profile's directory URL. Examples for
`internal.example.com`:

### certbot
```bash
certbot certonly \
  --server http://localhost:3000/profile/default/directory \
  --standalone \
  --domain internal.example.com \
  --email admin@example.com \
  --agree-tos \
  --no-eff-email
```

### acme.sh
```bash
acme.sh --issue \
  --server http://localhost:3000/profile/default/directory \
  -d internal.example.com \
  --standalone
```

### lego
```bash
lego --server http://localhost:3000/profile/default/directory \
  --email admin@example.com \
  --domains internal.example.com \
  --http \
  run
```

### Traefik
In Traefik's static configuration (`traefik.yml`):
```yaml
certificatesResolvers:
  myresolver:
    acme:
      caServer: http://localhost:3000/profile/default/directory
      email: admin@example.com
      httpChallenge:
        entryPoint: web
```

### Caddy
In your `Caddyfile`:
```caddyfile
internal.example.com {
    tls admin@example.com {
        ca http://localhost:3000/profile/default/directory
    }
    respond "Hello, world!"
}
```

**What just happened?**
1. The client fetched the directory from `acme-proxy`.
2. It registered an account and created a new order.
3. `acme-proxy` offered an HTTP-01 challenge.
4. Because `challenge.bypass = true`, the proxy marked the challenge `valid` the
   moment the client triggered it, without making any network request back to
   the client's responder.
5. The proxy signed the CSR with its auto-generated local ECDSA CA and returned
   the certificate.

The certificate is signed by a CA nothing trusts yet. See [Trusting the
CA](trusting_the_ca.md) for how to install `ca.pem` where your clients will
accept it.

## Step 4 — Moving to production

The defaults are safe; this quick start deliberately relaxed them. Before
exposing the server:

1. **Remove the bypass.** Delete `challenge.bypass = true` so `acme-proxy`
   actually validates domain control. With bypass on, `[filter]` is the *only*
   access control there is — which is exactly why bypass is not the default. See
   [Challenge Validation](../challenges/index.md).
2. **Enable filters.** Configure `allowed_ip`, `identifiers` or `netbox` to
   restrict which clients may request which names. See
   [Filters & Policies](../filters/index.md).
3. **Choose where state lives.** The defaults write `sqlite.db` and the CA
   material to the current working directory. Set `database.url` and
   `signer.local_ca.cert_path` / `signer.local_ca.key_path` to permanent paths —
   note these are the *CA*'s files, distinct from `server.tls.cert_path` /
   `server.tls.key_path`, which belong to the HTTPS listener.
4. **Serve over HTTPS.** RFC 8555 §6.1 expects ACME over HTTPS: either put the
   server behind a reverse proxy, or turn on
   [TLS termination](../features/tls_termination.md).
