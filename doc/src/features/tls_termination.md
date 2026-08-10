# TLS Termination

ACME strictly expects traffic over HTTPS (RFC 8555 §6.1).

While you can place `acme-proxy` behind a reverse proxy (like Nginx, HAProxy, or
Traefik) and let it terminate TLS, `acme-proxy` is fully capable of terminating
TLS itself via the highly secure `rustls` crate.

## Architectural security (Slowloris protection)

Terminating TLS in async frameworks requires care to avoid denial-of-service
vectors. In `acme-proxy`, **handshakes run off the accept path**. When a TCP
connection arrives, a background task spawns the TLS handshake into a bounded
channel. The handshake is strictly bounded by `handshake_timeout_ms`. If this
were done inline, a single stalled client (e.g., a Slowloris attack) could block
every other connection for the length of the timeout.

## Client IP preservation
Under the hood, `acme-proxy` wraps the TLS listener in a `TapIo` struct. This is
load-bearing. Without this wrapper, the Axum HTTP layer would lose visibility
into the underlying TCP socket's peer address once TLS is wrapped around it. By
using `TapIo`, `acme-proxy` ensures that the `allowed_ip` and `reverse_dns`
filters can correctly identify the true client IP, failing closed if it cannot
be determined.

## Configuration

To serve HTTPS directly, configure the `[server.tls]` section.

> **Note:** Setting `server.tls.enabled = true` replaces the cleartext HTTP
> listener entirely. You do not get both HTTP and HTTPS simultaneously.

```toml
[server]
base_url = "https://acme.internal:3000"
bind_address = "[::]:3000"

[server.tls]
enabled = true

# The PEM encoded certificate chain (leaf first) and private key
cert_path = "server.pem"
key_path  = "server.key"

# Budget for one TLS handshake
handshake_timeout_ms = 10000
```

If `cert_path` or `key_path` files are missing on disk at startup, `acme-proxy`
will **automatically generate a self-signed certificate** for the host specified
in `server.base_url` and write it to disk.

## The web admin listener

`[admin.tls]` is the same mechanism on a second socket: the same
load-or-generate provisioning, the same `TapIo` wrapper preserving the peer
address, the same `0600` on a generated key. Only the defaults differ.

```toml
[admin.tls]
enabled   = true
cert_path = "admin.pem"     # not server.pem
key_path  = "admin.key"
```

The paths are separate on purpose: the two listeners answer to different names
(`admin.base_url` versus `server.base_url`, and a generated certificate takes
its name from whichever applies), and sharing one certificate between them
should be a decision, not an accident. The log lines carry a `listener` field
(`"acme"` or `"admin"`) so certificate churn on one is distinguishable from the
other.

Unlike the ACME listener, TLS here is **not optional once the panel leaves
loopback** — startup refuses that combination outright. See
[Web Admin](../operations/webadmin.md#binding-to-a-real-interface).
