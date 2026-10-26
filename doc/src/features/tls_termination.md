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

## The server's own certificate

A self-signed certificate means every client has to be told to trust it: Traefik
wants `caCertificates`, curl wants `--cacert`, a browser wants the certificate
in the system store. `acme_enabled` removes that chore by having the server ask
its **own upstream** for a certificate for itself, the same way it obtains one
for a client.

```toml
[server]
base_url = "https://acme.int.example.com:3000"

[server.tls]
enabled = true
acme_enabled = true
# Only needed when more than one profile relays with dns01.
acme_profile = "letsencrypt"

[profiles.letsencrypt]
signer.backend = "relay"
signer.relay.directory_url = "https://acme-v02.api.letsencrypt.org/directory"
signer.relay.challenge_strategy = "dns01"
# …plus the [signer.relay.dns01] updater that can write the zone.
```

The name is the host of `server.base_url` — the only name a client will ever ask
this listener for — and it is proved with **dns-01** through that profile's
`[signer.relay.dns01]` updater, the one it already uses for its clients. Three
things follow from that:

- The profile has to be a relay answering `dns01`. `http01` and `bypass` publish
  nothing, so nothing could have proved the server owns its own hostname; a
  profile that cannot prove control is refused at startup. A configuration with
  two candidates is refused too until `acme_profile` picks one, because the
  choice decides whose CA is asked and whose DNS credential writes the record.
- Nothing here goes through this server's own ACME surface, so `[challenge]` has
  no bearing on it: no `enabled`, no resolvable `base_url`, no client answering.
  dns-01 needs no listener, so there is no certificate needed in order to
  obtain the certificate.
- The name has to be in the zone the updater can write. That is the usual
  split-horizon arrangement, and it works: the public zone carries only the
  `_acme-challenge.*` TXT records while `acme.int.example.com` itself resolves
  privately. Alias mode (`dns01.challenge_alias`) works here too, since the
  updater decides the record name exactly as it does for a client, and so does
  the `[signer.relay.dns01.propagation]` wait for it to become visible.

### What it does, and when

One row in the [job queue](../operations/cli.md#job-queue), kind
`server_self_tls`, owns it. It checks the certificate on disk and asks for a new
one when that file is missing, will not parse, is the self-signed placeholder,
or is within 30 days of expiring; otherwise it reschedules itself twelve hours
later. Booting never waits for an order — the listener serves what is on disk —
so a CA or a DNS API that is down costs a `server_self_tls_failed` warning and
the certificate already being served, not a server that will not start. Turning
the toggle off later leaves the row in `jobs list`, simply never claimed — the
runner takes rows only of kinds it has a handler for — and turning it back on
reuses that same row rather than adding a second.

A new chain is written to `cert_path` and then installed the way a `SIGHUP`
would have installed it: the server asks for a configuration reload, which
rebuilds the acceptor from the files on disk. There is one path by which a
listener certificate takes effect, and a renewal cannot drift from what a
restart would have produced.

Enabling the toggle hands `cert_path` and `key_path` to the server, and the key
at `key_path` is the one the certificate is issued for — so the placeholder's
key becomes the issued certificate's key, and no renewal needs a new private
key. A chain that a CA issued and that is nowhere near expiry is left alone
until it is: enable the toggle before a hand-supplied certificate's renewal
window, or delete the file to take it over now.

Only a process running the [worker role](../getting_started/roles.md) issues,
because only one builds signer backends and holds a DNS credential. Instances
sharing a database issue once: the queue holds one row, and the process that
claims it writes the file the others read — so with separate filesystems the
others never see that chain and serve what their own disk holds until it
expires. Put `cert_path` and `key_path` on a volume every instance mounts, or
run the toggle on one instance whose files the others read. Instances sharing a
*filesystem* but not a database cannot see each other's row and will each renew
on their own schedule, spending the CA's weekly allowance twice. A separate
`acme` process picks the renewed files up at its own next reload or restart.

> **Warning:** a public CA's certificates are published to Certificate
> Transparency logs, which the
> [CA/B Forum](https://cabforum.org/working-groups/certificate-transparency/)
> requires for anything browsers trust. Issuing `acme.int.example.com` from
> Let's Encrypt therefore puts that internal hostname in a log anyone can read,
> and revocation cannot remove it. If the name itself is secret, use an internal
> CA instead: `signer.backend = "local_ca"`, or a private section of a public
> CA.

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
