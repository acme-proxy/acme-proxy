# Configuration Scenarios

This page outlines complete, practical examples of configuring `acme-proxy` for
different real-world use cases. Each block is a whole `config.toml`.

> All four scenarios below use the `relay` backend. **Starting the server
> registers an account at `directory_url`** — see
> [Relay](../signers/relay.md#reference). Use a staging endpoint while you are
> still working the configuration out.

## Let's Encrypt relay with DNS validation

This scenario configures `acme-proxy` to act as an internal relay. It intercepts
ACME clients locally, but ultimately relays the issuance requests to Let's
Encrypt.

The proxy takes the burden of solving Let's Encrypt's DNS-01 challenges on
behalf of internal users by utilizing an RFC 2136 dynamic DNS provider. Internal
clients never see a DNS credential; the single TSIG key lives here.

```toml
[server]
base_url = "https://acme.internal.company.com"
bind_address = "[::]:3000"

[signer]
backend = "relay"

[signer.relay]
directory_url = "https://acme-v02.api.letsencrypt.org/directory"
account_key_path = "le_upstream.key"
contact = ["mailto:admin@company.com"]
challenge_strategy = "dns01"
poll_interval_ms = 2000
poll_timeout_secs = 300

[signer.relay.dns01]
provider = "rfc2136"

[signer.relay.dns01.rfc2136]
server = "10.0.0.53:53"
zone = "internal.company.com."
tsig_key_name = "acme-update-key"
# MUST be standard base64 (not base64url). Prefer the environment variable
# ACME_PROXY_SIGNER__RELAY__DNS01__RFC2136__TSIG_KEY_SECRET to a file.
# A non-base64 value here is a startup error, not a runtime one.
tsig_key_secret = "c2VjcmV0LXJlcGxhY2UtbWU="
tsig_algorithm = "hmac-sha256"

[challenge]
# Require local clients to prove control to the proxy via HTTP-01
enabled = ["http-01"]
bypass = false

[profiles.default]
enabled = true
```

The key above writes only inside `internal.company.com.`. For names spread over
several zones, [DNS alias mode](../signers/relay.md#dns-alias-mode) points every
domain's challenge at one alias zone instead of needing a profile per zone.

## Let's Encrypt relay with a Cloudflare-hosted zone

The same relay, for names in a zone Cloudflare's own nameservers serve.
Cloudflare takes no RFC 2136 update, so `provider = "cloudflare"` writes the
upstream's TXT record through its API. Internal clients still never see a DNS
credential; the token lives here, scoped to the one zone it may edit.

```toml
[server]
base_url = "https://acme.internal.company.com"
bind_address = "[::]:3000"

[signer]
backend = "relay"

[signer.relay]
directory_url = "https://acme-v02.api.letsencrypt.org/directory"
account_key_path = "le_upstream.key"
contact = ["mailto:admin@company.com"]
challenge_strategy = "dns01"
poll_interval_ms = 2000
poll_timeout_secs = 300

[signer.relay.dns01]
provider = "cloudflare"
# Names spread over several Cloudflare zones? CNAME each domain's
# _acme-challenge name into one alias zone and scope the token to that zone.
# challenge_alias = "acme-alias.net."

[signer.relay.dns01.cloudflare]
zone = "internal.company.com"
zone_id = "0f4c1c0e97b34a37a9e1a6f0d4b9c2f1"
# The one key here that belongs in the environment instead:
#   ACME_PROXY_SIGNER__RELAY__DNS01__CLOUDFLARE__API_TOKEN=<token>

[signer.relay.dns01.propagation]
# The API accepts a record before every Cloudflare edge serves it, and the
# upstream looks exactly once: triggering early makes the authorization
# `invalid` for good.
mode = "delay"
delay_secs = 30

[challenge]
# Local clients still prove control to the proxy independently.
enabled = ["http-01", "dns-01"]
bypass = false

[profiles.default]
enabled = true
```

The token needs `Zone / DNS / Edit` on that zone and nothing else. A name under
a different Cloudflare zone is either another profile with its own token, or one
more domain CNAMEed into the alias zone.

## Public CA relay with HTTP validation

The same relay as above, for an operator who has no RFC 2136 write access to the
zone but *does* control the reverse proxy already fronting the names being
issued. Instead of publishing a TXT record, `acme-proxy` serves the upstream's
challenge file itself.

```toml
[server]
base_url = "https://acme.internal.company.com"
bind_address = "[::]:3000"

[signer]
backend = "relay"

[signer.relay]
directory_url = "https://acme-v02.api.letsencrypt.org/directory"
account_key_path = "le_upstream.key"
contact = ["mailto:admin@company.com"]
# No [signer.relay.http01] table exists — this line is the whole
# configuration. The responder is a route on this server's own root router;
# acme-proxy does NOT open a second listener or bind port 80.
challenge_strategy = "http01"
poll_interval_ms = 2000
poll_timeout_secs = 300

[challenge]
# Local clients still prove control to the proxy independently.
enabled = ["http-01"]
bypass = false

[profiles.default]
enabled = true
```

This only works if the upstream CA's fetch reaches `acme-proxy`. Add one
location to whatever already answers on port 80 for each name being issued:

```nginx
location /.well-known/acme-challenge/ {
    proxy_pass http://acme-proxy:3000;
    # A `return 301 http://acme-proxy:3000$request_uri;` works equally well —
    # RFC 8555 §8.3 permits following redirects.
}
```

Note this strategy **cannot issue wildcards** (nothing answers HTTP on the name
`*.example.com`); those need scenario 1's `dns01`. See
[Relay](../signers/relay.md#deploying-the-http-01-responder) for Caddy and
Traefik equivalents.

## Commercial ACME CA with EAB and NetBox filtering

This scenario uses a commercial CA backend. It enforces External Account Binding
(EAB) on the internal proxy so only authorized users can register. It
additionally uses NetBox, through the `ipam` filter, to verify if a client's
IP is actually permitted to request a certificate for a specific DNS name.

```toml
[server]
base_url = "https://ca.internal.company.com"

[signer]
backend = "relay"

[signer.relay]
directory_url = "https://commercial-ca.example.com/acme/directory"
account_key_path = "commercial_upstream.key"

# The commercial CA already trusts this server's upstream account implicitly,
# so the upstream challenge is bypassed.
challenge_strategy = "bypass"

[eab]
# Require all internal clients to register with an EAB credential generated by the admin
enabled = true

[filter]
# Ask the inventory about every internal request
enabled = ["ipam"]

[ipam]
backend = "netbox"
timeout_ms = 5000

[ipam.netbox]
url = "https://netbox.internal.company.com"
# Store this in ACME_PROXY_IPAM__NETBOX__TOKEN ideally
token = "your_netbox_read_only_token"
custom_field = "acme_domains"
sources = ["dns_name", "custom_field", "device"]

[profiles.default]
enabled = true
```
