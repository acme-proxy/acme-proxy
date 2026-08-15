# IPAM

An **IPAM backend** answers one question: *which names does this address own?*

`acme-proxy` asks it through the [`ipam` filter](../filters/index.md), which
turns the answer into a decision — may this client have a certificate for the
names it is asking for? The two halves are deliberately separate. The
inventory reports what it holds; the filter alone decides what to do about
that, and it decides the same way whichever product answered.

> **Renamed at this release.** This used to be a filter called `netbox`, with
> its settings under `[filter.netbox]`. Both moved. See
> [Migrating from `filter.netbox`](#migrating-from-filternetbox) below — the
> old spelling is refused by name at startup, with an error naming all three
> moves, rather than silently ignored.

## Backends

| Backend | Product | Page |
| --- | --- | --- |
| `netbox` | [NetBox](https://netbox.dev) | [NetBox](netbox.md) |
| `phpipam` | [phpIPAM](https://phpipam.net) | [phpIPAM](phpipam.md) |

One backend per profile. `[ipam]` is a per-profile section, so two endpoints
served by the same process may consult different inventories.

## Sources

Each backend takes a `sources` list naming the places a permitted name may come
from. It is validated at startup against that backend's own vocabulary.

| Source | What it reads | `netbox` | `phpipam` |
| --- | --- | --- | --- |
| `dns_name` | the address object's own name | ✓ | ✓ |
| `custom_field` | the custom field on the address | ✓ | ✓ |
| `device` | the same field on the assigned device or VM | ✓ | ✓ |
| `vip` | role-tagged service addresses on the same device | ✓ | — |
| `fhrp` | addresses of an FHRP group the client's interface is in | ✓ | — |

Two things the list does **not** say, and both matter:

- **Order is meaningless.** The result is a union of sets, unlike
  `filter.enabled` (evaluation order) or `challenge.enabled` (offer order).
- **`device` is a fallback, not a union.** It is read only when the address
  object itself carried no value for the custom field. A value set on the
  address is the more specific statement, and an operator narrowing one address
  of a machine must not have the machine-wide list quietly widen it again.
  `vip` and `fhrp` *are* unions.

**Empty, or an unknown entry, is a startup error.** An inventory trusted for
nothing can never permit a name, so it is a filter that refuses everything —
and a typo that silently narrows an allowlist is worse than a refusal to boot.
A source that exists but belongs to another backend is refused by name too:
naming `fhrp` under `[ipam.phpipam]` says a check will run that phpIPAM cannot
run, and answering that with silence would leave an operator believing it does.

The default for both backends is `["dns_name", "custom_field", "device"]` —
exactly what the old `netbox` filter always did. The two service-address
sources are off because both widen what a client may certify.

## Matching is exact

Case-insensitive and ignoring a trailing dot, but otherwise literal. There is
no suffix rule and no wildcard expansion: an entry `example.com` does **not**
permit `a.example.com`, and a request for `*.example.com` requires that exact
string in the inventory. Same reasoning as the anchored patterns in
[Identifiers](../filters/identifiers.md) — a rule that quietly covers more than
it says is the bypass an allowlist exists to prevent.

An `ip` identifier is permitted when it *is* the connecting address (a machine
may always certify the address it is talking from) or when it is listed like
any other name. A common name (`cn`) is skipped, as in `identifiers`. Any other
type is refused: an inventory has nothing to say about an email address or a
URI, and a filter whose job is to confirm entitlement must refuse what it
cannot confirm.

## Denied versus Internal

The most consequential property of the whole subsystem.

"The inventory does not associate this name with this address" is a decision
about the client and **denies** the request (403 `rejectedIdentifier`). So is
"the inventory holds no record of this address at all", worded differently so
an operator can tell the two apart.

"It answered 500", "the token was refused", "the lookup timed out" are not
decisions about anybody — the server failed to *reach* one. Those become a
**500** the client can retry.

This is enforced by the types, not by care at each call site: the error an
`Ipam` backend can return has no "denied" variant to reach for. An inventory
outage therefore stops issuance rather than permitting everything, and never
looks like a permanent refusal.

## What it costs per request

The lookup runs inline in `newOrder` and again at `finalize`, so it is part of
those requests' worst case. `timeout_ms` is one budget covering the *whole*
lookup however many requests the backend makes to answer it — not one per
request — and it must stay below `server.request_timeout_ms`.

## Migrating from `filter.netbox`

Three changes, and the server states all three if it finds the old spelling:

1. A check declared with `type = "netbox"` becomes `type = "ipam"`, plus
   `ipam.backend = "netbox"`.
2. `[filter.netbox]` becomes `[ipam.netbox]`. Most keys are unchanged.
3. Three keys moved or changed shape:

| Was | Now |
| --- | --- |
| `filter.netbox.timeout_ms` | `ipam.timeout_ms` |
| `filter.netbox.use_dns_name = true` | `"dns_name"` in `ipam.netbox.sources` |
| `filter.netbox.device_fallback = true` | `"device"` in `ipam.netbox.sources` |

Since the default `sources` is `["dns_name", "custom_field", "device"]`, a
deployment that left both booleans at their defaults needs no `sources` line at
all. Environment variables move from `ACME_PROXY_FILTER__NETBOX__*` to
`ACME_PROXY_IPAM__NETBOX__*`.

Startup **fails** on the old filter name rather than aliasing it. The section
moved too, so a silent alias would leave `[filter.netbox]` read by nothing
while the server came up looking configured — the same reasoning that made
`signer.backend = "acme_proxy"` a named refusal when it became `relay`. Both are
error messages rather than compatibility paths: nothing reads the old spelling,
and the refusals go away at 1.0.0. Renames like this are expected before then
and are listed in the
[changelog](https://github.com/acme-proxy/acme-proxy/blob/main/CHANGELOG.md#compatibility).

## Configuration

```toml
[ipam]
backend = "netbox"
timeout_ms = 5000

[ipam.netbox]
url = "https://netbox.internal.example.com"
token = "..."
sources = ["dns_name", "custom_field", "device"]

[filter]
enabled = ["ipam"]
```

### Reference

**`backend`** (`String`) — *Default: `""` | Env: `ACME_PROXY_IPAM__BACKEND`*

Which inventory to consult: `netbox`, `phpipam`, or empty for none. Anything
else is a startup error rather than a silent fallback. Enabling the `ipam`
filter while this is empty is also a startup error.

**`timeout_ms`** (`Integer`) — *Default: `5000` | Env: `ACME_PROXY_IPAM__TIMEOUT_MS`*

Budget for one whole lookup, however many requests the backend makes to answer
it. Applied once around all of them, so a wedged inventory cannot pin a request
open. Exceeding it is reported as a server error, not a denial.
