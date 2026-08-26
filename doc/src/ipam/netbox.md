# NetBox

Reads what [NetBox](https://netbox.dev) associates with the client's address.
Supports every [source](index.md#sources), including the two that resolve a
shared service address.

## What NetBox is asked

One lookup always happens:

```text
GET <url>/api/ipam/ip-addresses/?address=<client ip>
```

Up to four more are made, each gated by a source:

| Query | Source |
| --- | --- |
| `dcim/devices/{id}/` or `virtualization/virtual-machines/{id}/` | `device` |
| `ipam/ip-addresses/?device_id=N&role=…` | `vip` |
| `ipam/fhrp-group-assignments/?interface_type=…&interface_id=…` | `fhrp` |
| `ipam/ip-addresses/?fhrpgroup_id=…` | `fhrp` |

A read-only API token is enough.

## Authenticating

NetBox has two generations of API token, and this backend sends whichever it is
given: the scheme is derived from the token itself, so there is nothing to
configure.

| Token | Sent as | Where it comes from |
| --- | --- | --- |
| `nbt_<key>.<secret>` | `Authorization: Bearer nbt_<key>.<secret>` | v2, the default since NetBox 4.5 |
| anything else | `Authorization: Token <token>` | the legacy v1 token, not accepted from NetBox 4.7 |

The `nbt_` prefix is NetBox's own marker for a v2 token, and the whole string —
key, dot and secret — is displayed once when the token is created, so paste it
verbatim. A value starting `nbt_` that carries no `.` is the key half on its
own: that is refused at startup, because NetBox would otherwise answer every
lookup with a `403`, which looks exactly like a token that has been revoked.

## Declaring names

Two places, and either or both can be trusted:

- **`dns_name`** on the IP address object — the ordinary case, one name per
  address.
- **A custom field** (`custom_field`, by default `acme_allowed_names`) for the
  extra names that address may request. Configure it in NetBox as a
  multi-select or a text field on `ipam.ipaddress` and — for the `device`
  source — on `dcim.device` and `virtualization.virtualmachine`. A single
  string is accepted as well as a list.

With the `device` source, an address that carries no value of its own falls
back to the field on its device or virtual machine, so names can be declared
once per machine rather than once per address. It is a fallback and not a
union: see [Sources](index.md#sources).

## Shared and service addresses

A VRRP, CARP or keepalived pair answers on an address that belongs to the
*pair*, not to either member — but the client connects from its own member
address, so without one of the sources below it is refused a certificate for
the service name. Both are unions: the member's own names and the service
address's names are true at the same time.

Which one an estate needs depends on how it models redundancy in NetBox.

### `vip` — a role on an address of the same device

The classic modelling: the service address is created on one of the members'
interfaces and tagged with a role.

```text
GET <url>/api/ipam/ip-addresses/?device_id=3&role=vip&role=vrrp
```

`vip_roles` says which roles count. The role is **re-checked on the answer** as
well as sent as a filter — a filter parameter this server got wrong must never
degrade into "every address on the device", which would widen an allowlist
without saying so.

### `fhrp` — membership of an FHRP group

NetBox's own model for first-hop redundancy: the service address is assigned to
an `ipam.FHRPGroup`, and each member's *interface* is recorded as belonging to
that group.

```text
client address ─▶ its interface ─▶ fhrp-group-assignments?interface_id=7
                                        └─▶ group ids ─▶ their addresses
```

**The direction of that chain is the membership proof.** A group is only ever
reached through an assignment naming the client's own interface. Nothing is
ever looked up by group name, by the service address, or by the identifier the
client asked for — so there is no query that could reach a group the client is
not recorded in, and no way to turn the check into a lookup of "who owns this
name?" by choosing a request carefully. An interface in no group contributes
nothing and costs one request.

No role filter applies here: an address assigned to an FHRP group *is* the
group's service address by construction, and applying `vip_roles` would drop
legitimately untagged VIPs.

A client connecting **from** the service address needs neither source — that
address object comes back from the first query with its own names attached.

## TLS

Unlike the challenge validators, where the certificate is deliberately not
checked because the *proof* is what matters, NetBox's certificate is the only
thing identifying the service whose answers decide who may have a name
certified. The public roots apply, plus any operator-supplied CA. Switching
that off is explicit, logged on every start, and meant to be temporary.

## Configuration

```toml
[ipam]
backend = "netbox"

[ipam.netbox]
url = "https://netbox.internal.example.com"
token = "your_netbox_read_only_token"
custom_field = "acme_allowed_names"
sources = ["dns_name", "custom_field", "device"]
```

Turning on service addresses:

```toml
[ipam.netbox]
sources = ["dns_name", "custom_field", "device", "vip", "fhrp"]
vip_roles = ["vrrp", "carp"]
```

### Reference

**`url`** (`String`) — *Default: `""` | Env: `ACME_PROXY_IPAM__NETBOX__URL`*

Base URL of the NetBox instance. Any path is kept, so an instance served under
a subpath works. Required when `ipam.backend` is `netbox`.

**`token`** (`String`) — *Default: `""` | Env: `ACME_PROXY_IPAM__NETBOX__TOKEN`*

NetBox API token, of either generation — see
[Authenticating](#authenticating). A secret: prefer the environment variable.

**`custom_field`** (`String`) — *Default: `"acme_allowed_names"` | Env: `ACME_PROXY_IPAM__NETBOX__CUSTOM_FIELD`*

Custom field holding the permitted names, on the address object and on its
device or virtual machine. Only read when `sources` names `custom_field` or
`device`.

**`sources`** (`Array`) — *Default: `["dns_name", "custom_field", "device"]` | Env: `ACME_PROXY_IPAM__NETBOX__SOURCES`*

Where a permitted name may come from. All five sources are available here. See
[Sources](index.md#sources).

**`vip_roles`** (`Array`) — *Default: `["vip", "vrrp", "hsrp", "glbp", "carp", "anycast"]` | Env: `ACME_PROXY_IPAM__NETBOX__VIP_ROLES`*

Which NetBox address roles mark a service address. Read only when `sources`
names `vip`, so this is *which* roles rather than whether to look at all.

**`ca_cert_path`** (`String`) — *Default: `""` | Env: `ACME_PROXY_IPAM__NETBOX__CA_CERT_PATH`*

Extra CA certificates (PEM) to trust on top of the public roots, for a NetBox
behind an internal PKI. Ignored when `insecure_skip_verify` is on.

**`insecure_skip_verify`** (`Boolean`) — *Default: `false` | Env: `ACME_PROXY_IPAM__NETBOX__INSECURE_SKIP_VERIFY`*

Skip verification of NetBox's TLS certificate entirely. Meant as a temporary
way out of an expired NetBox certificate. Startup logs an
`ipam_netbox_tls_verification_disabled` warning for as long as it is set.
