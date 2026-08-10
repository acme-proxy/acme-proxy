# phpIPAM

Reads what [phpIPAM](https://phpipam.net) associates with the client's address.
Supports `dns_name`, `custom_field` and `device`; phpIPAM records no address
roles and no redundancy groups, so `vip` and `fhrp` are
[refused by name](index.md#sources) at startup.

## What phpIPAM is asked

One lookup always happens:

```text
GET <url>/api/<app_id>/addresses/search/<client ip>/
```

One more is made when `sources` names `device`:

```text
GET <url>/api/<app_id>/devices/<deviceId>/
```

## Setting up the API application

In phpIPAM, under **Administration → API**, create an application:

- **App id** — becomes `app_id`, and appears in every API path.
- **App permissions** — *Read* is enough.
- **App security** — *SSL with App code*. The app code becomes `token` and is
  sent as a bare `token` header (phpIPAM's own scheme, not `Authorization`).

The alternative *SSL with User token* scheme — user credentials exchanged for a
six-hour session token — is **not implemented**: it needs a refresh loop and
somewhere to keep the token, for no gain over a credential that can be rotated
in the environment.

## Declaring names

- **`hostname`** on the address — the direct analogue of NetBox's `dns_name`,
  read when `sources` names `dns_name`.
- **A custom column** (`custom_field`, by default
  `custom_acme_allowed_names`). phpIPAM prefixes custom columns with `custom_`,
  so the default carries that prefix; write whatever your column is actually
  called. Add it under **Administration → Custom fields** for *IP addresses*
  and — for the `device` source — for *Devices*.

A phpIPAM custom field is a **plain text column**, so several names are written
comma-separated:

```text
www.example.com, api.example.com, mail.example.com
```

The split is on commas and is not configurable — a comma is not legal in a DNS
name, so there is no estate it could need to differ for.

With the `device` source, an address whose column is empty falls back to the
same column on the device named by its `deviceId`. A fallback, not a union:
see [Sources](index.md#sources).

## An unknown address is a 404

The one place phpIPAM's wire behaviour differs in a way worth knowing about.
NetBox answers an unknown address with `200` and an empty result list; phpIPAM
answers `404` with its own envelope:

```json
{"code": 404, "success": false, "message": "No addresses found"}
```

That is read as **"no such address"** — a denial naming the address — rather
than as a transport failure, which would turn every request from an unrecorded
machine into a retryable 500. Every *other* non-2xx status is still a failure,
so a broken or misconfigured phpIPAM stops issuance rather than reading as
"this address owns no names". See
[Denied versus Internal](index.md#denied-versus-internal).

## Configuration

```toml
[ipam]
backend = "phpipam"

[ipam.phpipam]
url = "https://ipam.internal.example.com"
app_id = "acme"
token = "your_app_code"
custom_field = "custom_acme_allowed_names"
sources = ["dns_name", "custom_field", "device"]
```

### Reference

**`url`** (`String`) — *Default: `""` | Env: `ACME_PROXY_IPAM__PHPIPAM__URL`*

Base URL of the phpIPAM instance. Any path is kept, so an instance served under
a subpath works. Required when `ipam.backend` is `phpipam`.

**`app_id`** (`String`) — *Default: `"acme"` | Env: `ACME_PROXY_IPAM__PHPIPAM__APP_ID`*

The API application's identifier, which appears in every API path. One path
segment: letters, digits, `-` and `_`. Anything else is a startup error, since
a stray slash would silently retarget the API rather than fail.

**`token`** (`String`) — *Default: `""` | Env: `ACME_PROXY_IPAM__PHPIPAM__TOKEN`*

The application's app code, sent as a `token` header. A secret: prefer the
environment variable.

**`custom_field`** (`String`) — *Default: `"custom_acme_allowed_names"` | Env: `ACME_PROXY_IPAM__PHPIPAM__CUSTOM_FIELD`*

Column holding the permitted names, on the address and on its device. Only read
when `sources` names `custom_field` or `device`.

**`sources`** (`Array`) — *Default: `["dns_name", "custom_field", "device"]` | Env: `ACME_PROXY_IPAM__PHPIPAM__SOURCES`*

Where a permitted name may come from. Only these three are available here;
naming `vip` or `fhrp` is a startup error.

**`ca_cert_path`** (`String`) — *Default: `""` | Env: `ACME_PROXY_IPAM__PHPIPAM__CA_CERT_PATH`*

Extra CA certificates (PEM) to trust on top of the public roots. Ignored when
`insecure_skip_verify` is on.

**`insecure_skip_verify`** (`Boolean`) — *Default: `false` | Env: `ACME_PROXY_IPAM__PHPIPAM__INSECURE_SKIP_VERIFY`*

Skip verification of phpIPAM's TLS certificate entirely. Startup logs an
`ipam_phpipam_tls_verification_disabled` warning for as long as it is set.
