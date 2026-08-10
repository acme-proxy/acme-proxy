# Custom Script Signer

The `custom` signer backend delegates certificate issuance, revocation and
metadata retrieval to an external script (Bash, Python, Go, …). Use it to
integrate `acme-proxy` with legacy PKI systems, HSMs, or internal APIs that do
not speak ACME natively.

`acme-proxy` still serves ACME to its own clients and still enforces domain
control, filters and EAB; only the signing step is handed off.

## Configuration

```toml
[signer]
backend = "custom"

[signer.custom]
script_path = "/usr/local/bin/legacy-pki-bridge.sh"
timeout_ms = 15000
args = []
supports_crl = false
supports_renewal_info = false
```

### Reference

**`script_path`** (`String`) — *Default: `""` | Env: `ACME_PROXY_SIGNER__CUSTOM__SCRIPT_PATH`*

Path to the executable. An empty value is a **startup error** once this backend
is selected.

**`timeout_ms`** (`Integer`) — *Default: `5000` | Env: `ACME_PROXY_SIGNER__CUSTOM__TIMEOUT_MS`*

Budget for one invocation. Because issuance runs inline in the `finalize`
request, this must stay below `server.request_timeout_ms` — the server refuses
to start otherwise.

**`args`** (`Array`) — *Default: `[]` | Env: `ACME_PROXY_SIGNER__CUSTOM__ARGS`*

Static arguments passed on every invocation. These are the **only** command-line
arguments the script receives; the hook is *not* passed as an argument.

**`supports_crl`** (`Boolean`) — *Default: `false` | Env: `ACME_PROXY_SIGNER__CUSTOM__SUPPORTS_CRL`*

Whether the script implements the `crl` hook. While `false`, the hook is **never
invoked** — no process is spawned at all — and `GET /crl` has nothing to serve.

**`supports_renewal_info`** (`Boolean`) — *Default: `false` | Env: `ACME_PROXY_SIGNER__CUSTOM__SUPPORTS_RENEWAL_INFO`*

Whether the script implements the `renewal_info` hook. While `false`, the hook
is **never invoked** and `GET /renewalInfo/{certID}` falls back to the server's
own local estimate.

> These two flags default to `false` and gate the hooks entirely. A
> `renewal_info` hook written without setting `supports_renewal_info = true`
> will simply never run, with no error to explain why.

## Hooks

The hook is selected by the **`ACME_SIGNER_HOOK` environment variable**, not by
a command-line argument. Every hook receives a JSON object on **stdin**.

| Hook | stdin | stdout | Gated by |
| --- | --- | --- | --- |
| `issue` | `{"hook":"issue","order_id":…,"identifiers":[{"type":"dns","value":"…"}],"csr_der_base64":"…"}` | PEM certificate chain, leaf first | always |
| `revoke` | `{"hook":"revoke","cert_der_base64":"…","reason":<int\|null>}` | ignored | always |
| `crl` | `{"hook":"crl"}` | raw DER of the CRL | `supports_crl` |
| `renewal_info` | `{"hook":"renewal_info","cert_der_base64":"…"}` | see below | `supports_renewal_info` |

`csr_der_base64` and `cert_der_base64` are **standard** base64 of the **DER**
bytes — not PEM, and not ACME's base64url.

### `issue`

Exit codes are the contract:

- **`0`** — stdout is the PEM chain (leaf first, issuers after). Trailing
  whitespace is trimmed and exactly one newline re-appended, since a strict
  parser needs a newline after the final `-----END CERTIFICATE-----`.
- **`3`** — reserved: the CSR is bad. The client gets `400 badCSR` and the order
  stays `ready`, so it can retry with a corrected CSR. Do not use this exit code
  for backend failures.
- **anything else** — an internal failure. The client gets `500` and the order
  is marked `invalid` (terminal, but pollable).

This backend always answers **synchronously**: a shelled-out script cannot call
back later, so the order never enters the `processing` state.

> The order's requested `notBefore`/`notAfter` (RFC 8555 §7.4) are **not**
> passed to the script — there is no contract for it, and inventing one would
> break existing scripts. Your script decides validity on its own. (The
> `local_ca` backend does honour them, clamped.)

### `revoke`

Exit `0` means revoked. Any non-zero exit is an internal failure, and
`acme-proxy` then leaves the order un-revoked so the operation can be retried —
the CA-side action is authoritative.

Revocation must be **idempotent**: `acme-proxy` may call this hook for a
certificate your PKI already considers revoked, and that must succeed rather
than error.

### `renewal_info`

stdout drives RFC 9773:

- **empty** — no opinion; the server falls back to its own estimate.
- **`<start> <end>`** — the renewal window, as epoch seconds.
- **`<start> <end> <explanationURL>`** — additionally supplies RFC 9773 §4.2's
  optional `explanationURL`. The URL is last and optional so an existing
  two-token script keeps working unchanged.

Any other token count, or a non-integer timestamp, is an internal failure.

### `crl`

stdout is the raw DER of the CRL, served by `GET /crl`. Empty stdout means "no
CRL". Failures here are logged and swallowed — a broken `crl` hook degrades to
no CRL rather than taking the endpoint down.

## Environment variables

| Variable | Set for | Value |
| --- | --- | --- |
| `ACME_SIGNER_HOOK` | every hook | `issue`, `revoke`, `crl` or `renewal_info` |
| `ACME_SIGNER_ORDER_ID` | `issue` | The order being finalized |
| `ACME_SIGNER_IDENTIFIERS` | `issue` | Comma-joined identifier values |
| `ACME_SIGNER_REASON` | `revoke` | RFC 5280 reason code, empty when none given |

There is no `ACME_SIGNER_PROFILE`; the signer backend is never told which
profile it is serving. (Backends are shared between profiles with identical
`[signer]` configuration, so there would not always be one answer.)

## Security & process isolation

1. **Environment clearing**: `env_clear()` is called. The script inherits a
   minimal `PATH` plus the `ACME_SIGNER_*` variables above — nothing else. The
   server's own environment may hold the NetBox token, SMTP password or RFC 2136
   TSIG key, and a signing script has no business reading them.
2. **Zombie protection**: the child runs with `kill_on_drop(true)` under a
   `tokio::time::timeout`. A timeout alone only drops the future, so without
   this a hung script would outlive its deadline and leak a process per request.
3. **Failure reporting**: on a non-zero exit, the first non-empty line of stdout
   (falling back to stderr) is used as the error detail.

See [Custom Plugins Examples](../dev/custom_plugins.md) for a complete script.
