# External Account Binding (EAB)

`acme-proxy` supports enforcing **External Account Binding** (RFC 8555 §7.3.4).
When enabled, any client attempting to register a new account must provide an
EAB credential that was minted out-of-band by the server operator.

This is a highly effective security mechanism for internal CA endpoints: it
restricts account creation to authorized entities without relying purely on IP
filtering.

### Solving commercial CA EAB limits

Beyond security, EAB support in `acme-proxy` solves a significant operational
hurdle when using Commercial CAs (like ZeroSSL, Sectigo, or GlobalSign).

When working with external or commercial CAs, organizations are sometimes
restricted to a single account or a limited number of EAB credentials validated
for specific domains. It is impractical to distribute these scarce upstream
credentials to hundreds of individual internal servers.

By placing `acme-proxy` in front of the commercial CA:
1. The proxy consumes a **single** upstream EAB credential to register its own
   master account with the Commercial CA.
2. The proxy then issues its own **unlimited** local EAB credentials to your
   internal servers.
3. This effectively multiplexes the upstream account, allowing thousands of
   internal clients to securely acquire certificates without exhausting your
   upstream quotas or spreading sensitive upstream secrets across your
   infrastructure.

## Configuration

```toml
[eab]
enabled = true
```

### Reference

**`enabled`** (`Boolean`) — *Default: `false` | Env: `ACME_PROXY_EAB__ENABLED`*

When enabled, the `newAccount` endpoint will refuse any request that doesn't
carry a valid, unused EAB payload. Standard `onlyReturnExisting` lookups are
exempt because they only query existing accounts and never create new ones.

## Minting credentials via CLI

You manage EAB credentials with the Admin CLI, because the secret is sensitive
and is shown exactly once.

To create a new credential for a client:
```bash
acme-proxy eab create --label "DevOps Team"

# Bind it to a single endpoint in a multi-profile deployment:
acme-proxy eab create --label "DevOps Team" --profile prod
```

The CLI prints a `kid` (Key Identifier) and an HMAC secret. **The secret is
printed only once.** It is stored but never displayed again, so a lost secret is
replaced, not recovered.

`--profile` matters in a multi-tenant deployment: **omitted, the credential is
accepted at every profile**, which is what an unscoped credential means. Bind it
unless you intend that.

A client then uses the credential at registration:
```bash
certbot register \
  --server https://acme.internal/profile/default/directory \
  --eab-kid "the-kid" \
  --eab-hmac-key "the-secret"
```

## Credentials are reusable, not single-use

> A credential is **not** consumed by the account it creates. The same `kid` can
> bind any number of accounts and keeps working until you explicitly revoke it.
> There is no `used` state — only `active` and `revoked`.

This is worth being deliberate about. Handing one credential to a team means any
number of hosts can register with it, and a leaked credential stays valid until
someone notices. If you want one-client-one-credential, mint one per client and
revoke it once that client has registered.

(This differs from the upstream credential consumed by [`acme-proxy upstream
register`](../signers/relay.md#eab-considerations) — or, alternatively,
`signer.relay.eab` in configuration. Commercial CAs typically issue
single-use EAB credentials, which is precisely why that one is consumed once by
registration and then no longer needed at all, unlike the credentials described
on this page.)

## Revocation

Revoke a credential to prevent any further use:
```bash
acme-proxy eab revoke <kid>
```

This takes effect immediately, with no restart — credentials are read from the
live database on every `newAccount`. Revocation is idempotent.

Revoking does **not** disturb accounts that already registered with the
credential; it only stops new ones from being bound. To shut out an existing
account, deactivate it: `acme-proxy account deactivate <id>`.

## Inspecting credentials

```bash
acme-proxy eab list --json
acme-proxy eab show <kid>
```

Neither ever renders the secret. `eab list` is newest first and paged
([Admin CLI → Paging](../operations/cli.md#paging)); it reads the same query
`GET /api/eab` and the panel's `/ui/eab` do, so the three cannot come to
describe the credential set differently.
