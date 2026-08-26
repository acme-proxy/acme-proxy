# EAB Check

`type = "eab"` matches on the External Account Binding credential the
requesting account registered under. It is the multi-tenant lever: mint one
credential per tenant, bind each to its own name space, and no tenant can
request another's names.

```toml
[filter]
rules = ["tenant-a", "tenant-b"]

[filter.check.is-tenant-a]
type  = "eab"
allow = ["tenant-a"]

[filter.check.tenant-a-names]
type  = "identifiers"
allow = ["*.tenant-a.example.com"]

[filter.rule.tenant-a]
when = "is-tenant-a and tenant-a-names"
then = "allow"
```

Identifier stage only — at the connection stage no account has been
authenticated, so there is no credential to ask about.

## Why the label and not the account

The obvious handle for "which client is this" would be the account id, and it
is the wrong one. An account id is a UUID v7 generated when the account is
created, so a policy naming one can only be written *after* the fact, and you
would be editing configuration in response to a client registering.

An EAB credential is the other way round: `acme-proxy eab create --label
tenant-a` mints it **before any account exists**, and you choose the label. It
also survives what the account does next — a key rollover keeps the same
account, and a client re-registering under the same credential lands in the
same tenant. Credentials are deliberately reusable, so one label
naturally covers a whole team.

Blocking a single misbehaving account is a different job and already has a
lever: `acme-proxy account deactivate <id>`.

## No credential means refused

An account registered without EAB has no credential, and this check refuses it.
That is the only defensible reading of a question about *which* credential
authorised the account — "none" cannot satisfy a tenant rule.

It follows that an `eab` check under a profile whose `eab.enabled` is `false`
could never do anything but refuse, so that combination is a **startup error**
rather than a policy.

## Matching

`allow`/`deny` are globs over the **label**, with the usual semantics described
in [Checks](checks.md#allow-and-deny) — `deny` first and winning, an empty
`allow` imposing no constraint. `allow_regex`/`deny_regex` take anchored
regexes and union with them.

`kids` pins credentials by their `kid` instead, for an operator who would
rather not rely on labels being unique. It is a **second allow source** rather
than a separate gate: either the kid being listed or the label matching is
enough.

```toml
[filter.check.is-tenant-a]
type  = "eab"
allow = ["tenant-a"]
kids  = ["4f1c…"]     # this exact credential, whatever its label says
```

A credential minted with no label cannot match a label allowlist. That is the
same rule seen from the other side, and it is why `eab create` is worth always
giving a `--label`.

## Making revocation retroactive

Revoking an EAB credential stops new *registrations*. Accounts already created
under it keep issuing, for ever — which is what the credential's role as a
registration-time authorisation implies, and what
`accounts.eab_kid`'s own migration meant by calling it an audit trail.

`require_active = true` changes that for this check: the credential must still
be `active`, so `acme-proxy eab revoke <kid>` reaches existing accounts too.

```toml
[filter.check.live-credential]
type           = "eab"
require_active = true
```

Off by default, because turning it on retroactively changes what `eab revoke`
means for a deployment. It is the lever to reach for when a tenant's credential
leaks — and it is a usable policy on its own, with no labels at all: "any
tenant, but not one whose credential we have withdrawn".

## Cost

Resolving the credential is two indexed reads, and they happen **only when the
policy contains an `eab` check**. A deployment without one pays nothing.

### Reference

**`filter.check.<name>.kids`** (`Array`) — *Default: `[]` | Env: `ACME_PROXY_FILTER__CHECK__<NAME>__KIDS`*

Credential `kid`s matched exactly, beside the label globs in `allow`. A second
allow source, not a separate gate.

**`filter.check.<name>.require_active`** (`Boolean`) — *Default: `false` | Env: `ACME_PROXY_FILTER__CHECK__<NAME>__REQUIRE_ACTIVE`*

Also require the credential to still be active, so revoking it refuses accounts
already registered under it.

A check that sets none of `allow`, `deny`, `kids` or `require_active` only asks
whether the account used EAB at all, which the `[eab]` section already
guarantees. That is a startup error rather than a check that always passes.
