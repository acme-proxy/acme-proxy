# Checks

A `[filter.check.<name>]` is one named question about a request. It takes a
`type` saying which question, plus that type's own keys:

```toml
[filter.check.mgmt-net]
type  = "allowed_ip"
allow = ["10.0.0.0/8"]

[filter.check.corp-names]
type  = "identifiers"
allow = ["*.corp.example.com", "corp.example.com"]
```

Two checks of the same type are ordinary — two identifier lists with different
rules, an address list per network, several script hooks — which is the main
thing the older `filter.enabled` shape could not express.

## Naming

Each name must match `^[a-z0-9-]+$`: lowercase letters, digits and `-`, the same
restriction profile names have. The reason is that a name is also an environment
variable segment (`ACME_PROXY_FILTER__CHECK__<NAME>__…`), and the `config` crate
lowercases those, so `MgmtNet` in a file and `MGMTNET` in the environment would
silently become two entries instead of one overriding the other.

`and`, `or` and `not` are the [condition language](policy.md)'s own words and
cannot name a check.

## Only what a rule names is built

A check defined here but mentioned by no selected rule is **never constructed**.
It opens no connection, spawns no client and validates nothing; it is reported
once at startup as `filter_check_unused`.

That is deliberate, and it is what makes profile inheritance usable: a global
`[filter]` section can carry a library of checks, every profile inherits all of
them, and each profile's `filter.rules` picks the subset it actually wants
without paying for — or failing startup on — the rest.

## Keys by type

`type` and `stages` are universal. Everything else belongs to one type, and
**setting a key that belongs to a different type is a startup error naming
both** — the keys are one flat namespace, so without that check `script_path` on
an `allowed_ip` check would simply be read by nothing.

| Type | Keys | Page |
| --- | --- | --- |
| `allowed_ip` | `allow`, `deny` | [allowed_ip](allowed_ip.md) |
| `path` | `allow`, `deny` | [path](path.md) |
| `reverse_dns` | `allow`, `deny`, `allow_regex`, `deny_regex`, `require_forward_confirm`, `timeout_ms` | [reverse_dns](reverse_dns.md) |
| `identifiers` | `allow`, `deny`, `allow_regex`, `deny_regex`, `allowed_types`, `allow_wildcards` | [identifiers](identifiers.md) |
| `ipam` | *(none — configured by the `[ipam]` section)* | [ipam](../ipam/index.md) |
| `custom` | `script_path`, `timeout_ms`, `pass_stdin`, `args` | [custom](custom.md) |

Defaults, where a type has one: `require_forward_confirm = true`,
`timeout_ms = 2000` for `reverse_dns` and `5000` for `custom`,
`pass_stdin = true`, `allow_wildcards = false`,
`allowed_types = ["dns", "cn"]`.

Every list defaults to empty, and **empty always means "this type's natural
default", never "none"**. That is not a style choice: an unset list environment
variable arrives as an empty list rather than as absent, so `stages = []` has to
mean "infer" and `allowed_types = []` has to mean `["dns", "cn"]`.

## Matching: globs first, regexes on request

The name-matching checks take **globs** in `allow`/`deny`, where `*` matches one
label:

- `*.example.com` matches `a.example.com`; it does **not** match
  `a.b.example.com`, and it does **not** match `example.com`. List the bare
  name too, exactly as you would in a certificate.
- Everything else is literal. No `?`, no character classes, no `**`.
- Matching is case-insensitive.

`allow_regex`/`deny_regex` take regexes instead, automatically anchored as
`^(?:…)$`, and are **unioned** with the globs — so a policy can be mostly globs
with one regex where a glob will not do. Anchoring is not optional: the `regex`
crate searches rather than matches, so an unanchored `example\.com` would also
accept `example.com.evil.net`, which is precisely the bypass an allowlist exists
to prevent. Write `.*\.example\.com` for a suffix.

On `allowed_ip` the two lists are CIDRs or bare addresses instead; on `path`
they are path globs where `*` stops at `/`.

### Allow and deny

One rule, shared by every check that has the pair:

- **`deny` is checked first and wins.** Plain membership, not
  longest-prefix-match: a `/32` in `allow` does not beat a `/8` in `deny`.
- **An empty `allow` imposes no constraint**, so a deny-only configuration is a
  working blocklist rather than a list that refuses everything.

Which gives three usable shapes: allow-only (a strict allowlist), deny-only (a
blocklist, everything else served), or both (an allowlist with holes punched in
it).

## Stages

There are two hook points — the connection, and the identifiers — and each type
answers at the ones it can:

| Type | Default stages | Capable of |
| --- | --- | --- |
| `allowed_ip`, `custom` | connection + identifiers | the same |
| `path` | connection | connection |
| `reverse_dns` | connection | connection + identifiers |
| `identifiers`, `ipam` | identifiers | identifiers |

`reverse_dns` is the one whose default is narrower than its capability: it could
answer at the identifier stage from the same address, but a PTR plus
forward-confirmation exchange at `newOrder` **and** again at `finalize` triples
the lookups for an answer that has not changed. Opt in when you need it in an
identifier-stage rule:

```toml
[filter.check.has-ptr]
type   = "reverse_dns"
stages = ["identifiers"]
```

Naming a stage the type cannot serve is a startup error saying why — an `ipam`
check at the connection stage would query the inventory on every `newNonce`.

That `allowed_ip` answers at **both** stages is load-bearing rather than
incidental: it is what makes `mgmt-net or inventory` a rule that can be
evaluated at all, since the address half must still be answerable at the point
where the names are known.

### Reference

**`filter.check.<name>.type`** (`String`) — *Required | Env: `ACME_PROXY_FILTER__CHECK__<NAME>__TYPE`*

Which check type this instance is: `allowed_ip`, `path`, `reverse_dns`,
`identifiers`, `ipam` or `custom`. An unknown value is refused by name, as is
the old `netbox`, which became `ipam` with its settings in `[ipam.netbox]`.

**`filter.check.<name>.stages`** (`Array`) — *Default: `[]` | Env: `ACME_PROXY_FILTER__CHECK__<NAME>__STAGES`*

Override where this instance decides: `"connection"`, `"identifiers"`, or both.
Empty infers from the type, per the table above.
