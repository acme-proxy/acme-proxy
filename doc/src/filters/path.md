# Path Check

`type = "path"` matches the request path, so a rule can be about *what* is being
asked for as well as *who* is asking.

```toml
[filter.check.public-paths]
type  = "path"
allow = ["/crl"]

[filter.rule.public]
when = "public-paths"
then = "allow"
```

Connection stage only. By the identifier stage the path is always `/newOrder` or
`/finalize/{id}`, so a rule combining this with a name check would be asking a
question with a constant answer.

## The `/crl` and `/ca.pem` trap

**Both are served by the profile router**, which means they sit behind the
filter policy exactly like `/newOrder` does. Turn on an address-based check
without accounting for them and two things break quietly:

- every relying party outside your allowlist loses revocation checking, and
  relying parties are precisely *not* the ACME clients you allowlisted;
- a host that has not installed the root yet cannot fetch it — which is the one
  moment it needs to, and the refusal looks like the CA being down.

So any address-based policy wants a companion rule:

```toml
[filter]
rules = ["public", "mgmt-only"]

[filter.check.public-paths]
type  = "path"
allow = ["/crl", "/ca.pem"]

[filter.check.mgmt-net]
type  = "allowed_ip"
allow = ["10.0.0.0/8"]

[filter.rule.public]
when = "public-paths"
then = "allow"

[filter.rule.mgmt-only]
when = "mgmt-net"
then = "allow"
```

Because `public` comes first and first match wins, both are served to anyone
while everything else still requires the management network.

Server-level routes — `GET /health`, `GET /`, and the `http-01` responder — are
served by the **root** router, which no profile's policy ever sees. They are
already unfiltered and need no entry here.

## Paths are profile-stripped

Matching is against the path with the `/profile/<name>` prefix removed, so
`/directory` — not `/profile/default/directory` — is the value to list, and one
check covers every endpoint the process serves.

## Globs

`*` matches one or more characters other than `/`, i.e. one path segment:

| Glob | Matches | Does not match |
| --- | --- | --- |
| `/crl` | `/crl` | `/crl/extra` |
| `/renewalInfo/*` | `/renewalInfo/abc123` | `/renewalInfo/a/b`, `/renewalInfo/` |
| `/*` | `/directory`, `/newOrder` | `/renewalInfo/abc` |

Everything else in a glob is literal, so a path containing regex syntax cannot
smuggle a pattern in. `allow`/`deny` follow the shared rule described in
[Checks](checks.md#allow-and-deny): `deny` wins, an empty `allow` imposes no
constraint.

A check with **both** lists empty is a startup error — it would match every
request, which is a check that does nothing.

## Combining with other checks

The reason this is a check rather than the flat `filter.exempt_paths` list it
replaces is that a path is rarely the whole answer:

```toml
# Only the operator network may revoke.
[filter.check.revocation]
type  = "path"
allow = ["/revokeCert"]

[filter.rule.no-remote-revocation]
when    = "revocation and not mgmt-net"
then    = "deny"
message = "revocation is restricted to the management network"
```

The old list could only say "skip the connection stage entirely for this exact
string", and could not express `/renewalInfo/*` at all.
