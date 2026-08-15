# Security Policy

`acme-proxy` is a certificate authority, or the thing standing in front of one.
A flaw here can mean a certificate issued to someone who should not have it, for
a name they do not control. Reports are taken seriously.

## Supported versions

| Version | Supported |
| --- | --- |
| 0.1.x | yes |

Before 1.0.0 there is no long-term support branch: fixes land on `main` and in
the next release. The database schema is frozen and append-only, so upgrading is
starting the new binary against the existing database — but that schema is the
only compatibility guarantee before 1.0.0, so a security release may also move a
configuration key. See [Compatibility](CHANGELOG.md#compatibility).

## Reporting a vulnerability

**Please do not open a public issue.**

Use GitHub's private vulnerability reporting — the **Security** tab of this
repository, then **Report a vulnerability**. It is private to the maintainers
and gives us a place to work with you on a fix and a disclosure timeline.

Useful things to include, roughly in order of how much they help:

- What an attacker gains — issuance for a name they do not control, revocation
  of someone else's certificate, access to the admin listener, key disclosure.
- The configuration it needs. Much of this server's behaviour is switchable, so
  "with `challenge.bypass = false` and `filter.enabled = []`" is the difference
  between a serious finding and an expected one.
- The signer backend in use (`local_ca`, `relay`, `custom`), which changes
  who ultimately signs.
- A reproduction, and any relevant log lines — every line carries an
  `event = "..."` field and a request id.

Expect an acknowledgement within a few days. We will tell you what we think the
impact is, and we would rather hear about something that turns out not to be
exploitable than not hear about it.

## What is in scope

Anything that lets a party obtain, revoke, or interfere with a certificate
beyond what the configuration should allow; anything that bypasses the challenge,
filter, EAB or admin-authentication gates; and disclosure of any of the secrets
listed in the
[Security Model](https://acme-proxy.github.io/acme-proxy/security/index.html).

## What is not

Some behaviour looks alarming and is documented and deliberate. Please read the
[Security Model](https://acme-proxy.github.io/acme-proxy/security/index.html)
first — it names the trust boundaries and what each gate does and does not
cover. In particular:

- **`challenge.bypass = true` issuing without proof.** That is what the setting
  does. It is off by default, and warns on every startup while on.
- **`http-01` validation reaching private addresses.** Serving private networks
  is the purpose of this server, so Boulder's RFC 1918 blocklist does not apply.
  The containment is documented under
  [HTTP-01](https://acme-proxy.github.io/acme-proxy/challenges/http_01.html).
- **EAB secrets and TOTP secrets being readable from the database file.** Both
  are verified by recomputing an HMAC, so the server needs the same bytes back
  each time. File permissions are the boundary, and any wrapping key would live
  in the same directory.
- **A `custom` script doing something dangerous with its input.** The hooks run
  hardened (`env_clear()`, a minimal `PATH`, a timeout, `kill_on_drop`), but the
  script is operator-supplied and quoting its inputs is the operator's job.
- **The audit trail not being compared against live requests.** Deliberate:
  pinning an identity to an address breaks CGNAT and mobile clients. It is a
  record, not a control.

An attack that requires an attacker who already holds the CA private key, root
on the host, or a valid operator session with a second factor is generally not a
separate finding — but tell us anyway if it lets them do something the design
says it should not.
