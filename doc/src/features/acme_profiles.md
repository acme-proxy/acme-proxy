# ACME Profiles

An ACME profile (draft-ietf-acme-profiles) is a named kind of certificate a
server offers — Let's Encrypt's `classic`, `tlsserver` and `shortlived`, for
instance. The directory lists them in `meta.profiles`, a client names one in
`newOrder`, and the order object says which one it got.

In `acme-proxy` the [signer](../signers/index.md) behind each endpoint decides
what is offered:

| Backend | What it offers |
| --- | --- |
| [`local_ca`](../signers/local_ca.md#acme-profiles) | The profiles you define, each a leaf lifetime. None by default. |
| [`relay`](../signers/relay.md#acme-profiles) | The upstream CA's own profiles, relayed — or the one profile you force. |
| [`custom`](../signers/custom.md) | None. |

## What a client sees

**The directory** lists each offered profile with its description:

```json
"meta": {
  "profiles": {
    "classic": "90-day certificates",
    "shortlived": "160-hour certificates"
  }
}
```

The member is absent, not empty, when nothing is offered.

**`newOrder`** takes an optional `profile`, resolved in this order:

1. A profile the endpoint **forces** (a relay's `signer.relay.profile`) is used,
   whatever the client named. The order object shows the profile actually used,
   and the override is logged as `order_profile_forced`.
2. A profile the client **names** must be one the directory lists, or the order
   is refused with `400` and `urn:ietf:params:acme:error:invalidProfile`.
3. A client naming **none** gets the default profile, if the backend has one
   (`signer.local_ca.default_profile`); a relay leaves the choice to the
   upstream.
4. Where nothing is offered, a client naming a profile is **not** refused: the
   field is ignored, as it always was, and the order carries none.

**The order object** carries `profile` from then on, on every read. A renewal
does not inherit its predecessor's profile through `replaces`: the client names
it again, or the default applies, as the draft describes.

**A profile removed by a reload** after an order was accepted under it fails
that order at finalize with `invalidProfile`, rather than issuing a certificate
of a different kind.

## Forcing short-lived certificates

The case issue #54 asked about: whatever a client requests, issue only
short-lived certificates, with a renewal window to match.

On a **local CA**, offer only the short-lived profile and make it the default.
A client naming nothing gets it, and a client naming anything else is refused:

```toml
[signer.local_ca]
default_profile = "shortlived"

[signer.local_ca.profiles.shortlived]
description = "160-hour certificates"
leaf_validity = "160h"
```

Without profiles at all, `leaf_validity = "160h"` does the same for every
client, profile-aware or not — see [Short-lived
certificates](../signers/local_ca.md#short-lived-certificates).

On a **relay**, force the upstream's profile. The worker refuses to start if
the upstream does not advertise it:

```toml
[signer.relay]
directory_url = "https://acme-v02.api.letsencrypt.org/directory"
profile = "shortlived"
```

Either way a client's `notAfter` can only shorten a certificate, and
[renewal information](renewal_info.md) follows each certificate's own lifetime,
`Retry-After` included, so ARI-aware clients renew in time without a setting of
their own.

## Operating it

- `acme-proxy order show` and the web admin's order page show an order's
  profile; the admin API's order object carries it as `profile`.
- A relay's read side learns the upstream's profiles from its directory on
  first use. In a process with no worker, an upstream that does not answer
  within five seconds leaves `meta.profiles` out and passes a client's choice
  on for the upstream to judge (`upstream_profiles_unavailable` is logged).
  The worker discovers the directory at startup and needs no such wait.
- The list a relay learned is kept until its backend is rebuilt: a profile the
  upstream adds appears after a reload that changes the relay's configuration,
  or a restart.
