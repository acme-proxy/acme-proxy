# ADR 0015: The web admin trusts OpenID Connect and LDAP providers, hand-rolling OIDC and taking `ldap3`

## Status

Accepted. Narrows [ADR 0009](0009-dependency-policy.md)'s "hand-roll a small,
stable protocol" for LDAP, and
[ADR 0006](0006-no-slow-or-privileged-work-in-a-request.md)'s "a request does
no slow work" for a sign-in.

## Context

The web admin had its own operators only: a password and an optional TOTP
factor per person, created from the host. Larger deployments already run an
identity provider, and asked for the panel to use it (issue #14): OpenID
Connect, and LDAP / Active Directory, with operators created at their first
sign-in and their role following their groups.

Three things in the tree pushed against doing that naively:

- **Dependencies.** The usual crates are `openidconnect` and `ldap3`.
  `openidconnect` verifies ID tokens with RustCrypto's `rsa`, `p256`, `p384` and
  `ed25519-dalek`: a second public-key stack beside `ring`, on the path that
  decides who becomes an admin. ADR 0014 accepted RustCrypto hashes reachable
  only from a database driver's handshake; this would not be that.
- **Requests do no slow work.** ADR 0006 moved every outbound call a client
  could provoke out of the request path. A directory bind and a token exchange
  are outbound calls.
- **Identity is a name.** The panel addresses operators by username, and
  `admin_users` had no notion of who vouches for one.

## Decision

- **OpenID Connect is hand-rolled**: the authorization code flow with PKCE
  `S256`, on the tree's own outbound client (so `[dns]`, `[proxy]` and an
  operator CA apply) and on `core::jws::jwt`, which verifies an ID token with
  the same `ring` code and the same two algorithms (`RS256`, `ES256`) as every
  ACME request. The key always chooses the algorithm; `none` and `HS*` are
  refused before a key is looked at.
- **LDAP uses `ldap3`**, with `default-features = false` and
  `tls-rustls-ring`, and is always handed this server's own `ring`
  `ClientConfig` through `set_config`. Its fallback builds a config from the
  process-default provider, which this tree never installs; a test asserts no
  provider appears. LDAP's BER, paged and referral results, and Active
  Directory's quirks are a library's job: a page of code against a frozen
  specification is what ADR 0009 asks to hand-roll, and this is not that page.
- **A sign-in may make its provider round trip inline.** The provider is chosen
  by the operator, not by the caller; the call is on the admin listener only,
  behind the login limiter, bounded by the provider's `timeout_ms`; and the
  person is waiting for exactly that answer. It is the shape of
  `signer.custom`'s inline read hooks, not of a challenge validation.
- **An identity is `(auth_provider, external_id)`**, the provider's stable name
  for the person, under a partial unique index. A username another operator
  already holds refuses the sign-in: **never a link by name**, or whoever
  controls a provider could name somebody `admin` and become the break-glass
  operator.
- **The role is recomputed at every sign-in** from the groups, the highest one
  granted. No mapped group refuses the sign-in. A local `disable` still wins,
  the last-admin guard still holds, and a role change by hand is refused for an
  external operator, since it would revert at their next sign-in.
- **An external operator has no password here.** Their row holds a sentinel
  that is not a hash, refused before it is read. Step-up re-proves them through
  their realm: a directory bind for LDAP, and for OpenID Connect a sign-in less
  than five minutes old, begun with `?reauth=1` so the provider is asked to
  authenticate the person again (`prompt=login`, `max_age`) and the token's
  `auth_time` is checked — a provider's silent single sign-on is not a
  re-authentication. An OpenID Connect operator's second factor is the
  provider's (`required_amr`); an LDAP operator's is local, as a password is.
- **Local operators stay**, as the break-glass realm. `admin.auth.local = false`
  closes the password form's local realm without deleting anybody.

## Consequences

- `cargo deny` gains `ldap3` and `lber`, a second `nom` (`lber` is on 7), and
  `rustls-native-certs`, which `ldap3`'s rustls support requires for its
  fallback root store: on macOS and Windows that brings the OS bindings
  (`security-framework`, `schannel`), which are compiled in but never called,
  since a config is always passed. No second public-key implementation enters
  the build, and no C toolchain is needed.
- The relying party is code this project owns. Its claim checks have their own
  tests in `core::jws::jwt`, and the flow has an end-to-end suite against a
  provider on loopback (`tests/admin_oidc.rs`). Encrypted ID tokens, `PS256` and
  RP-initiated logout are not implemented.
- A provider that is down makes its realm answer `503`, never "wrong password",
  and never stops the panel or the local realm from starting: discovery and the
  key set are fetched on first use, not at startup.
- The OpenID Connect callback cannot use the session machinery's origin gate:
  the provider's redirect is cross-site by design. A single-use `state` row and
  a `SameSite=Lax` cookie bound to it stand in, and the callback answers with a
  page that refreshes into the panel, because a `SameSite=Strict` session
  cookie is not sent on any hop of a cross-site redirect chain.
- `acme-proxy-admin` depends on `acme-proxy-net`, which it did not before.

## Enforced by

- `crate_dependencies_follow_the_layers` in `tests/layering.rs` (the new edge).
- `ldaps_verifies_the_directory_and_installs_no_crypto_provider` in
  `tests/admin_ldap.rs`.
- The refusal tests in `crates/core/src/jws/jwt.rs`
  (`none_and_hmac_are_refused`,
  `a_token_is_never_tried_against_a_key_of_another_type`,
  `each_claim_is_checked`).
- `a_taken_username_is_refused_never_linked` and
  `demoting_the_last_admin_refuses_the_sign_in` in
  `crates/admin/src/identity/mod.rs`;
  `a_name_a_local_operator_holds_is_refused_not_linked` and
  `a_state_answers_one_callback` in `tests/admin_oidc.rs`.
- `one_external_identity_is_one_operator_on_both_backends` in
  `tests/postgres.rs`.
- `webadmin::check_config`'s refusals: plain `ldap://` off loopback, a non-https
  issuer, an empty role map, no realm at all, and an OpenID Connect provider
  asserting no second factor while `admin.require_mfa` is on.
- `a_reauth_sign_in_demands_a_fresh_authentication`,
  `a_cross_site_start_is_refused_and_writes_nothing` and
  `abandoned_starts_are_bounded_and_a_sign_in_clears_them` in
  `tests/admin_oidc.rs`; `losing_every_group_ends_the_operators_sessions` in
  `crates/admin/src/identity/mod.rs`.
