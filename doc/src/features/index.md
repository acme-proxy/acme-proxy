# Protocol Support

`acme-proxy` implements RFC 8555 in full, plus the extensions an ACME client in
2026 expects to find. This page is the conformance summary: what a client can
call, which RFC section governs it, and what is deliberately not implemented.

Everything here is served **per profile**, under `/profile/<name>/`. There is no
ACME at the bare root — see [Profiles & Routing](../core/profiles.md).

## Resources

Every row is reachable at `{base_url}/profile/<name><path>`. The **Advertised**
column says whether the directory object names it: a client is expected to find
advertised resources by reading the directory rather than by constructing paths.

| Path | Method | RFC | Advertised | Notes |
| --- | --- | --- | --- | --- |
| `/directory` | `GET`, `POST` | §7.1.1 | — | It is the entry point; §6.3 requires POST-as-GET to work too. |
| `/newNonce` | `HEAD`, `GET`, `POST` | §7.2 | yes | All three forms. |
| `/newAccount` | `POST` | §7.3 | yes | Find-or-create by public key: `201` for a new account, `200` for an existing one, `Location` either way. |
| `/acct/{id}` | `POST` | §7.3.2, §7.3.6 | — | Contact update and deactivation. `kid`-authenticated. There is deliberately no unauthenticated `GET`. |
| `/acct/{id}/orders` | `POST` | §7.1.2.1 | — | The account's order list, filtered as §7.1.2.1 requires. |
| `/keyChange` | `POST` | §7.3.5 | yes | [Key Rollover](key_change.md). |
| `/newOrder` | `POST` | §7.4 | yes | Accepts `notBefore`/`notAfter` and RFC 9773's `replaces`. |
| `/order/{id}` | `POST` | §7.1.3 | — | POST-as-GET. |
| `/order/{id}/finalize` | `POST` | §7.4 | — | Takes the CSR; hands it to the configured [signer](../signers/index.md). |
| `/authz/{id}` | `POST` | §7.5, §7.5.2 | — | One URL serves both the read and the deactivation, told apart by whether a payload arrived. |
| `/chall/{id}` | `POST` | §7.5.1 | — | Triggers [validation](../challenges/index.md). Both outcomes are `200`. |
| `/certificate/{id}` | `POST` | §7.4.2 | — | POST-as-GET; PEM chain. |
| `/revokeCert` | `POST` | §7.6 | yes | [Revocation & CRL](../operations/revocation.md). |
| `/renewalInfo/{certID}` | `GET` | RFC 9773 §4.1 | yes | Unauthenticated. Advertised **without** the id — §4.1 has the client append it. |
| `/crl` | `GET` | RFC 5280 | **no** | Routed but not advertised: a CRL is CA infrastructure, not an ACME resource. |
| `/ca.pem` | `GET` | — | **no** | The profile's trust anchor, so installing it is one `curl`. `404` unless the backend has one of its own. Not advertised, for the same reason as `/crl`. See [Trusting the CA](../getting_started/trusting_the_ca.md). |

Two paths sit outside every profile, on the root router:

| Path | Purpose |
| --- | --- |
| `/health` | Liveness. Outside the filter chain, the admission limiter and the nonce middleware — see [Monitoring](../operations/monitoring.md). |
| `/.well-known/acme-challenge/{token}` | Mounted **only** when a signer backend has an http-01 token store to publish, i.e. `signer.relay.challenge_strategy = "http01"`. See [Relay](../signers/relay.md). |

## Protocol behaviour worth knowing

**Every signed request is checked the same way.** The media type
(`application/jose+json`), any `crit` header, the JWS `url` against the route
actually reached, and the nonce are all verified before a handler runs, so no
resource can forget one. `jwk` and `kid` are mutually exclusive per §6.2, and
the verification algorithm never rests on the client's `alg` alone. See
[Architecture](../dev/architecture.md#the-jws-extractor-core).

**Refusals are problem documents.** Every rejection is
`application/problem+json` with an RFC 8555 URN type. A multi-identifier order
rejected on several names comes back as one `compound` problem with a
`subproblems` entry per identifier (§6.7.1); a single rejection stays its own
type, unwrapped.

**A `POST` always carries a fresh `Replay-Nonce`**, errors included (§6.5). `GET
/directory`, `GET /crl`, `GET /ca.pem` and `GET /renewalInfo` do not mint one —
nothing asks them to, and each nonce is a committed database write.

## Extensions

| Extension | RFC | Default | Page |
| --- | --- | --- | --- |
| External Account Binding | §7.3.4 | off | [EAB](eab.md) |
| Account key rollover | §7.3.5 | always on | [Key Rollover](key_change.md) |
| Renewal Information (ARI) | RFC 9773 | always on | [ARI](renewal_info.md) |
| Terms of service | §7.3.3 | off | Set `meta.terms_of_service` and `newAccount` starts enforcing it. |
| Wildcard identifiers | §7.1.3 | requires `dns-01` | [Challenge Validation](../challenges/index.md#wildcards) |

## Directory metadata

The directory's `meta` object carries only what is configured. An unset member
is **omitted**, never sent empty — `"website": ""` says less than saying
nothing.

- `externalAccountRequired` appears as `true` when EAB is on for that profile.
- `termsOfService`, `website` and `caaIdentities` come from `[meta]`.

`meta.terms_of_service` is the one with teeth: setting it turns on §7.3.3, so
`newAccount` then refuses a request without `termsOfServiceAgreed: true` (`403
userActionRequired` plus a `Link: rel="terms-of-service"` header), and the
account object starts reflecting the field.

## Not implemented

Stated explicitly, because each is something a reader may reasonably expect:

- **CAA checking.** `meta.caa_identities` is advertised to clients; this server
  does no CAA lookup of its own. Where the [relay
  backend](../signers/relay.md) is in use, the upstream CA performs its own.
- **OCSP.** Revocation is published as a CRL at `GET /crl`. There is no OCSP
  responder, and no `authorityInfoAccess` OCSP pointer is ever written into an
  issued certificate. The local CA does write the `caIssuers` half of that
  extension, and a `cRLDistributionPoints` pointer, once an operator names the
  URLs — see [Local CA](../signers/local_ca.md#reference).
- **Identifier types other than `dns`.** `newOrder` accepts DNS names, including
  wildcards; `ip` identifiers (RFC 8738) and `permanent-identifier` are not
  supported.
- **Pre-authorization** (§7.4.1). The directory does not advertise `newAuthz`,
  and it is not routed. Authorizations exist only as part of an order.
- **`POST` to `/renewalInfo`** — RFC 9773 §4.3's optional client-side renewal
  signal. The `GET` half is implemented.
