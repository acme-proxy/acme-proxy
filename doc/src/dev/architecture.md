# Architecture

`acme-proxy` is built with asynchronous Rust components, heavily leveraging `axum` and `tokio`. The design focuses on strict RFC 8555 compliance, isolated profile routing, and modular components for signing, filtering, and notifications.

## Request Flow and Extractors

Nearly every ACME endpoint is signed by the client using JSON Web Signatures (JWS). Rather than parsing this manually in each handler, the server leverages an `AcmeRequest<T>` Extractor.

### The JWS Extractor Core
1. **Header Validation**: Checks `Content-Type: application/jose+json` (returns `415` if mismatched).
2. **JWS Decoding**: Decodes the flattened JWS and protected header.
3. **Critical Extensions**: Rejects any `crit` extension (as the server implements none, so every value is by definition unrecognized — RFC 7515 §4.1.11).
4. **Signature Verification**: Uses the `ring` crate to verify ECDSA (ES256) or RSA (RS256) signatures.
5. **URL & Nonce**: Validates the JWS `url` field against the actual route hit (RFC 8555 §6.4) and consumes the nonce (RFC 8555 §6.5).

Only once all of this succeeds is the request handed to the Axum handler. Hoisting
these checks into the extractor makes them structural: a new signed route cannot
forget them, and no handler repeats a four-line preamble.

Three extractors build on that core: `AcmeRequest<T>` (decode and deserialize the
payload), `AcmePostAsGet` (require an empty payload, else `malformed`), and
`AcmeOptionalPayload<T>` — the last exists for the authorization resource, where
one URL serves both a POST-as-GET read and a §7.5.2 deactivation.

### Two security properties worth not breaking

**`jwk` and `kid` are mutually exclusive** (RFC 8555 §6.2). Both present, or
neither, is `malformed`. An embedded `jwk` is verified and re-encoded as DER SPKI;
a `kid` is resolved to its account and verified against the account's **stored**
SPKI.

**The verification algorithm never rests on `alg` alone.** On the `kid` path, the
stored SPKI's own `AlgorithmIdentifier` OID is checked against the client's
claimed `alg` before verification. EC coordinates must additionally be exactly 32
octets (RFC 7518 §6.2.1.2) — a short or long one parses as a *different* point,
which would register one key as two accounts.

## Database & Persistence

The server uses `sqlx` with `sqlite`. 

### Migrations
Database migrations are embedded into the binary using `sqlx::migrate!()` and run automatically at startup. The database connects with two crucial pragmas:
- `foreign_keys = ON`: Ensures the `ON DELETE CASCADE` constraints work, allowing accounts and orders to be genuinely deleted without leaving orphans.
- `journal_mode = WAL`: Write-Ahead Logging allows high concurrency, crucial because every single request consumes and mints a nonce.

**The migration set is frozen as of 0.1.0 and append-only from here.** A schema
change is a new `sqlx migrate add` file, never an edit to a committed one:
`sqlx` records each migration's checksum, so editing a file that has already run
somewhere fails that deployment at startup. See
[Contributing](contributing.md#changing-the-database-schema) for the two
consequences that catch people out — a new column is a new file, and a new
`CHECK`/`UNIQUE`/foreign key needs a full table rebuild because SQLite cannot
add one in place.

Because upgrading is therefore just "run the new binary against the existing
database", there is no separate upgrade procedure and no dump/restore step.

### Schema Details
- **Profiles Isolation**: Both the `accounts` and `orders` tables include a `profile` column. The `accounts` table uses `UNIQUE(profile, pubkey)`. This means the same client key connecting to two different profiles is treated as two entirely isolated accounts.
- **Constraints**: Heavy use of `CHECK (status IN (...))` for the state machines to ensure an invalid state cannot be parked in the database.
- **Revocation**: The `cert_serial` column is indexed to allow rapid lookup during `POST /revokeCert`. Revocation writes a reason and timestamp, but deliberately does not touch the order `status` (as RFC 8555 defines no "revoked" order status).
- **The audit trail has no foreign keys, deliberately.** `audit_log` is the one table that names an `account_id` and an `order_id` without a constraint behind either, because an audit row has to survive the account or order it describes being deleted — a `CASCADE` there would destroy the evidence along with its subject. The identifiers are frozen into the row for the same reason, and the primary key is `AUTOINCREMENT` so SQLite cannot reuse the rowid of a purged row. Rows are only ever inserted: there is no setter and no `UPDATE` anywhere in the crate. See [Audit Trail](../operations/audit.md).
- **Admin identities**: `admin_users` and `admin_sessions` are the web admin's own tables and never join to an ACME concept — an `admin_users` row is an operator, an `accounts` row is a client key. They are deliberately the *opposite* of `eab_keys`: that table stores its secret as retrievable bytes because HMAC verification needs the same secret back on every request, whereas a password is only ever compared, so it is stored one-way and no code path can read it out. A session row stores only the SHA-256 of its token, so a database read yields nothing replayable.

## Two front ends, one operation layer

`src/cli/` and `src/webadmin/` are **two front ends**; `src/admin/` is the
operation layer both dispatch to and neither owns.

```text
src/cli/            src/webadmin/
   (clap)              (axum)
      \                 /
       \               /
        src/admin/ops.rs      — delete_account, revoke_order, load_order_detail…
        src/admin/users.rs    — create_user, authenticate, set_password…
        src/admin/render.rs   — render_*_line (human) / render_*_json (API)
        src/admin/password.rs — the KDF, shared by both
```

A handler in `src/webadmin/handlers/` is a few lines over an `admin::ops` call
and a `render_*_json`, the same way a `src/cli/` command body is a few lines
over the same call and a `render_*_line`. That is what keeps the password
policy, the duplicate check and the rehash-on-login identical between them.

Two consequences worth knowing:

- **The destructive operations come in pairs.** `delete_account(id, db)` simply
  deletes; `confirm_delete_account(id, yes, reader, db)` asks first. The split
  exists because `assume_yes: bool` + `reader: &mut impl BufRead` are a
  terminal's concerns — a caller with no terminal was passing `true` and an
  empty reader, asserting a confirmation that never happened. The CLI calls the
  wrapper; the web calls the bare form.
- **`src/webadmin/` is not `src/admin/web/`.** That would invert the dependency,
  putting an HTTP server inside the operation layer.

The admin listener is assembled by `webadmin::build_admin_app`, which takes
`&[Arc<Profile>]` as a **slice** — `build_app` consumes the `Vec`, so the admin
side must be built first, and the signature is where that ordering is stated
rather than a borrow error to rediscover. Its state is `AdminState`, not
`AppState`: the latter holds exactly one `Profile`, and this listener is
cross-profile by nature (revoking an order needs *that order's own* profile's
signer, which may be a different CA from any default).

## Order Lifecycle

```mermaid
sequenceDiagram
    participant Client
    participant Axum Router
    participant Filters
    participant Order Manager
    participant Challenge Validator
    participant Signer Backend

    Client->>Axum Router: POST /newOrder
    Axum Router->>Filters: Validate Client IP & Identifiers
    Filters-->>Axum Router: Allow/Deny
    Axum Router->>Order Manager: Create Order + Authorizations + Challenges
    Order Manager-->>Axum Router: Order Object (status: pending)
    Axum Router-->>Client: 201 Created

    Client->>Axum Router: POST /chall/{id} (trigger)
    Axum Router->>Challenge Validator: Validate domain control (inline)
    Challenge Validator-->>Axum Router: Pass/Fail
    Axum Router->>Order Manager: Commit challenge + authz + order
    Note over Order Manager: Order -> "ready" once every<br/>authorization is valid
    Axum Router-->>Client: 200 OK + challenge object (either way)

    Client->>Axum Router: POST /finalize (with CSR)
    Axum Router->>Filters: Re-validate identifiers from CSR
    Filters-->>Axum Router: Allow/Deny
    Axum Router->>Signer Backend: Request Signature
    Signer Backend-->>Axum Router: Signed Certificate
    Axum Router-->>Client: 200 OK (Certificate URL)
```

Three transactional properties hold this together:

- Order creation inserts the order, its authorizations and their challenges in
  **one transaction**. A half-written order would be finalizable for names that
  were never authorized.
- A validation outcome commits the challenge, the authorization and the order
  **together**, and the "is every authorization valid?" read happens *inside* that
  transaction. From the pool, two concurrent validations of one order could each
  read before the other's write landed, and neither would promote the order to
  `ready`.
- Challenge validation returns **`200` plus the challenge object whether it
  passed or failed** (§7.5.1). A 4xx would surface as a transport failure to
  certbot's `acme` library rather than as a failed challenge.


## Pluggable Signing Keys

The [`SignerBackend`](../signers/index.md) trait is the seam for *how a
certificate is obtained* — locally, from an upstream ACME server, or from a
script. Inside the `local_ca` backend there is a second, narrower seam for
*where the private key lives*, and it is worth knowing that it is **rcgen's own
trait, not one this project invented**.

`rcgen::SigningKey` is public, and every signing entry point `local_ca` uses is
generic over it:

| call | signature |
|---|---|
| `csr.signed_by(&issuer)` | `signed_by(&self, issuer: &Issuer<impl SigningKey>)` |
| `CertificateRevocationListParams::signed_by(&issuer)` | `signed_by(&self, issuer: &Issuer<'_, impl SigningKey>)` |
| `params.self_signed(&key)` | `self_signed(&self, signing_key: &impl SigningKey)` |

So `LocalCa` holds an `Issuer<'static, CaSigningKey>` — a small enum in
`src/signer/local_ca/key.rs` with a `Software(KeyPair)` variant and, behind the
`hsm` feature, a `Pkcs11(..)` one. Adding a key source (a cloud KMS, a remote
signer daemon) means adding a variant that implements two rcgen trait methods:
`sign`, `der_bytes`/`algorithm`. Nothing in `issue`, `revoke`, `crl_der` or the
CSR sanitisation changes, because none of it ever names the key type.

Two consequences worth preserving:

- **Signing runs on the blocking pool.** `rcgen::SigningKey::sign` is
  synchronous and called from deep inside `signed_by`, so there is nothing to
  await through. A key source that talks to hardware or a network would
  otherwise stall a runtime worker for its whole round trip, so `LocalCa::issue`
  and the CRL rebuild in `revoke` both go through `spawn_blocking`
  unconditionally — not gated on the variant, which would be a branch someone
  eventually gets wrong.
- **The key type must be `Send + Sync`.** It lives inside an
  `Arc<dyn SignerBackend>`. Where the underlying handle is not (cryptoki's
  `Session` is `Send` but not `Sync`), a `std::sync::Mutex` is the right wrapper:
  the signing call never awaits, so an async mutex would buy nothing.
