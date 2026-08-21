# Local CA Signer

The `local_ca` backend uses an internal ECDSA key to act as a fully functional
Certificate Authority. It is capable of generating its own self-signed root, or
it can act as a subordinate (Intermediate) CA if provided with an existing key
and certificate.

Reach for it for development environments, CI pipelines, and isolated internal
networks — anywhere the certificates only need to be trusted by machines you
control.

## Security constraints

When processing a Certificate Signing Request (CSR) from a client, the
`local_ca` is deeply distrustful of the requested extensions:

1. **Overwriting Extensions**: The Local CA overwrites every extension the CSR
   asked for before signing — a fresh random serial, fixed key usages, and its
   own validity window. This matters more than it sounds: the CSR parser
   otherwise copies a requested `basicConstraints`/`keyUsage` straight into the
   signed leaf.
2. **Basic Constraints**: The issued leaf is never a CA. Without the reset
   above, a client authorized for one name could submit a CSR carrying `CA:TRUE`
   + `keyCertSign` and receive a **working intermediate CA**, which it could
     then use to mint arbitrary trusted certificates. (In implementation terms
     the leaf is built with `IsCa::NoCa` rather than `ExplicitNoCa` — an
     explicit `CA:FALSE` broke certbot's chain parser — but the security
     property is the same.)
3. **Subject Alternative Names (SANs)**: The DNS SANs in the CSR must be
   **exactly** the set of identifiers the order authorized — no more, no fewer —
   or issuance fails with `badCSR`.
4. **Non-DNS SANs are rejected, not stripped**: a CSR carrying an IP, email or
   URI SAN is refused outright with `badCSR`. Do not expect `local_ca` to
   quietly drop them.
5. **The subject is emptied**: the issued leaf carries no distinguished name at
   all, so a Common Name in the CSR cannot leak into it. (A CN that *looks like*
   a domain the order does not cover is separately rejected earlier, at finalize
   — see [Troubleshooting](../operations/troubleshooting.md).)

## Certificate validity

Leaves are valid for `leaf_validity_days`, starting one hour in the past to
absorb clock skew between the CA and its clients.

A client may narrow that window using the order's `notBefore`/`notAfter` (RFC
8555 §7.4), but never widen it: a requested start is honoured only if it is
*later* than the default start, and a requested end only if it is *earlier* than
the default end. A request whose clamped window would be empty or inverted is
discarded whole, the policy default is used, and a
`local_ca_requested_validity_discarded` warning is logged.

## Configuration

```toml
[signer]
backend = "local_ca"

[signer.local_ca]
cert_path = "ca.pem"
key_path = "ca.key"
key_type = "ecdsa-p256"
crl_path = "ca.crl"
leaf_validity_days = 90
```

### Reference

**`cert_path`** (`String`) — *Default: `"ca.pem"` | Env: `ACME_PROXY_SIGNER__LOCAL_CA__CERT_PATH`*

The path where the CA certificate is stored. If this file does not exist, a new
self-signed Root CA is generated on startup and saved here.

**`key_path`** (`String`) — *Default: `"ca.key"` | Env: `ACME_PROXY_SIGNER__LOCAL_CA__KEY_PATH`*

The path where the CA private key is stored. A generated key is created with
mode `0600` at creation time, not chmod'ed afterwards, so there is no window in
which another local user could read it.

**`key_type`** (`String`) — *Default: `"ecdsa-p256"` | Env: `ACME_PROXY_SIGNER__LOCAL_CA__KEY_TYPE`*

Algorithm for a **generated** CA key. `"ecdsa-p256"` is currently the only
accepted value; anything else is a startup error. (An existing key supplied on
disk is used as-is, whatever its type.)

**`crl_path`** (`String`) — *Default: `"ca.crl"` | Env: `ACME_PROXY_SIGNER__LOCAL_CA__CRL_PATH`*

Where the Certificate Revocation List (RFC 5280) is written and served from `GET
/crl`. It is regenerated on every revocation and at startup. The durable ledger
of revoked serials is a **JSON sidecar** beside it — the same path with the
extension swapped to `.json` (so `ca.crl` → `ca.json`) — not the CRL's own DER
read back. Back up both. Entries are dropped once the certificates they name
have expired, and the sidecar also carries the CRL's ever-increasing number; see
[Revocation](../operations/revocation.md).

**`crl_distribution_points`** (`Array<String>`) — *Default: `[]` | Env: `ACME_PROXY_SIGNER__LOCAL_CA__CRL_DISTRIBUTION_POINTS`*

Where a relying party can **fetch** that CRL. Each URL is written into every
issued leaf as `cRLDistributionPoints` (RFC 5280 §4.2.1.13); empty — the default
— emits no extension at all, which is why a certificate from this CA says
nothing about revocation until you set this.

Nothing derives it, deliberately. The URL is frozen into every certificate
signed while it is set, so a value read from `server.base_url` would silently
break certificates already issued the day that changed. And this server's own
copy is served at `{base_url}/profile/<name>/crl`, *inside* the profile router
and therefore behind that profile's filter policy — an address-based rule would
refuse it to exactly the relying parties the extension exists for. Name a URL
you know is publicly reachable; a webroot or CDN copy of `crl_path` is the usual
answer.

Several entries mean **one CRL reachable in several places**, not several
different CRLs. `http://` is idiomatic and gets no warning: fetching a signed
CRL over TLS means validating that connection's certificate first, which is the
loop this extension exists to break. Credentials in the URL, a non-`http(s)`
scheme, and any value the URL parser would normalize (a missing trailing `/`, a
leading space from an environment-variable list) are each a startup error naming
the key and the value.

Note that two profiles sharing one CA share this list too: they share one
`[signer]` section, one ledger and one CRL, so there is one place that CRL is
published. Giving them different URLs while they share `ca.key` is refused at
startup — see [Profiles & Routing](../core/profiles.md).

**`ca_issuer_urls`** (`Array<String>`) — *Default: `[]` | Env: `ACME_PROXY_SIGNER__LOCAL_CA__CA_ISSUER_URLS`*

Where a relying party can fetch **this CA's own certificate**, written into
every issued leaf as `authorityInfoAccess` with the `caIssuers` access method
(RFC 5280 §4.2.2.1). Empty — the default — emits no extension. Same reasoning,
same validation and the same startup errors as `crl_distribution_points` above.

The sibling access method, `id-ad-ocsp`, is never written: this server runs no
OCSP responder, and a pointer at one that does not exist is worse than none.

**`leaf_validity_days`** (`Integer`) — *Default: `90` | Env: `ACME_PROXY_SIGNER__LOCAL_CA__LEAF_VALIDITY_DAYS`*

The validity period (in days) for issued leaf certificates. Distinct from
`order.validity_seconds`, which bounds the ACME *order object*, not the
certificate.

**`key_source`** (`String`) — *Default: `"file"` | Env: `ACME_PROXY_SIGNER__LOCAL_CA__KEY_SOURCE`*

Where the issuing private key lives. `"file"` is everything described on this
page: a PEM key at `key_path`, loaded or generated. `"pkcs11"` puts the key in a
hardware token instead, and reads the `[signer.local_ca.pkcs11]` table — see
[Hardware Keys](local_ca_hsm.md#reference). Any other value is a startup error,
and so is `"pkcs11"` on a binary built without `--features hsm`: there is
deliberately no silent fallback, since falling back would hand an operator who
asked for hardware a software key with no indication of it.

## Hardware-backed keys

The CA key described above is a file, and a file can be copied. If the CA is one
your fleet actually trusts, the issuing key can instead live in a PKCS#11 token
— a YubiKey, an enterprise HSM, or SoftHSM2 for development — where it is
created once and can never be read back out.

Everything on this page still applies; only where the signature comes from
changes. See [Hardware Keys (PKCS#11)](local_ca_hsm.md). Note that it requires a
build with `--features hsm`, which is not the default.

## Multi-tier PKI (using an intermediate CA)

For production internal deployments, you should avoid using an auto-generated
Root CA directly on the server. Instead, you can use a **Multi-Tier Hierarchy**:
create an offline Root CA, use it to sign an Intermediate CA, and hand the
Intermediate CA to `acme-proxy`.

Here is how you can do this in practice using OpenSSL.

### Step 1 — Create the offline root CA

Generate a private key and a self-signed Root certificate (keep this key highly
secure and offline):

```bash
# Generate the Root private key
openssl ecparam -genkey -name prime256v1 -out root_ca.key

# Create the self-signed Root certificate (valid for 10 years)
openssl req -x509 -new -nodes -key root_ca.key -sha256 -days 3650 \
  -out root_ca.pem \
  -subj "/CN=My Company Offline Root CA"
```

### Step 2 — Create the intermediate CA for acme-proxy

Generate the private key and CSR for the Intermediate CA:

```bash
# Generate the Intermediate private key
openssl ecparam -genkey -name prime256v1 -out acme_intermediate.key

# Create the CSR
openssl req -new -key acme_intermediate.key -out acme_intermediate.csr \
  -subj "/CN=My Company ACME Intermediate CA"
```

Create an OpenSSL extension file (`v3_ext.cnf`) to ensure the Intermediate CA is
allowed to sign other certificates:

```ini
[ v3_intermediate_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
```
*(Note: `pathlen:0` ensures this intermediate can issue leaf certificates, but
cannot issue further intermediate CAs).*

Now, sign the Intermediate CSR using the Offline Root CA:

```bash
openssl x509 -req -in acme_intermediate.csr -CA root_ca.pem -CAkey root_ca.key \
  -CAcreateserial -out acme_intermediate.pem -days 1825 -sha256 \
  -extfile v3_ext.cnf -extensions v3_intermediate_ca
```

### Step 3 — Configure acme-proxy

Finally, point `acme-proxy` to your newly minted Intermediate CA. The
`cert_path` must contain the Intermediate certificate *followed by* the Root
certificate (the bundle), so clients can verify the full chain.

```bash
cat acme_intermediate.pem root_ca.pem > ca_bundle.pem
```

Update your `config.toml`:

```toml
[signer.local_ca]
cert_path = "ca_bundle.pem"
key_path = "acme_intermediate.key"
```

Now `acme-proxy` issues certificates signed by the Intermediate CA, mirroring a
standard enterprise PKI hierarchy.

> **The order inside the bundle is load-bearing.** The signing issuer is parsed
> from the **first** PEM block in `cert_path`; the remaining blocks are only
> appended to the chain served to clients. Concatenating root-first instead
> would not fail loudly — it would sign with the root's identity using the
> intermediate's key, producing certificates nothing can verify. Always `cat
> intermediate.pem root.pem`, never the reverse.

Two further caveats:

- Nothing checks that `key_path` actually corresponds to the certificate in
  `cert_path`. A mismatched pair produces unverifiable certificates rather than
  a startup error. (This caveat is specific to `key_source = "file"`; the
  [PKCS#11 path](local_ca_hsm.md) does verify the pair at startup.)
- The whole bundle is emitted with every issued certificate, root included. Most
  clients tolerate this, but if you would rather not ship the root, put only the
  intermediate in `cert_path` and distribute the root out of band — see
  [Trusting the CA](../getting_started/trusting_the_ca.md).
