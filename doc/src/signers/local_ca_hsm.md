# Hardware Keys (PKCS#11)

By default the Local CA's issuing key is a PEM file on disk, protected by
nothing but its `0600` permissions. `key_source = "pkcs11"` moves that key into
a hardware token — a YubiKey, a network HSM, or SoftHSM2 for development — where
it is created once and can never be read back out. `acme-proxy` sends the token
the bytes to be signed and receives a signature; the private key never enters
this process's memory.

PKCS#11 rather than a vendor-specific PIV library, so a YubiKey today and an
enterprise HSM tomorrow are the same configuration with a different
`module_path`.

## What this protects, and what it does not

Everything else about the Local CA is unchanged: the same
[CSR sanitisation](local_ca.md#security-constraints), the same
`leaf_validity_days` clamping, the same CRL and revocation ledger. Only *where
the signature comes from* moves.

It protects **the CA issuing key** — the one that, if stolen, lets an attacker
mint certificates your fleet trusts. It does **not** protect the ACME account
keys, the TLS server key (`server.tls.key_path`), or the database; those stay on
disk.

## Requirements

- **A build with the `hsm` feature.** It is off by default, so the stock binary
  does not have it and `key_source = "pkcs11"` on one is a startup error naming
  the feature:

  ```bash
  cargo build --release --features hsm
  ```

- **A PKCS#11 module** (`.so`), loaded at runtime — nothing is linked at build
  time.
- **An existing CA certificate**, for the reason below.

## Two rules that differ from the software path

Both are startup errors, so you will meet them immediately rather than in
production.

### The CA is never generated

With `key_source = "file"`, a missing `cert_path`/`key_path` means "generate a
CA and write it here". With `key_source = "pkcs11"` there is no such thing: the
private key is created inside the token by its own tooling, and this server
cannot produce one that a token would then hold. So `cert_path` **must already
exist**, and `key_path` is neither read nor written.

Both walkthroughs below cover creating that certificate.

### The key and the certificate are cross-checked

At startup, the token key's `SubjectPublicKeyInfo` is compared against the one
in `cert_path`. A mismatch — almost always a wrong `key_label` — stops the
server.

This is **stricter than the file path**, where (as
[Local CA](local_ca.md#multi-tier-pki-using-an-intermediate-ca) warns) nothing
checks that `key_path` corresponds to `cert_path`, and a mismatched pair simply
produces certificates that verify nowhere. Here a typo is caught before the
first certificate is issued rather than discovered by a client days later.

## Reference

**`key_source`** (`String`)
*Default: `"file"` | Env: `ACME_PROXY_SIGNER__LOCAL_CA__KEY_SOURCE`*
Where the issuing private key lives. `"file"` is the historical behaviour and
the default; `"pkcs11"` reads the table below. Any other value is a startup
error — there is deliberately no silent fallback, since falling back would hand
an operator who asked for hardware a software key with no indication of it.

**`pkcs11.module_path`** (`String`)
*Default: `""` | Env: `ACME_PROXY_SIGNER__LOCAL_CA__PKCS11__MODULE_PATH`*
The PKCS#11 module to load. Required. See each walkthrough for the usual paths.

**`pkcs11.token_label`** (`String`)
*Default: `""` | Env: `ACME_PROXY_SIGNER__LOCAL_CA__PKCS11__TOKEN_LABEL`*
Which token to use, by label. Preferred over `slot_id`: slot numbers are
assigned dynamically and change across reboots and re-plugs on most drivers
(SoftHSM2 will hand you something like `276468771`).

**`pkcs11.slot_id`** (`Integer`)
*Default: unset | Env: `ACME_PROXY_SIGNER__LOCAL_CA__PKCS11__SLOT_ID`*
Which slot to use, for tokens with no usable label. Consulted only when
`token_label` is empty.

**`pkcs11.key_label`** (`String`)
*Default: `""` | Env: `ACME_PROXY_SIGNER__LOCAL_CA__PKCS11__KEY_LABEL`*
The private key's `CKA_LABEL`. Required. On a YubiKey the labels are fixed by
the driver, so this is something you look up rather than choose — see below.

**`pkcs11.key_id`** (`String`)
*Default: `""` | Env: `ACME_PROXY_SIGNER__LOCAL_CA__PKCS11__KEY_ID`*
The key's `CKA_ID` as hex (`01`, or `01:ff`), to disambiguate a token holding
several keys under one label. Optional; two keys sharing a label and no `key_id`
to separate them is a startup error rather than a coin flip.

**`pkcs11.pin_file`** (`String`)
*Default: `""` | Env: `ACME_PROXY_SIGNER__LOCAL_CA__PKCS11__PIN_FILE`*
A file holding the user PIN. Trailing whitespace is trimmed, so a PIN written
with `echo` works. The file is checked for permissions and warns if it is
world-readable, exactly as `ca.key` does.

**`pkcs11.pin`** (`String`)
*Default: `""` | Env: `ACME_PROXY_SIGNER__LOCAL_CA__PKCS11__PIN`*
**SENSITIVE.** The PIN directly. Prefer `pin_file`, or set this through the
environment variable; a PIN in `config.toml` is a long-lived secret in a file
that tends to get copied around. `pin_file` wins when both are set, and having
neither is a startup error.

> **A PIN is not a password.** Tokens block after a small number of wrong
> attempts — three on a YubiKey PIV applet, after which you need the PUK. This
> is why `acme-proxy` retries a failed signature at most **once**, and why the
> trailing newline in your PIN file is worth getting right.

---

## Walkthrough A — SoftHSM2

SoftHSM2 is a software token: no hardware needed, and the same setup the project
uses in CI. Use it to try the feature before committing to hardware.

```bash
# Debian/Ubuntu
sudo apt install softhsm2
# Arch
sudo pacman -S softhsm
```

### 1. Create a token

```bash
softhsm2-util --init-token --free --label acme-ca --so-pin 3737 --pin 1234
```

`--free` takes the first uninitialised slot. Note that the token is reassigned
to a *new* slot number afterwards — which is exactly why `token_label` is the
selector to use, not `slot_id`.

### 2. Create the CA key and certificate

The key must exist inside the token, and `cert_path` must hold a certificate
for it. For SoftHSM2 the simplest route is to generate both locally, import the
key, and destroy the local copy:

```bash
# The CA key and its self-signed certificate
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out ca.key

openssl req -x509 -new -key ca.key -sha256 -days 3650 -out ca.pem \
  -subj "/CN=Example Corp Issuing CA/O=Example Corp" \
  -addext "basicConstraints=critical,CA:true,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"

# Move the key into the token, then remove it from disk
softhsm2-util --import ca.key --token acme-ca --label ca-key --id 01 --pin 1234
shred -u ca.key
```

> For a real HSM, generate the key **in the token** instead so it never exists
> outside it — `pkcs11-tool --module <module> --token-label acme-ca --login
> --keypairgen --key-type EC:prime256v1 --label ca-key --id 01` (from the
> `opensc` package), then certify that public key with your offline root. The
> import above is a development convenience, and the reason it is acceptable
> here is that a SoftHSM2 token is a directory of files anyway.

`pathlen:0` matches what the Local CA generates for itself: it may issue leaves
but no further CAs.

### 3. Configure

```toml
[signer]
backend = "local_ca"

[signer.local_ca]
cert_path  = "ca.pem"
crl_path   = "ca.crl"
key_source = "pkcs11"

[signer.local_ca.pkcs11]
module_path = "/usr/lib/softhsm/libsofthsm2.so"
token_label = "acme-ca"
key_label   = "ca-key"
pin_file    = "/etc/acme-proxy/hsm.pin"
```

```bash
printf '1234' > /etc/acme-proxy/hsm.pin
chmod 600 /etc/acme-proxy/hsm.pin
```

If SoftHSM2's token store is not in its default location, `SOFTHSM2_CONF` must
be set in the server's environment — it is read by the module, not by
`acme-proxy`.

### 4. Confirm it is really using the token

```bash
RUST_LOG=info acme-proxy serve
```

```text
INFO acme_proxy::signer::local_ca::pkcs11: the local CA's issuing key is on a PKCS#11 token
  event="local_ca_pkcs11_opened" module=/usr/lib/softhsm/libsofthsm2.so
  slot=276468771 key_label=ca-key algorithm=PKCS_ECDSA_P256_SHA256
  mechanism=CKM_ECDSA_SHA256
INFO acme_proxy::signer::local_ca: event="local_ca_pkcs11_loaded" cert_path="ca.pem" key_label=ca-key
```

`local_ca_pkcs11_opened` is the line that proves it: it names the module, the
slot the token actually landed in, the curve read off the key, and the mechanism
chosen. If you see `local_ca_loaded` or `local_ca_generated` instead, the
configuration is still on the file path.

Then issue something and check it chains:

```bash
openssl verify -CAfile ca.pem /path/to/issued/cert.pem
# cert.pem: OK
```

---

## Walkthrough B — YubiKey (`libykcs11`)

A YubiKey 5 exposes its PIV applet through `libykcs11`, shipped with
`yubico-piv-tool`.

```bash
# Debian/Ubuntu → /usr/lib/x86_64-linux-gnu/libykcs11.so
sudo apt install yubico-piv-tool
# Arch → /usr/lib/libykcs11.so
sudo pacman -S yubico-piv-tool
```

Both paths are in circulation; check which one you have before configuring
`module_path`.

### 1. Generate the key and certificate on the device

Use slot **9c** (Digital Signature). Its PIV policy requires the PIN for
*every* private-key operation, which is the right posture for a CA key and the
reason to prefer it over 9a.

```bash
# Generate the key inside the YubiKey — it never leaves
yubico-piv-tool -s 9c -a generate -A ECCP256 -o ca_pub.pem

# Self-sign a certificate for it, on the device
yubico-piv-tool -s 9c -a verify-pin -a selfsign-certificate \
  -S '/CN=Example Corp Issuing CA/O=Example Corp/' \
  --valid-days 3650 -i ca_pub.pem -o ca.pem

# Store the certificate in the slot as well (optional, but conventional)
yubico-piv-tool -s 9c -a import-certificate -i ca.pem
```

Copy `ca.pem` to wherever `cert_path` points.

> **Touch policy must be `never` for the CA slot.** If the slot is provisioned
> to require a touch, *every issuance blocks until somebody physically touches
> the key*. That is correct for an offline root and catastrophic for an ACME
> server expected to issue unattended.

### 2. Find the key label

You do not choose the label on a YubiKey — `libykcs11` assigns fixed ones per
PIV slot. Read it off the device:

```bash
pkcs11-tool --module /usr/lib/libykcs11.so --list-objects --login
```

Slot 9c reports as `Private key for Digital Signature`; 9a as `Private key for
PIV Authentication`. Use that string verbatim.

### 3. Configure

```toml
[signer.local_ca]
cert_path  = "ca.pem"
crl_path   = "ca.crl"
key_source = "pkcs11"

[signer.local_ca.pkcs11]
module_path = "/usr/lib/libykcs11.so"
token_label = "YubiKey PIV #12345678"
key_label   = "Private key for Digital Signature"
pin_file    = "/etc/acme-proxy/hsm.pin"
```

The PIN is the **PIV PIN** (factory default `123456`), not the PIV management
key and not the FIDO PIN.

### 4. Expect `CKM_ECDSA`

`libykcs11` does not offer `CKM_ECDSA_SHA256`, so `acme-proxy` computes the
SHA-256 digest itself and asks the token to sign that. The startup line reads:

```text
mechanism=CKM_ECDSA+SHA256
```

This is normal and not a downgrade — the same signature, with the hashing done
on this side of the USB cable.

### Performance

A YubiKey signature takes roughly 50–300 ms, and signings are serialised by a
mutex. That is comfortable for hundreds of certificates a day and is not a
throughput solution; the signing call runs on the blocking thread pool, so it
does not stall the rest of the server while it waits. For higher volumes use a
networked HSM, or the [Custom Script](custom.md) signer against a KMS.

---

## Operations

### Backup and disaster recovery

**The key cannot be backed up.** That is the point of the feature, and it makes
recovery something to plan *before* you need it. Two workable approaches:

- **Two tokens, one offline root.** Keep an offline root CA, use it to certify
  an intermediate held on each of two tokens, and hand `acme-proxy` one of them.
  A lost token is replaced by provisioning a new intermediate; clients trust the
  root and never notice. See
  [Multi-Tier PKI](local_ca.md#multi-tier-pki-using-an-intermediate-ca).
- **Accept re-enrolment.** For a small internal fleet, losing the CA and
  distributing a new one is survivable — just make sure it is a decision rather
  than a discovery.

Back up `crl_path` and its `.json` ledger sidecar as before; those are ordinary
files, and the ledger is what makes revocations durable.

### When the token disappears

If the session drops — the YubiKey is unplugged, a network HSM times out —
`acme-proxy` reopens the session, logs back in and retries the signature **once**.
The relevant log lines are `local_ca_pkcs11_session_lost` followed by either a
successful issuance or `local_ca_pkcs11_reconnect_failed`.

If that fails, finalize requests return `serverInternal` (500) and clients
retry, which is the right behaviour: the order stays valid and issuance resumes
once the token is back. `GET /crl` keeps working throughout — the current CRL is
held in memory and serving it signs nothing.

### Sharing one token between profiles

Several [profiles](../core/profiles.md) may use the same module, and even the
same key. `acme-proxy` opens one PKCS#11 context per module for the whole
process and shares it, so this works without special configuration. Two profiles
naming the same token key with *otherwise different* signer settings is refused
at startup, for the same reason two profiles sharing `ca.key` are: each would
keep its own revocation ledger and overwrite the other's CRL.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `key_source = "pkcs11"` … `built without` | The binary has no PKCS#11 support. Rebuild with `--features hsm`. |
| `CKR_PIN_INCORRECT` at startup | Usually a stray character in `pin_file`. Trailing newlines are trimmed, but leading or embedded whitespace is not. Check with `xxd`. **Do not retry blindly** — see the PIN warning above. |
| `CKR_PIN_LOCKED` | Too many wrong attempts. A YubiKey PIV PIN is unblocked with the PUK (`yubico-piv-tool -a unblock-pin`). |
| `is not the key certified by …` | The SPKI cross-check failed: `key_label`/`key_id` resolve to a different key than `cert_path` describes. List the token's objects and compare. |
| `no PKCS#11 token labelled …` | The label is wrong, or the token is not plugged in. The message lists the labels actually present. |
| `N PKCS#11 private keys are labelled …` | Set `key_id` to pick one. |
| `unsupported PKCS#11 curve` | Only P-256 and P-384 are supported. The message prints the `CKA_EC_PARAMS` it found. |
| `supports neither … nor CKM_ECDSA` | The token cannot do ECDSA signing at all, or will not report its mechanisms. |
| Certificates that verify nowhere | Should not happen — the SPKI cross-check catches the usual cause at startup. If it does, capture the `local_ca_pkcs11_opened` line and the failing certificate and open an issue. |

See also [Maintenance & Troubleshooting](../operations/troubleshooting.md).
