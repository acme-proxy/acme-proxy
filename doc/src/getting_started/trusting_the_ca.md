# Trusting the CA

With the [`local_ca`](../signers/local_ca.md) signer, `acme-proxy` mints
certificates from a CA it generated itself. Those certificates are perfectly
valid, but nothing on your network trusts the CA that signed them yet — so
browsers, `curl`, and every TLS library will reject them until you install the
root.

This page covers distributing that root. It does not apply when you use the
[`acme_proxy`](../signers/acme_proxy.md) backend to relay to a public CA, whose
roots are already trusted everywhere.

## Getting the root certificate

The CA certificate is the file at `signer.local_ca.cert_path`, `ca.pem` by
default, in the server's working directory. Copy it from the server:

```bash
scp acme-host:/var/lib/acme-proxy/ca.pem ./internal-root.pem
```

Inspect it before distributing it:

```bash
openssl x509 -in internal-root.pem -noout -subject -issuer -dates -ext basicConstraints
```

A freshly generated root is self-signed (subject equals issuer) and carries
`CA:TRUE, pathlen:0`.

If `cert_path` holds a **bundle** — an intermediate followed by a root, as in
the [multi-tier
setup](../signers/local_ca.md#multi-tier-pki-using-an-intermediate-ca) — then
the *last* certificate in the file is the root, and it is the only one your
clients need to trust. The intermediate is shipped with every issued certificate
and does not need installing.

```bash
# Split a bundle into its constituent certificates.
csplit -z -f cert- -b '%02d.pem' ca_bundle.pem '/-----BEGIN CERTIFICATE-----/' '{*}'
```

## Installing it

### Debian / Ubuntu

The file **must** have a `.crt` extension, and must be PEM despite the name.

```bash
sudo cp internal-root.pem /usr/local/share/ca-certificates/acme-proxy-root.crt
sudo update-ca-certificates
```

### RHEL / Fedora / CentOS

```bash
sudo cp internal-root.pem /etc/pki/ca-trust/source/anchors/acme-proxy-root.pem
sudo update-ca-trust extract
```

### Alpine

```bash
sudo cp internal-root.pem /usr/local/share/ca-certificates/acme-proxy-root.crt
sudo update-ca-certificates
```

### Verify

```bash
curl -v https://internal.example.com 2>&1 | grep -i 'SSL certificate verify'
# or, without a server:
openssl verify -CAfile internal-root.pem issued-cert.pem
```

## Applications with their own trust store

Updating the system store is not enough for everything. These maintain their
own:

| Runtime | How to add the root |
| --- | --- |
| **Firefox** | Its own store, always. Settings → Privacy & Security → Certificates → View Certificates → Authorities → Import. Enterprise deployments can use the `Certificates` policy in `policies.json`. |
| **Chrome / Edge** | Uses the system store on Windows and macOS; on Linux it reads the NSS database — `certutil -d sql:$HOME/.pki/nssdb -A -t "C,," -n acme-proxy-root -i internal-root.pem`. |
| **Java / JVM** | `keytool -importcert -trustcacerts -alias acme-proxy-root -file internal-root.pem -keystore "$JAVA_HOME/lib/security/cacerts"`. |
| **Node.js** | Ignores the system store by default. Set `NODE_EXTRA_CA_CERTS=/path/to/internal-root.pem`. |
| **Python `requests`** | Uses `certifi`, not the system store. Set `REQUESTS_CA_BUNDLE` (or `SSL_CERT_FILE` for `ssl`/`urllib`). |
| **Go** | Uses the system store on Linux; no action needed after `update-ca-certificates`. |
| **Containers** | Each image has its own store. Mount the root in and run the distribution's update command in your `Dockerfile`, or bake it into a base image. |

## Distributing at scale

Installing a root by hand does not survive a fleet. In practice:

- **Ansible / Puppet / Chef** — ship the file and run the update command as a
  handler. This is the common approach for Linux estates.
- **Active Directory Group Policy** — Computer Configuration → Windows Settings
  → Security Settings → Public Key Policies → Trusted Root Certification
  Authorities.
- **MDM (Jamf, Intune, …)** — deploy as a certificate payload.
- **Golden images** — bake the root into your base image so new hosts trust it
  from first boot.

Whichever you use, deploy the root **before** you start issuing certificates
from it, or the first clients to renew will break.

## Revocation

If you revoke certificates, clients need to be able to see the CRL. It is served
unauthenticated at `{base_url}/profile/<name>/crl` as `application/pkix-crl`:

```bash
curl -o internal.crl https://acme.internal/profile/default/crl
openssl crl -in internal.crl -inform DER -noout -text
```

Note the CRL is not advertised in the ACME directory, and issued certificates do
not currently carry a CRL distribution point extension — so a client will not
find it automatically. Distribute the URL alongside the root if your validation
policy needs it. See [Revocation & CRL](../operations/revocation.md).

## Planning ahead

The root's validity is finite, and replacing it later means touching every host
that trusts it. Two things make that easier:

- **Use an intermediate.** Keep an offline root and hand `acme-proxy` only an
  intermediate. The root you distribute then long outlives any single signing
  key, and a compromised proxy costs you an intermediate rather than your whole
  trust anchor. See
  [Multi-Tier PKI](../signers/local_ca.md#multi-tier-pki-using-an-intermediate-ca).
- **Distribute early, rotate overlapping.** Trust stores accept multiple roots,
  so push a replacement root well before it is needed and remove the old one
  only after nothing is signed by it.
