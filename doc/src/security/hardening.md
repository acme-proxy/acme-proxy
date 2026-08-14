# Hardening Checklist

Run through this before an `acme-proxy` deployment issues a certificate anything
depends on. Every item links to the page that explains it; nothing here is
explained only here.

The defaults are already the safe end of most of these. The items that need a
decision from you are marked **decide**.

## Before it serves anything

- [ ] **`challenge.bypass` is `false`.** It is the default. With it on,
  `[filter]`
      is the only thing between a client and a certificate for any name it names.
      → [Challenge Validation](../challenges/index.md#bypass-is-not-a-shortcut)
- [ ] **At least one gate is configured** — filters, EAB, or both. Validation
      alone proves the client controls the name; it does not say the client is
      allowed to have a certificate from *you*.
      → [Filters](../filters/index.md), [EAB](../features/eab.md)
- [ ] **decide — `server.bind_address` is the interface you meant.** The default
      `[::]:3000` is every interface.
      → [Configuration Reference](../configuration/reference.md#server)
- [ ] **`server.base_url` matches how clients actually reach the server**,
      including the scheme. It is checked against the JWS `url` of every signed
      request, so a mismatch fails every request rather than degrading.
      → [Configuration Reference](../configuration/reference.md#server)
- [ ] **ACME is served over HTTPS** — either `server.tls.enabled = true` or a
      reverse proxy in front. RFC 8555 §6.1 expects it.
      → [TLS Termination](../features/tls_termination.md)
- [ ] **`acme-proxy filter explain` agrees with what you meant**, for both a
      client that should be served and one that should not. A policy is easier
      to get subtly wrong than a list.
      → [CLI](../operations/cli.md#access-policy)
- [ ] **`/crl` is still reachable** if any check is address-based. It is served
      by the profile router, so an allowlist covers it too, and the relying
      parties that fetch it are not the ACME clients you allowlisted.
      → [Path Check](../filters/path.md#the-crl-trap)

### An `or` is a hole you opened deliberately

A check that cannot reach its authority answers "unknown" rather than "no", and
`pass or unknown` is `pass`. That is the point — it is what keeps an inventory
outage from locking every client out — but it means **an `or` weakens the
fail-closed property to whatever its other side says**.

```toml
when = "mgmt-net or inventory"
```

reads as "the inventory decides, unless the address is already trusted". If
`mgmt-net` is wide, the inventory is decorative for everything inside it. That
may be exactly what you want; what you must not do is write it believing both
checks apply.

The rule of thumb: **an `or` over an address check is a bypass for that
address range**, so keep the range as small as the outage you are insuring
against. `and` has no such property — `fail and unknown` is `fail`, so a
conjunction never becomes more permissive because something broke.

## The CA key

- [ ] **decide — the issuing key is an intermediate, not a root.** An offline
  root
      means a compromise is recoverable by re-issuing the intermediate rather than
      re-trusting every endpoint.
      → [Local CA](../signers/local_ca.md#multi-tier-pki-using-an-intermediate-ca)
- [ ] **decide — the key lives in a PKCS#11 token** if the deployment justifies
      it. The key then cannot be copied, only used.
      → [Hardware Keys](../signers/local_ca_hsm.md)
- [ ] **`ca.key` is `0600` and owned by the service user.** `acme-proxy` creates
      it that way; a key restored from a backup may not be.
- [ ] **The CRL is reachable** by everything that validates your certificates,
      and `signer.local_ca.crl_path` is on durable storage — the JSON ledger
      beside it is the authoritative record, not the CRL itself.
      → [Revocation & CRL](../operations/revocation.md)

## Behind a proxy

- [ ] **`filter.trusted_proxies` names the hops you trust**, or the forwarded
      header is ignored entirely. Setting `filter.forwarded_header` alone does not
      make it trusted.
      → [Allowed IP](../filters/allowed_ip.md#client-ip-resolution--proxies)
- [ ] **The proxy does not forward `/health`** if you do not want it public — it
      is mounted outside the filter chain on purpose.
      → [Monitoring](../operations/monitoring.md#health-checks)
- [ ] **With `signer.relay.challenge_strategy = "http01"`**, port 80 of
  every
      name being issued forwards or redirects `/.well-known/acme-challenge/` here.
      Nothing in the process can do this for you.
      → [Relay](../signers/relay.md#deploying-the-http-01-responder)

## The web admin

Skip this section entirely if `admin.enabled` is `false`, which is the default.

- [ ] **`admin.bind_address` is loopback**, or `admin.tls.enabled` is `true` —
      startup refuses the other combination.
      → [Web Admin](../operations/webadmin.md#exposing-it)
- [ ] **decide — reach it over an SSH tunnel or a VPN** rather than exposing the
      socket. It has no filter chain and no admission control.
      → [Deployment](../getting_started/deployment.md#exposing-the-web-admin-or-rather-not)
- [ ] **`admin.base_url` is the origin operators actually type.** It is
      load-bearing four ways — the CSRF origin check, the generated certificate's
      host, and the label an authenticator app shows.
- [ ] **Every operator has a second factor**, and `admin.require_mfa = true` so
      the next one does too. It does not retroactively end sessions that predate
      it; `admin session revoke --all` does.
      → [Users & Sessions](../operations/webadmin_users.md#second-factor-totp)
- [ ] **Recovery codes are stored somewhere that is not the panel.** Without
      them, a lost authenticator needs `admin user totp reset` on the host.
      → [Users & Sessions](../operations/webadmin_users.md#recovery-codes)
- [ ] **No `--password` anywhere in your provisioning.** There is no such flag;
      the password arrives on stdin or via `--password-file`.
      → [Users & Sessions](../operations/webadmin_users.md#the-password-never-goes-in-argv)

## Secrets

- [ ] **Tokens and TSIG keys come from the environment, not the file** where the
      option exists — `ipam.netbox.token`,
      `signer.relay.dns01.rfc2136.tsig_key_secret`.
- [ ] **`[signer.relay.eab]` is emptied after the first registration.** It
  is
      a bootstrap credential that authorizes exactly one `newAccount`; the server
      warns on every startup for as long as it stays set.
      → [Relay](../signers/relay.md#eab-considerations)
- [ ] **`insecure_skip_verify` is unset.** It warns on every startup by design,
  so
      it stays visible for exactly as long as it is needed.
      → [NetBox](../ipam/netbox.md)
- [ ] **The database file is `0600`.** It holds EAB secrets and TOTP secrets in
  a
      form the server reads back, so anyone who can read the file can too.
      → [Database Schema](../dev/database.md#secrets-are-stored-three-different-ways-on-purpose)

## Ongoing

- [ ] **Backups copy the WAL.** `sqlite.db` alone is missing every recent write;
      use `.backup`, or take all three files.
      → [Database Schema](../dev/database.md#reading-it-directly)
- [ ] **decide — `audit.retention_days`.** `0`, the default, keeps everything
  for
      ever, which is the right default for a trail whose value is that it is
      complete.
      → [Audit Trail](../operations/audit.md#retention)
- [ ] **Something watches the logs for refusals** — `certificate_issue_failed`
      and `certificate_revoke_failed` rows, and a run of unknown-certificate
      revocation attempts, which is somebody enumerating serials.
      → [Monitoring](../operations/monitoring.md#suggested-alerts)
- [ ] **Startup warnings are read, not filtered out.** Three of them repeat on
      every start precisely so they cannot become background noise:
      `challenge_validation_bypassed`, `ipam_netbox_tls_verification_disabled`,
      `signer_relay_eab_secret_in_config`.
      → [Monitoring](../operations/monitoring.md#structured-events)
