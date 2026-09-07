# Secret Rotation

The [Hardening Checklist](hardening.md) is run once, before a deployment issues
a certificate anything depends on. This page is the other half: what to do on a
schedule after that. Every secret in the Security Model's
[inventory](index.md#what-each-secret-protects) is here, with a recommended
interval and the events that force a rotation early.

The intervals are a starting point, not a protocol requirement — adjust them to
what the deployment is worth to an attacker. Nothing in `acme-proxy` expires
these on a timer: rotation is an operator action, except for the session cookie,
which ages out on its own.

## The schedule

| Secret | Rotate every | Rotate now when | How |
| --- | --- | --- | --- |
| The CA issuing key | not on a timer — see [below](#the-ca-key-is-the-exception) | the root or intermediate key may have been exposed; someone who could read it leaves | re-issue the intermediate from the offline root — [Local CA](../signers/local_ca.md#multi-tier-pki-using-an-intermediate-ca) |
| An EAB HMAC secret | 12 months, per credential | the client system is rebuilt; the person who held it leaves | `acme-proxy eab revoke <kid>`, then `eab create` for the replacement — [CLI](../operations/cli.md#external-account-binding-eab) |
| The upstream ACME account key | not on a timer | the disk may have been read; the relay profile is being decommissioned | register a fresh upstream account — new `account_key_path`, delete the `.kid` sidecar, restart — [CLI](../operations/cli.md#upstream-account-management) |
| An RFC 2136 TSIG key | 12 months, with whoever runs the zone | anyone with the zone's write path leaves; an update you did not make appears in the nameserver log | add the new key on the nameserver, update `signer.relay.dns01.rfc2136.tsig_key_secret` in the environment, `SIGHUP` — [Relay](../signers/relay.md#dns01-rfc-2136-tsig) |
| A web admin password | not on a timer, by design | it was shared, phished, or typed into the wrong window; the operator leaves | `acme-proxy admin user passwd <user>` — it also ends every session that user holds — [Users & Sessions](../operations/webadmin_users.md#changing-your-own-password) |
| A web admin session cookie | rotates itself — `admin.session_ttl_seconds` (12 h absolute), and the idle timeout | a laptop is lost; a session is suspected stolen | `acme-proxy admin session revoke --user <u>`, or `--all` — [Users & Sessions](../operations/webadmin_users.md#sessions) |
| A TOTP secret | not on a timer | the authenticator device is lost or replaced | `acme-proxy admin user totp reset <user>` — it takes the recovery codes and the sessions with it — [Users & Sessions](../operations/webadmin_users.md#second-factor-totp) |
| Recovery codes | regenerate when few remain | one has been used in anger; the printed or stored copy is exposed | `acme-proxy admin user totp recovery-codes <user>` — [Users & Sessions](../operations/webadmin_users.md#recovery-codes) |
| An IPAM API token | 12 months, or whatever the IPAM's own policy says | the token appears in a log or a ticket; an operator with IPAM access leaves | issue a new read-only token, update `ipam.netbox.token` (or `ipam.phpipam.token`) in the environment, `SIGHUP` — [NetBox](../ipam/netbox.md#authenticating) |

Only the session cookie expires on its own — an absolute lifetime and an idle
timeout, whichever comes first. The password deliberately has no forced periodic
change: an operator's stored hash is re-encoded on their next login when the KDF
cost rises, so there is nothing a scheduled reset would achieve. Everything else
is a manual cadence because nothing revokes it for you.

## The CA key is the exception

Losing the CA key is not something rotation recovers from. Every certificate it
signed stays trusted until the CA itself is distrusted everywhere, and there is
no audit row for a signature made outside this server. So the practice for this
one key is structural rather than scheduled.

- **Give `acme-proxy` an intermediate, not a root, and keep the root offline.**
  A compromise of the online key is then recoverable by re-issuing the
  intermediate rather than by re-trusting every endpoint in the fleet. See
  [Local CA](../signers/local_ca.md#multi-tier-pki-using-an-intermediate-ca) and
  its [security constraints](../signers/local_ca.md#security-constraints).
- **Re-issue the intermediate from the root before it expires.** Doing it on a
  calendar, well ahead of the `notAfter`, keeps the recovery path exercised
  rather than theoretical.
- **Rotating the root is a multi-year event.** Distribute the replacement long
  before it is needed, run both roots in the trust store, and remove the old one
  only once nothing is signed by it. See
  [Trusting the CA](../getting_started/trusting_the_ca.md#planning-ahead).
- **An actual key compromise is a distrust-and-reissue event, not a rotation.**
  Publish the revocation, pull the root, and re-issue what mattered under the
  new one. See
  [Trusting the CA](../getting_started/trusting_the_ca.md#revocation).

## Rotating a secret that lives in the environment

The TSIG key and the IPAM token belong in environment variables rather than in
`config.toml`, and so does the relay's bootstrap EAB secret until the first
registration clears it — the [Hardening Checklist](hardening.md#secrets) says
which. Rotating one of these is the same three steps every time.

- Stage the new value on the system that backs it — a second TSIG key on the
  nameserver, a fresh token in NetBox or phpIPAM — so that both the old and the
  new one work for a moment.
- Update the environment and send `SIGHUP` (or `systemctl reload`). The
  `[signer]` and `[ipam]` sections both reload with no restart and no dropped
  request. See
  [Reloading the configuration](../operations/reload.md#what-a-reload-does-change).
- Confirm from the logs, or from a test issuance, that the new credential is the
  one in use, then retire the old value on the far side.

The EAB HMAC secrets and the TOTP secrets are held in the database in a form the
server reads back, so a rotation does not remove the need to protect the file
itself — file mode is the boundary. See
[Database Schema](../dev/database.md#secrets-are-stored-three-different-ways-on-purpose).
