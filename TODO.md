# TODO

## Global

### Main

- [ ] Support reloading config (SIGHUP)
- [ ] Support PostgreSQL
- [ ] Implement a worker for async tasks with persistence and retries

### Account

- [x] Add more security-related information (IP and reverse DNS) — in the
      database (`accounts.created_*`/`last_seen_*`, `orders.created_*`) and
      durably in `audit_log`
  - [ ] In the logs ! — still open, and the gap is the *access line*: the
        server-wide `request` span carries method/uri/request_id/profile but
        **not the client address**, so an ordinary request never names who
        connected. Only the audit rows and a few targeted lines
        (`admin_login_*`) do. The address is already resolved into
        `ClientIp` by the filter middleware, but that layer is per-profile and
        sits *inside* the span, so recording it wants either a
        `field::Empty` on the span filled in lower down (the `profile`
        pattern) or the peer address read in `access.rs` itself — the latter
        being the honest one, since `/health` and the http-01 responder sit
        outside every profile.

### Admin Commands

- [ ] Colorize standard output

### Web Admin

- [x] Explore feasibility of a Web Admin interface
  - [x] Create a REST API
    - [x] Second listener (`[admin]`, off by default, loopback, optional TLS)
    - [x] Accounts / Orders / EAB / nonces / profiles, with SQL pagination
    - [x] Its own error shape (`{error, message}`), never an ACME problem document
  - [ ] Authentification :
    - [ ] 2FA (Webauthn)
      - [ ] WebAuthn — **both checks were run, and it was deferred.**
            `webauthn-rs` 0.5.5 is MPL-2.0, which `deny.toml`'s allow list does
            not carry, and `webauthn-rs-core` hard-depends on
            `openssl`/`openssl-sys` (non-optional), which this tree has avoided
            at every turn. The 0.6.1-dev line drops OpenSSL for `crypto-glue`
            but is a `-dev` prerelease — the category already refused for
            htmx 4.x. Nothing here precludes it: another factor kind is another
            `MfaStep` variant and another branch in `verify_second_factor`, not
            a change to the state machine. The remaining choice is that
            dependency versus hand-rolling COSE/CBOR on `ring` + `ciborium`
            (Apache-2.0, already an allowed licence) with attestation `none`.
  - [x] Pages (minijinja + htmx, no npm) :
    - [ ] Certificates: show the issued chain, and offer it for download.
          `Order::to_json` has the URL but the panel never renders the PEM.
    - [ ] Live view of a pending order (poll `/ui/orders/{id}` with
          `hx-trigger="every 5s"`), so an operator can watch a challenge
          resolve instead of reloading.

### Prometheus /metrics

- [ ] Expose `requests` metric
- [ ] Expose `cert_delivery` metric
- [ ] Expose `cert_failure` metric
- [ ] Expose `database_pool_active_connections` metric
- [ ] Create a Grafana Dashboard

## Signers

### LocalCA

- [x] Support autogeneration customization (e.g., name) in the config file
- [X] Support using an HSM (eg. with a Yubikey)
- [ ] Support OCSP
- [ ] Purge expired CRTs from CRL
- [ ] Expose endpoints to serve `CA.crt`, `intermediate.crt`, and `crl` to ease client setup

## Filters

## IPAM

- [ ] Implement Netbox as an IPAM backend (generic implementation)
  - [ ] Support VRRP IP in Netbox
- [ ] Support phpIPAM as an IPAM backend

## Notification

- [ ] Create a generic webhook that implements: Slack, Telegram, Matrix, Teams
- [ ] Add notifications for certificates that will expire (e.g., one message per week)
  - [ ] Support sending renewal messages to the "account" email address
