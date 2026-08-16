# Customizing Templates

`acme-proxy` uses the [MiniJinja](https://docs.rs/minijinja/latest/minijinja/)
templating engine to render notification payloads. The server embeds sensible
default templates inside the binary, but you can override any of them by
pointing the server to a custom template directory.

## Enabling custom templates
In your `config.toml`, define a `template_dir`:

```toml
[notify]
enabled = ["email", "webhook"]
template_dir = "/etc/acme-proxy/templates"
```

The server will look in this directory before falling back to its embedded
defaults. You only need to create the files you want to override.

## Template file structure
Templates are grouped by backend and event name. Email requires separate files
for the subject line and body.

```text
/etc/acme-proxy/templates/
├── email/
│   ├── account_created.subject.j2
│   ├── account_created.body.j2
│   ├── certificate_issued.subject.j2
│   └── certificate_issued.body.j2
└── webhook/
    ├── certificate_issued.j2
    └── challenge_failed.j2
```

*(Available event names: `profile_mounted`, `account_created`,
`account_deactivated`, `certificate_issued`, `certificate_revoked`,
`challenge_failed`).*

A `webhook/<event>.j2` renders the **message**, not the payload: every
`[notify.webhook.<name>]` entry then wraps it in its own `body` template. So a
file here restyles the text for every webhook target at once, and an entry's
`body` restructures one target's request without touching the text. See
[Webhook](webhook.md#how-a-body-is-rendered).

## Context variables

When rendering a template, `acme-proxy` passes a context object containing the
event's data. All events include `profile` (the name of the profile triggered)
and most include `client_ip` (the IP address of the ACME client that initiated
the request).

### `certificate_issued`
Triggered when an order is finalized and the signer mints a certificate.
- `profile` (String)
- `order_id` (String)
- `account_id` (String)
- `cert_serial` (String) - Hex-encoded serial number
- `identifiers` (List of Strings) - The SANs/Domains requested
- `client_ip` (Option&lt;String&gt;)

**Example (`webhook/certificate_issued.j2`)**:
```jinja
✅ **Certificate Issued** on profile `{{ profile }}`
**Domains:** {{ identifiers | join(", ") }}
**Serial:** `{{ cert_serial }}`
**Requested By IP:** `{{ client_ip | default("system") }}`
```

### `challenge_failed`
Triggered when an HTTP-01 or DNS-01 validation attempt fails.
- `profile` (String)
- `order_id` (String)
- `account_id` (String)
- `authz_id` (String)
- `challenge_id` (String)
- `challenge_type` (String) - e.g. "http-01"
- `identifier` (String) - The domain that failed
- `error` (String) - The detailed error from the validation attempt
- `client_ip` (Option&lt;String&gt;)

### `account_created` / `account_deactivated`
Triggered on account lifecycle events.
- `profile` (String)
- `account_id` (String)
- `contact` (List of Strings) - e.g. `["mailto:admin@example.com"]` *(only on
  created)*
- `client_ip` (Option&lt;String&gt;)

### `certificate_revoked`
Triggered via the ACME API or Admin CLI.
- `profile` (String)
- `order_id` (String)
- `account_id` (String)
- `cert_serial` (String)
- `reason` (Option&lt;Integer&gt;) - RFC 5280 revocation reason code
- `client_ip` (Option&lt;String&gt;)

### `profile_mounted`
Triggered during server startup when a profile is successfully initialized.
- `profile` (String)
