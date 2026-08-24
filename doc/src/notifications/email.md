# Email Notifications

The `email` notification backend sends alerts via SMTP, using the `lettre` crate
to format and dispatch multipart messages.

## Delivery semantics
Notifications in `acme-proxy` are designed to be entirely non-blocking.
1. When an event occurs (e.g., a certificate is issued or revoked), the
   notification subsystem spawns a background Tokio task.
2. The task attempts to connect to the SMTP server and send the email.
3. **Fire and Forget**: If the delivery fails (e.g., the SMTP server is
   unreachable), `acme-proxy` logs an error at the `warn` level but does *not*
   retry. Notification failure does not cause the ACME transaction (like
   `finalize`) to fail.

## Template customization

By default, `acme-proxy` sends plain, functional emails rendered from templates
compiled into the binary. You can override any of them by setting
`notify.template_dir`.

The engine is **MiniJinja** and the files are `.j2`. Email needs **two** files
per event — one for the subject line and one for the body — under an `email/`
subdirectory of `template_dir`:

```text
/etc/acme-proxy/templates/
└── email/
    ├── certificate_issued.subject.j2
    └── certificate_issued.body.j2
```

Lookup is per file, so overriding one message leaves the rest at their defaults.
See [Customizing Templates](templates.md) for the full layout and the context
variables available to each event.

## Configuration

```toml
[notify]
enabled = ["email"]
# Note: the path is the templates root, NOT the email/ directory inside it —
# "email/" is appended by the loader.
template_dir = "/etc/acme-proxy/templates"

[notify.email]
smtp_host = "smtp.internal.corp"
smtp_port = 587
smtp_username = "acme_bot"
smtp_password = "super_secret_password"
smtp_security = "starttls"
from = "acme-proxy@internal.corp"
to = ["pki-admins@internal.corp", "security@internal.corp"]
events = ["certificate_issued", "certificate_revoked"]
timeout_ms = 5000
```

### Reference

`notify.enabled` and `notify.template_dir` are subsystem-wide keys documented in
[Notifications](index.md#reference). The keys below are specific to this
backend.

**`smtp_host`** (`String`) — *Default: `""` | Env: `ACME_PROXY_NOTIFY__EMAIL__SMTP_HOST`*

SMTP server hostname.

**`smtp_port`** (`Integer`) — *Default: `587` | Env: `ACME_PROXY_NOTIFY__EMAIL__SMTP_PORT`*

SMTP server port.

**`smtp_username`** (`String`) — *Default: `""` | Env: `ACME_PROXY_NOTIFY__EMAIL__SMTP_USERNAME`*

SMTP authentication username.

**`smtp_password`** (`String`) — *Default: `""` | Env: `ACME_PROXY_NOTIFY__EMAIL__SMTP_PASSWORD`*

SMTP authentication password. **Sensitive** — prefer the environment variable to
a file on disk, as with every other secret in the configuration.

**`smtp_security`** (`String`) — *Default: `"starttls"` | Env: `ACME_PROXY_NOTIFY__EMAIL__SMTP_SECURITY`*

TLS requirement: `"starttls"`, `"tls"`, or `"none"`.

**`from`** (`String`) — *Default: `""` | Env: `ACME_PROXY_NOTIFY__EMAIL__FROM`*

Sender email address.

**`to`** (`Array`) — *Default: `[]` | Env: `ACME_PROXY_NOTIFY__EMAIL__TO`*

List of recipient email addresses.

**`events`** (`Array`) — *Default: every event | Env: `ACME_PROXY_NOTIFY__EMAIL__EVENTS`*

Lifecycle events this backend reacts to.

**`timeout_ms`** (`Integer`) — *Default: `5000` | Env: `ACME_PROXY_NOTIFY__EMAIL__TIMEOUT_MS`*

Timeout budget for the SMTP exchange.
